#!/bin/bash
# Runs one agent command in a sandbox. Called by core.py as root inside `unshare -m -p -f --mount-proc`.
# Env: RV_ENG, RV_UID, RV_HOME, RV_SRC (newline-separated /src paths in scope), RV_CMD.
# The command sees only its own engagement folder and in-scope source (read-only), with SCOPE.md and RULES.md
# replaced by the authoritative read-only copies, and runs as the engagement's unprivileged user with only
# CAP_NET_RAW (ambient, for nmap). no_new_privs blocks setuid escalation. Git trusts every repository (the
# client code under /src is owned by another user; without this, history scans such as gitleaks git silently
# scan nothing; a hostile repo config can only run code as this same sandboxed user). The firewall (nftables, by
# uid) limits its network to the engagement scope.
set -euo pipefail
mount --make-rprivate /
stage=/run/rvns; mkdir -p "$stage/eng" "$stage/src"
mount --bind "/work/$RV_ENG" "$stage/eng"
i=0; srcs=()
while IFS= read -r p; do
  [ -n "$p" ] && [ -d "$p" ] || continue
  i=$((i+1)); mkdir -p "$stage/src/$i"; mount --bind "$p" "$stage/src/$i"; srcs+=("$i:$p")
done <<< "${RV_SRC:-}"

mount -t tmpfs -o mode=755 tmpfs /work
mkdir -p "/work/$RV_ENG"; mount --bind "$stage/eng" "/work/$RV_ENG"
mount -t tmpfs -o mode=755 tmpfs /src
for e in "${srcs[@]}"; do
  n="${e%%:*}"; p="${e#*:}"
  mkdir -p "$p"; mount --bind "$stage/src/$n" "$p"; mount -o remount,bind,ro "$p"
done
for f in SCOPE.md RULES.md; do
  [ -e "/work/$RV_ENG/$f" ] || : > "/work/$RV_ENG/$f"
  mount --bind "/control/eng/$RV_ENG/$f" "/work/$RV_ENG/$f"; mount -o remount,bind,ro "/work/$RV_ENG/$f"
done
mkdir -p "$RV_HOME"; [ "$(stat -c %u "$RV_HOME")" = "$RV_UID" ] || chown "$RV_UID:$RV_UID" "$RV_HOME"
[ -e "$RV_HOME/nuclei-templates" ] || ln -s /opt/nuclei-templates "$RV_HOME/nuclei-templates"
mount -t tmpfs tmpfs /control
mount -t tmpfs -o mode=1777 tmpfs /tmp
umount -R "$stage/eng"; for e in "${srcs[@]}"; do umount -R "$stage/src/${e%%:*}"; done
mount -t tmpfs tmpfs /run

cd "/work/$RV_ENG"
exec setpriv --reuid="$RV_UID" --regid="$RV_UID" --clear-groups \
  --inh-caps=-all,+net_raw --ambient-caps=-all,+net_raw --bounding-set=-all,+net_raw --no-new-privs \
  env -i HOME="$RV_HOME" USER="rv-$RV_UID" LANG=C.UTF-8 TERM=dumb \
      PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
      NMAP_PRIVILEGED=1 SEMGREP_SEND_METRICS=off \
      GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0='*' \
  bash -lc "$RV_CMD"
