#!/bin/bash
# Runs one agent command in a sandbox. Called by core.py as root inside `unshare -m -p -f --mount-proc`.
# Env: RV_ENG, RV_UID, RV_HOME, RV_SRC (newline-separated /src paths in scope), RV_CMD.
# The command sees only its own engagement folder and in-scope source (read-only), with SCOPE.md and RULES.md
# replaced by the authoritative read-only copies and the kit's state folder (.rv) read-only, and runs as the engagement's unprivileged user with only
# CAP_NET_RAW (ambient, for nmap). no_new_privs blocks setuid escalation. Git trusts every repository (the
# client code under /src is owned by another user; without this, history scans such as gitleaks git silently
# scan nothing; a hostile repo config can only run code as this same sandboxed user). The firewall (nftables, by
# uid) limits its network to the engagement scope.
set -euo pipefail
# The kit's state folder (.rv: findings.db) is made here, as root, before agent code first runs, and mounted
# read-only below. Older kits kept findings.db in the engagement folder itself: move it in (the same rule as
# harness/findings_db.py adopt_state, under the same lock on the engagement folder).
eng="/work/$RV_ENG"
if [ -L "$eng/.rv" ] || { [ -e "$eng/.rv" ] && [ ! -d "$eng/.rv" ]; }; then
  echo "rv-sandbox: $eng/.rv is not the kit's state folder; refusing to run" >&2; exit 126; fi
if [ ! -d "$eng/.rv" ]; then
  flock "$eng" sh -c 'd="$1/.rv"; [ -d "$d" ] && exit 0; mkdir -p "$d"
    for f in findings.db findings.db-journal findings.db-wal findings.db-shm; do
      [ -f "$1/$f" ] && [ ! -L "$1/$f" ] && [ ! -e "$d/$f" ] && mv "$1/$f" "$d/$f"; done; exit 0' _ "$eng"
fi
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
mount --bind "/work/$RV_ENG/.rv" "/work/$RV_ENG/.rv"; mount -o remount,bind,ro "/work/$RV_ENG/.rv"
for f in SCOPE.md RULES.md; do
  [ -e "/work/$RV_ENG/$f" ] || : > "/work/$RV_ENG/$f"
  mount --bind "/control/eng/$RV_ENG/$f" "/work/$RV_ENG/$f"; mount -o remount,bind,ro "/work/$RV_ENG/$f"
done
mkdir -p "$RV_HOME/.cache"; [ "$(stat -c %u "$RV_HOME")" = "$RV_UID" ] || chown -R "$RV_UID:$RV_UID" "$RV_HOME"
mount -t tmpfs tmpfs /control
mount -t tmpfs -o mode=1777 tmpfs /tmp
umount -R "$stage/eng"; for e in "${srcs[@]}"; do umount -R "$stage/src/${e%%:*}"; done
mount -t tmpfs tmpfs /run
# A fresh home for every command: dotfiles that agent code wrote in an earlier command (.bash_profile, .curlrc,
# .gitconfig, tool configs) must not run or reconfigure a later one, an approved command included. Only the cache
# folder persists (XDG_CACHE_HOME, in the engagement's .home).
home=/run/home; mkdir -p "$home"; ln -s /opt/nuclei-templates "$home/nuclei-templates"; chown -R "$RV_UID:$RV_UID" "$home"

cd "/work/$RV_ENG"
# credentials of this engagement (./rvkit cred), for commands that use $RV_CRED_<NAME>
creds=()
while IFS= read -r v; do [ -n "$v" ] && creds+=("$v=${!v}"); done < <(compgen -e | grep -E '^(RV_CRED_|RV_BROWSER_SESSION$)' || true)
exec setpriv --reuid="$RV_UID" --regid="$RV_UID" --clear-groups \
  --inh-caps=-all,+net_raw --ambient-caps=-all,+net_raw --bounding-set=-all,+net_raw --no-new-privs \
  env -i HOME="$home" XDG_CACHE_HOME="$RV_HOME/.cache" USER="rv-$RV_UID" LANG=C.UTF-8 TERM=dumb \
      PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
      NMAP_PRIVILEGED=1 SEMGREP_SEND_METRICS=off \
      GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0='*' \
      ${creds[@]+"${creds[@]}"} \
  bash --noprofile --norc -c "$RV_CMD"
