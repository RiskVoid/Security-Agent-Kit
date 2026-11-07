"""Admin commands for the kali-mcp control plane. Run on the host through ./rvkit (docker compose exec).

  rvctl.py sync <eng> [--yes]        import /work/<eng>/SCOPE.md + RULES.md as authoritative (shows diff first)
  rvctl.py show <eng>                active scope and rules
  rvctl.py approvals <eng>           pending approvals
  rvctl.py approve|deny <eng> <id>   decide an approval
  rvctl.py halt|resume <eng>         stop all running commands and block new ones / allow again
  rvctl.py audit [eng] [n]           last n audit entries (authoritative log)
  rvctl.py close <eng>               export audit extract, SHA-256 manifest, archive to _archive/, halt
  rvctl.py apply                     rebuild firewall + DNS for all engagements
"""
import json, os, sys
import core


def main(a):
    if not a:
        print(__doc__); return 1
    cmd, rest = a[0], a[1:]
    if cmd == "sync":
        eng, yes = rest[0], "--yes" in rest
        new = eng not in core.registry()
        d = core.diff(eng)
        if not new and not d:
            print(f"{eng}: no changes"); return 0
        print(f"{'New engagement' if new else 'Changes to'} {eng}:\n{d}")
        if not yes:
            print("\nNot applied. Review the diff, then re-run with --yes."); return 2
        for w in core.sync(eng):
            print("warning:", w)
        print(f"applied. {eng} uses uid {core.registry()[eng]}"); return 0
    if cmd == "show":
        print(json.dumps(core.info(rest[0]), indent=1)); return 0
    if cmd == "approvals":
        rows = core.approvals(rest[0], "pending")
        for r in rows:
            print(f"{r['id']}  [{r['tier']}]  {r['command']}")
        print(f"{len(rows)} pending"); return 0
    if cmd in ("approve", "deny"):
        r = core.decide(rest[0], rest[1], cmd == "approve")
        print(f"{r['id']} {r['status']}: {r['command']}"); return 0
    if cmd in ("halt", "resume"):
        core.halt(rest[0], cmd == "halt")
        print(f"{rest[0]}: {'halted (running commands killed)' if cmd == 'halt' else 'resumed'}"); return 0
    if cmd == "audit":
        eng = rest[0] if rest and not rest[0].isdigit() else None
        n = int(rest[-1]) if rest and rest[-1].isdigit() else 20
        lines = open(core.AUDIT).read().splitlines() if os.path.exists(core.AUDIT) else []
        lines = [l for l in lines if not eng or json.loads(l).get("engagement") == eng]
        print("\n".join(lines[-n:])); return 0
    if cmd == "close":
        r = core.close(rest[0])
        print(f"{rest[0]} closed and halted. {r['files']} files hashed into MANIFEST.sha256\n"
              f"archive: {r['archive']}\nsha256:  {r['sha256']}"); return 0
    if cmd == "apply":
        core.apply_network(); print("network policy applied"); return 0
    print(__doc__); return 1


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except (ValueError, IndexError, FileNotFoundError) as e:
        print("error:", e or "missing argument", file=sys.stderr); sys.exit(1)
