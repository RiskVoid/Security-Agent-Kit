"""Admin commands for the kali-mcp control plane. Run on the host through ./rvkit (docker compose exec).

  rvctl.py sync <eng> [--yes]        import /work/<eng>/SCOPE.md + RULES.md as authoritative (shows diff first)
  rvctl.py show <eng>                active scope and rules
  rvctl.py approvals [eng] [--json]  pending approvals (all engagements if none given)
  rvctl.py list [--json]             engagements: scope summary, halt state, pending approvals
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
    if cmd == "approvals":  # approvals [eng] [--json]: one engagement, or all of them
        as_json = "--json" in rest
        engs = [a for a in rest if a != "--json"][:1] or core.engagements()
        rows = [dict(r, engagement=e) for e in engs for r in core.approvals(e, "pending")]
        if as_json:
            print(json.dumps(rows)); return 0
        for r in rows:
            print(f"{r['engagement']}  {r['id']}  [{r['tier']}]  {r['command']}")
        print(f"{len(rows)} pending"); return 0
    if cmd == "list":  # list [--json]: engagements with scope summary, halt state and pending approvals
        rows = []
        for e in core.engagements():
            i = core.info(e)
            rows.append({"engagement": e, "halted": i["halted"], "tiers": i["rules"]["tiers"],
                         "network": i["rules"]["network"], "worker": i["rules"].get("worker", "auto"),
                         "targets": i["scope"]["nets"] + i["scope"]["domains"] + i["scope"]["paths"],
                         "pending": len(core.approvals(e, "pending"))})
        if "--json" in rest:
            print(json.dumps(rows)); return 0
        for r in rows:
            t = ", ".join(r["targets"][:4]) + (f" +{len(r['targets']) - 4}" if len(r["targets"]) > 4 else "")
            flags = (" HALTED" if r["halted"] else "") + (f"  {r['pending']} pending approval(s)" if r["pending"] else "")
            print(f"{r['engagement']:<22} {'/'.join(r['tiers']):<24} {r['network']:<8} {t or '(no targets)'}{flags}")
        print(f"{len(rows)} engagement(s)"); return 0
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
