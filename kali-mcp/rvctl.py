"""Admin commands for the kali-mcp control plane. Run on the host through ./rvkit (docker compose exec).

  rvctl.py sync <eng> [--yes] [--expect <revision>] [--stdin]
                                     import /work/<eng>/SCOPE.md + RULES.md as authoritative (shows diff first).
                                     --expect: refuse (exit 3) if the active scope is no longer that revision.
                                     --stdin: write {"scope": ..., "rules": ...} from stdin to the folder first
  rvctl.py show <eng>                active scope and rules
  rvctl.py policy <eng> [--json]     effective policy: what is allowed, excluded, not enforced; revision history
  rvctl.py preview <eng>             diff + warnings for {"scope": ..., "rules": ...} on stdin (writes nothing)
  rvctl.py approvals [eng] [--json]  pending approvals (all engagements if none given)
  rvctl.py list [--json]             engagements: scope summary, halt state, pending approvals
  rvctl.py approve|deny <eng> <id>   decide an approval
  rvctl.py halt|resume <eng>         stop all running commands and block new ones / allow again
  rvctl.py audit [eng] [n]           last n audit entries (authoritative log)
  rvctl.py running [eng]             commands running now, as JSON
  rvctl.py live <eng> [n]            running commands, last n audit entries, pending approvals, halt state (JSON)
  rvctl.py close <eng>               export audit extract, SHA-256 manifest, archive to _archive/, halt
  rvctl.py delete <eng> [--force]    unregister a closed engagement; its folder becomes _deleted-<eng>-<time>
  rvctl.py apply                     rebuild firewall + DNS for all engagements
  rvctl.py record <eng>              add a change event from harness/ops.py (JSON on stdin) to the audit log
  rvctl.py conversations [eng] [--json]  OpenHands conversations bound to engagements
  rvctl.py bind <eng> <conversation-id> [title]   bind a conversation (its model calls follow the engagement)
  rvctl.py unbind <eng> <conversation-id>
  rvctl.py cred <eng> list [--json] | set <NAME> [--expires DATE] (value on stdin) | rm <NAME>
  rvctl.py approval <eng> <id>       one approval's status (JSON)
  rvctl.py cancel <eng> <task-id>    kill the commands of a worker task
  rvctl.py routes                    the routing table the model gateway uses (JSON; rewritten too)
  rvctl.py vault rotate              replace the vault key and re-encrypt every credential and session
  rvctl.py identity <eng> list [--json] | set <name> (JSON spec on stdin) | check <name> | revoke <name> | rm <name>
  rvctl.py capture <eng> list | import [--name N] (HAR/Burp XML on stdin) | show <id> | raw <id> | replay <id> | rm <id>
  rvctl.py authz <eng> list | show <name> | review <name> | approve <name> [--digest D] | run <name>
  rvctl.py appmap <eng> <path> [--build-url U] [--routes F]   Laravel application map (no code runs)
  rvctl.py php <eng> check <path>    the host path of an in-scope /src path, for the PHP profile (RW-013)
  rvctl.py php <eng> record <kind> <rel>... [--approved]   audit the PHP profile's outputs (evidence provenance)

Global option: --actor <console|cli>:<name> names who acts; it is recorded on every audit entry (default cli:host).
Exit codes: 0 ok, 1 error, 2 sync not confirmed, 3 conflict (the record changed since it was read).
"""
import json, os, sys

VENV = "/opt/venv/bin/python3"  # kali-mcp's own Python (the vault needs its cryptography package)
if os.path.exists(VENV) and os.path.realpath(sys.prefix) != "/opt/venv":
    os.execv(VENV, [VENV, os.path.abspath(__file__), *sys.argv[1:]])

import core  # noqa: E402


def _opt(a, name):
    """Remove --name <value> from the argument list and return the value (None if absent)."""
    if name in a:
        i = a.index(name)
        if i + 1 >= len(a):
            raise ValueError(f"{name} needs a value")
        v = a[i + 1]
        del a[i:i + 2]
        return v
    return None


def _print_policy(p):
    print("\nAllows:" if p["hosts"] or p["nets"] or p["urls"] or p["paths"] else "\nAllows: nothing yet")
    for line in core.rvpolicy.describe(p):
        print("  " + line)
    ex = p["exclude"]
    xs = [("*." if e["wildcard"] else "") + e["name"] for e in ex["hosts"]] + ex["nets"] + \
        [f"{u['scheme']}://{u['host']}:{u['port']}{u['prefix']}" for u in ex["urls"]]
    if xs:
        print("Excludes:\n  " + "\n  ".join(xs))
    r = p["rules"]
    when = [f"window {':'.join(f'{x:02d}' for x in r['window'][:2])}-{':'.join(f'{x:02d}' for x in r['window'][2:])}"
            if r["window"] else "", f"dates {r['dates'][0]} to {r['dates'][1]}" if r["dates"] else "",
            f"days {','.join(r['days'])}" if r["days"] else ""]
    print(f"Rules: tiers {'/'.join(r['tiers'])}, {r['max_rate']}/s, {r['network']}, execution {r['execution']}"
          + "".join(f", {w}" for w in when if w) + f" ({r['timezone']})")
    print("Client data may go to: " + (", ".join(r["client_data"]) if r.get("client_data") else
                                        "any model the stack is configured for"))
    for s in r["stop_conditions"]:
        print("Stop condition: " + s)
    if p["limits"]:
        print("Not enforced by the kit:\n  - " + "\n  - ".join(p["limits"]))
    for e in p["errors"]:
        print("ERROR: " + e)


def main(a):
    a = list(a)
    actor = _opt(a, "--actor") or "cli:host"
    if not core.ACTOR_RX.match(actor) or actor.startswith("agent:"):
        raise ValueError("--actor must be console:<name> or cli:<name>")
    core.ACTOR = actor
    if not a:
        print(__doc__); return 1
    cmd, rest = a[0], a[1:]
    if cmd == "sync":
        expect = _opt(rest, "--expect")
        texts = json.load(sys.stdin) if "--stdin" in rest else None
        eng, yes = rest[0], "--yes" in rest
        new = eng not in core.registry()
        if texts is not None and not yes:
            raise ValueError("--stdin needs --yes (preview first with rvctl preview)")
        if texts is None:
            d = core.diff(eng)
            if not new and not d:
                print(f"{eng}: no changes"); return 0
            print(f"{'New engagement' if new else 'Changes to'} {eng}:\n{d}")
            sp, rp = (os.path.join(core.WORK, eng, f) for f in ("SCOPE.md", "RULES.md"))
            p = core.policy_of(scope_text=open(sp).read() if os.path.exists(sp) else "",
                               rules_text=open(rp).read() if os.path.exists(rp) else "")
            _print_policy(p)
        if not yes:
            print("\nNot applied. Review the diff, then re-run with --yes."); return 2
        for w in core.sync(eng, expected=expect, texts=texts):
            print("warning:", w)
        print(f"applied. {eng} uses uid {core.registry()[eng]}"); return 0
    if cmd == "preview":
        d = json.load(sys.stdin)
        print(json.dumps(core.preview(rest[0], d.get("scope", ""), d.get("rules", "")))); return 0
    if cmd == "show":
        print(json.dumps(core.info(rest[0]), indent=1)); return 0
    if cmd == "policy":
        eng = rest[0]
        core.require(eng)
        p, hist = core.policy_of(eng), core.policy_history(eng)
        if "--json" in rest:
            print(json.dumps({"policy": {k: p[k] for k in core.POLICY_KEYS}, "rules": p["rules"],
                              "version": core.policy_version(eng), "revision": core.revision(eng),
                              "history": hist})); return 0
        print(f"{eng}: policy revision {core.policy_version(eng)} ({core.revision(eng)})")
        _print_policy(p)
        for h in hist[-10:]:
            print(f"  r{h['version']}  {h['activated']}  {h['actor']}  {h['revision']}")
        return 0
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
    if cmd == "running":  # running [eng]: commands running now, as JSON
        print(json.dumps(core.running(rest[0] if rest else None))); return 0
    if cmd == "live":  # live <eng> [n]: running commands, last n audit entries, pending approvals, halt (one call)
        eng, n = rest[0], int(rest[1]) if len(rest) > 1 else 15
        lines = open(core.AUDIT).read().splitlines() if os.path.exists(core.AUDIT) else []
        events = [json.loads(l) for l in lines if f'"engagement": "{eng}"' in l][-n:]
        print(json.dumps({"running": core.running(eng), "events": [e for e in events if e.get("engagement") == eng],
                          "approvals": [dict(a, engagement=eng) for a in core.approvals(eng, "pending")],
                          "halted": core.info(eng)["halted"]})); return 0
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
    if cmd == "delete":
        r = core.delete(rest[0], "--force" in rest)
        print(f"{rest[0]} deleted: scope, approvals and firewall rules removed (audit history kept)")
        if r["folder"]:
            print(f"folder:   {r['folder']} (in the engagements folder; remove it yourself when you no longer need it)")
        for a in r["archives"]:
            print(f"archive:  _archive/{a}")
        return 0
    if cmd == "apply":
        core.apply_network(); print("network policy applied"); return 0
    if cmd == "conversations":
        engs = [a for a in rest if a != "--json"][:1] or core.engagements()
        rows = [dict(c, engagement=e) for e in engs for c in core.conversations(e)]
        if "--json" in rest:
            print(json.dumps(rows)); return 0
        for r in rows:
            print(f"{r['engagement']:<22} {r['id']}  {r['bound']}  {r.get('title', '')}")
        print(f"{len(rows)} bound conversation(s)"); return 0
    if cmd == "bind":
        c = core.bind_conversation(rest[0], rest[1], " ".join(rest[2:]))
        print(f"conversation {c['id']} bound to {rest[0]}"); return 0
    if cmd == "unbind":
        core.unbind_conversation(rest[0], rest[1]); print(f"conversation {rest[1]} unbound from {rest[0]}"); return 0
    if cmd == "cred":
        eng, sub = rest[0], (rest[1] if len(rest) > 1 else "list")
        if sub == "list":
            rows = core.cred_list(eng)
            if "--json" in rest:
                print(json.dumps(rows)); return 0
            for r in rows:
                print(f"{r['name']:<24} ${r['env']:<30} {r['ref']:<30} set {r['set_at']} by {r['set_by']}")
            print(f"{len(rows)} credential(s)"); return 0
        if sub == "set":
            exp = _opt(rest, "--expires")
            core.cred_set(eng, rest[2], sys.stdin.read(), exp); print(f"{rest[2].upper()} stored for {eng}"); return 0
        if sub == "rm":
            core.cred_remove(eng, rest[2]); print(f"{rest[2].upper()} removed from {eng}"); return 0
        raise ValueError("usage: cred <eng> list | set <NAME> | rm <NAME>")
    if cmd == "vault":
        if rest[:1] == ["rotate"]:
            print(f"vault key replaced; {core.vault_rotate()} entries re-encrypted"); return 0
        raise ValueError("usage: vault rotate")
    if cmd == "identity":
        import identities
        eng, sub = rest[0], (rest[1] if len(rest) > 1 else "list")
        if sub == "list":
            rows = identities.identity_list(eng)
            if "--json" in rest:
                print(json.dumps(rows)); return 0
            for r in rows:
                st = r["status"]
                print(f"{r['name']:<16} {r['kind']:<7} role {r.get('role') or '-':<10} tenant {r.get('tenant') or '-':<10} "
                      f"{st.get('state', 'unchecked'):<10} {st.get('reason') or ''}")
            print(f"{len(rows)} identit{'y' if len(rows) == 1 else 'ies'}"); return 0
        if sub == "set":  # spec JSON on stdin
            print(json.dumps(identities.identity_set(eng, rest[2], json.load(sys.stdin)))); return 0
        if sub == "check":
            r = identities.check(eng, rest[2]); print(json.dumps(r)); return 0 if r["state"] == "valid" else 4
        if sub == "revoke":
            identities.revoke(eng, rest[2], " ".join(rest[3:])); print(f"{rest[2]} revoked"); return 0
        if sub == "rm":
            identities.identity_remove(eng, rest[2]); print(f"{rest[2]} removed"); return 0
        raise ValueError("usage: identity <eng> list | set <name> (JSON on stdin) | check <name> | revoke <name> | rm <name>")
    if cmd == "capture":
        import captures
        eng, sub = rest[0], (rest[1] if len(rest) > 1 else "list")
        if sub == "list":
            print(json.dumps(captures.listing(eng), indent=1)); return 0
        if sub == "import":  # file on stdin
            name = _opt(rest, "--name") or ""
            print(json.dumps(captures.import_capture(eng, sys.stdin.buffer.read(), name))); return 0
        if sub == "show":
            print(json.dumps(captures.load(eng, rest[2]), indent=1)); return 0
        if sub == "raw":
            sys.stdout.buffer.write(captures.raw(eng, rest[2])); return 0
        if sub == "replay":  # {"entry", "identity", "changes", "markers", "approval_id"} on stdin
            q = json.load(sys.stdin)
            r = captures.replay(eng, rest[2], q["entry"], q.get("identity"), q.get("changes"), q.get("approval_id"),
                                None, None, tuple(q.get("markers") or ()))
            print(json.dumps({k: v for k, v in r.items() if k != "text"} | {"text": r["text"]})); return 0
        if sub == "rm":
            captures.delete(eng, rest[2]); print(f"{rest[2]} deleted"); return 0
        raise ValueError("usage: capture <eng> list | import [--name N] (file on stdin) | show <id> | raw <id> | rm <id>")
    if cmd == "authz":
        import authz
        eng, sub = rest[0], (rest[1] if len(rest) > 1 else "list")
        if sub == "list":
            print(json.dumps(authz.listing(eng), indent=1)); return 0
        if sub == "show":  # validated, with the digest an approval will have: what the console reviews
            print(json.dumps(authz.review(eng, rest[2]), indent=1)); return 0
        if sub == "review":  # the same as text, last line "digest <D>": what ./rvkit authz approve shows
            print(authz.review_text(authz.review(eng, rest[2]))); return 0
        if sub == "approve":
            r = authz.approve(eng, rest[2], _opt(rest, "--digest"))
            print(f"matrix {rest[2]} approved (digest {r['digest']}, policy revision {r['policy_revision']})"); return 0
        if sub == "run":
            r = authz.run(eng, rest[2]); print(r["text"]); return 0
        raise ValueError("usage: authz <eng> list | show <name> | review <name> | approve <name> [--digest D] | "
                         "run <name>")
    if cmd == "appmap":
        import actions
        build, routes = _opt(rest, "--build-url"), _opt(rest, "--routes")
        out = actions.appmap(rest[0], rest[1], build, routes)
        print(out); return 1 if out.startswith("REFUSED") else 0
    if cmd == "php":  # the optional PHP profile runs on the host (docker); kali-mcp checks scope and audits it
        import actions
        eng, sub = rest[0], rest[1]
        if sub == "check":
            i = core.info(eng)
            if i["halted"]:
                raise ValueError(f"{eng} is halted")
            p = actions._source_path(eng, i, rest[2])
            if not p.startswith("/src/"):
                raise ValueError("the PHP profile runs on client code under /src")
            out = actions.work_dir(eng, "evidence", "php")  # chowned: never through a link the agent made
            os.chown(out, i["uid"], i["uid"], follow_symlinks=False)  # the profile runs as the engagement's user
            print(json.dumps({"path": p, "relative": p[len("/src/"):], "uid": i["uid"]})); return 0
        if sub == "record":
            approved = "--approved" in rest
            kind, rels = rest[2], [r for r in rest[3:] if r != "--approved"]
            if kind not in ("lint", "routes"):
                raise ValueError("kind: lint or routes")
            outs = {}
            for rel in rels:
                full = os.path.realpath(os.path.join(core.WORK, eng, rel))  # links resolved: hashed as root
                if not full.startswith(os.path.realpath(os.path.join(core.WORK, eng, "evidence", "php")) + "/") or \
                        not os.path.isfile(full):
                    raise ValueError(f"{rel}: not a PHP profile output of {eng}")
                outs[rel] = core.sha256_file(full)
            core._audit({"engagement": eng, "action": "php-profile", "kind": kind, "tier": "passive",
                         "network": "none", "command": f"rv-php {kind} (isolated PHP profile, no network)",
                         "executes_client_code": kind == "routes",
                         **({"approved_by": core.ACTOR} if approved else {}), "outputs": outs})
            print(f"recorded {len(outs)} output(s)"); return 0
        raise ValueError("usage: php <eng> check <path> | record <lint|routes> <rel>... [--approved]")
    if cmd == "approval":
        print(json.dumps(core.approval_status(rest[0], rest[1]))); return 0
    if cmd == "cancel":
        print(f"killed {core.cancel_task(rest[0], rest[1])} command(s)"); return 0
    if cmd == "routes":
        core.publish_routes(); print(json.dumps(core.routes(), indent=1)); return 0
    if cmd == "record":
        print(json.dumps(core.record(rest[0], json.load(sys.stdin)))); return 0
    print(__doc__); return 1


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except core.Conflict as e:
        print("conflict:", e, file=sys.stderr); sys.exit(3)
    except (ValueError, IndexError, FileNotFoundError) as e:
        print("error:", e or "missing argument", file=sys.stderr); sys.exit(1)
