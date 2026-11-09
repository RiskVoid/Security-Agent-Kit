"""Prints the result of a report operation for ./rvkit report (reads the ops.py answer on stdin).

  python3 scripts/report_cli.py build|revisions|verify|rebuild|export < answer.json
"""
import json
import sys


def main():
    mode = sys.argv[1]
    r = json.loads(sys.stdin.read().strip().splitlines()[-1])["result"]
    if mode == "build":
        rd = r["readiness"]
        print("{}: {}, {} finding(s), files in report/revisions/{}/".format(r["id"], r["state"],
                                                                         r["report"]["findings"], r["id"]))
        for b in rd["blocking"]:
            print("  blocks delivery  [{}] {}".format(b["check"], b["issue"]))
        for x in rd["excepted"]:
            print("  excepted         [{}] {} ({})".format(x["check"], x["rationale"], x["by"]))
        for w in rd["warnings"]:
            print("  warning          " + w)
        if r["state"] == "ready":
            print("Next: review it, then ./rvkit report <engagement> approve " + r["id"])
        else:
            print("Fix what blocks it (or record an exception where the methodology allows one), then run "
                  "./rvkit report again.")
    elif mode == "revisions":
        for v in r["revisions"]:
            print("{}  {:<11} {}  {}{}".format(v["id"], v["state"], v["created"], v["actor"] or "",
                                               "  approved by " + v["approved_by"] if v.get("approved_by") else ""))
        n = len(r["readiness"]["blocking"])
        print("ready now" if not n else "{} check(s) block delivery".format(n))
    elif mode == "verify":
        print("{}: {}".format(r["revision"], "; ".join(r["problems"]) if r["problems"]
                              else "all {} files match their hashes".format(r["files"])))
        return 1 if r["problems"] else 0
    elif mode == "rebuild":
        print("rebuilt in {}: HTML {}".format(r["folder"], "identical" if r["html_identical"] else "DIFFERENT"))
    elif mode == "export":
        print("{} ({}) exported to {}/: {}".format(r["revision"], r["state"], r["folder"], ", ".join(r["files"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
