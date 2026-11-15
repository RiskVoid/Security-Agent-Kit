"""Repeat guard for the planner's tool calls.

A planner model can copy its last call instead of acting on the reply. One benchmark run recorded every seeded
issue in eight minutes, then sent the same refused update_finding call about 60 times and scored 0 of 6; others
did the same with update_coverage and with a confirmation the quote check kept refusing. The worker has stall
detection in its own loop (worker.py). The planner's loop belongs to OpenHands, so its guard sits here, in the tool
server, where the calls arrive.

What it does, per engagement:

- A call turned down a second time with the same arguments and for the same reason: the reply says so, lists the
  arguments that were sent, and names the ones the answer mentions that were not. Turned down means refused, or
  saved without doing what the call was for (a confirmation that failed its checks: the caller passes the reason).
- A third time or more: the reply opens with STOP, so the instruction comes before the answer the model has
  already read past.
- A call that went through but gives the same result three times in a row: a note that repeating it changes
  nothing.

The call itself runs every time, so a reply is never stale: when the state changed and the call now succeeds, it
succeeds. Only the text around a repeated result changes. State is in memory, so a restart of the server starts
the counts again. PLANNER_REPEAT_GUARD=0 turns the guard off.
"""
import collections, hashlib, json, os, re, threading

REFUSED = "REFUSED"
SECOND = 2          # the same refusal this many times: say it is a repeat
STOP = 3            # this many times or more: open the reply with STOP
SAME_RESULT = 3     # a call that isn't refused, with the same result this many times in a row: a note
KEEP = 64           # refused calls remembered per engagement
SKIP = ("engagement",)   # arguments left out of the lists in a reply

_lock = threading.Lock()
_state = {}  # engagement -> {"refused": OrderedDict(call -> [reason, count]), "last": [call, result, count]}


def enabled():
    return os.environ.get("PLANNER_REPEAT_GUARD", "1") != "0"


def reset(engagement=None):
    """Forget the counts of one engagement, or of all."""
    with _lock:
        if engagement is None:
            _state.clear()
        else:
            _state.pop(engagement or "", None)


def sent(args):
    """The arguments a call carried: None and empty values count as not sent, as the tools treat them."""
    return {k: v for k, v in (args or {}).items() if v is not None and v != "" and v != [] and v != {}}


def _digest(x):
    return hashlib.sha256(json.dumps(x, sort_keys=True, default=str).encode()).hexdigest()


def _ordinal(n):
    return f"{n}{'th' if 10 <= n % 100 <= 20 else {1: 'st', 2: 'nd', 3: 'rd'}.get(n % 10, 'th')}"


def _names(args):
    return ", ".join(k for k in args if k not in SKIP) or "no arguments"


def missing(reply, args, params):
    """Parameters of the tool that the answer mentions and the call did not carry."""
    words = set(re.findall(r"[a-z_]+", reply.lower()))
    return [p for p in params or [] if p not in args and p not in SKIP and p.lower() in words]


def observe(engagement, tool, args, reply, params=None, problem=None):
    """Call after a tool ran. Returns the reply to send: the tool's own, or the same with the repeat pointed out.
    args: the call's arguments by name. params: the tool's parameter names, to name the ones the answer asks for.
    problem: why the call wasn't done, for a reply that isn't a refusal (a refusal is its own reason)."""
    if not enabled() or not isinstance(reply, str):
        return reply
    args = sent(args)
    call = _digest([tool, args])
    if problem is None and reply.startswith(REFUSED):
        problem = reply
    with _lock:
        st = _state.setdefault(engagement or "", {"refused": collections.OrderedDict(), "last": [None, None, 0]})
        refused = st["refused"]
        if problem is None:
            refused.pop(call, None)
            result = _digest(reply)
            last = st["last"]
            st["last"] = last = [call, result, last[2] + 1 if last[:2] == [call, result] else 1]
            n = last[2]
        else:
            st["last"] = [None, None, 0]
            reason = _digest(problem)
            seen = refused.pop(call, None)
            n = seen[1] + 1 if seen and seen[0] == reason else 1
            refused[call] = [reason, n]
            while len(refused) > KEEP:
                refused.popitem(last=False)
    if problem is None:
        if n >= SAME_RESULT:
            return (f"{reply}\n\nNOTE: this is the {_ordinal(n)} identical {tool} call in a row, with the same "
                    f"result each time. Repeating it changes nothing: go on to the next step.")
        return reply
    if n < SECOND:
        return reply
    lacking = missing(problem, args, params)
    asks = f" The answer asks for arguments this call did not carry: {', '.join(lacking)}." if lacking else ""
    what = "refused" if reply.startswith(REFUSED) else "not done"
    if n < STOP:
        return (f"{reply}\n\nSAME CALL, SAME ANSWER ({_ordinal(n)} time): {tool} came with exactly the same "
                f"arguments as before ({_names(args)}) and was {what} for the same reason. Sending it again "
                f"changes nothing.{asks} Change the call before you send it.")
    return (f"STOP: this is the {_ordinal(n)} identical {tool} call ({_names(args)}), {what} for the same reason "
            f"each time. Do not send it again.{asks} Your next call must differ from this one: fix what the answer "
            f"below names, or leave this item, note it in PLAN.md and go on with the rest of the plan.\n\n{reply}")
