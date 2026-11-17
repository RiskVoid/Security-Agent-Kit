"""Repeated tool calls: left out of what the planner model reads, then withheld, then the turn is ended.

Some models copy their last tool call when it was turned down: the same call with the same arguments, dozens of
times, until the run's budget is gone. Their own reasoning names what to change, and the next call is a copy all
the same. Telling the model to stop does not help: a reply that opened with STOP was ignored 43 times in one run,
and the "stopped as stuck" message a benchmark run sends was followed by the same call in 3 of 5 cases. What the
model copies is the conversation itself, a long run of identical call-and-result pairs. In 44 saved benchmark runs
198 of 3,104 planner turns were such a call sent a fourth time or later, 193 of them in five runs that found 9 of
42 expected issues.

The gateway acts on the request, in three steps that get stricter. The count is of identical assistant turns in a
row (the same tool calls with the same arguments); a user message or a text reply in between does not start the
count again, any other tool call does.

  RUN (3)       The run is replaced by one note that says what was called, how often and what the last result was.
                Keeping the last of them in place was not enough: replayed at a point where the model had sent a
                call 20 times, it sent it again in 2 of 3 tries. With the note it was 4 of 15.
  WITHHOLD (4)  The model read the note and sent the call again. The tools of that call are left out of the
                request, so it can't send it; they are back after it makes any other call.
  CUT (6)       The call came all the same (a model can name a tool it was not offered). The gateway answers the
                request itself, with a text that says what happened, and the model is not called. A text reply
                ends the planner's turn, so the loop costs nothing from here. The next message from the user or
                the benchmark runner goes to the model again, with the call still withheld.

The conversation OpenHands keeps is not changed. Calls that wait for something (a task, an approval, a sleep) are
left alone: repeating those is the point.

REPEAT_COLLAPSE=0 turns all of it off.
"""
import json, os, re

RUN, WITHHOLD, CUT = 3, 4, 6
WAITS = re.compile(r"get_task|list_tasks|approval_status|wait|sleep", re.I)
NOTE = ("[harness] After this you made the same tool call {n} times in a row: {calls}. It ended the same way every "
        "time, and those turns are not shown. The last result was:\n{result}\n\nThat call is closed: sending it "
        "again will not change the result. Do one of two things now: make a call that differs in the way the result "
        "asks (other arguments, or the step it names first), or leave this item as it is and go on with the next "
        "step of your plan.")
WITHHELD = ("\n\nYou were told this before and sent the call again, so {tools} is not available for your next step. "
            "Go on with the next step of your plan. The tool is back after you make a different call.")
CUT_TAG = "[RiskVoid] Loop stopped"
CUT_TEXT = (CUT_TAG + ": the planner sent the same tool call {n} times in a row ({calls}) and it ended the same way "
            "every time, so the model gateway ended this turn instead of spending more on it. Nothing is lost: the "
            "findings, the plan and the evidence are saved in the engagement.\n\nThe last result was: {result}\n\n"
            "To go on, send a message here (that call stays unavailable until the planner makes a different one), or "
            "start a new conversation that picks up from the records: ./rvkit conversation {engagement} new "
            "\"continue from the handover\".")
RESULT_CHARS = 1500


def enabled():
    return os.environ.get("REPEAT_COLLAPSE", "1") != "0"


def _signature(msg):
    """What an assistant turn calls, or None when it calls nothing or waits for something."""
    calls = msg.get("tool_calls") or []
    if msg.get("role") != "assistant" or not calls:
        return None
    sig = []
    for c in calls:
        f = (c.get("function") or {}) if isinstance(c, dict) else {}
        name, args = f.get("name") or "", f.get("arguments") or ""
        if WAITS.search(name) or (name == "terminal" and WAITS.search(str(args))):
            return None
        try:
            args = json.dumps(json.loads(args), sort_keys=True) if isinstance(args, str) else json.dumps(args, sort_keys=True)
        except ValueError:
            pass
        sig.append((name, args))
    return tuple(sig)


def _text(msg):
    c = msg.get("content")
    if isinstance(c, list):
        return "\n".join(str(p.get("text") or "") for p in c if isinstance(p, dict))
    return str(c or "")


def _shown(sig):
    """A call as the notes show it: argument names and short values, not the call to copy."""
    calls = []
    for name, args in sig:
        try:
            a = json.loads(args)
            shown = ", ".join(f"{k}={json.dumps(v)[:40]}" for k, v in a.items()) if isinstance(a, dict) else str(a)[:120]
        except ValueError:
            shown = str(args)[:120]
        calls.append(f"{name}({shown})")
    return "; ".join(calls)


def _result(group, chars=RESULT_CHARS):
    return "\n".join(_text(m) for m in group[1:]).strip()[:chars] or "(no result)"


def _note(sig, group, n):
    """The user message that stands in for a run of identical turns: what was called, how often, and what the
    last one returned."""
    return {"role": "user", "content": NOTE.format(n=n, calls=_shown(sig), result=_result(group))}


def _turns(messages):
    """[(kind, signature, messages)]: "call" for an assistant turn with tool calls and its results (signature None
    when it waits for something), "other" for every other message."""
    turns, i = [], 0
    while i < len(messages):
        m = messages[i]
        group, call = [m], isinstance(m, dict) and m.get("role") == "assistant" and bool(m.get("tool_calls"))
        i += 1
        if call:
            while i < len(messages) and isinstance(messages[i], dict) and messages[i].get("role") == "tool":
                group.append(messages[i])
                i += 1
        turns.append(("call" if call else "other", _signature(m) if call else None, group))
    return turns


def _runs(turns):
    """Runs of identical call turns: [(signature, [index into turns, ...])], messages without a call in between
    are skipped over."""
    runs = []
    for i, (kind, sig, _) in enumerate(turns):
        if kind != "call":
            continue
        if sig is not None and runs and runs[-1][0] == sig:
            runs[-1][1].append(i)
        else:
            runs.append((sig, [i]))
    return runs


def review(messages, tools=None):
    """What the gateway does with a planner request. Returns a dict:
      messages  the messages to send: each run of RUN or more identical call turns replaced by a note
      removed   how many turns that left out
      streak    how long the run at the end of the conversation is (0 when the last call was not a repeat)
      calls     that call as text, for messages and the event log
      withhold  tool names left out of this request (streak of WITHHOLD or more)
      tools     the tool list without them (the list as given when nothing is withheld)
      cut       the text the gateway answers with instead of calling the model, or None
    """
    turns = _turns(messages)
    runs = _runs(turns)
    drop, notes, removed = set(), {}, 0
    for sig, idx in runs:
        if sig is not None and len(idx) >= RUN:
            drop.update(idx)
            notes[idx[-1]] = _note(sig, turns[idx[-1]][2], len(idx))
            removed += len(idx)
    out = {"messages": messages, "removed": removed, "streak": 0, "calls": "", "withhold": [], "tools": tools,
           "cut": None}
    if not removed:
        return out
    sig, idx = runs[-1]
    last = sig is not None and len(idx) >= RUN
    if last:
        out["streak"], out["calls"] = len(idx), _shown(sig)
    if last and len(idx) >= WITHHOLD:
        names = sorted({name for name, _ in sig})
        left = [t for t in tools or [] if ((t.get("function") or {}).get("name") if isinstance(t, dict) else None) not in names]
        if left and len(left) < len(tools or []):       # never a request without tools
            out["withhold"], out["tools"] = names, left
            notes[idx[-1]] = dict(notes[idx[-1]])
            notes[idx[-1]]["content"] += WITHHELD.format(tools=" and ".join(names))
        # the model was not asked since this call came back: answer for it. After a message from the user it is
        # asked again.
        if len(idx) >= CUT and idx[-1] == len(turns) - 1:
            out["cut"] = {"n": len(idx), "calls": _shown(sig), "result": _result(turns[idx[-1]][2], 400)}
    msgs = []
    for i, (_, _, group) in enumerate(turns):
        if i in notes:
            msgs.append(notes[i])
        elif i not in drop:
            msgs += group
    out["messages"] = msgs
    return out


def cut_text(cut, engagement=None):
    return CUT_TEXT.format(engagement=engagement or "<engagement>", **cut)


def collapse(messages):
    """(messages with each run of identical tool-call turns replaced by a note, number of turns removed)."""
    r = review(messages)
    return r["messages"], r["removed"]
