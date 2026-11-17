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

A cycle of two or three different calls made in turn (A, B, A, B, ...) is counted the same way, in rounds: the
note at the third round, the tools of the cycle withheld at the fourth, the turn ended at the sixth. A round counts
only when each of its calls is the same as in the round before and came back with the same result (ids and
numbers aside), so work that moves on (other arguments, a result that changed) is never a cycle. In 48 saved
benchmark runs (3,260 planner turns) no two calls alternated for even two rounds, so the rule changed nothing
there: it is for the loop nothing else stops.

The conversation OpenHands keeps is not changed. Calls that wait for something (a task, an approval, a sleep) are
left alone: repeating those is the point.

REPEAT_COLLAPSE=0 turns all of it off.
"""
import json, os, re

RUN, WITHHOLD, CUT = 3, 4, 6     # rounds; for one call a round is one turn
CYCLES = (2, 3)                  # cycles of this many different calls are counted too
WAITS = re.compile(r"get_task|list_tasks|approval_status|wait|sleep", re.I)
IDS = re.compile(r"\b[0-9a-f]{6,}\b|\d+")   # results that differ only in ids, times or counts end the same way
NOTE = ("[harness] After this you made {what}. It ended the same way every time, and those turns are not shown. "
        "The last result was:\n{result}\n\nThat call is closed: sending it again will not change the result. Do one of "
        "two things now: make a call that differs in the way the result asks (other arguments, or the step it names "
        "first), or leave this item as it is and go on with the next step of your plan.")
CYCLE_NOTE = ("[harness] After this you made {what}. They ended the same way every time, and those turns are not "
              "shown. The last results were:\n{result}\n\nThose calls are closed: making them again will not change "
              "the results. Do one of two things now: make a call that differs in the way the results ask, or leave "
              "this item as it is and go on with the next step of your plan.")
WITHHELD = ("\n\nYou were told this before and sent the call again, so {tools} {be} not available for your next step. "
            "Go on with the next step of your plan. The tool is back after you make a different call.")
CUT_TAG = "[RiskVoid] Loop stopped"
CUT_TEXT = (CUT_TAG + ": the planner sent {what}, and it ended the same way every time, so the model gateway ended "
            "this turn instead of spending more on it. Nothing is lost: the findings, the plan and the evidence are "
            "saved in the engagement.\n\nThe last result was: {result}\n\nTo go on, send a message here (that call "
            "stays unavailable until the planner makes a different one), or start a new conversation that picks up "
            "from the records: ./rvkit conversation {engagement} new \"continue from the handover\".")
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


class Run:
    """Call turns that repeat: one call made again and again (period 1), or a cycle of 2 or 3 different calls made
    in turn. idx: indexes into the turns, oldest first."""

    def __init__(self, period, idx, turns):
        self.period, self.idx, self.turns = period, idx, turns
        self.last = idx[-period:]                     # the last round, in the order it was made
        self.rounds = len(idx) // period

    def calls(self):
        return " | ".join(_shown(self.turns[i][1]) for i in self.last)

    def what(self):
        if self.period == 1:
            return f"the same tool call {self.rounds} times in a row: {self.calls()}"
        return f"the same {self.period} tool calls in turn, {self.rounds} times over: {self.calls()}"

    def names(self):
        return sorted({name for i in self.last for name, _ in self.turns[i][1]})

    def result(self, chars=RESULT_CHARS):
        if self.period == 1:
            return _result(self.turns[self.idx[-1]][2], chars)
        each = max(chars // self.period, 100)
        return "\n".join(f"{_shown(self.turns[i][1])}: {_result(self.turns[i][2], each)}" for i in self.last)

    def note(self):
        """The user message that stands in for the run: what was called, how often, and what it returned."""
        return {"role": "user", "content": (NOTE if self.period == 1 else CYCLE_NOTE).format(what=self.what(),
                                                                                            result=self.result())}


def _runs(turns):
    """The runs worth a note (RUN rounds or more), oldest first. Messages without a call in between are skipped
    over; any other call, or a call that waits for something, ends a run. In a cycle each call must also come back
    with the same result as the round before. A turn belongs to one run at most, the one that started first (on
    the same turn, the shorter period)."""
    calls = [i for i, (kind, _, _) in enumerate(turns) if kind == "call"]
    sig = [turns[i][1] for i in calls]
    out = [IDS.sub("#", _result(turns[i][2], 10 ** 6)) for i in calls]

    def same(j, p):   # the call at j repeats the one p calls before it
        return sig[j] is not None and sig[j] == sig[j - p] and (p == 1 or out[j] == out[j - p])

    found = []
    for p in (1,) + CYCLES:
        j = p
        while j < len(calls):
            if not same(j, p):
                j += 1
                continue
            k = j
            while k + 1 < len(calls) and same(k + 1, p):
                k += 1
            if len(set(sig[j - p:j])) == p:            # p different calls (fewer: a shorter period covers it)
                found.append((j - p, k, p))
            j = k + 1
    runs, taken = [], -1
    for start, end, p in sorted(found, key=lambda f: (f[0], f[2])):
        start = max(start, taken + 1)
        if (end - start + 1) // p >= RUN:
            runs.append(Run(p, [calls[x] for x in range(start, end + 1)], turns))
            taken = end
    return runs


def review(messages, tools=None):
    """What the gateway does with a planner request. Returns a dict:
      messages  the messages to send: each run of RUN or more rounds replaced by a note
      removed   how many turns that left out
      streak    rounds of the run at the end of the conversation (0 when the last call was not a repeat)
      period    1 when that run is one call, 2 or 3 for a cycle (0 when streak is 0)
      calls     its call (or the calls of the cycle) as text, for messages and the event log
      what      the same in words: "the same tool call 4 times in a row: ..."
      stage     what this request does about that run: "note", "withhold" or "cut" (None when streak is 0)
      withhold  tool names left out of this request (streak of WITHHOLD or more)
      tools     the tool list without them (the list as given when nothing is withheld)
      cut       {"what", "result"} for the text the gateway answers with instead of calling the model, or None
    """
    turns = _turns(messages)
    runs = _runs(turns)
    drop, notes = set(), {}
    for run in runs:
        drop.update(run.idx)
        notes[run.idx[-1]] = run.note()
    out = {"messages": messages, "removed": len(drop), "streak": 0, "period": 0, "calls": "", "what": "",
           "stage": None, "withhold": [], "tools": tools, "cut": None}
    if not runs:
        return out
    run = runs[-1]
    if run.idx[-1] == max(i for i, (kind, _, _) in enumerate(turns) if kind == "call"):
        out.update(streak=run.rounds, period=run.period, calls=run.calls(), what=run.what(), stage="note")
        if run.rounds >= WITHHOLD:
            names = run.names()
            left = [t for t in tools or [] if ((t.get("function") or {}).get("name") if isinstance(t, dict) else None) not in names]
            if left and len(left) < len(tools or []):       # never a request without tools
                out["withhold"], out["tools"], out["stage"] = names, left, "withhold"
                notes[run.idx[-1]] = dict(notes[run.idx[-1]])
                notes[run.idx[-1]]["content"] += WITHHELD.format(tools=" and ".join(names),
                                                                 be="is" if len(names) == 1 else "are")
            # the model was not asked since this call came back: answer for it. After a message from the user it
            # is asked again.
            if run.rounds >= CUT and run.idx[-1] == len(turns) - 1:
                out["stage"], out["cut"] = "cut", {"what": run.what(), "result": run.result(400)}
    msgs = []
    for i, (_, _, group) in enumerate(turns):
        if i in notes:
            msgs.append(notes[i])
        elif i not in drop:
            msgs += group
    out["messages"] = msgs
    return out


def cut_text(cut, engagement=None):
    """cut: {"what", "result"} from review(), or {"n", "calls", "result"} for one call."""
    what = cut.get("what") or f"the same tool call {cut.get('n')} times in a row: {cut.get('calls')}"
    return CUT_TEXT.format(engagement=engagement or "<engagement>", what=what, result=cut.get("result", ""))


def collapse(messages):
    """(messages with each run of repeated tool-call turns replaced by a note, number of turns removed)."""
    r = review(messages)
    return r["messages"], r["removed"]
