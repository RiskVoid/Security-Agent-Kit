# Agent playbook (for Claude Code, Codex, Gemini CLI, Cursor or any coding agent)

You are operating the RiskVoid agent kit for the user. Use `./rvkit` for everything on this machine.
Keep the user informed in one short line per step. When the user has to act, say exactly what to click.

## First-time setup

1. Ask the user two questions in one message: where to keep client code and engagements (default `~/riskvoid`),
   and the organisation name for reports (default RiskVoid; another name gives a neutral report with that name).
   Then run `RVKIT_DATA_DIR="<folder>" RVKIT_ORG="<name>" RVKIT_WORKER=later ./rvkit setup --yes` (the command
   can't prompt from here). If it reports that Docker is missing or stopped, tell the user to install or start
   Docker (Docker Desktop, OrbStack or Docker Engine), wait, then retry. If the OpenHands step fails, run
   `./rvkit openhands` and show the user its error. If `.env` already existed, setup keeps it and ignores the
   answers: say so.
2. If setup warned that `OPENROUTER_API_KEY` is empty, ask the user to add their OpenRouter key to `.env` themselves
   (never ask them to paste it into chat), then run `./rvkit up` and `./rvkit test planner`. Without a key, tell them
   the `riskvoid-local` agent works with the worker model alone.
3. Ask which worker model to use: Google Colab (default; continue with "Start the model"), a server on this machine
   (`./rvkit worker local` finds Ollama, LM Studio or llama-server by itself), or another OpenAI-compatible
   endpoint (`./rvkit worker api <url> <model>`; the user types the API key into the command themselves), or, with
   no GPU at all, a hosted model on OpenRouter (`./rvkit worker openrouter`; tell the user in one line that tool
   output and client code then go to OpenRouter). Check with `./rvkit test`.
4. Run `./rvkit doctor` and explain any problem it reports. Then tell the user to open http://localhost:8000/ and
   start a conversation with the `riskvoid-planner` agent. Suggest `./rvkit quickstart` for a safe first try (a
   practice engagement against the isolated lab), and `./rvkit watch` in a terminal to approve intrusive commands.

## Start the model

Arguments may name a profile (`auto`, `l4`, `a100-40`, `a100-80`; default `auto`), `thinking`, and/or `abliterated`.
The default model is the mainstream Qwen3.8-27B (`qwen`, served as `qwen38-27b`). Use the abliterated build
(`abliterated`, served as `qwen38-27b-obl`, refusals removed) only when the user's arguments say `abliterated`;
before starting it, tell the user in one line that its refusals are removed and they are responsible for how it is used.

1. **Local stack.** Run `./rvkit status`. If containers are not running, run `./rvkit up`.
2. **Key.** Run `./rvkit key colab` and keep the value as KEY. Never print it in chat beyond what's needed.
3. **Connect to Colab.** Call the Colab MCP tool `open_colab_browser_connection`.
   - It opens a Colab notebook in the user's browser. If it returns false, tell the user:
     "A Colab tab just opened. Sign in with the Google account that has Colab Pro or AI Pro. If Colab asks to connect to the local agent, allow it." Then call the tool again (up to 3 times).
   - Once it returns true, notebook editing tools become available. Use them for the steps below.
   - If a notebook tool later fails with "Unknown tool" (this happens after a runtime restart), call `open_colab_browser_connection` again.
4. **GPU.** Ask the user: "In that Colab tab, open Runtime → Change runtime type, pick **L4** (cheapest) or **A100** (faster), click Save, then click Connect. Tell me when it's connected." Wait for confirmation.
5. **Upload the launcher.** Read `colab/serve.py` from this folder. Add a code cell whose first line is `%%writefile /content/serve.py` followed by the exact file contents. Run it, and check that the output says `Writing /content/serve.py` or `Overwriting /content/serve.py`.
   Then add and run a check cell, and compare the hash with `md5 -q colab/serve.py` on this Mac:
   ```python
   import hashlib; print(hashlib.md5(open('/content/serve.py','rb').read()).hexdigest())
   !nvidia-smi --query-gpu=name,memory.total --format=csv,noheader
   ```
   - If the hashes differ, rewrite the launcher cell. If `nvidia-smi` is not found or shows the wrong GPU, the runtime type was reset: repeat step 4, then re-run the launcher cell (a runtime change wipes `/content`).
6. **Mount Drive.** Tell the user: "Approve the Google Drive popup now. It may open as a separate window." Add and run, in its **own** cell:
   ```python
   from google.colab import drive
   drive.mount("/content/drive")
   !ls -la /content/drive/MyDrive/riskvoid-llm/ 2>/dev/null
   ```
   - It must print `Mounted at /content/drive`. If it fails, ask the user to approve the popup and run the cell again. **Don't start the launcher until Drive is mounted**: without it, the launcher rebuilds llama.cpp from scratch (~25 min).
7. **Run it.** Add and run this code cell, filling in the values:
   ```python
   import os
   os.environ.update(RVKIT_API_KEY="<KEY>", RVKIT_PROFILE="<profile or auto>",
                     RVKIT_MODEL="<abliterated if 'abliterated' was requested else qwen>",
                     RVKIT_THINKING="<1 if 'thinking' was requested else 0>", RVKIT_IDLE_MINUTES="30")
   %run /content/serve.py
   ```
   - With the Drive cache, a run takes ~3–6 min (mostly the model download). Without a cache, the one-time llama.cpp build adds ~25 min. If the execute tool times out, keep reading the cell's output every ~60 s until it finishes. Don't re-run the cell while it's still running.
   - Check the first output lines: if the GPU isn't the one the user picked, tell them, and ask whether to continue or switch.
     The `Model:` line must name the model you asked for (`qwen` or `abliterated`).
   - If the output says "No GPU" or that the GPU is too small, repeat step 4, then steps 5–7.
   - If it fails elsewhere, show the user the last ~30 lines of output and suggest a fix. To read the logs, run `!tail -50 /content/server.log` or `!tail -50 /content/rvkit-build.log` in a new cell.
8. **Connect the stack.** Find the output line that starts with `RVKIT_ENDPOINT ` and parse its JSON. Run `./rvkit connect <url> <key> <model>` with its `url`, `key` and `model` values. It must end with "Model reachable".
9. **Report** in 2–3 lines: the model (`qwen38-27b` or `qwen38-27b-obl`), the profile and GPU, that OpenHands can be used now, and that the GPU disconnects after 30 idle minutes or when the user runs `/rv-stop`. If an existing OpenHands conversation shows a connection error, start a new one.

## Stop the model

1. If the Colab connection is open, add and run a cell: `from google.colab import runtime; runtime.unassign()`.
2. Otherwise tell the user: "In the Colab tab: Runtime → Disconnect and delete runtime."
3. Confirm. The local stack can keep running. `./rvkit down` stops it if the user wants.

## Everyday operation

The user may ask in plain words. Map the request to `./rvkit`, run it, and summarise the result in a line or two:

| The user asks | Run |
|---|---|
| "Is everything working?" | `./rvkit status`, then `./rvkit doctor` if something is wrong |
| "Create an engagement for <client>, scope <targets>" | `./rvkit engagement <name> --client "<client>" <targets…>` (confirm the targets with the user first) |
| "What's waiting for me?" | `./rvkit approvals`; show each command, its tier and id |
| "Approve <id>" / "Deny <id>" | `./rvkit approve <eng> <id>` / `./rvkit deny <eng> <id>` |
| "Stop everything on <eng>" | `./rvkit halt <eng>` (`./rvkit resume <eng>` undoes it) |
| "Show me the findings / the audit log" | `./rvkit show <eng>`, `./rvkit audit <eng>` |
| "Build the report" / "Close it out" | `./rvkit report <eng>` / `./rvkit close <eng>` (confirm before closing) |
| "Open the console" | `./rvkit console --no-open`, and give the user the sign-in link |
| "Use another worker / planner model" | `./rvkit worker …` / `./rvkit planner …` |

The security testing itself happens in the agent UI (http://localhost:8000/, `riskvoid-planner` agent), not here:
suggest a prompt for it when the user wants to start testing. `./rvkit help` lists every command.

## Rules

- Only run the kit's commands, the cells described here, and diagnostic `tail`/`ls` cells. Don't run anything else in Colab.
- Don't change `.env` except through `./rvkit`.
- Never ask the user to paste an API key into chat. They add keys to `.env` themselves or type them into the command.
- Approve or deny a command only when the user explicitly tells you to for that approval id. Never approve on your own.
- Don't widen an engagement's scope or rules unless the user asked for that exact change; show the diff first.
