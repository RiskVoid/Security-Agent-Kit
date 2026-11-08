# RiskVoid Security Agent Kit: instructions for coding agents

This folder is a self-hosted AI security agent stack in Docker: OpenHands (the agent UI), LiteLLM, SearXNG, MCP
tool servers and a Kali toolbox, with a worker model on Colab, a local or rented GPU, or OpenRouter.

You (Codex, Gemini CLI, Cursor, Copilot or another coding agent) operate the kit for the user from this folder:

- Control script: `./rvkit` (`./rvkit help` lists every command).
- **Follow [AGENT_PLAYBOOK.md](AGENT_PLAYBOOK.md)** for first-time setup, starting and stopping the Colab model,
  everyday operation and the rules.
- Starting the model on Colab needs the Colab MCP server. Its entry is in `.mcp.json`; add the same server to
  your own MCP settings if you don't read that file. Without it, use another worker (`./rvkit worker local`,
  `./rvkit worker api …` or `./rvkit worker openrouter`).

The rules that matter most:

- Never ask the user to paste an API key into chat, and don't edit `.env` by hand: use `./rvkit`.
- Approve or deny a command only when the user explicitly tells you to for that approval id.
- Don't widen an engagement's scope or rules unless the user asked for that exact change.

Changing the kit's code: see [CONTRIBUTING.md](CONTRIBUTING.md). `colab/rvkit_model_server.ipynb` is generated
from `colab/serve.py` by `python3 colab/build_notebook.py`.
