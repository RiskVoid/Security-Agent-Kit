# RiskVoid agent kit

This folder is a self-hosted research and security agent stack: OpenHands, LiteLLM, SearXNG, MCP tools and a Kali toolbox in Docker, plus a worker model on Colab, a local or rented GPU, or OpenRouter.

- Control script: `./rvkit` (run `./rvkit help`)
- Operating procedures: `AGENT_PLAYBOOK.md`. Follow it for setup, starting and stopping the model, everyday operation, and its rules (never ask for keys in chat; approve commands only when the user says so for that id).
- Slash commands: `/rv-setup`, `/rv-start [profile] [thinking]`, `/rv-stop`
- The Colab launcher is `colab/serve.py`. `colab/rvkit_model_server.ipynb` is generated from it by `python3 colab/build_notebook.py`.
