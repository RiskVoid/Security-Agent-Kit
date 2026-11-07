"""Regenerates rvkit_model_server.ipynb from serve.py. Run: python3 colab/build_notebook.py"""
import json, pathlib
here = pathlib.Path(__file__).parent
serve = (here / "serve.py").read_text()

def md(s): return {"cell_type": "markdown", "metadata": {}, "source": s.strip("\n").splitlines(True)}
def code(s, hidden=False):
    meta = {"cellView": "form"} if hidden else {}
    return {"cell_type": "code", "metadata": meta, "execution_count": None, "outputs": [], "source": s.strip("\n").splitlines(True)}

cells = [
md("""
# RiskVoid agent kit: model server

1. **Runtime → Change runtime type → L4** (cheapest, ~1.7 units/h) or **A100** (faster, ~5–8 units/h).
2. **Runtime → Run all.** Approve the Google Drive popup. Drive stores the llama.cpp build so later starts are fast.
3. When it finishes, copy the `./rvkit connect …` line into a terminal in the kit folder on your Mac.

First start: ~25–30 min (one-time build). Later starts: ~3–6 min. The runtime disconnects itself after the idle timeout.

Model: Qwen3.8-27B (Apache-2.0). `MODEL = "qwen"` serves Qwen's weights unchanged; `"abliterated"` serves a community build with refusals removed.
"""),
code("""
#@title Settings
PROFILE = "auto"  #@param ["auto", "l4", "a100-40", "a100-80"]
MODEL = "qwen"  #@param ["qwen", "abliterated"]
#@markdown `qwen` is the mainstream Qwen3.8-27B. `abliterated` has its refusals removed; you are responsible for how you use it.
THINKING = False  #@param {type:"boolean"}
IDLE_MINUTES = 30  #@param {type:"integer"}
API_KEY = ""  #@param {type:"string"}
#@markdown Leave API_KEY empty for a random key, or paste the output of `./rvkit key` to keep it fixed.
import os
os.environ.update(RVKIT_PROFILE=PROFILE, RVKIT_MODEL=MODEL, RVKIT_THINKING="1" if THINKING else "0",
                  RVKIT_IDLE_MINUTES=str(IDLE_MINUTES), RVKIT_API_KEY=API_KEY)
""", hidden=True),
code("%%writefile /content/serve.py\n" + serve, hidden=True),
code("%run /content/serve.py"),
md("**Done?** Runtime → Disconnect and delete runtime. Logs: `!tail -50 /content/server.log`"),
]
nb = {"cells": cells, "metadata": {"accelerator": "GPU", "colab": {"gpuType": "L4", "provenance": []},
      "kernelspec": {"name": "python3", "display_name": "Python 3"}}, "nbformat": 4, "nbformat_minor": 0}
(here / "rvkit_model_server.ipynb").write_text(json.dumps(nb, indent=1))
print("wrote", here / "rvkit_model_server.ipynb")
