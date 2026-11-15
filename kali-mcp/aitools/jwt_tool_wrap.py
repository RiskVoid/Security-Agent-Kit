"""Run ticarpi/jwt_tool under Python 3.13+.

jwt_tool writes a config file (~/.jwt_tool/jwtconf.ini) whose generated contents include comment lines stored as
keys with a None value. Since Python 3.13 configparser refuses to write a None value unless the parser was built
with allow_no_value=True, so jwt_tool's first run leaves a truncated config and every later run crashes with
KeyError: 'argvals'. We default ConfigParser to allow_no_value=True and drop any stale, incomplete config so it is
regenerated correctly.

jwt_tool also stops after writing that config on its first run ("Configuration file built ...", exit 1), without
doing what it was asked. The sandbox gives every command a fresh HOME (rv-sandbox.sh), so every call was a first
run: a crack (-C) printed the setup message and nothing else, and a weak signing key was found only when a command
happened to call jwt_tool twice. When the config is missing, we build it first in a quiet run of this wrapper, then
run the call. Nothing else in jwt_tool's behaviour changes.
"""
import configparser
import os
import runpy
import subprocess
import sys

_Orig = configparser.ConfigParser


class _CP(_Orig):
    def __init__(self, *a, **k):
        k.setdefault("allow_no_value", True)
        super().__init__(*a, **k)

    def _validate_key_contents(self, key):  # py3.14 rejects keys containing ':' / '='; jwt_tool stores
        return  # comment text as keys. These files are tool-internal, never re-parsed as key=value.


configparser.ConfigParser = _CP

cfg = os.path.expanduser("~/.jwt_tool/jwtconf.ini")
try:
    if os.path.isfile(cfg) and "[argvals]" not in open(cfg).read():
        os.remove(cfg)  # truncated by an earlier failed run; let jwt_tool rebuild it
except OSError:
    pass
if not os.path.isfile(cfg) and not os.environ.get("RV_JWT_TOOL_SETUP"):
    # the setup run only writes the config and exits; -b skips the banner
    subprocess.run([sys.executable, os.path.abspath(__file__), "-b"], env={**os.environ, "RV_JWT_TOOL_SETUP": "1"},
                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60,
                   check=False)

runpy.run_path("/opt/jwt_tool/jwt_tool.py", run_name="__main__")
