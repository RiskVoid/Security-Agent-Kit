"""Run ticarpi/jwt_tool under Python 3.13+.

jwt_tool writes a config file (~/.jwt_tool/jwtconf.ini) whose generated contents include comment lines stored as
keys with a None value. Since Python 3.13 configparser refuses to write a None value unless the parser was built
with allow_no_value=True, so jwt_tool's first run leaves a truncated config and every later run crashes with
KeyError: 'argvals'. We default ConfigParser to allow_no_value=True and drop any stale, incomplete config so it is
regenerated correctly. No behaviour of jwt_tool changes.
"""
import configparser
import os
import runpy

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

runpy.run_path("/opt/jwt_tool/jwt_tool.py", run_name="__main__")
