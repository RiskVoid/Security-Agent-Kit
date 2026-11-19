"""The OAuth lab's seeded flaws and clean controls, over HTTP with no model and no Docker (the lab app is stdlib
http.server). The same checks run in Docker against the real lab by evals/oauth_lab_test.sh.

Run: python3 evals/oauth_lab_test.py
"""
import importlib.util, os, threading, unittest
from http.server import ThreadingHTTPServer

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = os.path.join(KIT, "evals", "targets", "rv-oauth-lab")


def _load(name, fn):
    spec = importlib.util.spec_from_file_location(name, os.path.join(BASE, fn))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


app = _load("oauth_lab", "app.py")
checks = _load("oauth_checks", "checks.py")


class OAuthLab(unittest.TestCase):
    """#138: the vulnerable build shows the seeded flaws, the fixed build shows none of them."""

    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), app.H)
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def _reset(self):
        app.codes.clear()
        app.access.clear()
        app.refresh.clear()

    def test_vulnerable_build_has_the_flaws(self):
        app.FIXED = False
        self._reset()
        res = checks.checks("127.0.0.1", self.port)
        self.assertEqual([n for n, _, _ in res], ["redirect_uri validated by prefix",
                                                  "authorize without state accepted",
                                                  "code exchanged without PKCE",
                                                  "authorization code replay accepted"])
        self.assertTrue(all(present for _, present, _ in res), res)

    def test_fixed_build_has_clean_controls(self):
        app.FIXED = True
        self._reset()
        res = checks.checks("127.0.0.1", self.port)
        self.assertEqual(len(res), 4)
        self.assertFalse(any(present for _, present, _ in res), res)


if __name__ == "__main__":
    unittest.main(verbosity=2)
