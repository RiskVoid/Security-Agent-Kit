"""HTTP protocol checks for the self-hosted catcher. No Docker, model or external network required."""
import http.client, importlib.util, json, pathlib, threading, unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("catcher", pathlib.Path(__file__).parents[1] / "callback-catcher/server.py")
catcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(catcher)


class Callbacks(unittest.TestCase):
    def setUp(self):
        self.server = catcher.Catcher(("127.0.0.1", 0))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()

    def request(self, path, method="GET", body=None):
        conn = http.client.HTTPConnection(*self.server.server_address, timeout=2)
        try:
            conn.request(method, path, body)
            response = conn.getresponse()
            return response.status, json.loads(response.read())
        finally:
            conn.close()

    def test_exact_token_only_and_poll_does_not_create_events(self):
        self.assertEqual(self.request("/events/rvprobe123"), (200, {"token": "rvprobe123", "count": 0}))
        self.request("/callback/rvother123", "POST", "client body must not be stored")
        self.assertEqual(self.request("/events/rvprobe123")[1]["count"], 0)
        self.request("/callback/rvprobe123")
        self.assertEqual(self.request("/events/rvprobe123")[1]["count"], 1)
        self.assertEqual(set(self.server.events), {"rvother123", "rvprobe123"})
        self.assertTrue(all(len(event) == 2 for event in self.server.events.values()))
        for path in ("/callback/short", "/callback/rvprobe123?other=1", "/events/../rvprobe123"):
            self.assertEqual(self.request(path)[0], 404)
        self.assertEqual(self.request("/events/rvprobe123", "POST")[0], 405)

    def test_bounded_store_and_expiration(self):
        with patch.object(catcher, "MAX_TOKENS", 1):
            self.request("/callback/rvfirst123")
            self.assertEqual(self.request("/callback/rvsecond123")[0], 503)
            # A full store still permits polling and repeated callbacks for an existing token.
            self.request("/callback/rvfirst123")
            self.assertEqual(self.request("/events/rvfirst123")[1]["count"], 2)
            with self.server.lock:
                self.server.events["rvfirst123"] = (2, 0)
            self.assertEqual(self.request("/events/rvfirst123")[1]["count"], 0)
            self.assertEqual(self.request("/callback/rvsecond123")[0], 200)


if __name__ == "__main__":
    unittest.main()
