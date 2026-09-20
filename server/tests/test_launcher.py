from pathlib import Path
import logging
import tempfile
import unittest
from unittest.mock import patch

from app.__main__ import main


class LauncherTests(unittest.TestCase):
    def setUp(self):
        self.handlers = logging.getLogger().handlers[:]
        self.level = logging.getLogger().level
        self.addCleanup(self.restore_logging)

    def restore_logging(self):
        logging.getLogger().handlers = self.handlers
        logging.getLogger().setLevel(self.level)

    def test_launcher_never_enables_proxy_headers_or_framework_access_logs(self):
        with tempfile.TemporaryDirectory() as temporary:
            with patch.dict("os.environ", {"SERVERSENTINEL_DATA_DIRECTORY": str(Path(temporary))}, clear=True):
                with patch("uvicorn.run") as run:
                    self.assertEqual(main(), 0)
            options = run.call_args.kwargs
            self.assertEqual(options["host"], "127.0.0.1")
            for name in ("server_header", "date_header", "access_log", "proxy_headers"):
                self.assertIs(options[name], False)
            self.assertIsNone(options["log_config"])
            self.assertEqual(options["forwarded_allow_ips"], "")
            self.assertEqual(options["ws"], "none")

    def test_missing_settings_do_not_start_listener(self):
        with patch.dict("os.environ", {}, clear=True), patch("uvicorn.run") as run:
            self.assertEqual(main(), 1)
            run.assert_not_called()
