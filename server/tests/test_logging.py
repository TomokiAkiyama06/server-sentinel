import io
from contextlib import redirect_stderr
import json
import logging
import unittest

from app.logging import Event, SafeJsonFormatter, SafeStreamHandler


class LoggingTests(unittest.TestCase):
    def setUp(self):
        self.output = io.StringIO()
        self.logger = logging.Logger("synthetic", level=logging.INFO)
        handler = SafeStreamHandler(self.output)
        handler.setFormatter(SafeJsonFormatter())
        self.logger.addHandler(handler)

    def test_secret_values_dropped_from_messages_args_exceptions_and_all_extras(self):
        marker = "SYNTHETIC_PRIVATE_VALUE"
        try:
            raise ValueError(marker)
        except ValueError:
            self.logger.exception("raw %s", marker, extra={
                "headers": {"authorization": marker}, "cookie": marker,
                "pairing": marker, "embedding": [marker], "media": marker,
                "path": marker, "query": marker, "arbitrary": marker,
                "status": marker, "duration_ms": marker,
            })
        result = json.loads(self.output.getvalue())
        self.assertNotIn(marker, self.output.getvalue())
        self.assertEqual(result["event"], "unstructured_redacted")
        self.assertEqual(set(result), {"timestamp", "level", "event"})

    def test_known_event_retains_only_bounded_numeric_metadata(self):
        self.logger.info(Event.REQUEST_DENIED, extra={"status": 404, "duration_ms": 1.25})
        result = json.loads(self.output.getvalue())
        self.assertEqual(result["event"], "request_denied")
        self.assertEqual(result["status"], 404)
        self.assertEqual(result["duration_ms"], 1.25)

    def test_nan_bool_and_out_of_range_values_are_discarded(self):
        for status, duration in ((True, float("nan")), (99, -1), (600, float("inf"))):
            self.logger.info(Event.REQUEST_DENIED, extra={"status": status, "duration_ms": duration})
        for line in self.output.getvalue().splitlines():
            self.assertEqual(set(json.loads(line)), {"timestamp", "level", "event"})

    def test_forged_event_string_cannot_be_logged(self):
        self.logger.info("application_started")
        self.assertEqual(json.loads(self.output.getvalue())["event"], "unstructured_redacted")

    def test_huge_numeric_input_cannot_trigger_raw_stderr_fallback(self):
        error_output = io.StringIO()
        with redirect_stderr(error_output):
            self.logger.error("raw %s", "SYNTHETIC_PRIVATE_VALUE",
                              extra={"duration_ms": 10 ** 1000})
        self.assertEqual(error_output.getvalue(), "")
        self.assertNotIn("SYNTHETIC_PRIVATE_VALUE", self.output.getvalue())
        self.assertNotIn("duration_ms", json.loads(self.output.getvalue()))

    def test_failed_stream_does_not_echo_raw_record_or_exception(self):
        class BrokenStream:
            def write(self, value):
                raise OSError("SYNTHETIC_PRIVATE_VALUE")
        self.logger.handlers[0].stream = BrokenStream()
        error_output = io.StringIO()
        with redirect_stderr(error_output):
            self.logger.error("raw %s", "SYNTHETIC_PRIVATE_VALUE")
        self.assertEqual(json.loads(error_output.getvalue())["event"], "logging_failed")
        self.assertNotIn("SYNTHETIC_PRIVATE_VALUE", error_output.getvalue())
