"""The remote preview hub hands frames and stream ends to scene monitoring (Issue #205)."""

import unittest
from uuid import UUID

from app.main import _RemoteSceneForwarder
from app.media.live.remote_preview import RemotePreviewHub


NODE = UUID(int=1)
SOURCE = UUID(int=2)
JPEG = b"\xff\xd8synthetic\xff\xd9"


class Listener:
    def __init__(self, fail=False):
        self.frames, self.ended, self.fail = [], [], fail

    def on_remote_frame(self, source_id, stream, jpeg):
        self.frames.append((source_id, stream, jpeg))
        if self.fail:
            raise RuntimeError("synthetic")

    def on_remote_stream_end(self, source_id):
        self.ended.append(source_id)
        if self.fail:
            raise RuntimeError("synthetic")


class HubListenerTests(unittest.TestCase):
    def test_accepted_frames_and_session_ends_reach_the_listener(self):
        listener = Listener()
        hub = RemotePreviewHub(listener=listener)
        hub.open_node(NODE, 1)
        self.assertTrue(hub.publish(NODE, 1, SOURCE, JPEG))
        self.assertFalse(hub.publish(NODE, 0, SOURCE, JPEG))  # an old session: refused
        self.assertEqual(listener.frames, [(SOURCE, (NODE, 1), JPEG)])
        hub.open_node(NODE, 2)  # a newer session ends the old one's sources
        self.assertEqual(listener.ended, [SOURCE])
        hub.publish(NODE, 2, SOURCE, JPEG)
        hub.close_node(NODE, 2)
        self.assertEqual(listener.ended, [SOURCE, SOURCE])
        hub.open_node(NODE, 3)
        hub.publish(NODE, 3, SOURCE, JPEG)
        hub.clear()
        self.assertEqual(listener.ended, [SOURCE] * 3)

    def test_listener_errors_never_reach_the_ingest_session(self):
        hub = RemotePreviewHub(listener=Listener(fail=True))
        hub.open_node(NODE, 1)
        self.assertTrue(hub.publish(NODE, 1, SOURCE, JPEG))
        hub.close_node(NODE, 1)

    def test_an_invalid_listener_is_refused(self):
        with self.assertRaises(ValueError):
            RemotePreviewHub(listener=object())

    def test_the_forwarder_drops_everything_until_a_runtime_is_attached(self):
        forwarder = _RemoteSceneForwarder()
        forwarder.on_remote_frame(SOURCE, (NODE, 1), JPEG)
        forwarder.on_remote_stream_end(SOURCE)
        runtime = Listener()
        forwarder.runtime = runtime
        forwarder.on_remote_frame(SOURCE, (NODE, 1), JPEG)
        forwarder.on_remote_stream_end(SOURCE)
        self.assertEqual((runtime.frames, runtime.ended), ([(SOURCE, (NODE, 1), JPEG)], [SOURCE]))


if __name__ == "__main__":
    unittest.main()
