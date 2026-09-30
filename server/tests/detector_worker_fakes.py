"""Synthetic detector plugins for isolated-worker tests; no model or media.

Factories are importable top-level callables because the worker process is
spawned and receives them by reference.
"""

import os
import socket
import time

from app.detection.foundation import (Detection, DetectorKind, MotionBaseline,
                                     Observation, Reason)


class _Fake:
    kind = DetectorKind.PERSON
    implementation = "synthetic-worker-double"
    version = "1"

    def __init__(self, behaviour, argument=None):
        self.behaviour = behaviour
        self.argument = argument
        self.resets = 0

    def reset(self):
        self.resets += 1
        if self.behaviour == "hang_reset":
            time.sleep(3600)
        if self.behaviour == "fail_reset":
            raise RuntimeError("secret plugin path /private/model must not escape")

    def evaluate(self, frame):
        if self.behaviour == "hang":
            time.sleep(3600)
        if self.behaviour == "crash":
            os._exit(9)
        if self.behaviour == "raise":
            raise RuntimeError("secret plugin path /private/model must not escape")
        if self.behaviour == "allocate":
            # Exceeds the worker address-space limit chosen by the test.
            bytearray(self.argument)
        if self.behaviour == "resets":
            return Detection(Observation.PRESENT if self.resets else Observation.ABSENT,
                             Reason.EVALUATED)
        if self.behaviour == "outbound_evaluate":
            _swallowed_lookup()
        if self.behaviour == "crash_after":
            self.argument -= 1
            if self.argument < 0:
                os._exit(9)
        return Detection(Observation.ABSENT, Reason.EVALUATED, frame.pixels[0] / 255)


def fake(behaviour, argument=None):
    return _Fake(behaviour, argument)


def failing_start():
    raise RuntimeError("secret plugin path /private/model must not escape")


def hanging_start():
    time.sleep(3600)


def impostor():
    detector = _Fake("absent")
    detector.implementation = "unreviewed-model"
    return detector


def motion(pixel_delta, changed_fraction):
    return MotionBaseline(pixel_delta=pixel_delta, changed_fraction=changed_fraction)


def _swallowed_lookup():
    # Local name only; the refusal is swallowed like a careless library would.
    try:
        socket.getaddrinfo("localhost", None)
    except Exception:
        pass


def _smoke_adapter(behaviour, implementation):
    detector = _Fake(behaviour)
    detector.implementation = implementation
    detector.version = "0.1.1rc0"
    return detector


def smoke_adapter(implementation, **_arguments):
    """Stand-in for the YOLOX adapter in model-smoke worker tests."""
    return _smoke_adapter("absent", implementation)


def smoke_adapter_outbound_at_start(implementation, **_arguments):
    _swallowed_lookup()
    return _smoke_adapter("absent", implementation)


def smoke_adapter_outbound_at_evaluation(implementation, **_arguments):
    return _smoke_adapter("outbound_evaluate", implementation)
