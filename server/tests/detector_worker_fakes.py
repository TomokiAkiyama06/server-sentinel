"""Synthetic detector plugins for isolated-worker tests; no model or media.

Factories are importable top-level callables because the worker process is
spawned and receives them by reference.
"""

import os
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
