"""Daily recorder health orchestration, using the recorder's own worker/I/O.

A configured adapter must obtain bounded real encoded video from the actual
recording pipeline and validate container/duration/size and decoded video.
No default adapter pretends that arbitrary bytes or a checksum prove playback.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from typing import Protocol
import math
import time


class HealthState(StrEnum):
    OK = "OK"
    FAILED = "FAILED"
    UNAVAILABLE = "UNAVAILABLE"


class Stage(StrEnum):
    CLEANUP = "CLEANUP"
    PIPELINE = "PIPELINE"
    STORAGE = "STORAGE"
    WRITE = "WRITE"
    REOPEN_DECODE = "REOPEN_DECODE"
    DEVICE_HEALTH = "DEVICE_HEALTH"
    ADAPTER = "ADAPTER"


@dataclass(frozen=True)
class PipelineStatus:
    # The source adapter applies its configured freshness threshold. Unknown
    # freshness is None, rather than a made-up universally safe age threshold.
    fresh_sources: tuple[bool | None, ...]
    recorder_alive: bool
    encoder_alive: bool

    @property
    def ready(self):
        return (1 <= len(self.fresh_sources) <= 4 and all(value is True for value in self.fresh_sources)
                and self.recorder_alive is True and self.encoder_alive is True)


@dataclass(frozen=True)
class HealthResult:
    state: HealthState
    stages: tuple[Stage, ...]


class RecorderProbe(Protocol):
    """Implemented on the serialized RecordingStore worker, not an HTTP path."""
    def cleanup(self) -> None:
        """Verify expected root and reclaim only journaled self-test artifacts.

        Raise if incomplete. New test writes must remain blocked; on-disk
        leftovers remain included in the shared filesystem admission budget.
        """
    def pipeline_status(self) -> PipelineStatus:
        ...
    def check_storage(self) -> None:
        """Verify intended filesystem, writability and reserve/admission."""
    def write_test_segment(self) -> None:
        """Journal before bounded write, then flush/fsync the actual media path."""
    def reopen_and_decode(self) -> None:
        """Validate actual reopened size/container/duration and video decoding."""
    def storage_health(self) -> tuple[str, ...]:
        """OK, CRITICAL or UNVERIFIABLE for configured recording devices."""


class RecordingHealthService:
    def __init__(self, adapter: RecorderProbe | None, record_result, *,
                 monotonic=time.monotonic, utcnow=lambda: datetime.now(timezone.utc)):
        self.adapter = adapter
        # The integration supplies a durable local/UI result recorder plus #21
        # immediate notification enqueue; a failed call must propagate.
        self.record_result = record_result
        self.monotonic = monotonic
        self.utcnow = utcnow
        self._last_check = None

    def startup(self):
        return self._run()

    def tick(self):
        now = self.monotonic()
        if not math.isfinite(now):
            raise ValueError("INVALID_MONOTONIC_CLOCK")
        if self._last_check is None or now < self._last_check or now - self._last_check >= 86400:
            return self._run()
        return None

    def _run(self):
        started = self.monotonic()
        if not math.isfinite(started):
            raise ValueError("INVALID_MONOTONIC_CLOCK")
        failures = []
        unavailable = False
        adapter = self.adapter
        if adapter is None:
            result = HealthResult(HealthState.UNAVAILABLE, (Stage.ADAPTER,))
        else:
            stage = Stage.CLEANUP
            cancelled = None
            try:
                # Startup/previous-run cleanup must succeed before new writes.
                adapter.cleanup()
                stage = Stage.PIPELINE
                if not adapter.pipeline_status().ready:
                    failures.append(stage)
                else:
                    stage = Stage.STORAGE
                    adapter.check_storage()
                    stage = Stage.WRITE
                    adapter.write_test_segment()
                    stage = Stage.REOPEN_DECODE
                    adapter.reopen_and_decode()
            except Exception:
                failures.append(stage)
            except BaseException as exc:
                cancelled = exc
                failures.append(stage)
            finally:
                try:
                    adapter.cleanup()
                except Exception:
                    failures.append(Stage.CLEANUP)
                except BaseException as exc:
                    cancelled = cancelled or exc
                    failures.append(Stage.CLEANUP)
            if cancelled is None:
                try:
                    health = adapter.storage_health()
                    if not health or any(value not in {"OK", "CRITICAL", "UNVERIFIABLE"} for value in health):
                        unavailable = True
                    if "CRITICAL" in health:
                        failures.append(Stage.DEVICE_HEALTH)
                    if "UNVERIFIABLE" in health:
                        unavailable = True
                except Exception:
                    unavailable = True
                except BaseException as exc:
                    cancelled = exc
                    failures.append(Stage.DEVICE_HEALTH)
            failed = bool(failures)
            if unavailable:
                failures.append(Stage.DEVICE_HEALTH)
            state = HealthState.FAILED if failed else (
                HealthState.UNAVAILABLE if unavailable else HealthState.OK
            )
            result = HealthResult(state, tuple(dict.fromkeys(failures)))
            if cancelled is not None:
                self.record_result(result, self.utcnow())
                raise cancelled
        self.record_result(result, self.utcnow())
        self._last_check = started
        return result
