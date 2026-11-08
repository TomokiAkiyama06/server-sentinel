"""Daily recorder health orchestration, using the recorder's own worker/I/O.

A configured adapter must obtain bounded real encoded video from the actual
recording pipeline and validate container/duration/size and decoded video.
No default adapter pretends that arbitrary bytes or a checksum prove playback.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from typing import Callable, Protocol
import logging
import math
import time

from app.logging import Event
from app.stop_budget import INTERRUPTED, StopInterrupted, never


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
                 monotonic=time.monotonic, utcnow=lambda: datetime.now(timezone.utc),
                 stopping: Callable[[], bool] = never):
        self.adapter = adapter
        # The integration supplies a durable local/UI result recorder plus #21
        # immediate notification enqueue; a failed call must propagate.
        self.record_result = record_result
        self.monotonic = monotonic
        self.utcnow = utcnow
        # Issue #385: once the Main shutdown began, the self-test starts no
        # further stage (`_stage`).
        self.stopping = stopping
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

    def _stage(self):
        """Issue #385: refuse to start another stage once the stop began."""
        if self.stopping():
            raise StopInterrupted()

    def _interrupted(self, failures):
        """Issue #385: end a self-test the Main shutdown cut short.

        A stage that failed before the stop began, or a failed cleanup, is a
        complete and real failure and is recorded (and notified) as one;
        without one the test is neither failed nor healthy, so nothing is
        recorded.
        """
        if failures:
            self.record_result(HealthResult(HealthState.FAILED, tuple(dict.fromkeys(failures))),
                               self.utcnow())
        logging.getLogger(__name__).warning(Event.MONITORING_CHECK_INTERRUPTED)

    def _run(self):
        """One self-test; `INTERRUPTED` when the Main shutdown cut it short.

        Once the stop began no further stage starts and the device health
        read is skipped; the cleanup still runs (INTEGRITY-004). A partial
        test is never reported as failed or healthy (`_interrupted`). A stage
        that fails once the stop has begun is not counted as a failure either
        (PR #389 review): the shutdown tears capture and storage down while it
        runs, so its failure proves nothing. A failed cleanup, the first or
        the final one, is always kept and recorded (PR #389 Codex P1): it only
        removes the test's own files, and the recording filesystem stays open
        until the monitoring runtime closes after this test, so the failure
        leaves real leftovers rather than reflecting the teardown. The next
        start runs the startup self-test.
        """
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
            interrupted = False
            try:
                # Startup/previous-run cleanup must succeed before new writes.
                adapter.cleanup()
                stage = Stage.PIPELINE
                self._stage()
                if not adapter.pipeline_status().ready:
                    if self.stopping():
                        raise StopInterrupted()
                    failures.append(stage)
                else:
                    stage = Stage.STORAGE
                    self._stage()
                    adapter.check_storage()
                    stage = Stage.WRITE
                    self._stage()
                    adapter.write_test_segment()
                    stage = Stage.REOPEN_DECODE
                    self._stage()
                    adapter.reopen_and_decode()
            except StopInterrupted:
                interrupted = True
            except Exception:
                if self.stopping() and stage != Stage.CLEANUP:
                    interrupted = True
                else:
                    # A failed startup/previous-run cleanup is kept even
                    # once the stop began (PR #389 Codex P1): it is the
                    # cleanup INTEGRITY-004 requires, not a stage the
                    # shutdown tore down, so it is recorded and notified
                    # like the final cleanup's failure.
                    if self.stopping():
                        interrupted = True
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
            if cancelled is None and (interrupted or self.stopping()):
                self._interrupted(failures)
                return INTERRUPTED
            if cancelled is None:
                try:
                    health = adapter.storage_health()
                    if not health or any(value not in {"OK", "CRITICAL", "UNVERIFIABLE"} for value in health):
                        unavailable = True
                    if "CRITICAL" in health:
                        failures.append(Stage.DEVICE_HEALTH)
                    if "UNVERIFIABLE" in health:
                        unavailable = True
                except StopInterrupted:
                    # A device health read killed at the stop (Issue #385).
                    self._interrupted(failures)
                    return INTERRUPTED
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
