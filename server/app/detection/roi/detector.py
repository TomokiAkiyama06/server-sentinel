"""Calibrated global compensation and persistent, neutral critical observations."""

from dataclasses import dataclass
from uuid import uuid4

from app.cameras.registry.models import timestamp
from app.detection.foundation import GrayFrame, Observation, Quality
from .contracts import Calibration, CriticalKind, CriticalObservation, SceneObservation
from .geometry import (candidates, contains, coverage, dissimilarity, match,
                       validate_polygon, variance)


@dataclass
class _Confirmation:
    first_ns: int | None = None
    count: int = 0
    emitted: bool = False

    def interrupt(self):
        """End the episode so a later confirmation is reported as new evidence.

        The emitted latch is cleared as well: after occlusion, quality loss, a
        stream restart or a sampling gap, a re-confirmed condition is a new
        confirmed observation and must not be silently dropped as a duplicate
        of an episode whose continuity this detector already lost.
        """
        self.first_ns, self.count, self.emitted = None, 0, False

    def observe(self, present, now, policy):
        if not present:
            self.interrupt()
            return False, False
        if self.first_ns is None:
            self.first_ns = now
        self.count += 1
        confirmed = self.count >= policy.confirmation_frames and now - self.first_ns >= policy.confirmation_ns
        emit = confirmed and not self.emitted
        self.emitted = self.emitted or confirmed
        return confirmed, emit


class SceneDetector:
    """One immutable calibration/binding per instance, run by an inference worker.

    A person-presence input is deliberately absent: it cannot establish physical
    movement. Presence suppression is also absent: confirmed critical outputs are
    always returned for a durable downstream event/evidence outbox.
    """

    def __init__(self, calibration: Calibration):
        if not isinstance(calibration, Calibration):
            raise ValueError("calibration is required")
        validate_polygon(calibration.polygon)
        self.calibration, self.policy = calibration, calibration.policy
        reference = calibration.reference
        self.frame_center = ((reference.width - 1) / 2, (reference.height - 1) / 2)
        xs, ys = zip(*calibration.polygon)
        self.roi_center = ((min(xs) + max(xs)) / 2, (min(ys) + max(ys)) / 2)
        padding = self.policy.roi_search_pixels
        self.roi_points, self.background = [], []
        for y in range(reference.height):
            for x in range(reference.width):
                if contains(calibration.polygon, x, y):
                    self.roi_points.append((x, y))
                if not (min(xs) - padding <= x <= max(xs) + padding
                        and min(ys) - padding <= y <= max(ys) + padding):
                    self.background.append((x, y))
        if not self.roi_points or not self.background:
            raise ValueError("calibration requires ROI and independent background support")
        if (variance(reference, self.background) < self.policy.minimum_background_variance
                or variance(reference, self.roi_points) < self.policy.minimum_roi_variance):
            raise ValueError("calibration lacks distinctive ROI or background texture")
        # A reference that already meets the obscured-scene threshold would make
        # every unchanged sample look obscured and confirm a tamper that never
        # happened, so it cannot serve as this policy's baseline.
        dark = sum(value <= self.policy.dark_pixel_ceiling for value in reference.pixels)
        if dark / len(reference.pixels) >= self.policy.camera_dark_fraction:
            raise ValueError("calibration reference already meets the obscured-scene threshold")
        self.global_candidates = candidates(self.policy.global_search_pixels, self.policy.global_quarter_turns)
        self.roi_candidates = candidates(self.policy.roi_search_pixels, self.policy.roi_quarter_turns)
        # Budget the costlier of the two per-sample paths. A registered scene
        # pays for ROI matching; an unmatched one skips it and pays for the
        # background scene-difference instead, so neither may exceed the bound.
        comparisons = (len(self.background) * len(self.global_candidates)
                       + max(len(self.roi_points) * len(self.roi_candidates), len(self.background))
                       + len(reference.pixels))
        if comparisons > self.policy.maximum_comparisons:
            raise ValueError("calibration exceeds comparison budget")
        # The policy checks that a search radius reaches its threshold, but this
        # support may drop those candidates at the coverage gate: background
        # points on the frame edge leave the frame under any translation. A
        # calibration that cannot register the displacement it must detect would
        # report it as an unmatched scene instead, so it is refused here.
        if not self._reachable(self.background, self.global_candidates, self.frame_center,
                               self.policy.camera_shift_pixels, reference):
            raise ValueError("no usable global transform reaches the camera-shift threshold")
        if not self._reachable(self.roi_points, self.roi_candidates, self.roi_center,
                               self.policy.movement_pixels, reference):
            raise ValueError("no usable ROI transform reaches the movement threshold")
        self.reference_digest = calibration.reference_sha256
        self.stream_id = None
        self.last_sequence = -1
        self.last_ns = -1
        self.last_scene_shift_ns = None
        self.last_scene_shift_confidence = None
        # One correlated source-loss event per tracked scene-shift episode. This
        # deduplication is deliberately separate from confirmation state, which
        # must never suppress a newly confirmed critical observation.
        self.shift_reported = False
        self.movement = _Confirmation()
        self.tamper = _Confirmation()

    def _reachable(self, points, transforms, center, threshold, reference):
        """Does a translating candidate at the threshold survive the coverage gate?

        A usable rotation does not substitute for one. The threshold is a pixel
        displacement, so if every translation of that size fails the coverage
        gate, a real shift stays unregistered however many quarter turns are
        configured.
        """
        for transform in transforms:
            if transform.dx ** 2 + transform.dy ** 2 < threshold ** 2:
                continue
            if coverage(points, transform, center, reference.width,
                        reference.height) >= self.policy.minimum_coverage:
                return True
        return False

    def _interrupt(self):
        self.movement.interrupt()
        self.tamper.interrupt()

    def _event(self, kind, frame, now, observed_at, confidence, reason):
        c = self.calibration
        return CriticalObservation(uuid4(), kind, c.source_id, c.source_type,
                                   self.stream_id or c.reference.stream_id,
                                   frame.sequence if frame is not None else None,
                                   observed_at, now, c.identifier, c.version, c.created_at,
                                   self.reference_digest, confidence, Quality.SUFFICIENT, reason)

    def _observation(self, frame, now, observed_at, *, movement=Observation.UNKNOWN,
                     movement_quality=Quality.UNKNOWN, tamper=Observation.UNKNOWN,
                     tamper_quality=Quality.UNKNOWN, movement_reason="unavailable",
                     tamper_reason="unavailable", movement_confidence=None,
                     tamper_confidence=None, global_transform=None, relative_transform=None,
                     critical=()):
        c = self.calibration
        return SceneObservation(c.source_id, self.stream_id or c.reference.stream_id,
                                frame.sequence if frame is not None else None,
                                observed_at, now, c.identifier, c.version, c.created_at,
                                self.reference_digest, movement, movement_quality,
                                tamper, tamper_quality, movement_reason, tamper_reason,
                                movement_confidence, tamper_confidence, global_transform,
                                relative_transform, critical)

    def _good_match(self, result):
        return (result is not None and result.error <= self.policy.maximum_match_error
                and result.margin >= self.policy.minimum_match_margin)

    def _accept(self, frame, monotonic_ns, observed_at, movement_quality, tamper_quality,
                roi_occluded):
        observed_at = timestamp(observed_at)
        if type(monotonic_ns) is not int or monotonic_ns < 0:
            raise ValueError("observation clock must be monotonic nanoseconds")
        if not isinstance(movement_quality, Quality) or not isinstance(tamper_quality, Quality):
            raise ValueError("detector-specific quality is required")
        if roi_occluded is not None and type(roi_occluded) is not bool:
            raise ValueError("occlusion context must be explicit")
        if not isinstance(frame, GrayFrame) or frame.source_id != self.calibration.source_id:
            raise ValueError("frame does not belong to this calibration")
        return observed_at

    def inspect(self, frame: GrayFrame, *, monotonic_ns: int, observed_at,
                movement_quality: Quality, tamper_quality: Quality,
                roi_occluded: bool | None = None):
        try:
            observed_at = self._accept(frame, monotonic_ns, observed_at, movement_quality,
                                       tamper_quality, roi_occluded)
        except Exception:
            # A refused sample breaks continuity exactly as a missing one does.
            # Ending confirmation here stops a later confirmed observation from
            # spanning a frame this detector never evaluated, such as one that
            # belongs to a different source.
            self._interrupt()
            raise
        c = self.calibration
        if (monotonic_ns <= self.last_ns or self.stream_id == frame.stream_id and frame.sequence <= self.last_sequence):
            self._interrupt()
            return self._observation(frame, monotonic_ns, observed_at, movement_reason="clock_or_sequence_regression",
                                     tamper_reason="clock_or_sequence_regression")
        restarted = self.stream_id is not None and self.stream_id != frame.stream_id
        gap = self.last_ns >= 0 and monotonic_ns - self.last_ns > self.policy.maximum_gap_ns
        # Record the observed progression before any fail-unknown return. The
        # source has already advanced past this sample, so a later buffered
        # frame from the superseded geometry or stream must not pass the
        # regression check and re-enter temporal confirmation.
        self.stream_id, self.last_sequence, self.last_ns = frame.stream_id, frame.sequence, monotonic_ns
        if restarted or gap:
            self.last_scene_shift_ns, self.last_scene_shift_confidence = None, None
        if (frame.channels != 1 or (frame.width, frame.height) != (c.reference.width, c.reference.height)):
            self._interrupt()
            return self._observation(frame, monotonic_ns, observed_at, movement_reason="reference_shape_mismatch",
                                     tamper_reason="reference_shape_mismatch")
        if restarted or gap:
            self._interrupt()
            return self._observation(frame, monotonic_ns, observed_at, movement_reason="stream_or_sampling_discontinuity",
                                     tamper_reason="stream_or_sampling_discontinuity")
        if movement_quality is not Quality.SUFFICIENT and tamper_quality is not Quality.SUFFICIENT:
            self._interrupt()
            return self._observation(frame, monotonic_ns, observed_at, movement_quality=movement_quality,
                                     tamper_quality=tamper_quality, movement_reason="quality_unavailable",
                                     tamper_reason="quality_unavailable")
        global_match = match(c.reference, frame, self.background, self.global_candidates,
                             self.frame_center, minimum_coverage=self.policy.minimum_coverage)
        global_good = self._good_match(global_match)
        movement = tamper = Observation.UNKNOWN
        movement_reason = tamper_reason = "quality_unavailable"
        movement_confidence = tamper_confidence = None
        relative = None
        critical = []
        if movement_quality is Quality.SUFFICIENT:
            if roi_occluded is True:
                self.movement.interrupt()
                movement_reason = "roi_occluded"
            elif not global_good:
                self.movement.interrupt()
                movement_reason = "global_alignment_unavailable"
            else:
                roi_match = match(c.reference, frame, self.roi_points, self.roi_candidates,
                                  self.roi_center, minimum_coverage=self.policy.minimum_coverage,
                                  outer=global_match.transform, outer_center=self.frame_center)
                if not self._good_match(roi_match):
                    self.movement.interrupt()
                    movement_reason = "roi_reference_unavailable_or_occluded"
                else:
                    relative = roi_match.transform
                    movement_confidence = min(1 - global_match.error, 1 - roi_match.error)
                    displaced = relative.dx ** 2 + relative.dy ** 2 >= self.policy.movement_pixels ** 2 or relative.rotated > 0
                    confirmed, emit = self.movement.observe(displaced, monotonic_ns, self.policy)
                    movement = Observation.PRESENT if confirmed else Observation.UNKNOWN if displaced else Observation.ABSENT
                    movement_reason = "server_geometry_changed" if confirmed else "awaiting_confirmation" if displaced else "reference_geometry_matches"
                    if emit:
                        critical.append(self._event(CriticalKind.SERVER_MOVEMENT, frame, monotonic_ns,
                                                    observed_at, movement_confidence, movement_reason))
        else:
            self.movement.interrupt()
        if tamper_quality is Quality.SUFFICIENT:
            dark = sum(value <= self.policy.dark_pixel_ceiling for value in frame.pixels) / len(frame.pixels)
            global_shift = global_good and (global_match.transform.dx ** 2 + global_match.transform.dy ** 2 >= self.policy.camera_shift_pixels ** 2
                                            or global_match.transform.rotated > 0)
            obscured = dark >= self.policy.camera_dark_fraction
            # A covered or redirected camera often cannot register at all. Such a
            # scene is a persistence candidate when it also differs measurably.
            # A scene whose best transform is acceptable but ambiguous is not:
            # on a repetitive scene the untransformed difference is large even
            # when the registered transform is small, so that case stays
            # indeterminate instead of being confirmed or called untampered.
            registered = (global_match is not None
                          and global_match.error <= self.policy.maximum_match_error)
            difference = 0.0 if global_good else dissimilarity(c.reference, frame, self.background)
            unmatched = not registered and difference > self.policy.maximum_match_error
            indeterminate = not (global_good or obscured or unmatched)
            changed = global_shift or obscured or unmatched
            if global_shift:
                tamper_reason, tamper_confidence = "global_scene_shift", 1 - global_match.error
                if self.last_scene_shift_ns is None:
                    self.shift_reported = False
                self.last_scene_shift_ns, self.last_scene_shift_confidence = monotonic_ns, tamper_confidence
            elif obscured:
                tamper_reason, tamper_confidence = "scene_obscured_or_changed", dark
            elif unmatched:
                tamper_reason, tamper_confidence = "scene_unmatched_persistently", difference
            elif indeterminate:
                tamper_reason, tamper_confidence = "global_alignment_unavailable", None
            else:
                # The calibrated background registers again: the tracked shift
                # episode is over and must not correlate a later source loss.
                tamper_reason, tamper_confidence = "background_matches", 1 - global_match.error
                self.last_scene_shift_ns, self.last_scene_shift_confidence = None, None
            if indeterminate:
                self.tamper.interrupt()
            else:
                confirmed, emit = self.tamper.observe(changed, monotonic_ns, self.policy)
                tamper = Observation.PRESENT if confirmed else Observation.UNKNOWN if changed else Observation.ABSENT
                if emit:
                    self.shift_reported = self.shift_reported or global_shift
                    critical.append(self._event(CriticalKind.CAMERA_TAMPER, frame, monotonic_ns,
                                                observed_at, tamper_confidence, tamper_reason))
        else:
            self.tamper.interrupt()
        return self._observation(frame, monotonic_ns, observed_at, movement=movement,
                                 movement_quality=movement_quality, tamper=tamper,
                                 tamper_quality=tamper_quality, movement_reason=movement_reason,
                                 tamper_reason=tamper_reason, movement_confidence=movement_confidence,
                                 tamper_confidence=tamper_confidence,
                                 global_transform=global_match.transform if global_good else None,
                                 relative_transform=relative, critical=tuple(critical))

    def source_lost(self, *, monotonic_ns: int, observed_at, health_signal_trusted: bool):
        try:
            observed_at = timestamp(observed_at)
            if type(monotonic_ns) is not int or monotonic_ns < 0 or type(health_signal_trusted) is not bool:
                raise ValueError("invalid source-health observation")
        except Exception:
            # A health observation this detector cannot accept still marks an
            # outage it could not evaluate, so the episode ends here too rather
            # than letting a later sample confirm across it.
            self._interrupt()
            raise
        self._interrupt()
        critical = ()
        correlated = (health_signal_trusted and self.last_scene_shift_ns is not None
                      and self.last_ns <= monotonic_ns
                      and 0 <= monotonic_ns - self.last_scene_shift_ns <= self.policy.loss_correlation_ns)
        if correlated and not self.shift_reported:
            critical = (self._event(CriticalKind.CAMERA_TAMPER, None, monotonic_ns, observed_at,
                                    self.last_scene_shift_confidence, "source_loss_after_scene_shift"),)
            self.shift_reported = True
        self.last_ns = max(self.last_ns, monotonic_ns)
        return self._observation(None, monotonic_ns, observed_at, movement_reason="source_unavailable",
                                 tamper=Observation.PRESENT if correlated else Observation.UNKNOWN,
                                 tamper_quality=Quality.SUFFICIENT if correlated else Quality.UNKNOWN,
                                 tamper_reason="source_loss_after_scene_shift" if correlated else "source_unavailable",
                                 tamper_confidence=self.last_scene_shift_confidence if correlated else None,
                                 critical=critical)
