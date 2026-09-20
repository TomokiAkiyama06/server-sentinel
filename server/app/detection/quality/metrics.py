"""Bounded, local measurements of transient 8-bit decoded frames."""

from app.detection.foundation import GrayFrame
from .contracts import FrameIdentity, Metric, QualityContext, QualityReason


class MeasurementUnavailable(ValueError):
    """The explicit measurement budget or required geometry was unavailable."""

    def __init__(self, reason: QualityReason):
        super().__init__("quality measurements unavailable")
        self.reason = reason


def obstruction_fraction(mask: bytes, *, maximum_pixels: int) -> float:
    """Measure a caller-supplied binary ROI obstruction mask (0 clear, 1 blocked).

    This does not infer obstruction from an image. The calibrated producer owns
    mask meaning/attribution; empty/malformed masks must never imply a clear ROI.
    """
    if (type(maximum_pixels) is not int or maximum_pixels <= 0 or type(mask) is not bytes
            or not mask or len(mask) > maximum_pixels or any(value not in (0, 1) for value in mask)):
        raise ValueError("obstruction mask must contain binary observations")
    return sum(mask) / len(mask)


def measure(frame: GrayFrame, *, maximum_pixels: int,
            context: QualityContext | None = None) -> tuple[tuple[Metric, float | int | None], ...]:
    """O(pixel count) time, O(width) extra memory; no retained decoded history.

    Luminance is normalized grayscale or the weighted RGB brightness estimate
    0.2126 R + 0.7152 G + 0.0722 B. Sharpness is mean squared neighboring luma
    difference. It is a calibrated texture/sharpness proxy, not proof of focus.
    Saturation is the fraction of pixels with at least one clipped 255 channel.
    """
    if (not isinstance(frame, GrayFrame)
            or (context is not None and not isinstance(context, QualityContext))):
        raise ValueError("invalid quality measurement input")
    if context is not None and context.frame != FrameIdentity.from_frame(frame):
        raise MeasurementUnavailable(QualityReason.CONTEXT_MISMATCH)
    count = frame.width * frame.height
    if type(maximum_pixels) is not int or maximum_pixels <= 0 or count > maximum_pixels:
        raise MeasurementUnavailable(QualityReason.RESOURCE_LIMIT)
    if context is not None and (
        (context.target_width is not None and context.target_width > frame.width)
        or (context.target_height is not None and context.target_height > frame.height)
    ):
        raise MeasurementUnavailable(QualityReason.METRIC_UNAVAILABLE)
    previous = [0.0] * frame.width
    total, differences, clipped, edges = 0.0, 0.0, 0, 0
    for y in range(frame.height):
        left = 0.0
        for x in range(frame.width):
            offset = (y * frame.width + x) * frame.channels
            if frame.channels == 1:
                pixel = frame.pixels[offset]
                luminance = pixel / 255
                clipped += pixel == 255
            elif frame.channels == 3:
                red, green, blue = frame.pixels[offset:offset + 3]
                luminance = (0.2126 * red + 0.7152 * green + 0.0722 * blue) / 255
                clipped += 255 in (red, green, blue)
            else:
                raise MeasurementUnavailable(QualityReason.METRIC_UNAVAILABLE)
            total += luminance
            if x:
                differences += (luminance - left) ** 2
                edges += 1
            if y:
                differences += (luminance - previous[x]) ** 2
                edges += 1
            previous[x], left = luminance, luminance
    return (
        (Metric.WIDTH, frame.width), (Metric.HEIGHT, frame.height),
        (Metric.LUMINANCE, min(1.0, max(0.0, total / count))),
        (Metric.SHARPNESS, min(1.0, max(0.0, differences / edges)) if edges else None),
        (Metric.SATURATION, clipped / count),
        (Metric.TARGET_WIDTH, context.target_width if context else None),
        (Metric.TARGET_HEIGHT, context.target_height if context else None),
        (Metric.OCCLUSION, context.occlusion_fraction if context else None),
        (Metric.CONFIDENCE, context.detector_confidence if context else None),
    )
