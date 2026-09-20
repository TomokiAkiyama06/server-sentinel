"""Bounded rigid integer/quarter-turn template comparison, no image library."""

from dataclasses import dataclass
import math

from app.detection.foundation import GrayFrame
from .contracts import Transform


def cross(a, b, c):
    return (b[0] - a[0]) * (c[1] - a[1]) - (b[1] - a[1]) * (c[0] - a[0])


def on_segment(a, b, point):
    return (cross(a, b, point) == 0 and min(a[0], b[0]) <= point[0] <= max(a[0], b[0])
            and min(a[1], b[1]) <= point[1] <= max(a[1], b[1]))


def validate_polygon(points):
    if len(set(points)) != len(points):
        raise ValueError("polygon has duplicate vertices")
    area = sum(a[0] * b[1] - b[0] * a[1] for a, b in zip(points, points[1:] + points[:1]))
    if area == 0:
        raise ValueError("polygon has no area")
    edges = list(zip(points, points[1:] + points[:1]))
    for i, (a, b) in enumerate(edges):
        for j, (c, d) in enumerate(edges):
            if i >= j or j == i + 1 or (i == 0 and j == len(edges) - 1):
                continue
            proper = cross(a, b, c) * cross(a, b, d) < 0 and cross(c, d, a) * cross(c, d, b) < 0
            touching = any((on_segment(a, b, c), on_segment(a, b, d), on_segment(c, d, a), on_segment(c, d, b)))
            if proper or touching:
                raise ValueError("polygon must not intersect itself")


def contains(points, x, y):
    inside = False
    for a, b in zip(points, points[1:] + points[:1]):
        if on_segment(a, b, (x, y)):
            return True
        if (a[1] > y) != (b[1] > y):
            intersect_x = (b[0] - a[0]) * (y - a[1]) / (b[1] - a[1]) + a[0]
            if x < intersect_x:
                inside = not inside
    return inside


def apply(point, transform, center):
    x, y = point[0] - center[0], point[1] - center[1]
    for _ in range(transform.quarter_turns):
        x, y = -y, x
    return round(x + center[0] + transform.dx), round(y + center[1] + transform.dy)


def candidates(radius, angles):
    return tuple(Transform(dx, dy, angle) for angle in angles
                 for dy in range(-radius, radius + 1) for dx in range(-radius, radius + 1))


def variance(reference, points):
    values = [reference.pixels[y * reference.width + x] / 255 for x, y in points]
    if not values:
        return 0.0
    mean = sum(values) / len(values)
    return sum((value - mean) ** 2 for value in values) / len(values)


def coverage(points, transform, center, width, height):
    """Fraction of support points a candidate keeps inside the frame."""
    if not points:
        return 0.0
    inside = 0
    for point in points:
        x, y = apply(point, transform, center)
        if 0 <= x < width and 0 <= y < height:
            inside += 1
    return inside / len(points)


def dissimilarity(reference: GrayFrame, current: GrayFrame, points):
    """Mean absolute untransformed difference in [0, 1] over support points.

    This is a scene-change measurement, not a probability and not an identity:
    it never describes who or what is in the frame. It stays available when
    bounded rigid registration fails, so a persistently unmatched scene can be
    measured instead of being discarded every sample.
    """
    if not points:
        return 0.0
    total = sum(abs(reference.pixels[y * reference.width + x]
                    - current.pixels[y * current.width + x]) for x, y in points)
    return total / (255 * len(points))


@dataclass(frozen=True)
class Match:
    transform: Transform
    error: float
    margin: float
    coverage: float


def match(reference: GrayFrame, current: GrayFrame, points, transforms, center, *,
          minimum_coverage, outer=None, outer_center=None):
    ranked = []
    for transform in transforms:
        count, difference = 0, 0
        for point in points:
            destination = apply(point, transform, center)
            if outer is not None:
                destination = apply(destination, outer, outer_center)
            x, y = destination
            if 0 <= x < current.width and 0 <= y < current.height:
                count += 1
                difference += abs(reference.pixels[point[1] * reference.width + point[0]]
                                  - current.pixels[y * current.width + x])
        coverage = count / len(points)
        if coverage >= minimum_coverage:
            ranked.append((difference / (255 * count), transform, coverage))
    ranked.sort(key=lambda item: item[0])
    if not ranked:
        return None
    error, transform, coverage = ranked[0]
    margin = ranked[1][0] - error if len(ranked) > 1 else math.inf
    return Match(transform, error, margin, coverage)
