# Synthetic and Generated Fixtures

Owns intentionally version-controlled synthetic/generated test media and documented non-sensitive inputs for empty scenes, motion/person events, occlusion/displacement, camera motion, low light, and stream interruption.

Keep fixtures minimal and reproducible with generation/provenance details where applicable. No real-person, real-room, or deployment footage, secrets, private hardware identifiers, or externally sourced real-person benchmark datasets belong here. This fixture allowance never exempts secret/runtime-data exclusions.

`manifest.json` currently registers `checkerboard.ppm` using the fixed `checkerboard-8x8-v1` recipe in `scripts/ci/repository_guard.py`. CI regenerates those geometric pixels and compares every byte. A new media format or synthetic inventory export needs a reviewed generator extension; arbitrary hashes or self-declared provenance are insufficient. See `docs/CI.md` for limits.
