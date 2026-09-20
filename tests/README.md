# Tests

Owns hardware-independent unit, integration, and mock end-to-end verification of Main Server, agent, and web contracts. `fixtures/synthetic/` is the only repository media-fixture location.

CI guard and component-runner regression tests live in `unit/test_repository_guard.py` and `unit/test_component_checks.py`. Run `python3 -m unittest discover -s tests/unit -p 'test_*.py' -v`. Their negative inputs are generated in temporary directories and contain no real deployment data.

Use mocks, virtual sources, dependency injection, and synthetic/generated data. Cover access boundaries, source identity, buffering/evidence retention, mount loss, storage safety, integrity, and truthful degradation. Real hardware/network/browser acceptance belongs in `MANUAL_TEST.md`; do not claim it from mock results or commit real deployment data/media.
