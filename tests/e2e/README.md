# End-to-End Tests

Owns mock/virtual-source workflows across Main Server, capture agent, and browser UI: setup, invitations, 1–4 sources, viewing, recording/timeline permissions, interruption, protected incidents, and visible integrity/storage failures.

Use synthetic/generated inputs and isolated runtime state. Do not claim real UVC, LAN, GPU, or phone/Mac acceptance from mock E2E; those checks belong in `MANUAL_TEST.md`. No real media or deployment credentials may enter CI artifacts.
