# Main Server Media

Owns validated ingest, independent capture/recording/inference/viewer profiles, compressed pre-roll, durable recording, and authorized browser delivery through the Main Server.

Event defaults are 30 seconds pre + 120 seconds post, with a 20-minute maximum; manual recording is capped at 20 minutes. Prefer compatible stream copy and stop/scale down viewer-only processing without subscribers. `health/` owns daily recording-path self-tests; `../storage/` owns write admission and retention.

Do not capture audio, expose unprotected playback URLs, send viewers directly to agents, or store runtime media in this source directory.
