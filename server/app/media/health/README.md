# Main Server Recording Health

Owns at least daily checks of source freshness, recorder/encoder state, expected recording filesystem/mount/device, writability, free space, and safety reserve.

Validate a bounded deployment-local recording-path write, flush/fsync, reopen/parse/decode cycle; delete successful temporary artifacts and report available SMART/NVMe health. Coordinate write admission with `../../storage/` and immediate failure notifications with `../../notifications/`.

Never report healthy after known recording failure, silently fall back to the root filesystem when a media mount disappears, upload self-test media, or treat Agent health as this Main Server self-test.
