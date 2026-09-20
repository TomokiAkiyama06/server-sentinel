# Main Server Recording Health

Owns at least daily checks of source freshness, recorder/encoder state, expected recording filesystem/mount/device, writability, free space, and safety reserve.

Validate a bounded deployment-local recording-path write, flush/fsync, reopen/parse/decode cycle and report available SMART/NVMe health. Delete only self-test-owned temporary/partial media on success, failure, or cancellation. Verify the expected filesystem and clean interrupted leftovers at next startup before creating more test media; never delete ordinary recordings or protected incidents.

Cleanup failure blocks further self-test media writes until safe cleanup succeeds. Count leftovers against storage admission/reserve in `../../storage/` and report failures immediately through `../../notifications/`; do not retain diagnostic media.

Never report healthy after known recording failure, silently fall back to the root filesystem when a media mount disappears, upload self-test media, or treat Agent health as this Main Server self-test.
