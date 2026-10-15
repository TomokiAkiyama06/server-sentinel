# Main storage policy and retention

Issue #21 provides an internal, single-worker domain service over #18's
`RecordingStore`; no human routes or deployed auth mechanism are introduced.
Construct `MainStoragePolicy` with explicit `StorageLimits`, an
`ExpectedFilesystem.snapshot` callback, testable clock and audit sink. Construct
the recorder, then `bind(store, RetentionService(store))`. Constructor recovery
uses physical-only `admit_control` before binding; media admission fails closed
until binding. All recorder metadata/media writes hold a reservation until
commit/fsync. The same `policy.control` context protects `StorageAudit` and the
daily scheduler, including transitions triggered during admission.
`ExpectedFilesystem(root, identity, metadata_path)` also verifies a private regular
metadata file on the same filesystem without following symlinks. Deployment
integration must reserve space before opening/migrating it. Provisioning migrations need their own
reserved initialization phase; these services never open a production volume.

Thresholds, quota, maximum request size, critical allowance, cleanup batch and
metadata/journal/temp overhead are deployment requirements, not guessed product
defaults. The configured overhead must bound the entire serialized operation,
including recovery and cleanup. `statvfs` uses space available to the service
account, includes unrelated process consumption and checks the existing private
root's device/inode/owner without following symlinks or creating a fallback.
An unrelated process may consume space after a sample; this policy cannot reserve
kernel disk blocks against unrelated writers. It never intentionally admits a
request beyond the hard safety reserve.

Ordinary/manual writes stop under `STORAGE_PRESSURE`; only explicitly confirmed
critical work supplied through the trusted recorder port can use the allowance.
`admit_external` reserves bytes for optional non-recording local artifacts such
as an Owner-initiated diagnostic bundle. It never runs retention or reclamation,
so such an artifact cannot evict monitoring evidence to make room; it refuses
with the current state whenever the deployment is not `NORMAL`. It classifies
the real filesystem condition first and then evaluates the projected allocation
without persisting it, so a refused artifact never latches pressure and never
pushes the next admissible recording into recovery-mode reclamation.
The allowance conservatively caps resident critical segment bytes plus the new
reservation (including after restart), and also bounds total quota overflow.
No evidence classifier is implemented here. Cleanup tries expired completed
unstarred recordings first, then oldest eligible recordings in bounded batches.
Cleanup and state classification share one threshold predicate, so a request
never stops reclaiming exactly where admission still rejects it. While pressured
or hard stopped, bounded cleanup targets the recovery thresholds; stopping at the
entry boundary would latch the state and reject later recordings indefinitely.
The recorder rechecks stars/active status before deleting its own generated
segments and preserves shared/spool links. Star changes and admission serialize
on the same owning worker. Agent protected incident lifecycles are untouched.

Low physical space or filesystem uncertainty enters `STORAGE_HARD_STOP` before
unsafe writes. Physical free-space and allocation recovery thresholds provide
hysteresis. Transitions go to an injected audit sink; persistence failure remains
visible in `StorageStatus.audit_delivery_failed`, rather than silently healthy.
Control/cleanup writes can continue under ordinary pressure if the reserve fits.
The default retention periods are Main recordings 20 days and Main audit 90 days;
audit expiry processes an explicit bounded batch (at most 1000 oldest rows) per
call, so its journal work fits the configured operation budget. Agent's separately
implemented 60-day expiry is not handled by this module.

`RecordingBrowser` authorizes every read with `recordings:view` and every
star/unstar/delete with `owner`, using a denied-by-default injected contract.
Owner permission adapters must also grant the read action. No download or human
HTTP endpoint exists. The store supplies truthful read-only integrity metadata
when hard stop prevents persistence. Production session integration remains #10.

Tests use temporary synthetic SQLite/files only. Exact threshold sizing, shared
filesystem verification, real codecs/volumes, production timer/outbox and human
route integration remain deployment/integration acceptance, not claims made by
these tests. No dependency was added; all new Python code uses the stdlib.
The lifespan binding, periodic retention and state-audit wiring live in
`../monitoring/`.

## Held database descriptors (Issues #152, #248)

`database.py` keeps one read-only descriptor per database file (device, inode)
that the process opened or created through it, and never closes it: closing
any descriptor on the file would drop this process's SQLite POSIX locks on it.
In production the count is bounded by the database files the process uses.

The test suite creates and deletes one temporary database per test, so each
used to keep one descriptor open until the test process exited (about 2000 for
the full suite, `EMFILE` under `ulimit -n 1024`). The test-only
`_release_unlinked_held_files_for_tests()` closes the held descriptors of a
file only when it is no longer linked anywhere and no other descriptor in the
process refers to its inode (an open or leaked SQLite connection, or a close
SQLite deferred, keeps it held, so no lock is ever dropped). `tests/__init__.py`
calls it after every test's cleanups. Application code never calls it, which a
test enforces, and the production lock behavior is unchanged. The server CI
test command runs with `ulimit -n 1024` (soft and hard) so a regression fails.

Each held descriptor also gets an adoption serial that is never reused.
`PinnedDatabase` and the local admin ledger record it when they pin and refuse
once `held_descriptor_is_current()` no longer matches. After the test-only
release, the descriptor number and even the inode may be reused, for example
by a database recreated at the same path, so a stale pin is refused because
of the serial, not because of the file identity. In production a held
descriptor is never closed, so the serial never changes. The release keeps a
file held when it cannot examine some other descriptor (any `fstat` error
other than `EBADF`). `read_database_prefix()` reads after leaving the
holder's lock, so the release must not run concurrently with other threads
that use those databases. The per-test hook runs it between tests.
