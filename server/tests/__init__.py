"""Synthetic Main Server tests; no deployment fixtures."""

# The application never closes a descriptor it opened on a database file
# (``app.storage.database._HELD``, Issues #140/#152): closing one would drop
# this process's SQLite locks on the file. Each test's temporary database
# therefore keeps one descriptor open for the rest of the test process, and
# the full suite accumulates several hundred. A test-only "reset" that closed
# them would reintroduce exactly that hazard for any connection a test leaked,
# so instead the test process raises its own soft descriptor limit (within
# the hard limit; nothing outside this process changes) so the suite cannot
# fail with EMFILE on hosts whose default soft limit is 1024.
TEST_DESCRIPTOR_LIMIT = 65536


def _raise_descriptor_limit() -> None:
    try:
        import resource
    except ImportError:  # not POSIX; the Main is Linux-only
        return
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        wanted = TEST_DESCRIPTOR_LIMIT if hard == resource.RLIM_INFINITY else min(hard, TEST_DESCRIPTOR_LIMIT)
        if soft != resource.RLIM_INFINITY and soft < wanted:
            resource.setrlimit(resource.RLIMIT_NOFILE, (wanted, hard))
    except (OSError, ValueError):
        pass


_raise_descriptor_limit()
