"""Synthetic Main Server tests; no deployment fixtures."""

import functools
import unittest

# The application never closes a descriptor it opened on a database file
# (``app.storage.database._HELD``, Issues #140/#152): closing one would drop
# this process's SQLite locks on the file. Each test's temporary database
# therefore used to keep one descriptor open for the rest of the test
# process, and the full suite accumulated about 2000 (Issue #248).
#
# After every test (once its cleanups, and so its temporary directories, are
# gone) the test-only ``_release_unlinked_held_files_for_tests`` closes the
# held descriptors of database files that are no longer linked and that no
# other descriptor in the process still refers to. A connection a test leaked
# keeps SQLite's own descriptor on the inode, so that file stays held and its
# locks are never dropped. Application code never calls the release.
#
# The soft descriptor limit is still raised within the hard limit (nothing
# outside this process changes) as a margin; CI runs the suite with a hard
# limit of 1024 (``ci.toml``), where raising cannot help, so a descriptor
# regression fails there.
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


def release_unlinked_test_databases() -> tuple[int, int]:
    """Close held descriptors of deleted, unused temporary databases."""
    from app.storage.database import _release_unlinked_held_files_for_tests
    return _release_unlinked_held_files_for_tests()


def _install_release_after_each_test() -> None:
    """Wrap ``TestCase.run`` (which includes tearDown and cleanups) once.

    Discovery imports every test module, and so this package, before the
    first test runs; ``IsolatedAsyncioTestCase.run`` delegates here too.
    Class- and module-level temporary databases are released after the
    test that follows their teardown.
    """
    original = unittest.TestCase.run
    if getattr(original, "_releases_test_databases", False):
        return

    @functools.wraps(original)
    def run(self, result=None):
        try:
            return original(self, result)
        finally:
            release_unlinked_test_databases()

    run._releases_test_databases = True
    unittest.TestCase.run = run


_raise_descriptor_limit()
_install_release_after_each_test()
