from pathlib import Path
import tempfile
import unittest

from app.settings import ConfigurationError, Settings


class SettingsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def test_defaults_and_typed_environment(self):
        settings = Settings.from_env({
            "SERVERSENTINEL_DATA_DIRECTORY": str(self.directory),
            "SERVERSENTINEL_HUMAN_PORT": "8123",
        })
        self.assertEqual(settings.human_port, 8123)
        self.assertEqual(settings.human_host, "127.0.0.1")
        self.assertEqual(settings.database_path, self.directory / "state.sqlite3")
        self.assertNotIn(str(self.directory), repr(settings))

    def test_requires_explicit_existing_external_directory(self):
        for directory in (Path("relative"), self.directory / "missing"):
            with self.subTest(directory=directory), self.assertRaises(ConfigurationError):
                Settings(directory)
        with self.assertRaises(ConfigurationError):
            Settings.from_env({})
        with self.assertRaises(ConfigurationError):
            Settings(Path(__file__).resolve().parent)

    def test_source_tree_symlink_cannot_bypass_path_validation(self):
        link = self.directory / "linked"
        link.symlink_to(Path(__file__).resolve().parent, target_is_directory=True)
        with self.assertRaises(ConfigurationError):
            Settings(link)

    def test_rejects_public_bind_and_invalid_ports(self):
        for host in ("0.0.0.0", "::", "192.0.2.1", "example.invalid", "localhost"):
            with self.subTest(host=host), self.assertRaises(ConfigurationError):
                Settings(self.directory, human_host=host)
        for port in (True, 0, 65536, 1.5, "8000"):
            with self.subTest(port=port), self.assertRaises(ConfigurationError):
                Settings(self.directory, human_port=port)
        self.assertEqual(Settings(self.directory, human_host="::1").human_host, "::1")

    def test_invalid_values_and_unknown_keys_never_echo(self):
        marker = "SYNTHETIC_PRIVATE_VALUE"
        for key in ("HUMAN_HOST", "HUMAN_PORT", "LOG_LEVEL", marker):
            with self.subTest(key=key), self.assertRaises(ConfigurationError) as caught:
                Settings.from_env({"SERVERSENTINEL_DATA_DIRECTORY": str(self.directory),
                                   "SERVERSENTINEL_" + key: marker})
            self.assertNotIn(marker, str(caught.exception))

    def test_environment_port_is_strict(self):
        for value in ("1.5", "-1", " 8000", "８０００", "", "9" * 5000):
            with self.subTest(value=value[:10]), self.assertRaises(ConfigurationError):
                Settings.from_env({"SERVERSENTINEL_DATA_DIRECTORY": str(self.directory),
                                   "SERVERSENTINEL_HUMAN_PORT": value})
