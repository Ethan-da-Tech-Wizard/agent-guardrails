"""test_host_paths.py: prove host_paths gives per-host names and a read fallback.

Why: per-host file names are what keep two computers from writing one synced file, so the naming rule, the legacy-read
fallback and the environment override are each pinned down here.
Run: python3 -B -m unittest discover -s scripts -p 'test_*.py'  (temporary directories only).
"""
import os, sys, tempfile, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import host_paths


class HostPathsTest(unittest.TestCase):
    """Naming, fallback and override behaviour of host_paths."""

    def test_per_host_inserts_name_before_suffix(self):
        """Proves: the host name goes before the final suffix (a/LATEST.json -> a/LATEST.laptop.json)."""
        self.assertEqual(host_paths.per_host("a/LATEST.json", "laptop").as_posix(), "a/LATEST.laptop.json")
        self.assertEqual(host_paths.per_host("a/anchor.hb", "desktop").as_posix(), "a/anchor.desktop.hb")

    def test_two_hosts_never_share_a_name(self):
        """Proves: different hosts map the same logical file to different names, so they never collide."""
        self.assertNotEqual(host_paths.per_host("x/h.jsonl", "laptop"), host_paths.per_host("x/h.jsonl", "desktop"))

    def test_resolve_prefers_mine_then_legacy(self):
        """Proves: resolve() returns the legacy shared file until a per-host file exists, then prefers the per-host one."""
        with tempfile.TemporaryDirectory() as t:
            root = Path(t); (root / "d").mkdir()
            (root / "d/LATEST.json").write_text("legacy")
            self.assertEqual(host_paths.resolve(root, "d/LATEST.json", "laptop").name, "LATEST.json")
            (root / "d/LATEST.laptop.json").write_text("mine")
            self.assertEqual(host_paths.resolve(root, "d/LATEST.json", "laptop").name, "LATEST.laptop.json")

    def test_env_override(self):
        """Proves: HOST_PATHS_HOST overrides the hostname and is lower-cased."""
        os.environ["HOST_PATHS_HOST"] = "TestBox"
        try:
            self.assertEqual(host_paths.host_name(), "testbox")
        finally:
            del os.environ["HOST_PATHS_HOST"]


if __name__ == "__main__":
    unittest.main()
