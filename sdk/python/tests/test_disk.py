"""Offline disk integration test; requires the built native extension, no VM."""

import tempfile
import unittest
from pathlib import Path

from microsandbox import Disk


class DiskTest(unittest.TestCase):
    def test_grow_copy_preserves_identity_and_source(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.ext4"
            destination = Path(directory) / "next.ext4"
            created = Disk.create(str(source), 128 * 1024**2)
            grown = Disk.grow_copy(str(source), str(destination), 256 * 1024**2)
            self.assertEqual(grown.uuid, created.uuid)
            self.assertEqual(grown.capacity_bytes, 256 * 1024**2)
            self.assertEqual(Disk.inspect(str(source)).capacity_bytes, created.capacity_bytes)
            with self.assertRaises(RuntimeError):
                Disk.grow_copy(str(source), str(destination), 512 * 1024**2)
            with self.assertRaises(RuntimeError):
                Disk.inspect(str(Path(directory) / "missing"))
