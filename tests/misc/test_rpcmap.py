import subprocess
import sys
import unittest
from pathlib import Path


class RPCMapTests(unittest.TestCase):

    def test_invalid_uuid_is_reported_as_argument_error(self):
        repository = Path(__file__).parents[2]
        result = subprocess.run(
            [
                sys.executable,
                str(repository / "examples" / "rpcmap.py"),
                "ncacn_ip_tcp:127.0.0.1[135]",
                "-uuid",
                "not-a-uuid",
            ],
            cwd=repository,
            capture_output=True,
            text=True,
        )

        self.assertEqual(2, result.returncode)
        self.assertIn("UUID and optional version not found", result.stderr)
        self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=1)
