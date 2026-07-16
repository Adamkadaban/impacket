import contextlib
import io
import runpy
import unittest
from pathlib import Path


class RegistryReadTests(unittest.TestCase):

    def test_boot_key_reorders_binary_registry_fragments(self):
        module = runpy.run_path(
            str(Path(__file__).parents[2] / "examples" / "registry-read.py")
        )

        class Registry:
            values = {
                "JD": "00010203",
                "Skew1": "04050607",
                "GBG": "08090a0b",
                "Data": "0c0d0e0f",
            }

            def getClass(self, path):
                name = path.rsplit("\\", 1)[-1]
                return self.values[name].encode("utf-16le")

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            module["bootKey"](Registry())

        self.assertEqual(
            "b'080504020b090d030006010c0e0a0f07'",
            output.getvalue().strip(),
        )


if __name__ == "__main__":
    unittest.main(verbosity=1)
