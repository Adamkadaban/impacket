import contextlib
import io
import unittest

from examples.DumpNTLMInfo import DumpNtlm, SMB3


class DumpNTLMInfoTests(unittest.TestCase):

    def test_display_time_does_not_subtract_missing_current_time(self):
        dumper = DumpNtlm("192.0.2.1", "server", 445, "SMB")
        output = io.StringIO()

        with contextlib.redirect_stdout(output):
            dumper.DisplayTime(
                {
                    "SystemTime": 0,
                    "ServerStartTime": 116444736000000000,
                }
            )

        self.assertIn("Current Time    : 0", output.getvalue())
        self.assertIn("Boot Time", output.getvalue())
        self.assertNotIn("Server Up Time", output.getvalue())

    def test_smb3_negotiation_rejects_missing_response(self):
        class Answer:
            def isValidAnswer(self, status):
                return False

        connection = object.__new__(SMB3)
        connection.send = lambda packet: None
        connection.receive = lambda: Answer()

        with self.assertRaisesRegex(RuntimeError, "valid response"):
            connection._negotiateSession()


if __name__ == "__main__":
    unittest.main(verbosity=1)
