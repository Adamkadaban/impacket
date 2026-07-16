import os
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from examples.keylistattack import KeyListDump


class KeyListAttackTests(unittest.TestCase):

    def test_cached_kerberos_login_failure_does_not_leave_connection(self):
        options = SimpleNamespace(
            aesKey=None,
            k=True,
            rodcKey="key",
            target_ip="192.0.2.1",
            dc_ip="192.0.2.2",
            rodcNo=1,
            full=False,
            hashes=None,
        )
        dumper = KeyListDump(
            "server", "user", "password", "DOMAIN", options, True, []
        )
        connection = Mock()
        connection.kerberosLogin.side_effect = RuntimeError("login failed")

        with patch(
            "examples.keylistattack.SMBConnection", return_value=connection
        ), patch.dict(os.environ, {"KRB5CCNAME": "/tmp/cache"}):
            with self.assertRaisesRegex(RuntimeError, "login failed"):
                dumper.connect()

        self.assertIsNone(dumper._KeyListDump__smbConnection)


if __name__ == "__main__":
    unittest.main(verbosity=1)
