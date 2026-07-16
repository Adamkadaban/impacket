import unittest
from unittest.mock import patch

from OpenSSL.SSL import SysCallError

from examples.CheckLDAPStatus import CheckLDAP


class CheckLDAPStatusTests(unittest.TestCase):

    def test_single_argument_syscall_error_is_classified(self):
        checker = CheckLDAP("example.com", "192.0.2.1", 1)

        with patch(
            "examples.CheckLDAPStatus.LDAPConnection",
            side_effect=SysCallError("Unexpected EOF"),
        ):
            status = checker.check_ldaps_cbt("dc.example.com")

        self.assertEqual("No TLS cert", status)


if __name__ == "__main__":
    unittest.main(verbosity=1)
