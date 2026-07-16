import unittest
from unittest.mock import patch

from examples.GetNPUsers import GetUserNoPreAuth
from impacket.ldap import ldap


class GetNPUsersTests(unittest.TestCase):

    def test_ldaps_retry_failure_does_not_use_unbound_connection(self):
        dumper = object.__new__(GetUserNoPreAuth)
        values = {
            "target": "dc.example.com",
            "kdcIP": None,
            "kdcHost": None,
            "doKerberos": False,
            "username": "user",
            "password": "password",
            "domain": "example.com",
            "lmhash": "",
            "nthash": "",
            "aesKey": None,
            "usersFile": None,
            "no_pass": False,
        }
        for name, value in values.items():
            setattr(dumper, "_GetUserNoPreAuth__" + name, value)
        dumper.baseDN = "dc=example,dc=com"

        error = ldap.LDAPSessionError(errorString="strongerAuthRequired")
        with patch("examples.GetNPUsers.ldap_login", side_effect=error):
            with self.assertRaises(ldap.LDAPSessionError):
                dumper.run()


if __name__ == "__main__":
    unittest.main(verbosity=1)
