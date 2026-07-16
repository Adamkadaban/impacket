import socket
import unittest

from impacket.krb5 import constants
from impacket.krb5.types import Address, Principal


class KerberosTypeTests(unittest.TestCase):

    def test_principal_equality_normalizes_enum_and_integer_types(self):
        enum_principal = Principal("service@REALM")
        integer_principal = Principal("service@REALM")
        integer_principal.type = constants.PrincipalNameType.NT_UNKNOWN.value

        self.assertEqual(enum_principal, integer_principal)

    def test_principal_equality_checks_component_count(self):
        short = Principal((["service"], "REALM"))
        long = Principal((["service", "host"], "REALM"))

        self.assertNotEqual(short, long)

    def test_ipv6_address_family_and_packed_value(self):
        address = Address()
        address.type = constants.AddressType.IPv6.value
        address.data = "2001:db8::1"

        self.assertEqual(socket.AF_INET6, address.family)
        self.assertEqual(
            socket.inet_pton(socket.AF_INET6, address.data), address.address
        )

    def test_unknown_address_string_uses_stored_data(self):
        address = Address()
        address.data = "unknown"

        self.assertEqual("(None, 'unknown')", str(address))


if __name__ == "__main__":
    unittest.main(verbosity=1)
