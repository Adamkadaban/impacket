import unittest

from examples.describeTicket import kerberoast_from_ccache
from impacket.krb5 import constants


class Octets:
    def __init__(self, data):
        self.data = data

    def asOctets(self):
        return self.data


class Cipher:
    def __init__(self, data):
        self.data = data

    def __getitem__(self, item):
        return Octets(self.data[item])


class DescribeTicketTests(unittest.TestCase):

    @staticmethod
    def ticket(etype):
        return {
            "ticket": {
                "enc-part": {
                    "etype": etype,
                    "cipher": Cipher(bytes(range(32))),
                },
                "sname": {"name-string": ["service", "host"]},
            }
        }

    def test_aes128_hash_contains_decoded_hex_text(self):
        result = kerberoast_from_ccache(
            self.ticket(
                constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value
            ),
            "service/host",
            "user",
            "example.com",
        )

        self.assertIsInstance(result, str)
        self.assertNotIn("built-in method", result)
        self.assertTrue(result.endswith(bytes(range(20)).hex()))

    def test_unsupported_encryption_type_returns_none(self):
        result = kerberoast_from_ccache(
            self.ticket(999), "service/host", "user", "example.com"
        )

        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main(verbosity=1)
