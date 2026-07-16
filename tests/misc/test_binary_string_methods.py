import unittest

from impacket import ntlm, spnego
from impacket.dcerpc.v5.dtypes import DWORD
from impacket.krb5 import ccache, keytab


class BinaryStringMethodTests(unittest.TestCase):

    def assert_binary_string_contract(self, value, data):
        value.getData = lambda: data

        self.assertEqual(data.hex(), str(value))
        self.assertEqual(data, bytes(value))

    def test_ntlm_av_pairs_string_and_bytes(self):
        self.assert_binary_string_contract(
            object.__new__(ntlm.AV_PAIRS), b"\x01\x02"
        )

    def test_spnego_string_and_bytes(self):
        self.assert_binary_string_contract(
            object.__new__(spnego.GSSAPI), b"\x03\x04"
        )
        self.assert_binary_string_contract(
            object.__new__(spnego.SPNEGO_NegTokenResp), b"\x05\x06"
        )

    def test_ndr_string_and_bytes(self):
        value = DWORD()
        value["Data"] = 0x12345678
        data = value.getData()

        self.assertEqual(data.hex(), str(value))
        self.assertEqual(data, bytes(value))

    def test_ccache_and_keytab_string_and_bytes(self):
        for value in (
            object.__new__(ccache.Principal),
            object.__new__(ccache.Credential),
            object.__new__(keytab.KeytabPrincipal),
        ):
            with self.subTest(value=value.__class__.__name__):
                self.assert_binary_string_contract(value, b"\x07\x08")


if __name__ == "__main__":
    unittest.main(verbosity=1)
