import unittest

from impacket import dpapi, smb, smb3structs
from impacket.dcerpc.v5 import dhcpm, drsuapi, par, rprn
from impacket.examples.secretsdump import USER_ACCOUNT_V
from impacket.examples.ntlmrelayx.servers.socksserver import SOCKS4_REPLY


class ProtocolStructureFieldTests(unittest.TestCase):

    def assert_unique_fields(self, structure):
        names = [field[0] for field in structure]
        self.assertEqual(len(names), len(set(names)))
        return names

    def test_dpapi_blob_uses_distinct_hmac_length_and_value_fields(self):
        names = self.assert_unique_fields(dpapi.DPAPI_BLOB.structure)

        self.assertIn("HMacLen", names)
        self.assertIn("HMac", names)

    def test_print_client_info_uses_distinct_size_field(self):
        for structure in (rprn.SPLCLIENT_INFO_3, par.SPLCLIENT_INFO_3):
            with self.subTest(structure=structure.__module__):
                names = self.assert_unique_fields(structure.structure)
                self.assertEqual(["cbSize", "dwFlags", "dwSize"], names[:3])

    def test_dhcp_bootp_range_has_documented_four_fields(self):
        names = self.assert_unique_fields(dhcpm.DHCP_BOOTP_IP_RANGE.structure)

        self.assertEqual(
            ["StartAddress", "EndAddress", "BootpAllocated", "MaxBootpAllowed"],
            names,
        )

    def test_replication_metadata_preserves_three_unused_fields(self):
        names = self.assert_unique_fields(
            drsuapi.VALUE_META_DATA_EXT_V3.structure
        )

        self.assertEqual(
            ["unused1", "unused2", "unused3"], names[2:5]
        )

    def test_socks4_reply_reserved_fields_are_distinct(self):
        names = self.assert_unique_fields(SOCKS4_REPLY.structure)

        self.assertEqual(["VER", "REP", "RSV1", "RSV2"], names)

    def test_smb_reserved_fields_are_distinct(self):
        for structure in (smb3structs.SMB3Packet, smb.SMBQueryFileAllInfo):
            with self.subTest(structure=structure.__name__):
                self.assert_unique_fields(structure.structure)

    def test_unknown_and_virtual_fields_do_not_overwrite_data_fields(self):
        for structure in (
            dpapi.VAULT_NGC_ACCOOUNT,
            dpapi.CREDENTIAL_BLOB,
            USER_ACCOUNT_V,
        ):
            with self.subTest(structure=structure.__name__):
                self.assert_unique_fields(structure.structure)


if __name__ == "__main__":
    unittest.main(verbosity=1)
