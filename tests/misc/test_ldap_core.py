import unittest
from unittest.mock import Mock, patch

from impacket.ldap import ldap, ldaptypes
from impacket.structure import Structure


class LDAPCoreTests(unittest.TestCase):

    def test_security_descriptor_without_dacl_preserves_sacl(self):
        acl = ldaptypes.ACL()
        acl['AclRevision'] = 4
        acl['Sbz1'] = 0
        acl['Sbz2'] = 0
        acl.aces = []

        descriptor = ldaptypes.SR_SECURITY_DESCRIPTOR()
        descriptor['Revision'] = b'\x01'
        descriptor['Sbz1'] = b'\x00'
        descriptor['Control'] = 0
        descriptor['Sacl'] = acl
        descriptor['Dacl'] = b''
        descriptor['OwnerSid'] = b''
        descriptor['GroupSid'] = b''

        parsed = ldaptypes.SR_SECURITY_DESCRIPTOR(descriptor.getData())

        self.assertIsInstance(parsed['Sacl'], ldaptypes.ACL)
        self.assertEqual(b'', parsed['Dacl'])

    def test_ace_padding_uses_bytes(self):
        ace = object.__new__(ldaptypes.ACE)
        ace.fields = {'AceSize': 8}

        with patch.object(ldaptypes, 'RECALC_ACE_SIZE', False), patch.object(
            Structure, 'getData', return_value=b'\x01' * 5
        ):
            self.assertEqual(b'\x01' * 5 + b'\x00' * 3, ace.getData())

    def test_ace_size_rounds_up_to_four_byte_boundary(self):
        ace = object.__new__(ldaptypes.ACE)
        ace.fields = {'Ace': Mock(getData=Mock(return_value=b'\x01'))}

        with patch.object(ldaptypes, 'RECALC_ACE_SIZE', True), patch.object(
            Structure, 'getData', return_value=b'\x01' * 5
        ):
            data = ace.getData()

        self.assertEqual(8, ace['AceSize'])
        self.assertEqual(8, len(data))

    def test_add_accepts_default_attributes(self):
        connection = object.__new__(ldap.LDAPConnection)
        connection.sendReceive = lambda request, controls: [
            {
                'protocolOp': {
                    'addResponse': {
                        'resultCode': ldap.ResultCode('success'),
                        'diagnosticMessage': '',
                    }
                }
            }
        ]

        self.assertIs(
            connection.add('CN=Test,DC=example,DC=com', ['top'], None),
            True,
        )


if __name__ == "__main__":
    unittest.main(verbosity=1)
