import unittest

from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig


class NTLMRelayxConfigTests(unittest.TestCase):

    def setUp(self):
        self.config = NTLMRelayxConfig()
        self.config.remove_target = True

    def test_domain_account_requires_domain_and_machine_name(self):
        with self.assertRaisesRegex(ValueError, "domain/machine_name"):
            self.config.setDomainAccount("MACHINE$", ":0123456789abcdef", "dc")

    def test_domain_account_requires_hash_separator(self):
        with self.assertRaisesRegex(ValueError, "LMHASH:NTHASH"):
            self.config.setDomainAccount("DOMAIN/MACHINE$", "0123456789abcdef", "dc")

    def test_domain_account_rejects_non_hex_hashes(self):
        with self.assertRaisesRegex(ValueError, "hexadecimal"):
            self.config.setDomainAccount("DOMAIN/MACHINE$", ":not-a-hash", "dc")

    def test_domain_account_accepts_valid_values(self):
        nthash = "0123456789abcdef0123456789abcdef"

        self.config.setDomainAccount("DOMAIN/MACHINE$", ":" + nthash, "dc")

        self.assertEqual("DOMAIN/MACHINE$", self.config.machineAccount)
        self.assertEqual(":" + nthash, self.config.machineHashes)
        self.assertEqual("dc", self.config.domainIp)


if __name__ == "__main__":
    unittest.main(verbosity=1)
