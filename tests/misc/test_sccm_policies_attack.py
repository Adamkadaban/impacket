import tempfile
import unittest
import zlib
from unittest.mock import Mock, patch

from impacket.examples.ntlmrelayx.attacks.httpattacks.sccmpoliciesattack import (
    SCCMPoliciesAttack,
)


class SCCMPoliciesAttackTests(unittest.TestCase):

    def run_policy(self, category, decrypted):
        attack = object.__new__(SCCMPoliciesAttack)
        attack.request_policy = lambda *args: b"encrypted"
        policy = {
            "PolicyCategory": category,
            "PolicyLocation": "http://server/policy",
        }

        with tempfile.TemporaryDirectory() as loot_dir, patch(
            "impacket.examples.ntlmrelayx.attacks.httpattacks.sccmpoliciesattack.decrypt_secret_policy",
            return_value=decrypted + "\x00",
        ):
            attack.secret_policy_process(
                "policy-id", policy, object(), "client", loot_dir
            )

    def test_secret_element_without_value_is_ignored(self):
        self.run_policy(
            "Machine",
            '<root><property secret="1" name="secret"/></root>',
        )

    def test_collection_property_without_value_is_ignored(self):
        inner = (
            '<root><instance><property name="Name"/></instance></root>'
        ).encode("utf-16")
        outer = "<root>%s</root>" % zlib.compress(inner).hex()

        self.run_policy("CollectionSettings", outer)

    def test_register_client_skips_malformed_multipart_segment(self):
        attack = object.__new__(SCCMPoliciesAttack)
        response = Mock()
        response.read.return_value = (
            b"--aAbBcCdDv1234567890VxXyYzZ\r\nmalformed"
        )
        attack.client = Mock()
        attack.client.getresponse.return_value = response

        self.assertIsNone(
            attack.register_client("http://server", b"request")
        )

    def test_missing_secret_policy_response_stops_before_decryption(self):
        attack = object.__new__(SCCMPoliciesAttack)
        attack.request_policy = lambda *args: None
        policy = {
            "PolicyCategory": "Machine",
            "PolicyLocation": "http://server/policy",
        }

        with tempfile.TemporaryDirectory() as loot_dir, patch(
            "impacket.examples.ntlmrelayx.attacks.httpattacks.sccmpoliciesattack.decrypt_secret_policy"
        ) as decrypt:
            result = attack.secret_policy_process(
                "policy-id", policy, object(), "client", loot_dir
            )

        self.assertIsNone(result)
        decrypt.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=1)
