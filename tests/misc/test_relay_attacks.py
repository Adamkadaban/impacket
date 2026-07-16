import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from impacket.examples.ntlmrelayx.attacks import ProtocolAttack
from impacket.examples.ntlmrelayx.attacks.imapattack import IMAPAttack
from impacket.examples.ntlmrelayx.attacks.winrmattack import _required_match
from impacket.examples.ntlmrelayx.attacks.httpattacks.sccmdpattack import (
    SCCMDPAttack,
)


class RelayAttackTests(unittest.TestCase):

    def test_protocol_attack_accepts_username_without_domain(self):
        attack = ProtocolAttack(object(), object(), "user")

        self.assertEqual("", attack.domain)
        self.assertEqual("user", attack.username)

    def test_imap_attack_decodes_message_ids_and_writes_binary_mail(self):
        with tempfile.TemporaryDirectory() as loot_dir:
            config = SimpleNamespace(
                mailbox="INBOX",
                dump_all=False,
                keyword="secret",
                dump_max=0,
                lootdir=loot_dir,
            )
            client = Mock()
            client.select.return_value = ("OK", [b"1"])
            client.search.return_value = ("OK", [b"1"])
            client.fetch.return_value = (
                "OK",
                [(b"RFC822", b"Subject: test\r\n\r\nbody")],
            )
            attack = IMAPAttack(config, client, "DOMAIN/user")

            attack.run()

            mail = Path(loot_dir, "mail_user-INBOX_1.eml").read_bytes()
            self.assertEqual(b"Subject: test\r\n\r\nbody", mail)

    def test_required_winrm_match_rejects_missing_field(self):
        with self.assertRaisesRegex(RuntimeError, "ShellId"):
            _required_match(r"<ShellId>(.*?)</ShellId>", "<root/>", "ShellId")

    def test_sccm_dp_recursive_extract_ignores_scalar_nodes(self):
        attack = object.__new__(SCCMDPAttack)
        attack.config = SimpleNamespace(SCCMDPExtensions=[".xml"])

        result = attack.recursive_file_extract(
            {"folder": {"policy.xml": None, "sentinel": "depth reached"}}
        )

        self.assertEqual(["policy.xml"], result)

    def test_sccm_dp_target_file_list_skips_blank_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            target_file = Path(directory, "targets.txt")
            target_file.write_text(
                "\nhttp://server/package/file.xml\n\n", encoding="utf-8"
            )
            attack = object.__new__(SCCMDPAttack)
            attack.config = SimpleNamespace(SCCMDPFiles=str(target_file))
            attack.loot_dir = directory
            attack.download_files = Mock()

            attack.download_target_files()

            attack.download_files.assert_called_once_with(
                ["http://server/package/file.xml"]
            )


if __name__ == "__main__":
    unittest.main(verbosity=1)
