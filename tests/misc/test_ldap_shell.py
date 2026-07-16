import unittest

from impacket.examples.ldap_shell import LdapShell


class LdapShellTests(unittest.TestCase):

    def test_write_gpo_dacl_validates_arguments_before_indexing(self):
        with self.assertRaisesRegex(
            Exception, "A samaccountname and GPO sid are required"
        ):
            LdapShell.do_write_gpo_dacl(object(), "")

    def test_add_computer_reports_invalid_third_argument(self):
        class Server:
            ssl = True

        class Client:
            server = Server()
            tls_started = False

        class DomainDumper:
            root = "DC=example,DC=com"

        shell = object.__new__(LdapShell)
        shell.client = Client()
        shell.domain_dumper = DomainDumper()

        with self.assertRaisesRegex(Exception, "Invalid third argument: invalid"):
            shell.do_add_computer("computer password invalid")


if __name__ == "__main__":
    unittest.main(verbosity=1)
