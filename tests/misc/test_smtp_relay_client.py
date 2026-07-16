import unittest
from unittest.mock import Mock, patch

from impacket.examples.ntlmrelayx.clients.smtprelayclient import SMTPRelayClient


class SMTPRelayClientTests(unittest.TestCase):

    def test_init_connection_accepts_binary_ehlo_response(self):
        session = Mock()
        session.ehlo_resp = b"server.example\nAUTH NTLM LOGIN"
        client = object.__new__(SMTPRelayClient)
        client.targetHost = "server.example"
        client.targetPort = 25

        with patch(
            "impacket.examples.ntlmrelayx.clients.smtprelayclient.smtplib.SMTP",
            return_value=session,
        ):
            result = client.initConnection()

        self.assertIs(result, True)

    def test_init_connection_handles_missing_ehlo_response(self):
        session = Mock()
        session.ehlo_resp = None
        client = object.__new__(SMTPRelayClient)
        client.targetHost = "server.example"
        client.targetPort = 25

        with patch(
            "impacket.examples.ntlmrelayx.clients.smtprelayclient.smtplib.SMTP",
            return_value=session,
        ):
            result = client.initConnection()

        self.assertIs(result, False)


if __name__ == "__main__":
    unittest.main(verbosity=1)
