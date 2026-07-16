import unittest

from impacket.ICMP6 import ICMP6


class ICMP6Tests(unittest.TestCase):

    def test_string_handles_unknown_message_type(self):
        packet = ICMP6()
        packet.set_type(250)
        packet.set_code(1)

        self.assertIn("Type: 250 - Unknown", str(packet))

    def test_string_handles_unknown_code_for_known_type(self):
        packet = ICMP6()
        packet.set_type(ICMP6.DESTINATION_UNREACHABLE)
        packet.set_code(250)

        self.assertIn("Code: 250 - Unknown", str(packet))


if __name__ == "__main__":
    unittest.main(verbosity=1)
