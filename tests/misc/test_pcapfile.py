import tempfile
import unittest

from impacket.pcapfile import PcapFile, PCapFilePacket


class PcapFileTests(unittest.TestCase):

    def test_write_serializes_packet_bytes(self):
        packet = PCapFilePacket()
        packet['data'] = b'packet-data'

        with tempfile.NamedTemporaryFile() as capture:
            pcap = PcapFile(capture.name, 'wb')
            pcap.write(packet)
            expected = pcap.hdr.getData() + packet.getData()
            pcap.close()

            with open(capture.name, 'rb') as stored:
                self.assertEqual(expected, stored.read())


if __name__ == "__main__":
    unittest.main(verbosity=1)
