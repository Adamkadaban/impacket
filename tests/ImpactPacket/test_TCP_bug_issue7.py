#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies 
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
import unittest
from threading import Thread
from impacket.ImpactPacket import TCP, ImpactPacketException


class TestTCP(unittest.TestCase):

    def setUp(self):
        # Dummy TCP header with "Maximum Segment Size" Option and zero length
        self.frame = b'\x12\x34\x00\x50\x00\x00\x00\x01\x00\x00\x00\x00\x60\x00\x00\x00\x8d\x5c\x00\x00\x02\x00\x00\x00'
        
    def test_01(self):
        'Test TCP options parsing hangs'
        class it_hangs(Thread):
            def __init__(self, frame):
                Thread.__init__(self)
                self.frame = frame
                self.error = None

            def run(self):
                try:
                    TCP(self.frame)
                except ImpactPacketException as e:
                    if str(e) != "'TCP Option length is too low'":
                        self.error = e
                except Exception as e:
                    self.error = e

        thread_hangs = it_hangs(self.frame)
        thread_hangs.daemon = True
        thread_hangs.start()

        thread_hangs.join(1.0)  # 1 seconds timeout
        self.assertEqual(thread_hangs.is_alive(), False)
        if thread_hangs.error is not None:
            raise thread_hangs.error


if __name__ == '__main__':
    unittest.main(verbosity=1)
