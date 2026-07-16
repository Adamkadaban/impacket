import unittest
from unittest.mock import Mock

from impacket.dcerpc.v5 import rpcrt


class RPCRTTests(unittest.TestCase):

    def test_base_rpc_context_starts_at_zero(self):
        rpc = rpcrt.DCERPC(Mock())

        self.assertEqual(0, rpc._ctx)


if __name__ == "__main__":
    unittest.main(verbosity=1)
