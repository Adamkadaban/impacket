import unittest

from examples.kintercept import InterceptServer


class KinterceptTests(unittest.TestCase):

    def test_handle_accept_ignores_empty_accept_result(self):
        server = object.__new__(InterceptServer)
        server.accept = lambda: None

        self.assertIsNone(server.handle_accept())


if __name__ == "__main__":
    unittest.main(verbosity=1)
