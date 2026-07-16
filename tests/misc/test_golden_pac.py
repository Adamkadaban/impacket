import unittest

from examples.goldenPac import MS14_068


class GoldenPacTests(unittest.TestCase):

    def test_exploit_stops_when_no_domain_controllers_are_available(self):
        exploit = object.__new__(MS14_068)
        exploit._MS14_068__kdcHost = None
        exploit._MS14_068__domain = "example.com"
        exploit._MS14_068__domainControllers = []
        exploit.getUserSID = lambda: ("domain-sid", 500)
        exploit.getForestSid = lambda: "forest-sid"
        exploit.getDomainControllers = lambda: []

        self.assertIsNone(exploit.exploit())


if __name__ == "__main__":
    unittest.main(verbosity=1)
