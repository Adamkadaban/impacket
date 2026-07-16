import unittest
from unittest.mock import Mock

from examples.badsuccessor import BADSUCCESSOR


class BadSuccessorTests(unittest.TestCase):

    def test_missing_domain_sid_stops_ou_processing(self):
        connection = Mock()
        connection.bound = True
        connection.entries = []
        connection.result = {}
        connection.search.side_effect = [True, True, False]
        checker = object.__new__(BADSUCCESSOR)
        checker._BADSUCCESSOR__baseDN = "DC=example,DC=com"

        self.assertIs(checker.search_ous(connection), False)


if __name__ == "__main__":
    unittest.main(verbosity=1)
