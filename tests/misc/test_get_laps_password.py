import unittest

from examples.GetLAPSPassword import GetLAPSPassword


class GetLAPSPasswordTests(unittest.TestCase):

    def test_invalid_encrypted_blob_returns_none(self):
        reader = object.__new__(GetLAPSPassword)

        self.assertIsNone(reader.getLAPSv2Decrypt(b"invalid"))


if __name__ == "__main__":
    unittest.main(verbosity=1)
