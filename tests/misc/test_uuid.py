import unittest

from impacket import uuid


class UUIDTests(unittest.TestCase):

    def test_invalid_hyphenated_uuid_raises_value_error(self):
        with self.assertRaisesRegex(ValueError, "Invalid UUID string"):
            uuid.string_to_bin("not-a-valid-uuid")

    def test_invalid_uuid_tuple_length_raises_value_error(self):
        with self.assertRaisesRegex(ValueError, "UUID tuple"):
            uuid.uuidtup_to_bin(("00000000-0000-0000-0000-000000000000",))

    def test_string_without_uuid_raises_value_error(self):
        with self.assertRaisesRegex(ValueError, "UUID and optional version"):
            uuid.string_to_uuidtup("not-a-valid-uuid")

    def test_uuid_without_version_uses_default(self):
        value = "00000000-0000-0000-0000-000000000000"

        self.assertEqual((value, "1.0"), uuid.string_to_uuidtup(value))


if __name__ == "__main__":
    unittest.main(verbosity=1)
