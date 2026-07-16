import unittest
from unittest.mock import patch

from examples import dcomexec


class DCOMExecTests(unittest.TestCase):

    def test_get_interface_preserves_distinct_oxid_and_oid(self):
        class Interface:
            def get_cinstance(self):
                return "instance"

            def get_ipidRemUnknown(self):
                return "remote-ipid"

            def get_target(self):
                return "target"

        std = {"ipid": "ipid", "oxid": "oxid", "oid": "oid"}
        parsed_objref = {"std": std}
        executor = object.__new__(dcomexec.DCOMEXEC)

        with patch.object(
            dcomexec, "OBJREF", return_value={"flags": dcomexec.FLAGS_OBJREF_STANDARD}
        ), patch.object(
            dcomexec, "OBJREF_STANDARD", return_value=parsed_objref
        ), patch.object(
            dcomexec, "INTERFACE", return_value="interface"
        ) as interface_type, patch.object(
            dcomexec, "IRemUnknown2", side_effect=lambda value: value
        ):
            result = executor.getInterface(Interface(), [b"objref"])

        self.assertEqual("interface", result)
        self.assertEqual("oxid", interface_type.call_args.kwargs["oxid"])
        self.assertEqual("oid", interface_type.call_args.kwargs["oid"])

    def test_get_interface_rejects_unknown_objref_type(self):
        executor = object.__new__(dcomexec.DCOMEXEC)

        with patch.object(dcomexec, "OBJREF", return_value={"flags": 0xDEADBEEF}):
            with self.assertRaisesRegex(ValueError, "Unknown OBJREF Type"):
                executor.getInterface(object(), [b"objref"])


if __name__ == "__main__":
    unittest.main(verbosity=1)
