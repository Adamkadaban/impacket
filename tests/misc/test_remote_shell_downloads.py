import unittest
from unittest.mock import patch

from examples import dcomexec, wmiexec


class RemoteShellDownloadTests(unittest.TestCase):

    def test_dcom_download_path_failure_does_not_use_unbound_filename(self):
        shell = object.__new__(dcomexec.RemoteShell)
        shell._pwd = "C:\\"

        with patch("ntpath.join", side_effect=RuntimeError("path failed")):
            shell.do_lget("file.txt")

    def test_wmi_download_path_failure_does_not_use_unbound_filename(self):
        shell = object.__new__(wmiexec.RemoteShell)
        shell._RemoteShell__pwd = "C:\\"

        with patch("ntpath.join", side_effect=RuntimeError("path failed")):
            shell.do_lget("file.txt")


if __name__ == "__main__":
    unittest.main(verbosity=1)
