"""Helper-tool output must not be decoded with the locale codepage.

Reported from a real Chinese Windows install: subprocess's ``text=True`` decodes child output
using the locale ANSI codepage, which there is GBK. verify.py hands ssh a config file this
project writes as UTF-8, and ``ssh -G`` echoes its content back verbatim - so a host alias
containing non-ASCII characters produced

    UnicodeDecodeError: 'gbk' codec can't decode byte 0xba in position 22

*inside subprocess's reader thread*. That thread died, ``stdout`` stayed None, and the run
crashed with ``'NoneType' object has no attribute 'splitlines'``.

Two failure modes, so two guarantees: decode as UTF-8 to match what we wrote, and never blow
up on a byte that is not decodable at all.
"""

import subprocess
import sys
import unittest

sys.path.insert(0, "src")

from termius_export.verify import _run, _ssh_config_value


def _emit(python_expr):
    return [sys.executable, "-c", f"import sys; sys.stdout.buffer.write({python_expr})"]


class RunDecodingTests(unittest.TestCase):
    def test_decodes_utf8_non_ascii_output(self):
        result = _run(_emit("'主机名'.encode('utf-8')"))
        self.assertEqual(result.stdout, "主机名")

    def test_does_not_raise_on_undecodable_bytes(self):
        # The exact shape of the Windows failure: bytes that are not valid in the assumed
        # codec. Must degrade to replacement characters, not kill the reader thread.
        result = _run(_emit(r"b'hostname \xba\xff\n'"))
        self.assertIsNotNone(result.stdout)
        self.assertIn("hostname", result.stdout)

    def test_stdout_is_never_none(self):
        result = _run(_emit("b''"))
        self.assertIsNotNone(result.stdout)
        self.assertEqual(result.stdout, "")

    def test_propagates_check_failures(self):
        with self.assertRaises(subprocess.CalledProcessError):
            _run([sys.executable, "-c", "raise SystemExit(3)"], check=True)

    def test_stderr_is_decoded_too(self):
        result = _run([sys.executable, "-c", "import sys; sys.stderr.buffer.write('端口'.encode())"])
        self.assertEqual(result.stderr, "端口")


class SshConfigValueTests(unittest.TestCase):
    def test_returns_empty_string_for_none_output(self):
        # Defence in depth: a None stdout should degrade to a failed check, never an
        # AttributeError that aborts the whole export after the files are already written.
        self.assertEqual(_ssh_config_value(None, "hostname"), "")

    def test_extracts_a_value(self):
        self.assertEqual(_ssh_config_value("hostname 10.0.0.1\nport 22\n", "hostname"), "10.0.0.1")

    def test_extracts_a_non_ascii_value(self):
        self.assertEqual(_ssh_config_value("host 主机\nport 22\n", "host"), "主机")

    def test_returns_empty_string_when_absent(self):
        self.assertEqual(_ssh_config_value("port 22\n", "hostname"), "")


if __name__ == "__main__":
    unittest.main()
