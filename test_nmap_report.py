import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import nmap_report as nr

FIXTURE = Path(__file__).parent / "fixtures" / "synthetic.xml"


class ReportTests(unittest.TestCase):
    def test_fixture_preserves_states_and_detection(self):
        report = nr.parse_report(FIXTURE.read_bytes())
        self.assertEqual(report["summary"], {"hosts_in_xml": 2,
                         "explicit_port_records": 4, "open_port_records": 2})
        self.assertEqual([p["port"] for p in report["hosts"][0]["ports"]], [22, 80, 443])
        self.assertEqual(report["hosts"][1]["ports"][0]["state"], "open|filtered")
        self.assertEqual(report["hosts"][0]["ports"][0]["service"]["method"], "table")
        self.assertNotIn("severity", json.dumps(report))

    def test_documented_minimal_and_missing_service(self):
        raw = b'<nmaprun><host><ports><port portid="0" protocol="tcp"/></ports></host></nmaprun>'
        report = nr.parse_report(raw)
        self.assertEqual(report["hosts"][0]["ports"][0]["state"], "unknown")
        self.assertIn("not reported", nr.to_markdown(report))

    def test_host_without_ports_is_visible(self):
        output = nr.to_markdown(nr.parse_report(b'<nmaprun><host/></nmaprun>'))
        self.assertIn("none listed", output)

    def test_rejects_internal_entities(self):
        with self.assertRaises(nr.InputError):
            nr.parse_report(b'<!DOCTYPE nmaprun [<!ENTITY x "EXPAND">]><nmaprun>&x;</nmaprun>')

    def test_rejects_external_entity(self):
        with self.assertRaises(nr.InputError):
            nr.parse_report(b'<!DOCTYPE nmaprun [<!ENTITY x SYSTEM "file:///etc/passwd">]><nmaprun>&x;</nmaprun>')

    def test_external_doctype_is_not_fetched(self):
        with mock.patch("socket.socket", side_effect=AssertionError("network attempted")), \
             mock.patch("builtins.open", side_effect=AssertionError("file access attempted")):
            report = nr.parse_report(b'<!DOCTYPE nmaprun SYSTEM "https://invalid.example/nmap.dtd"><nmaprun/>')
        self.assertEqual(report["hosts"], [])

    def test_utf16_entity_declaration_cannot_bypass_guard(self):
        raw = '<!DOCTYPE nmaprun [<!ENTITY x "EXPAND">]><nmaprun>&x;</nmaprun>'.encode("utf-16")
        with self.assertRaises(nr.InputError):
            nr.parse_report(raw)

    def test_malformed_and_wrong_root_rejected(self):
        for raw in (b"<nmaprun>", b"<other/>", b"", b'<!DOCTYPE other><nmaprun/>'):
            with self.subTest(raw=raw), self.assertRaises(nr.InputError):
                nr.parse_report(raw)

    def test_byte_limit(self):
        with self.assertRaises(nr.InputError):
            nr.parse_report(b"x" * (nr.MAX_BYTES + 1))

    def test_depth_limit(self):
        with self.assertRaises(nr.InputError):
            nr.parse_report(b"<nmaprun>" + b"<a>" * nr.MAX_DEPTH + b"</a>" * nr.MAX_DEPTH + b"</nmaprun>")

    def test_element_limit(self):
        with mock.patch.object(nr, "MAX_ELEMENTS", 3), self.assertRaises(nr.InputError):
            nr.parse_report(b"<nmaprun><a/><a/><a/></nmaprun>")

    def test_old_expat_rejected(self):
        with mock.patch.object(nr.expat, "version_info", (2, 5, 0)), self.assertRaises(nr.InputError):
            nr.parse_report(b"<nmaprun/>")

    def test_invalid_port_protocol_and_address(self):
        invalid = (b'<host><ports><port portid="70000" protocol="tcp"/></ports></host>',
                   b'<host><ports><port portid="1" protocol="bad"/></ports></host>',
                   b'<host><address addr="999.2.3.4" addrtype="ipv4"/></host>',
                   b'<host><address addr="192.0.2.1" addrtype="ipv6"/></host>')
        for body in invalid:
            with self.subTest(body=body), self.assertRaises(nr.InputError):
                nr.parse_report(b"<nmaprun>" + body + b"</nmaprun>")

    def test_markdown_neutralizes_table_html_and_links(self):
        value = '|\n<img src=x> [click](https://invalid.example) ![x](y) `code`'
        escaped = nr.markdown_cell(value)
        self.assertNotIn("|", escaped)
        self.assertNotIn("\n", escaped)
        self.assertNotIn("<img", escaped)
        self.assertIn("&#124;", escaped)
        self.assertIn(r"\[click\]\(", escaped)

    def test_identical_input_produces_identical_output(self):
        self.assertEqual(nr.to_markdown(nr.parse_report(FIXTURE.read_bytes())),
                         nr.to_markdown(nr.parse_report(FIXTURE.read_bytes())))

    def test_cli_json_and_preservation_of_existing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            self.assertEqual(nr.main([str(FIXTURE), "--format", "json", "--output", str(output)]), 0)
            first = output.read_bytes()
            self.assertEqual(json.loads(first)["summary"]["open_port_records"], 2)
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(nr.main([str(FIXTURE), "--output", str(output)]), 2)
            self.assertEqual(output.read_bytes(), first)


if __name__ == "__main__":
    unittest.main()
