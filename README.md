# Nmap Evidence Report

**Local XML in. Traceable service inventory out.**

A small, offline Python CLI for turning Nmap XML into Markdown or JSON. It retains observed port states and service detection information without presenting an open port or version banner as a confirmed vulnerability. Prepared for Nasser Aldin Farag's portfolio with AI assistance.

## Quick start

Python 3.12+ with Expat 2.6.0 or newer; no third-party packages. On Windows, replace `python3` with `py -3`.

```bash
python3 -m unittest -v
python3 nmap_report.py fixtures/synthetic.xml
python3 nmap_report.py fixtures/synthetic.xml --format json
python3 nmap_report.py fixtures/synthetic.xml --output my-report.md
```

The tool reads an existing local file. It never starts Nmap, accepts a network target, resolves hostnames or downloads stylesheets/DTDs. `--output` creates a new file and refuses to overwrite an existing one.

## Inspect the result

[`examples/synthetic-report.md`](examples/synthetic-report.md) and [`examples/synthetic-report.json`](examples/synthetic-report.json) are generated from [`fixtures/synthetic.xml`](fixtures/synthetic.xml).

The fixture is hand-authored synthetic data using documentation addresses. It is not a record of a scan. Two hosts, four explicitly listed port records and two `open` records are represented; `open|filtered` remains a distinct state.

## Design choices

| Choice | Reason |
| --- | --- |
| Include an input SHA-256 | Associate the summary with the exact source file. |
| Retain service method and confidence | Distinguish a port-table label from a probed service observation. |
| Preserve all explicit port states | Keep `closed` and `open\|filtered` distinct from `open`. |
| Deterministic sorting and no runtime timestamp | Make repeated output from identical input comparable. |
| Escape Markdown cells | Prevent banners from injecting raw HTML, links or additional table cells. |
| No CVE or severity inference | A banner alone does not establish a vulnerable deployment. |

## Input handling and limits

- Maximum input: 5 MiB, 100,000 XML elements and depth 64. Compressed archives are not accepted.
- Expat parses the XML with callbacks into an ElementTree builder. Internal DTD subsets and entity declarations are rejected. External parameter entity parsing is disabled; the external-entity callback rejects references. Ordinary Nmap DOCTYPE declarations are supported without fetching the DTD.
- The runtime must use Expat 2.6.0 or newer. The CLI rejects older versions.
- Standard XML character references such as `&amp;` remain supported. IP addresses, address families, port numbers and protocols are validated.
- Only explicit `host/ports/port` entries are summarized. `extraports`, NSE script output, command-line arguments, hostnames, OS guesses and MAC addresses are omitted. This is not a complete scan archive or full DTD validator.
- Output may still contain sensitive addresses or banner text from your input. Review it before sharing. Omission of some fields is not anonymisation.

## Tests

The regression suite covers expected service states, incomplete records, malformed XML, XML entities (including UTF-16 input), structural limits, external DTD handling, Markdown escaping and preservation of existing output files. These checks define the supported behaviour; they are not a claim of exhaustive parser security.

## Deutsche Kurzfassung

Das Werkzeug unterstützt die saubere Dokumentation vorhandener Nmap-Ergebnisse. Es erstellt offline eine prüfbare Übersicht, bewahrt den beobachteten Status und vermeidet unbelegte Schwachstellenbewertungen. Die Beispieldatei enthält ausschliesslich synthetische Daten.

## References

- [Nmap XML output documentation](https://nmap.org/book/output-formats-xml-output.html)
- [Python XML processing and security considerations](https://docs.python.org/3.12/library/xml.html)

Code: MIT License. Nmap is a separate project; this utility is not affiliated with it.
