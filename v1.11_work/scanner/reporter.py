import csv
import json
from pathlib import Path
from typing import List, Dict, Any
from config import CSV_NAME, JSON_NAME, HTML_NAME
from scanner.utils import html_escape

FIELDNAMES = [
    "plugin",
    "file",
    "line",
    "type",
    "severity",
    "score",
    "confidence",
    "flow_evidence",
    "source_kind",
    "source_origin",
    "source_match",
    "sink_kind",
    "sink_match",
    "storage_kind",
    "storage_match",
    "sanitizer_matches",
    "security_checks",
    "tainted_vars",
    "entrypoint_kind",
    "entrypoint_name",
    "entrypoint_exposure",
    "entrypoint_role",
    "entrypoint_line",
    "entrypoint_function",
    "admin_only_hint",
    "poc_priority",
    "context",
    "snippet",
]

def sort_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    return sorted(
        findings,
        key=lambda x: (
            severity_order.get(x["severity"], 99),
            -int(x.get("score", 0)),
            x.get("plugin", ""),
            x.get("file", ""),
            int(x.get("line", 0)),
        ),
    )

def spreadsheet_safe_cell(value: Any) -> Any:
    """Prefix potentially active spreadsheet text without changing raw evidence.

    CSV quoting protects cell boundaries, not formula interpretation. Check
    past leading Unicode whitespace as spreadsheet importers may discard it.
    Numeric values remain numeric; only the CSV representation is modified.
    """
    if isinstance(value, str):
        for character in value:
            if ord(character) < 32 or ord(character) == 127 or character in "=+-@":
                return "'" + value
            if not character.isspace():
                break
    return value


def write_csv(findings: List[Dict[str, Any]], output_path: Path):
    with output_path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        for row in findings:
            writer.writerow({key: spreadsheet_safe_cell(value) for key, value in row.items()})

def write_json(findings: List[Dict[str, Any]], output_path: Path):
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(findings, f, ensure_ascii=False, indent=2)

def write_html(findings: List[Dict[str, Any]], output_path: Path):
    rows = []
    for f in findings:
        rows.append(f"""
        <tr>
          <td>{html_escape(str(f['severity']))}</td>
          <td>{html_escape(str(f['score']))}</td>
          <td>{html_escape(str(f['type']))}</td>
          <td>{html_escape(str(f['plugin']))}</td>
          <td>{html_escape(str(f['file']))}:{html_escape(str(f['line']))}</td>
          <td>{html_escape(str(f['context']))}</td>
          <td><pre>{html_escape(str(f['snippet']))}</pre></td>
        </tr>
        """)

    html = f"""<!doctype html>
<html lang="ja">
<head>
<meta charset="utf-8">
<title>WP XSS Scanner Report</title>
<style>
body {{
  font-family: Arial, sans-serif;
  margin: 20px;
}}
table {{
  border-collapse: collapse;
  width: 100%;
}}
th, td {{
  border: 1px solid #ccc;
  padding: 8px;
  vertical-align: top;
}}
th {{
  background: #f3f3f3;
}}
pre {{
  white-space: pre-wrap;
  word-break: break-word;
  margin: 0;
}}
.high {{ background: #ffe5e5; }}
.medium {{ background: #fff3cd; }}
.low {{ background: #eef7ff; }}
</style>
</head>
<body>
<h1>WordPress XSS Candidate Report</h1>
<p>Total findings: {len(findings)}</p>
<table>
  <thead>
    <tr>
      <th>Severity</th>
      <th>Score</th>
      <th>Type</th>
      <th>Plugin</th>
      <th>Location</th>
      <th>Context</th>
      <th>Snippet</th>
    </tr>
  </thead>
  <tbody>
    {''.join(rows)}
  </tbody>
</table>
</body>
</html>
"""
    output_path.write_text(html, encoding="utf-8")

def write_reports(findings: List[Dict[str, Any]], output_dir: Path):
    output_dir.mkdir(parents=True, exist_ok=True)
    findings = sort_findings(findings)
    write_csv(findings, output_dir / CSV_NAME)
    write_json(findings, output_dir / JSON_NAME)
    write_html(findings, output_dir / HTML_NAME)
