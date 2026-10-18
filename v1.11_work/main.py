from config import PLUGIN_ROOT, OUTPUT_DIR
from scanner.collector import collect_php_files
from scanner.entrypoint_detector import (
    build_scanner_indexes,
)
from scanner.taint_engine import analyze_php_file, build_tainted_storage_index
from scanner.reporter import write_reports
from scanner.utils import plugin_name_from_path

def main():
    if not PLUGIN_ROOT.exists():
        print(f"[ERROR] Plugin root does not exist: {PLUGIN_ROOT}")
        return 1

    files = collect_php_files(PLUGIN_ROOT)
    (
        shortcode_callbacks,
        registered_callbacks,
        unique_function_definitions,
    ) = build_scanner_indexes(
        files, PLUGIN_ROOT
    )
    tainted_storage = build_tainted_storage_index(
        files, PLUGIN_ROOT, shortcode_callbacks
    )
    print(f"[+] Found PHP files: {len(files)}")

    findings = []
    for i, path in enumerate(files, start=1):
        try:
            plugin = plugin_name_from_path(path, PLUGIN_ROOT)
            file_findings = analyze_php_file(
                path,
                shortcode_callbacks.get(plugin, set()),
                tainted_storage.get(plugin, set()),
                registered_callbacks.get(plugin, set()),
                unique_function_definitions.get(plugin, {}),
            )
            findings.extend(file_findings)
            if i % 100 == 0:
                print(f"[+] Scanned {i}/{len(files)} files")
        except Exception as e:
            findings.append({
                "plugin": path.parts[-2] if len(path.parts) >= 2 else "",
                "file": str(path),
                "line": 0,
                "type": "SCAN_ERROR",
                "severity": "INFO",
                "score": 0,
                "confidence": "",
                "flow_evidence": "",
                "source_kind": "",
                "source_origin": "",
                "source_match": "",
                "sink_kind": "",
                "sink_match": "",
                "storage_kind": "",
                "storage_match": "",
                "sanitizer_matches": "",
                "security_checks": "",
                "tainted_vars": "",
                "context": "",
                "snippet": f"Scanner error: {e}",
            })

    write_reports(findings, OUTPUT_DIR)

    high = sum(1 for f in findings if f["severity"] == "HIGH")
    medium = sum(1 for f in findings if f["severity"] == "MEDIUM")
    low = sum(1 for f in findings if f["severity"] == "LOW")
    info = sum(1 for f in findings if f["severity"] == "INFO")

    print("=" * 60)
    print("Scan completed")
    print(f"Total  : {len(findings)}")
    print(f"HIGH   : {high}")
    print(f"MEDIUM : {medium}")
    print(f"LOW    : {low}")
    print(f"INFO   : {info}")
    print(f"[+] Output written to: {OUTPUT_DIR.resolve()}")
    print("=" * 60)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
