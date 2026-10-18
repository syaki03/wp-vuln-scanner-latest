import re
from pathlib import Path
from typing import Iterable, List, Dict

def compile_rule_dict(rule_dict: Dict[str, List[str]]) -> Dict[str, List[re.Pattern]]:
    compiled = {}
    for kind, patterns in rule_dict.items():
        compiled[kind] = [re.compile(p, re.IGNORECASE) for p in patterns]
    return compiled

def safe_read_text(path: Path) -> str:
    encodings = ["utf-8", "utf-8-sig", "cp932", "latin-1"]
    for enc in encodings:
        try:
            return path.read_text(encoding=enc, errors="strict")
        except Exception:
            continue
    return path.read_text(encoding="utf-8", errors="ignore")

def find_matches_by_kind(compiled_rules: Dict[str, List[re.Pattern]], text: str):
    hits = []
    for kind, regexes in compiled_rules.items():
        for rx in regexes:
            if rx.search(text):
                hits.append((kind, rx.pattern))
    return hits

def extract_php_variables(text: str) -> List[str]:
    return sorted(set(re.findall(r"(\$[a-zA-Z_][a-zA-Z0-9_]*)", text)))

def normalize_snippet(lines: Iterable[str]) -> str:
    return "\n".join(line.rstrip("\r\n") for line in lines)

def plugin_name_from_path(path: Path, plugin_root: Path | None = None) -> str:
    """Return the top-level plugin directory, including for nested PHP files."""
    if plugin_root is None:
        try:
            from config import PLUGIN_ROOT

            plugin_root = PLUGIN_ROOT
        except Exception:
            plugin_root = None

    if plugin_root is not None:
        try:
            relative = path.resolve().relative_to(plugin_root.resolve())
            if relative.parts:
                return relative.parts[0]
        except (OSError, ValueError):
            pass

    parts = path.parts
    return parts[-2] if len(parts) >= 2 else ""

def html_escape(s: str) -> str:
    return (
        s.replace("&", "&amp;")
         .replace("<", "&lt;")
         .replace(">", "&gt;")
         .replace('"', "&quot;")
    )
