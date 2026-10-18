from rules.sources import SOURCES
from scanner.legacy_models import detect_implicit_request_uri_calls
from scanner.utils import compile_rule_dict, find_matches_by_kind

COMPILED_SOURCES = compile_rule_dict(SOURCES)

def detect_sources(text: str):
    hits = find_matches_by_kind(COMPILED_SOURCES, text)
    hits.extend(detect_implicit_request_uri_calls(text))
    return list(dict.fromkeys(hits))
