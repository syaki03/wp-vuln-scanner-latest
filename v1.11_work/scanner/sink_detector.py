from rules.sinks import SINKS
from scanner.utils import compile_rule_dict, find_matches_by_kind

COMPILED_SINKS = compile_rule_dict(SINKS)

def detect_sinks(text: str):
    return find_matches_by_kind(COMPILED_SINKS, text)