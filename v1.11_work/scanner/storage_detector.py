from rules.storage import STORAGE
from scanner.utils import compile_rule_dict, find_matches_by_kind

COMPILED_STORAGE = compile_rule_dict(STORAGE)

def detect_storage(text: str):
    return find_matches_by_kind(COMPILED_STORAGE, text)