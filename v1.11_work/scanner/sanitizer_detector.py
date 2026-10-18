from rules.sanitizers import SANITIZERS
from scanner.utils import compile_rule_dict, find_matches_by_kind

COMPILED_SANITIZERS = compile_rule_dict({
    kind: patterns
    for kind, patterns in SANITIZERS.items()
    if kind != "security_checks"
})

COMPILED_SECURITY = compile_rule_dict({
    "security_checks": SANITIZERS["security_checks"],
})

def detect_sanitizers(text: str):
    return find_matches_by_kind(COMPILED_SANITIZERS, text)

def detect_security_checks(text: str):
    return find_matches_by_kind(COMPILED_SECURITY, text)
