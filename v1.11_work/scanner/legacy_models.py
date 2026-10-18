import re
from typing import Iterable, List, Sequence, Set, Tuple


CALL_RE = re.compile(r"\b(add_query_arg|remove_query_arg)\s*\(", re.IGNORECASE)
ANY_CALL_RE = re.compile(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(")
FALSE_URL_VALUES = {"", "false", "null", "''", '""'}


def _split_call_arguments(text: str, open_paren: int) -> List[str]:
    """Return top-level arguments for one PHP call, tolerating nested calls."""
    arguments: List[str] = []
    start = open_paren + 1
    stack = ["("]
    quote = ""
    escaped = False

    matching = {")": "(", "]": "[", "}": "{"}
    for index in range(start, len(text)):
        char = text[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue

        if char in ("'", '"'):
            quote = char
            continue
        if char in "([{":
            stack.append(char)
            continue
        if char in ")]}":
            if stack and matching[char] == stack[-1]:
                stack.pop()
            if not stack:
                value = text[start:index].strip()
                if value or arguments:
                    arguments.append(value)
                return arguments
            continue
        if char == "," and len(stack) == 1:
            arguments.append(text[start:index].strip())
            start = index + 1

    return []


def iter_query_arg_calls(text: str) -> Iterable[Tuple[str, Sequence[str]]]:
    for match in CALL_RE.finditer(text):
        yield match.group(1).lower(), _split_call_arguments(text, match.end() - 1)


def iter_named_function_calls(
    text: str,
    names: Iterable[str],
) -> Iterable[Tuple[str, Sequence[str]]]:
    allowed: Set[str] = {name.lower() for name in names}
    for name, arguments in iter_function_calls(text):
        if name in allowed:
            yield name, arguments


def iter_function_calls(text: str) -> Iterable[Tuple[str, Sequence[str]]]:
    """Yield fixed lexical call names without constructing an allow-list."""
    for match in ANY_CALL_RE.finditer(text):
        name = match.group(1).lower()
        yield name, _split_call_arguments(text, match.end() - 1)


def _is_implicit_url(name: str, arguments: Sequence[str]) -> bool:
    if not arguments:
        return False

    if name == "remove_query_arg":
        return len(arguments) == 1 or arguments[1].strip().lower() in FALSE_URL_VALUES

    # add_query_arg( $key, $value ) omits the URL.  The two-argument array
    # overload is explicit only when the first argument is visibly an array.
    if len(arguments) == 1:
        return True
    if len(arguments) == 2:
        first = arguments[0].lstrip().lower()
        second = arguments[1].strip().lower()
        if second in FALSE_URL_VALUES:
            return True
        return not (first.startswith("array") or first.startswith("["))
    return arguments[2].strip().lower() in FALSE_URL_VALUES


def detect_implicit_request_uri_calls(text: str) -> List[Tuple[str, str]]:
    hits = []
    for name, arguments in iter_query_arg_calls(text):
        if _is_implicit_url(name, arguments):
            hits.append(("legacy_implicit_request_uri", rf"\b{name}\s*\("))
    return hits
