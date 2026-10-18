import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Sequence, Set, Tuple

from config import WINDOW_AFTER, WINDOW_BEFORE
from scanner.entrypoint_detector import (
    analyze_entrypoints,
    function_for_line,
    summarize_entrypoints_for_line,
)
from scanner.legacy_models import _split_call_arguments, iter_function_calls, iter_named_function_calls
from scanner.sanitizer_detector import detect_sanitizers, detect_security_checks
from scanner.scorer import score_finding
from scanner.sink_detector import detect_sinks
from scanner.source_detector import detect_sources
from scanner.storage_detector import detect_storage
from scanner.utils import (
    extract_php_variables,
    normalize_snippet,
    plugin_name_from_path,
    safe_read_text,
)
from rules.sinks import JSONP_CALLBACK_PATTERN


PHP_QUOTED_STRING_PATTERN = (
    r"(?:'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\")"
)
ASSIGNMENT_RE = re.compile(
    r"(?P<lhs>\$[a-zA-Z_][a-zA-Z0-9_]*)\s*"
    r"(?P<operator>\.=|(?<![=!<>])=(?!=|>))\s*"
    r"(?P<rhs>.*?)(?:;|$)",
    re.DOTALL,
)
HELPER_ASSIGNMENT_RE = re.compile(
    r"(?P<lhs>\$[a-zA-Z_][a-zA-Z0-9_]*)\s*"
    r"(?P<operator>\.=|(?<![=!<>])=(?!=|>))\s*"
    rf"(?P<rhs>(?:{PHP_QUOTED_STRING_PATTERN}|[^;])*)(?:;|$)",
    re.DOTALL,
)
ARRAY_ELEMENT_ASSIGNMENT_RE = re.compile(
    r"(?P<lhs>\$[a-zA-Z_][a-zA-Z0-9_]*)\s*\[(?P<index>[^\]]*)\]\s*"
    r"(?P<operator>\.=|(?<![=!<>])=(?!=|>))\s*"
    r"(?P<rhs>.*?)(?:;|$)",
    re.DOTALL,
)
LIST_ASSIGNMENT_RE = re.compile(
    r"\blist\s*\((?P<targets>[^)]*)\)\s*=\s*(?P<rhs>.*?)(?:;|$)",
    re.IGNORECASE | re.DOTALL,
)
LITERAL_ARRAY_KEY_RE = re.compile(
    r"['\"](?P<key>[a-zA-Z_][a-zA-Z0-9_]*)['\"]\s*=>"
)
STORAGE_LITERAL_ARRAY_KEY_RE = re.compile(
    r"['\"](?P<key>[a-zA-Z0-9_.-]+)['\"]\s*=>"
)
STATIC_VARIABLE_RE = re.compile(r"^\s*(\$[a-zA-Z_][a-zA-Z0-9_]*)\s*$")
ARRAY_ELEMENT_ACCESS_RE = re.compile(
    r"(?P<container>\$[a-zA-Z_][a-zA-Z0-9_]*)\s*\[\s*"
    r"(?P<quote>['\"])(?P<field>[a-zA-Z0-9_.-]+)(?P=quote)\s*\]"
)
FOREACH_VALUE_RE = re.compile(
    r"\bforeach\s*\(\s*(?P<iterable>"
    r"(?P<container>\$[a-zA-Z_][a-zA-Z0-9_]*)(?:\s*\[[^\]]+\])?"
    r")\s+as\s+"
    r"(?:(?P<key>\$[a-zA-Z_][a-zA-Z0-9_]*)\s*=>\s*)?"
    r"&?\s*(?P<value>\$[a-zA-Z_][a-zA-Z0-9_]*)\s*\)",
    re.IGNORECASE,
)
RETURN_RE = re.compile(r"\breturn\b", re.IGNORECASE)
RETURN_VARIABLE_RE = re.compile(
    r"\breturn\s+(?P<variable>\$[a-zA-Z_][a-zA-Z0-9_]*)\s*;",
    re.IGNORECASE | re.DOTALL,
)
RETURN_EXPRESSION_RE = re.compile(
    r"\breturn\s+(?P<expression>.*?);",
    re.IGNORECASE | re.DOTALL,
)
FIXED_HELPER_RHS_RE = re.compile(
    r"^\s*(?:(?:\$[a-zA-Z_][a-zA-Z0-9_]*|[a-zA-Z_][a-zA-Z0-9_]*)"
    r"\s*(?:->|::)\s*)?(?P<name>[a-zA-Z_][a-zA-Z0-9_]*)\s*\(.*\)\s*$",
    re.IGNORECASE | re.DOTALL,
)
NO_ARGUMENT_HELPER_ASSIGNMENT_RE = re.compile(
    r"(?P<lhs>\$[a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*"
    r"(?:(?:\$[a-zA-Z_][a-zA-Z0-9_]*|[a-zA-Z_][a-zA-Z0-9_]*)"
    r"\s*(?:->|::)\s*)?(?P<name>[a-zA-Z_][a-zA-Z0-9_]*)\s*\(\s*\)",
    re.IGNORECASE | re.DOTALL,
)
URL_ATTRIBUTE_RE = re.compile(
    r"\b(?:href|src|action|formaction|poster|cite)\s*=",
    re.IGNORECASE,
)
ATTRIBUTE_RE = re.compile(
    r"\b(?:value|title|alt|class|id|name|placeholder|data-[a-zA-Z0-9_-]+)\s*=",
    re.IGNORECASE,
)
EVENT_ATTRIBUTE_RE = re.compile(
    r"\bon[a-zA-Z]+\s*=\s*['\"][^'\"]*(?:\$[a-zA-Z_][a-zA-Z0-9_]*|<\?=|<\?php\s*(?:echo|print)\b)[^'\"]*['\"]",
    re.IGNORECASE,
)
SCRIPT_CONTEXT_RE = re.compile(
    r"<script\b[^>]*>.*?(?:\$[a-zA-Z_][a-zA-Z0-9_]*|<\?=|<\?php\s*(?:echo|print)\b).*?</script\s*>",
    re.IGNORECASE | re.DOTALL,
)
STATIC_STRING_RE = re.compile(r"^\s*(['\"])(.*?)\1\s*$", re.DOTALL)
LITERAL_INCLUDE_RE = re.compile(
    r"\b(?P<kind>include_once|include|require_once|require)\s*"
    r"(?:\(\s*)?(?P<quote>['\"])(?P<path>[^'\"]*)(?P=quote)\s*"
    r"\)?\s*;?\s*(?:\?>)?\s*$",
    re.IGNORECASE,
)
STATIC_SUBJECT_RE = re.compile(
    r"^\s*(?:(['\"])(.*?)\1|(?P<number>\d+))\s*$", re.DOTALL
)
HTML_BUILD_RE = re.compile(
    r"(?:^|[;{}])\s*\$[a-zA-Z_][a-zA-Z0-9_]*\s*(?:=|\.=).*?"
    r"['\"][^'\"]*<[^'\"]*['\"]",
    re.IGNORECASE | re.DOTALL,
)
HTML_RETURN_RE = re.compile(
    r"\breturn\b.*?(?:'[^']*<[^']*'|\"[^\"]*<[^\"]*\")",
    re.IGNORECASE | re.DOTALL,
)
FUNCTION_HEADER_RE = re.compile(
    r"\bfunction\s+&?\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\([^)]*\)\s*\{",
    re.IGNORECASE | re.DOTALL,
)

CONTROL_ONLY_CALL_RE = re.compile(
    r"\b(?:isset|empty|array_key_exists|wp_verify_nonce|"
    r"check_admin_referer|check_ajax_referer)\s*\([^;{}]*?\)",
    re.IGNORECASE | re.DOTALL,
)
CONTROL_ONLY_CONDITION_RE = re.compile(
    r"\b(?:if|elseif|while|for|switch)\s*\([^{};]*?\)",
    re.IGNORECASE | re.DOTALL,
)
ALTERNATIVE_BRANCH_RE = re.compile(
    r"^\s*(?:<\?(?:php|=)?\s*)?(?:}\s*)?(?:else\b|elseif\s*\()",
    re.IGNORECASE,
)
MAX_HELPER_HANDOFF_DEPTH = 2
CUSTOM_SQL_DOMAIN = "custom_sql"
CUSTOM_SQL_WRAPPER_DOMAIN = "custom_sql_wrapper"
CUSTOM_SQL_CONSTANT_DOMAIN = "custom_sql_constant"
CUSTOM_SQL_HELPER_DOMAIN = "custom_sql_zero_arg_helper"
ATTACHMENT_EXIF_METADATA_DOMAIN = "attachment_exif_metadata"
ATTACHMENT_EXIF_OUTPUT_CALLBACK_DOMAIN = "attachment_exif_output_callback"
REST_POST_OBJECT_CALLBACK_DOMAIN = "rest_post_object_callback"
POST_META_CLASS_CONSTANT_DOMAIN = "post_meta_class_constant"
CLASS_HEADER_RE = re.compile(
    r"\bclass\s+(?P<class>[A-Za-z_][A-Za-z0-9_]*)\b(?P<header>[^\{]*)\{",
    re.IGNORECASE,
)
CLASS_LITERAL_CONST_RE = re.compile(
    r"\bconst\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"(['\"])(?P<key>[A-Za-z0-9_.-]+)\2\s*;",
    re.IGNORECASE,
)
ATTACHMENT_EXIF_FILTER_RE = re.compile(
    r"\badd_filter\s*\(\s*['\"]wp_read_image_metadata['\"]\s*,\s*"
    r"['\"](?P<callback>[A-Za-z_][A-Za-z0-9_]*)['\"]",
    re.IGNORECASE,
)
ATTACHMENT_METADATA_READ_RE = re.compile(
    r"^\s*wp_get_attachment_metadata\s*\([^)]*\)\s*$",
    re.IGNORECASE | re.DOTALL,
)
ATTACHMENT_METADATA_FIELD_READ_RE = re.compile(
    r"^\s*(?P<container>\$[A-Za-z_][A-Za-z0-9_]*)\s*"
    r"\[\s*['\"]image_meta['\"]\s*\]\s*"
    r"\[\s*['\"](?P<field>[A-Za-z_][A-Za-z0-9_]*)['\"]\s*\]\s*$",
    re.IGNORECASE | re.DOTALL,
)
CONTENT_FILTER_RE = re.compile(
    r"\badd_filter\s*\(\s*['\"]the_content['\"]\s*,\s*"
    r"['\"](?P<callback>[A-Za-z_][A-Za-z0-9_]*)['\"]",
    re.IGNORECASE,
)
PREG_REPLACE_CALLBACK_RETURN_RE = re.compile(
    r"\breturn\s+preg_replace_callback\s*\(\s*['\"][^'\"]+['\"]\s*,\s*"
    r"['\"](?P<callback>[A-Za-z_][A-Za-z0-9_]*)['\"]\s*,",
    re.IGNORECASE | re.DOTALL,
)
REST_POST_METHOD_RE = re.compile(
    r"['\"]methods['\"]\s*=>\s*['\"]POST['\"]",
    re.IGNORECASE,
)
REST_OBJECT_CALLBACK_RE = re.compile(
    r"['\"]callback['\"]\s*=>\s*array\s*\(\s*\$this\s*,\s*"
    r"['\"](?P<method>[A-Za-z_][A-Za-z0-9_]*)['\"]\s*\)",
    re.IGNORECASE,
)
REST_PERMISSION_CALLBACK_RE = re.compile(
    r"['\"]permission_callback['\"]\s*=>",
    re.IGNORECASE,
)
STATIC_REST_ROUTE_EXPRESSION_RE = re.compile(
    r"^\s*(?:['\"][^'\"]+['\"]|[A-Za-z_][A-Za-z0-9_:]*)"
    r"(?:\s*\.\s*(?:['\"][^'\"]+['\"]|[A-Za-z_][A-Za-z0-9_:]*))*\s*$",
    re.IGNORECASE,
)
CLASS_CONSTANT_REFERENCE_RE = re.compile(
    r"^\s*(?P<class>[A-Za-z_][A-Za-z0-9_]*)::"
    r"(?P<constant>[A-Za-z_][A-Za-z0-9_]*)\s*$",
    re.IGNORECASE,
)

# This is deliberately a *recognizer*, not a SQL parser.  The custom-SQL
# model accepts only the small legacy subset described below: a WordPress
# prefix plus a fixed suffix, fixed column names, and an executed wpdb call.
CUSTOM_TABLE_DIRECT_RE = re.compile(
    r"^\s*\$wpdb\s*->\s*prefix\s*\.\s*(['\"])(?P<suffix>[A-Za-z0-9_]+)\1\s*$",
    re.DOTALL,
)
CUSTOM_TABLE_DEFINE_RE = re.compile(
    r"\bdefine\s*\(\s*(['\"])(?P<name>[A-Za-z_][A-Za-z0-9_]*)\1\s*,\s*"
    r"\$wpdb\s*->\s*prefix\s*\.\s*(['\"])(?P<suffix>[A-Za-z0-9_]+)\3\s*\)",
    re.IGNORECASE | re.DOTALL,
)
CUSTOM_SQL_CALL_RE = re.compile(
    r"\$wpdb\s*->\s*(?P<api>query|get_results|get_row)\s*\(\s*(?P<arg>[^,)]*)",
    re.IGNORECASE | re.DOTALL,
)
CUSTOM_SQL_ASSIGNMENT_RE = re.compile(
    r"^\s*(?P<lhs>\$[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<rhs>.+?)\s*$",
    re.DOTALL,
)
CUSTOM_SQL_FUNCTION_RE = re.compile(
    r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(\s*(?P<param>\$[A-Za-z_][A-Za-z0-9_]*)\s*\)"
    r"\s*\{(?P<body>.*?)\}",
    re.IGNORECASE | re.DOTALL,
)
CUSTOM_SQL_LITERAL_COLUMN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
CUSTOM_SQL_FIELD_OBJECT_RE = re.compile(
    r"(?P<row>\$[A-Za-z_][A-Za-z0-9_]*)\s*->\s*(?P<column>[A-Za-z_][A-Za-z0-9_]*)"
)
CUSTOM_SQL_FIELD_ARRAY_RE = re.compile(
    r"(?P<row>\$[A-Za-z_][A-Za-z0-9_]*)\s*\[\s*(['\"])(?P<column>[A-Za-z_][A-Za-z0-9_]*)\2\s*\]"
)


WRITE_SPECS = {
    "update_option": ("option", 0, 1),
    "add_option": ("option", 0, 1),
    "update_site_option": ("site_option", 0, 1),
    "add_site_option": ("site_option", 0, 1),
    "update_blog_option": ("option", 1, 2),
    "set_transient": ("transient", 0, 1),
    "set_site_transient": ("site_transient", 0, 1),
    "update_post_meta": ("post_meta", 1, 2),
    "add_post_meta": ("post_meta", 1, 2),
    "update_user_meta": ("user_meta", 1, 2),
    "add_user_meta": ("user_meta", 1, 2),
    "update_term_meta": ("term_meta", 1, 2),
    "add_term_meta": ("term_meta", 1, 2),
}

READ_SPECS = {
    "get_option": ("option", 0),
    "get_site_option": ("site_option", 0),
    "get_blog_option": ("option", 1),
    "get_transient": ("transient", 0),
    "get_site_transient": ("site_transient", 0),
    "get_post_meta": ("post_meta", 1),
    "get_user_meta": ("user_meta", 1),
    "get_term_meta": ("term_meta", 1),
}
STORAGE_API_NAMES = frozenset(WRITE_SPECS) | frozenset(READ_SPECS)

PLUGIN_STORAGE_DOMAINS = {
    "option",
    "site_option",
    "post_meta",
    "user_meta",
    "term_meta",
}

DYNAMIC_STORAGE_SUBJECT = "<dynamic-subject>"
OPTION_CONSTANT_DOMAIN = "option_constant"
OPTION_SETTER_DOMAIN = "option_thin_setter"
OPTION_GETTER_DOMAIN = "option_thin_getter"
SAME_INSTANCE_OUTPUT_METHOD_DOMAIN = "same_instance_output_method"
GLOBAL_OPTION_FIELD_DOMAIN = "global_option_field"
GLOBAL_OPTION_BINDING_DOMAIN = "global_option_binding"
TOP_LEVEL_LITERAL_OPTION_ASSIGNMENT_RE = re.compile(
    r"^\s*(?:<\?(?:php)?\s*)?"
    r"(?P<global>\$[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"get_option\s*\(\s*(?P<quote>['\"])(?P<key>[A-Za-z0-9_.-]+)(?P=quote)\s*\)\s*;?"
    r"\s*(?:\?>)?\s*$",
    re.IGNORECASE | re.DOTALL,
)
GLOBAL_DECLARATION_RE = re.compile(
    r"\bglobal\s+(?P<variables>\$[A-Za-z_][A-Za-z0-9_]*"
    r"(?:\s*,\s*\$[A-Za-z_][A-Za-z0-9_]*)*)\s*;",
    re.IGNORECASE,
)
DIRECT_OBJECT_METHOD_CALL_RE = re.compile(
    r"\$[A-Za-z_][A-Za-z0-9_]*\s*->\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(",
    re.IGNORECASE,
)
SAME_INSTANCE_HELPER_RHS_RE = re.compile(
    r"^\s*\$this\s*->\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\([^;]*\)\s*$",
    re.IGNORECASE | re.DOTALL,
)

# This model deliberately resolves only plugin-local, quoted-string constants
# used by the standard single-site Options API.  It is not a PHP constant
# evaluator and does not cover site options, aliases, concatenation, or class
# constants.
OPTION_CONSTANT_DEFINE_RE = re.compile(
    r"\bdefine\s*\(\s*['\"](?P<name>[A-Za-z_][A-Za-z0-9_]*)['\"]\s*,\s*"
    r"['\"](?P<key>[A-Za-z0-9_.-]+)['\"]\s*\)",
    re.I,
)


@dataclass(frozen=True)
class Statement:
    start_line: int
    end_line: int
    text: str


@dataclass
class TaintInfo:
    origin_kind: str
    origin_match: str
    sanitizers: List[Tuple[str, str]]
    flow_evidence: str = "variable_assignment"


def line_has_source(line: str) -> bool:
    return bool(detect_sources(line))


def get_first_source(line: str) -> Tuple[str, str]:
    hits = detect_sources(line)
    return hits[0] if hits else ("", "")


def get_first_sink(text: str) -> Tuple[str, str]:
    hits = detect_sinks(text)
    return hits[0] if hits else ("", "")


def get_first_storage(text: str) -> Tuple[str, str]:
    hits = detect_storage(text)
    return hits[0] if hits else ("", "")


def _iter_statements(text: str) -> Iterable[Statement]:
    """Split PHP-like source into semicolon-delimited statements with lines.

    This is intentionally tolerant of obsolete or malformed PHP.  It is not a
    parser, but unlike a line window it never joins two ordinary statements.
    """
    buffer: List[str] = []
    start_line = 1
    line_no = 1
    paren_depth = 0
    bracket_depth = 0
    quote = ""
    escaped = False
    in_block_comment = False
    in_line_comment = False
    index = 0

    def flush(end_line: int) -> Statement | None:
        nonlocal buffer, start_line
        value = "".join(buffer).strip()
        buffer = []
        if not value:
            start_line = end_line
            return None
        statement = Statement(start_line=start_line, end_line=end_line, text=value)
        start_line = end_line
        return statement

    while index < len(text):
        char = text[index]
        pair = text[index : index + 2]

        # Keep adjacent PHP template blocks independent.  Without this split,
        # HTML between ``?>`` and the next opening tag is joined to the next
        # PHP statement, so an escape/cast in a later block can incorrectly
        # sanitize an earlier output expression.
        opening_tag = (
            text[index : index + 5].casefold() == "<?php"
            or text[index : index + 3] == "<?="
            or (
                pair == "<?"
                and text[index : index + 5].casefold() != "<?xml"
            )
        )
        if (
            opening_tag
            and not quote
            and not in_block_comment
            and not in_line_comment
            and buffer
        ):
            statement = flush(line_no)
            if statement:
                yield statement

        if not buffer and char.isspace():
            if char == "\n":
                line_no += 1
                start_line = line_no
            index += 1
            continue

        buffer.append(char)

        if in_line_comment:
            if char == "\n":
                in_line_comment = False
        elif in_block_comment:
            if pair == "*/":
                if index + 1 < len(text):
                    buffer.append(text[index + 1])
                index += 1
                in_block_comment = False
        elif quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
        elif pair == "/*":
            if index + 1 < len(text):
                buffer.append(text[index + 1])
            index += 1
            in_block_comment = True
        elif pair == "//" or char == "#":
            if pair == "//" and index + 1 < len(text):
                buffer.append(text[index + 1])
                index += 1
            in_line_comment = True
        elif char in ("'", '"'):
            quote = char
        elif char == "(":
            paren_depth += 1
        elif char == ")":
            paren_depth = max(0, paren_depth - 1)
        elif char == "[":
            bracket_depth += 1
        elif char == "]":
            bracket_depth = max(0, bracket_depth - 1)

        should_flush = (
            not quote
            and not in_block_comment
            and not in_line_comment
            and paren_depth == 0
            and bracket_depth == 0
            and (char == ";" or char == "}" or pair == "?>")
        )
        if should_flush:
            if pair == "?>" and index + 1 < len(text):
                buffer.append(text[index + 1])
                index += 1
            statement = flush(line_no)
            if statement:
                yield statement

        if char == "\n":
            line_no += 1
            if not buffer:
                start_line = line_no
        index += 1

    statement = flush(line_no)
    if statement:
        yield statement


def _strip_php_comments(text: str) -> str:
    """Mask PHP comments while preserving offsets and line numbers."""
    output = list(text)
    quote = ""
    escaped = False
    in_block_comment = False
    in_line_comment = False
    index = 0

    while index < len(text):
        char = text[index]
        pair = text[index : index + 2]

        if in_line_comment:
            if char == "\n":
                in_line_comment = False
            else:
                output[index] = " "
            index += 1
            continue
        if in_block_comment:
            if pair == "*/":
                output[index] = " "
                if index + 1 < len(output):
                    output[index + 1] = " "
                index += 2
                in_block_comment = False
            else:
                if char != "\n":
                    output[index] = " "
                index += 1
            continue
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            index += 1
            continue
        if char in ("'", '"'):
            quote = char
            index += 1
            continue
        if pair == "/*":
            output[index] = " "
            if index + 1 < len(output):
                output[index + 1] = " "
            index += 2
            in_block_comment = True
            continue
        if pair == "//":
            output[index] = " "
            if index + 1 < len(output):
                output[index + 1] = " "
            index += 2
            in_line_comment = True
            continue
        if char == "#":
            output[index] = " "
            index += 1
            in_line_comment = True
            continue
        index += 1

    return "".join(output)


def _static_key(argument: str) -> str:
    match = STATIC_STRING_RE.match(argument)
    if not match:
        return ""
    value = match.group(2)
    if match.group(1) == '"' and "$" in value:
        return ""
    return value


def _literal_include_target(statement_text: str, calling_path: Path) -> Path | None:
    """Resolve only a local, quoted literal include from the caller directory."""
    match = LITERAL_INCLUDE_RE.search(statement_text)
    if not match:
        return None
    raw_path = match.group("path")
    if not raw_path or (match.group("quote") == '"' and "$" in raw_path):
        return None

    normalized = raw_path.replace("\\", "/")
    if (
        normalized.startswith("/")
        or ":" in normalized
        or any(part == ".." for part in normalized.split("/"))
    ):
        return None

    target = (calling_path.parent / Path(raw_path)).resolve()
    return target if target.is_file() else None


def _is_include_once(statement_text: str) -> bool:
    """Return whether a recognized literal include has include-once semantics."""
    match = LITERAL_INCLUDE_RE.search(statement_text)
    return bool(match and match.group("kind").lower() in {"include_once", "require_once"})


def _literal_include_scope_taint(
    scope_state: Dict[str, TaintInfo],
) -> Dict[str, TaintInfo]:
    """Copy caller taint into an included file without losing sanitizer evidence."""
    return {
        variable: TaintInfo(
            origin_kind=info.origin_kind,
            origin_match=info.origin_match,
            sanitizers=list(info.sanitizers),
            flow_evidence=(
                "plugin_dynamic_subject_storage"
                if info.flow_evidence == "plugin_dynamic_subject_storage"
                else "literal_include_scope"
            ),
        )
        for variable, info in scope_state.items()
    }


def _array_taint_key(container: str, field: str) -> str:
    """Return an internal key for one exact local array field."""
    return f"{container}[{field!r}]"


def _array_wildcard_taint_key(container: str) -> str:
    """Return an internal key for an appended local array element."""
    return f"{container}[*]"


def _literal_array_accesses(text: str) -> Set[Tuple[str, str]]:
    """Return literal field accesses while leaving dynamic fields unresolved."""
    return {
        (match.group("container"), match.group("field"))
        for match in ARRAY_ELEMENT_ACCESS_RE.finditer(text)
    }


def _array_element_taint(
    container: str, scope_state: Dict[str, TaintInfo]
) -> List[Tuple[str, TaintInfo]]:
    """Return deterministic local taint entries belonging to one array."""
    prefix = f"{container}["
    return sorted(
        (
            (key, info)
            for key, info in scope_state.items()
            if key.startswith(prefix) and key.endswith("]")
        ),
        key=lambda item: item[0],
    )


def _tainted_literal_array_fields(
    expression: str, scope_state: Dict[str, TaintInfo]
) -> Dict[str, TaintInfo]:
    """Summarize direct source-bearing fields of one literal ``array(...)``."""
    match = re.match(r"^\s*array\s*\(", expression, re.IGNORECASE)
    if not match:
        return {}
    fields: Dict[str, TaintInfo] = {}
    for argument in _split_call_arguments(expression, match.end() - 1):
        entry = re.match(r"^\s*(?P<key>['\"][^'\"]+['\"])\s*=>\s*(?P<value>.*)$", argument, re.DOTALL)
        if not entry:
            continue
        field = _static_key(entry.group("key"))
        value = entry.group("value")
        sources = detect_sources(value)
        references = _tainted_references(value, scope_state)
        if sources:
            origin_kind, origin_match = sources[0]
            fields[field] = TaintInfo(
                origin_kind, origin_match, detect_sanitizers(value), "variable_assignment"
            )
        elif references:
            origin = scope_state[references[0]]
            fields[field] = TaintInfo(
                origin.origin_kind,
                origin.origin_match,
                _dedupe_hits([*origin.sanitizers, *detect_sanitizers(value)]),
                origin.flow_evidence,
            )
    return fields


def _tainted_top_level_option_globals(
    plugin_tainted_storage: Set[Tuple[str, str, str]],
) -> Dict[str, Dict[str, TaintInfo]]:
    """Resolve plugin-wide unique top-level literal option bindings.

    This is intentionally not a general global-state model.  It admits only a
    top-level ``$global = get_option('literal')`` whose option and literal
    array field were both recorded by this plugin's tainted-write prepass.
    """
    fields_by_option: Dict[str, Dict[str, TaintInfo]] = {}
    for domain, key, field in plugin_tainted_storage:
        if domain != GLOBAL_OPTION_FIELD_DOMAIN:
            continue
        fields_by_option.setdefault(key, {})[field] = TaintInfo(
            origin_kind="plugin_stored_read",
            origin_match=f"option:{key}:{field}",
            sanitizers=[],
            flow_evidence="plugin_literal_storage",
        )

    bindings = {
        global_name: key
        for domain, global_name, key in plugin_tainted_storage
        if domain == GLOBAL_OPTION_BINDING_DOMAIN
    }
    return {
        global_name: fields_by_option[key]
        for global_name, key in bindings.items()
        if key in fields_by_option
    }


def _uses_bare_container(text: str, container: str) -> bool:
    """Whether a container is consumed as a value rather than one field."""
    return bool(
        re.search(
            rf"{re.escape(container)}(?![a-zA-Z0-9_]|\s*(?:\[|->))",
            text,
        )
    )


def _tainted_references(
    text: str, scope_state: Dict[str, TaintInfo]
) -> List[str]:
    """Resolve variable, exact-field, and aggregate local taint used by text."""
    references = {
        variable
        for variable in extract_php_variables(text)
        if variable in scope_state
    }
    for container, field in _literal_array_accesses(text):
        key = _array_taint_key(container, field)
        if key in scope_state:
            references.add(key)
    for container in extract_php_variables(text):
        if not _uses_bare_container(text, container):
            continue
        elements = _array_element_taint(container, scope_state)
        if elements:
            references.add(elements[0][0])
    # Custom SQL reads intentionally expose only an exact fixed field.  A bare
    # result object/array, dynamic property, or dynamic key cannot consume it.
    for match in CUSTOM_SQL_FIELD_OBJECT_RE.finditer(text):
        key = _custom_sql_field_key(match.group("row"), match.group("column"), False)
        if key in scope_state:
            references.add(key)
    for match in CUSTOM_SQL_FIELD_ARRAY_RE.finditer(text):
        key = _custom_sql_field_key(match.group("row"), match.group("column"), True)
        if key in scope_state:
            references.add(key)
    return sorted(references)


def _clear_array_element_taint(
    container: str, scope_state: Dict[str, TaintInfo]
) -> None:
    for key, _info in _array_element_taint(container, scope_state):
        scope_state.pop(key, None)


def _foreach_body_text(text: str) -> str:
    """Hide foreach headers so binding variables count only when the body uses them."""
    return FOREACH_VALUE_RE.sub("foreach ()", text)


def _output_expression_flow_text(text: str) -> str:
    """Detach a leading control guard from a variable-free inline output.

    The lightweight statement splitter deliberately keeps a leading control
    condition with its first body statement.  A variable used only by that
    guard is not an argument to ``echo``/``print``/``printf`` and must not
    become the source for a clean, variable-free output expression.  Dynamic
    output remains unchanged because cross-file storage reads and assignments
    inside a condition can become tainted before the local scope set reflects
    that fact.
    """
    match = re.search(r"<\?=|\becho\b|\bprint\b|\bprintf\s*\(", text, re.IGNORECASE)
    if not match:
        return text

    prefix = text[: match.start()]
    if not re.search(r"\b(?:if|elseif)\s*\(", prefix, re.IGNORECASE):
        return text

    output_text = text[match.end() :]
    if extract_php_variables(output_text):
        return text
    return output_text


def _resolved_storage_keys(
    argument: str,
    key_aliases: Dict[str, Set[str]] | None = None,
    option_constant_keys: Dict[str, str] | None = None,
    post_meta_class_constant_keys: Dict[str, str] | None = None,
) -> Set[str]:
    static = _static_key(argument)
    if static:
        return {static}
    constant_key = (option_constant_keys or {}).get(argument.strip())
    if constant_key:
        return {constant_key}
    class_constant_key = (post_meta_class_constant_keys or {}).get(
        argument.strip().casefold()
    )
    if class_constant_key:
        return {class_constant_key}
    variable = STATIC_VARIABLE_RE.match(argument)
    if not variable or not key_aliases:
        return set()
    return set(key_aliases.get(variable.group(1), set()))


def _static_subject(argument: str) -> str:
    match = STATIC_SUBJECT_RE.match(argument)
    if not match:
        return ""
    return match.group("number") or match.group(2) or ""


def _plugin_storage_key(
    name: str, arguments: Sequence[str], resolved_key: str = ""
) -> Tuple[str, str, str] | None:
    specs = WRITE_SPECS if name in WRITE_SPECS else READ_SPECS
    domain, key_index, *_rest = specs[name]
    if len(arguments) <= key_index:
        return None
    key = resolved_key or _static_key(arguments[key_index])
    if not key or domain not in PLUGIN_STORAGE_DOMAINS:
        return None
    if domain in {"option", "site_option"}:
        return domain, "", key
    if not arguments:
        return None
    subject = _static_subject(arguments[0])
    return domain, subject or DYNAMIC_STORAGE_SUBJECT, key


def _storage_writes(
    text: str,
    key_aliases: Dict[str, Set[str]] | None = None,
    option_constant_keys: Dict[str, str] | None = None,
    option_setter_keys: Dict[str, str] | None = None,
    post_meta_class_constant_keys: Dict[str, str] | None = None,
) -> List[Tuple[Tuple[str, str], str, str, Tuple[str, str, str] | None]]:
    results = []
    for name, arguments in iter_named_function_calls(text, WRITE_SPECS):
        domain, key_index, value_index = WRITE_SPECS[name]
        if len(arguments) <= max(key_index, value_index):
            continue
        constants = option_constant_keys if name in {"update_option", "add_option"} else None
        class_constants = post_meta_class_constant_keys if domain == "post_meta" else None
        for key in sorted(
            _resolved_storage_keys(
                arguments[key_index], key_aliases, constants, class_constants
            )
        ):
            results.append(
                (
                    (domain, key),
                    arguments[value_index],
                    name,
                    _plugin_storage_key(name, arguments, key),
                )
            )
    for name, key in (option_setter_keys or {}).items():
        for _called, arguments in iter_named_function_calls(text, {name}):
            if len(arguments) == 1:
                results.append(
                    (("option", key), arguments[0], name, ("option", "", key))
                )
    return results


def _storage_reads(
    text: str,
    key_aliases: Dict[str, Set[str]] | None = None,
    option_constant_keys: Dict[str, str] | None = None,
    option_getter_keys: Dict[str, str] | None = None,
    post_meta_class_constant_keys: Dict[str, str] | None = None,
) -> List[Tuple[Tuple[str, str], str, Tuple[str, str, str] | None]]:
    results = []
    for name, arguments in iter_named_function_calls(text, READ_SPECS):
        domain, key_index = READ_SPECS[name]
        if len(arguments) <= key_index:
            continue
        constants = option_constant_keys if name == "get_option" else None
        class_constants = post_meta_class_constant_keys if domain == "post_meta" else None
        for key in sorted(
            _resolved_storage_keys(
                arguments[key_index], key_aliases, constants, class_constants
            )
        ):
            results.append(
                ((domain, key), name, _plugin_storage_key(name, arguments, key))
            )
    for name, key in (option_getter_keys or {}).items():
        for _called, arguments in iter_named_function_calls(text, {name}):
            if not arguments:
                results.append((("option", key), name, ("option", "", key)))
    return results


def _matched_storage_reads(
    text: str,
    local_tainted_storage: Set[Tuple[str, str]],
    plugin_tainted_storage: Set[Tuple[str, str, str]],
    key_aliases: Dict[str, Set[str]] | None = None,
    option_constant_keys: Dict[str, str] | None = None,
    option_getter_keys: Dict[str, str] | None = None,
    post_meta_class_constant_keys: Dict[str, str] | None = None,
) -> List[Tuple[Tuple[str, str], str, str]]:
    matches = []
    for local_key, api, plugin_key in _storage_reads(
        text,
        key_aliases,
        option_constant_keys,
        option_getter_keys,
        post_meta_class_constant_keys,
    ):
        if local_key in local_tainted_storage:
            matches.append((local_key, api, ""))
        elif plugin_key and plugin_key in plugin_tainted_storage:
            match_kind = (
                "dynamic_subject"
                if plugin_key[1] == DYNAMIC_STORAGE_SUBJECT
                else "exact"
            )
            matches.append((local_key, api, match_kind))
    return matches


def _custom_table_value(expression: str, constants: Dict[str, str], aliases: Dict[str, Tuple[str, int]]) -> Tuple[str, int] | None:
    """Resolve only ``$wpdb->prefix . 'fixed'`` and one simple alias."""
    direct = CUSTOM_TABLE_DIRECT_RE.match(expression)
    if direct:
        return f"wpdb_prefix:{direct.group('suffix')}", 0
    token = expression.strip()
    if token in constants:
        return constants[token], 0
    variable = STATIC_VARIABLE_RE.match(token)
    return aliases.get(variable.group(1)) if variable else None


def _custom_sql_key(table: str, column: str) -> Tuple[str, str, str]:
    return CUSTOM_SQL_DOMAIN, table, column


def _custom_sql_field_key(row: str, column: str, array_form: bool) -> str:
    return f"{row}[{column!r}]" if array_form else f"{row}->{column}"


def _custom_sql_alias_value(argument: str, sql_aliases: Dict[str, str]) -> str:
    variable = STATIC_VARIABLE_RE.match(argument)
    if variable:
        return sql_aliases.get(variable.group(1), "")
    return argument


def _flatten_php_concat(expression: str) -> str | None:
    """Flatten only closed PHP concat expressions, preserving values in order.

    PHP quote delimiters and outer ``.`` operators disappear; literal content,
    variables, constants and balanced fixed calls remain.  Any unterminated or
    otherwise ambiguous term is rejected rather than guessed.
    """
    index, pieces, expect_term = 0, [], True
    length = len(expression)
    while index < length:
        while index < length and expression[index].isspace():
            index += 1
        if index >= length:
            break
        if not expect_term:
            if expression[index] != ".":
                return None
            index += 1
            expect_term = True
            continue
        if expression[index] in ("'", '\"'):
            quote, index, value, escaped = expression[index], index + 1, [], False
            while index < length:
                char = expression[index]
                if escaped:
                    value.append(char)
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    break
                else:
                    value.append(char)
                index += 1
            if index >= length or expression[index] != quote:
                return None
            pieces.append("".join(value))
            index += 1
        else:
            start, depth, bracket_depth, quote, escaped = index, 0, 0, "", False
            while index < length:
                char = expression[index]
                if quote:
                    if escaped:
                        escaped = False
                    elif char == "\\":
                        escaped = True
                    elif char == quote:
                        quote = ""
                    index += 1
                    continue
                if char in ("'", '\"'):
                    quote = char
                elif char == "(":
                    depth += 1
                elif char == ")":
                    if depth == 0:
                        return None
                    depth -= 1
                elif char == "[":
                    bracket_depth += 1
                elif char == "]":
                    if bracket_depth == 0:
                        return None
                    bracket_depth -= 1
                elif char == "." and depth == 0 and bracket_depth == 0:
                    break
                index += 1
            term = expression[start:index].strip()
            if not term or depth or bracket_depth or quote:
                return None
            # SQL structure only needs term order. Preserve static array
            # fields, fixed object properties, and lexical fixed-name calls
            # as opaque terms. Dynamic keys/properties/callables and method
            # dispatch remain rejected.
            if not (
                re.fullmatch(
                    r"\$[A-Za-z_][A-Za-z0-9_]*"
                    r"(?:\s*->\s*[A-Za-z_][A-Za-z0-9_]*)?"
                    r"(?:\s*\[\s*(['\"])[A-Za-z_][A-Za-z0-9_]*\1\s*\])?",
                    term,
                    re.S,
                )
                or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", term)
                or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*\s*\(.*\)", term, re.S)
            ):
                return None
            pieces.append(term)
        expect_term = False
    return "".join(pieces) if pieces and not expect_term else None


def _iter_custom_sql_calls(text: str) -> Iterable[Tuple[str, str, int]]:
    for match in re.finditer(r"\$wpdb\s*->\s*(?P<api>query|get_results|get_row)\s*\(", text, re.I):
        arguments = _split_call_arguments(text, match.end() - 1)
        if arguments:
            yield match.group("api").casefold(), arguments[0], match.start()


def _iter_custom_sql_data_writes(text: str) -> Iterable[Tuple[str, Sequence[str]]]:
    for match in re.finditer(r"\$wpdb\s*->\s*(?P<api>insert|update)\s*\(", text, re.I):
        arguments = _split_call_arguments(text, match.end() - 1)
        if len(arguments) >= 2:
            yield match.group("api").casefold(), arguments


def _custom_sql_array_data_values(
    arguments: Sequence[str], table_aliases: Dict[str, Tuple[str, int]], constants: Dict[str, str]
) -> List[Tuple[Tuple[str, str, str], str]]:
    table_value = _custom_table_value(arguments[0], constants, table_aliases)
    if not table_value:
        return []
    data = arguments[1].strip()
    if not (data.lower().startswith("array(") and data.endswith(")")):
        return []
    result = []
    for match in re.finditer(
        r"(['\"])(?P<column>[A-Za-z_][A-Za-z0-9_]*)\1\s*=>\s*(?P<value>[^,)]*)",
        data[6:-1], re.S,
    ):
        result.append((_custom_sql_key(table_value[0], match.group("column")), match.group("value")))
    return result


def _local_zero_arg_helper_source(text: str, name: str) -> TaintInfo | None:
    """Reuse the bounded local source-to-return summary for one helper."""
    analysis = analyze_entrypoints(text)
    definitions = [
        function for function in analysis.get("functions", [])
        if str(function.get("name", "")).casefold() == name.casefold()
    ]
    if len(definitions) != 1 or definitions[0].get("parameters"):
        return None
    scope_state: Dict[str, TaintInfo] = {}
    for statement in _iter_statements(text):
        function_name = str(function_for_line(analysis, statement.end_line).get("name", "")).casefold()
        if function_name != name.casefold():
            continue
        body = FUNCTION_HEADER_RE.sub("", _strip_php_comments(statement.text), count=1)
        assignment = HELPER_ASSIGNMENT_RE.search(body)
        if assignment:
            value_taint = _expression_taint(assignment.group("rhs"), scope_state)
            if value_taint:
                scope_state[assignment.group("lhs")] = TaintInfo(
                    value_taint.origin_kind, value_taint.origin_match,
                    value_taint.sanitizers, "unique_helper_return",
                )
        for returned in RETURN_EXPRESSION_RE.finditer(body):
            value_taint = _expression_taint(returned.group("expression"), scope_state)
            if value_taint:
                return TaintInfo(
                    value_taint.origin_kind, value_taint.origin_match,
                    value_taint.sanitizers, "unique_helper_return",
                )
    return None


def _attachment_exif_metadata_fields(
    source_text: str, definition: Dict[str, Any]
) -> Set[str]:
    """Return literal metadata fields written from EXIF by one bare callback.

    This recognizes only the plugin-local ``wp_read_image_metadata`` callback
    shape used to add a literal EXIF value to the callback's first metadata
    parameter and return that exact parameter.  It is not a general filter,
    metadata, or nested-array model.
    """
    parameters = list(definition.get("parameters", []))
    if not parameters:
        return set()
    metadata_parameter = str(parameters[0]).strip()
    if not re.fullmatch(r"\$[A-Za-z_][A-Za-z0-9_]*", metadata_parameter):
        return set()
    start = int(definition.get("start_line", definition.get("line", 0)))
    end = int(definition.get("end_line", 0))
    if start <= 0 or end < start:
        return set()
    body = "\n".join(source_text.splitlines()[start - 1 : end])
    if not re.search(
        rf"\breturn\s+{re.escape(metadata_parameter)}\s*;",
        body,
        re.IGNORECASE,
    ):
        return set()
    exif_variables = {
        match.group("variable")
        for match in re.finditer(
            r"(?P<variable>\$[A-Za-z_][A-Za-z0-9_]*)\s*=\s*@?\s*"
            r"exif_read_data\s*\(",
            body,
            re.IGNORECASE,
        )
    }
    if not exif_variables:
        return set()
    fields: Set[str] = set()
    for exif_variable in exif_variables:
        assignment = re.compile(
            rf"{re.escape(metadata_parameter)}\s*\[\s*['\"]"
            r"(?P<field>[A-Za-z_][A-Za-z0-9_]*)['\"]\s*\]\s*=\s*"
            rf"{re.escape(exif_variable)}\s*\[\s*['\"]"
            r"[A-Za-z_][A-Za-z0-9_]*['\"]\s*\]",
            re.IGNORECASE,
        )
        fields.update(match.group("field") for match in assignment.finditer(body))
    return fields


def _attachment_exif_metadata_read_taint(
    expression: str,
    metadata_variables: Dict[str, Set[str]],
) -> TaintInfo | None:
    """Return taint for one exact ``image_meta`` field of a tracked read."""
    match = ATTACHMENT_METADATA_FIELD_READ_RE.fullmatch(expression)
    if not match:
        return None
    field = match.group("field")
    if field not in metadata_variables.get(match.group("container"), set()):
        return None
    return TaintInfo(
        origin_kind="external_structured_data",
        origin_match=f"{ATTACHMENT_EXIF_METADATA_DOMAIN}:{field}",
        sanitizers=[],
        flow_evidence="attachment_exif_metadata_filter",
    )


def _attachment_exif_return_accumulator(
    source_text: str, definition: Dict[str, Any]
) -> str:
    """Return one HTML-initialized accumulator accepted by the content chain."""
    start = int(definition.get("start_line", definition.get("line", 0)))
    end = int(definition.get("end_line", 0))
    if start <= 0 or end < start:
        return ""
    body = "\n".join(source_text.splitlines()[start - 1 : end])
    initializers = [
        match.group("lhs")
        for match in HELPER_ASSIGNMENT_RE.finditer(body)
        if match.group("operator") == "="
        and re.search(r"['\"][^'\"]*<[^'\"]*['\"]", match.group("rhs"))
        and match.group("lhs") not in extract_php_variables(match.group("rhs"))
    ]
    if len(initializers) != 1:
        return ""
    accumulator = initializers[0]
    if not re.search(rf"\breturn\s+{re.escape(accumulator)}\s*;", body, re.I):
        return ""
    return accumulator


def _is_attachment_exif_optional_clean_assignment(text: str, variable: str) -> bool:
    """Recognize only an inline conditional normalization of one EXIF value.

    The recognized callback model is otherwise path-insensitive. A clean
    assignment guarded by a literal ``if``/``elseif`` is optional, so the
    prior EXIF value remains feasible. This deliberately does not model
    arbitrary control flow or unconditional overwrites.
    """
    normalized = FUNCTION_HEADER_RE.sub("", text, count=1)
    return bool(
        re.match(
            rf"^\s*(?:<\?(?:php|=)?\s*)?(?:}}\s*)?"
            rf"(?:if|elseif)\s*\([^;{{}}]*\)\s*"
            rf"{re.escape(variable)}\s*=",
            normalized,
            re.IGNORECASE | re.DOTALL,
        )
    )


def _custom_sql_table(query: str, table_aliases: Dict[str, Tuple[str, int]], constants: Dict[str, str]) -> str:
    """Return one canonical table only when one accepted table token is used."""
    candidates: Set[str] = set()
    for variable, (table, _depth) in table_aliases.items():
        if re.search(rf"(?<![A-Za-z0-9_]){re.escape(variable)}(?![A-Za-z0-9_])", query):
            candidates.add(table)
    for name, table in constants.items():
        if re.search(rf"\b{re.escape(name)}\b", query):
            candidates.add(table)
    for match in re.finditer(r"\$wpdb\s*->\s*prefix(?:\s*\.\s*(['\"])?|)([A-Za-z0-9_]+)(?:\1|)", query):
        candidates.add(f"wpdb_prefix:{match.group(2)}")
    return next(iter(candidates)) if len(candidates) == 1 else ""


def _split_custom_sql_values(text: str) -> List[str]:
    """Split a simple VALUES/SET list; nested or dynamic SQL is rejected upstream."""
    values, current, depth, quote, escaped = [], [], 0, "", False
    for char in text:
        if quote:
            current.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in ("'", '\"'):
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth = max(depth - 1, 0)
        if char == "," and depth == 0:
            values.append("".join(current))
            current = []
        else:
            current.append(char)
    values.append("".join(current))
    return values


def _custom_sql_write_values(query: str, table: str) -> List[Tuple[Tuple[str, str, str], str]]:
    """Return exact literal custom-table columns paired with their value text."""
    if not table:
        return []
    normalized = re.sub(r"\s+", " ", query)
    result: List[Tuple[Tuple[str, str, str], str]] = []
    update = re.search(r"\bUPDATE\b.*?\bSET\s+(?P<values>.*?)(?:\bWHERE\b|$)", normalized, re.I)
    insert_set = re.search(r"\bINSERT\s+INTO\b.*?\bSET\s+(?P<values>.*)$", normalized, re.I)
    assignment_text = (update or insert_set).group("values") if (update or insert_set) else ""
    if assignment_text:
        for assignment in _split_custom_sql_values(assignment_text):
            match = re.match(r"\s*`?(?P<column>[A-Za-z_][A-Za-z0-9_]*)`?\s*=\s*(?P<value>.+)$", assignment, re.S)
            if match:
                result.append((_custom_sql_key(table, match.group("column")), match.group("value")))
        return result
    # Positional INSERT (...) VALUES (...) is deliberately excluded. Large
    # legacy event tables caused broad plugin-wide fan-out even with exact
    # columns. Named UPDATE/INSERT SET and wpdb insert/update stay supported.
    return result


def _custom_sql_select_columns(query: str) -> Set[str] | None:
    match = re.search(r"\bSELECT\s+(?P<columns>.*?)\s+\bFROM\b", re.sub(r"\s+", " ", query), re.I | re.S)
    if not match:
        return None
    raw = match.group("columns").strip()
    if raw == "*":
        return {"*"}
    # Preserve only unaliased literal result fields. Aggregate expressions,
    # aliases, and dynamic select terms neither invalidate a safe sibling nor
    # become fields themselves.
    columns = {
        part.strip().strip("`")
        for part in _split_custom_sql_values(raw)
        if CUSTOM_SQL_LITERAL_COLUMN_RE.fullmatch(part.strip().strip("`"))
    }
    return columns or None


def _thin_custom_sql_wrappers(text: str) -> Set[str]:
    """Recognize one unique ARRAY_A wrapper with an optional branch flag."""
    wrappers = set()
    analysis = analyze_entrypoints(text)
    for function in analysis.get("functions", []):
        parameters = list(function.get("parameters", []))
        if not parameters or len(parameters) > 2:
            continue
        name, query_param = str(function.get("name", "")), re.escape(parameters[0])
        start, end = int(function.get("line", 0)), int(function.get("end_line", 0))
        lines = text.splitlines()
        body = "\n".join(lines[max(start - 1, 0):end])
        body = FUNCTION_HEADER_RE.sub("", body, count=1)
        result_match = re.search(
            rf"\$(?P<result>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*\$wpdb\s*->\s*get_results\s*\(\s*{query_param}\s*,\s*['\"]ARRAY_A['\"]\s*\)",
            body, re.I | re.S,
        )
        if not result_match:
            continue
        result = re.escape("$" + result_match.group("result"))
        calls = {call_name for call_name, _args in iter_function_calls(body)}
        if calls - {"get_results", "current", "empty", "if", "elseif"}:
            continue
        returns = re.findall(r"\breturn\s+(.*?);", body, re.I | re.S)
        if not returns or not all(re.fullmatch(rf"\s*(?:current\s*\(\s*{result}\s*\)|{result})\s*", value, re.S) for value in returns):
            continue
        if len(parameters) == 2:
            second = re.escape(parameters[1])
            conditions = re.findall(r"\b(?:if|elseif)\s*\((.*?)\)", body, re.I | re.S)
            if any(not re.fullmatch(rf"\s*!?empty\s*\(\s*{second}\s*", condition, re.S) for condition in conditions):
                continue
        elif re.search(r"\b(?:if|elseif|else)\b", body, re.I):
            continue
        wrappers.add(name.casefold())
    return wrappers


def _thin_option_wrappers(
    text: str, option_constant_keys: Dict[str, str]
) -> Tuple[Dict[str, str], Dict[str, str]]:
    """Recognize exact one-argument setters and zero-argument getters.

    The function body must contain only the one Options API operation (or one
    local assignment followed by its return for a getter).  The caller filters
    the returned names for plugin-wide uniqueness.
    """
    setters: Dict[str, str] = {}
    getters: Dict[str, str] = {}
    lines = text.splitlines()
    for function in analyze_entrypoints(text).get("functions", []):
        name = str(function.get("name", "")).casefold()
        parameters = list(function.get("parameters", []))
        start, end = int(function.get("line", 0)), int(function.get("end_line", 0))
        body = "\n".join(lines[max(start - 1, 0):end])
        body = _strip_php_comments(FUNCTION_HEADER_RE.sub("", body, count=1)).strip()
        if body.endswith("}"):
            body = body[:-1].strip()
        if len(parameters) == 1:
            parameter = re.escape(parameters[0])
            for constant, key in option_constant_keys.items():
                if re.fullmatch(
                    rf"(?:return\s+)?update_option\s*\(\s*{re.escape(constant)}\s*,\s*{parameter}\s*\)\s*;?",
                    body,
                    re.I | re.S,
                ) or re.fullmatch(
                    rf"(?:return\s+)?add_option\s*\(\s*{re.escape(constant)}\s*,\s*{parameter}\s*\)\s*;?",
                    body,
                    re.I | re.S,
                ):
                    setters[name] = key
        elif not parameters:
            for constant, key in option_constant_keys.items():
                direct = rf"return\s+get_option\s*\(\s*{re.escape(constant)}\s*\)\s*;?"
                assigned = (
                    rf"\$(?P<value>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
                    rf"get_option\s*\(\s*{re.escape(constant)}\s*\)\s*;\s*"
                    rf"return\s+\$(?P=value)\s*;?"
                )
                if re.fullmatch(direct, body, re.I | re.S) or re.fullmatch(
                    assigned, body, re.I | re.S
                ):
                    getters[name] = key
    return setters, getters


def _scope_id(analysis: Dict[str, Any], line_no: int) -> str:
    function = function_for_line(analysis, line_no)
    if not function:
        return "<global>"
    return f"{function.get('name', '')}@{function.get('line', line_no)}"


def _shortcode_scopes(
    analysis: Dict[str, Any], extra_callbacks: Set[str] | None = None
) -> Dict[str, List[str]]:
    callbacks = set(extra_callbacks or set()) | {
        str(entry.get("callback", ""))
        for entry in analysis.get("entries", [])
        if entry.get("kind") == "shortcode" and entry.get("callback")
    }
    scopes: Dict[str, List[str]] = {}
    for function in analysis.get("functions", []):
        if function.get("name") in callbacks:
            scope = f"{function.get('name', '')}@{function.get('line', '')}"
            scopes[scope] = list(function.get("parameters", []))[:2]
    return scopes


def _context_for(text: str) -> str:
    lower = text.lower()
    if "wp_add_inline_script" in lower or "<script" in lower or EVENT_ATTRIBUTE_RE.search(text):
        return "javascript"
    if URL_ATTRIBUTE_RE.search(text):
        return "url_attribute"
    if "<textarea" in lower:
        return "textarea"
    if ATTRIBUTE_RE.search(text):
        return "html_attribute"
    return "html"


def _expression_has_taint(
    expression: str,
    tainted_variables: Iterable[str],
    wildcard_used: bool = False,
) -> bool:
    if detect_sources(expression):
        return True
    variables = set(extract_php_variables(expression))
    tainted = set(tainted_variables)
    tainted_containers = {
        variable
        for variable in variables
        if any(
            reference == variable
            or reference.startswith(f"{variable}[")
            or reference.startswith(f"{variable}->")
            for reference in tainted
        )
    }
    return bool(tainted_containers) or (wildcard_used and bool(variables))


def _iter_return_expressions(code_text: str) -> Iterator[str]:
    """Yield return values without treating semicolons in strings as terminators."""
    index, length = 0, len(code_text)
    quote, escaped = "", False
    while index < length:
        char = code_text[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            index += 1
            continue
        if char in {"'", '"'}:
            quote = char
            index += 1
            continue
        token = code_text[index : index + 6]
        before = code_text[index - 1] if index else ""
        after = code_text[index + 6] if index + 6 < length else ""
        if (
            token.casefold() == "return"
            and not (before.isalnum() or before == "_")
            and not (after.isalnum() or after == "_")
        ):
            start = index + 6
            cursor, nested_quote, nested_escaped = start, "", False
            paren_depth = bracket_depth = brace_depth = 0
            while cursor < length:
                current = code_text[cursor]
                if nested_quote:
                    if nested_escaped:
                        nested_escaped = False
                    elif current == "\\":
                        nested_escaped = True
                    elif current == nested_quote:
                        nested_quote = ""
                elif current in {"'", '"'}:
                    nested_quote = current
                elif current == "(":
                    paren_depth += 1
                elif current == ")" and paren_depth:
                    paren_depth -= 1
                elif current == "[":
                    bracket_depth += 1
                elif current == "]" and bracket_depth:
                    bracket_depth -= 1
                elif current == "{":
                    brace_depth += 1
                elif current == "}" and brace_depth:
                    brace_depth -= 1
                elif (
                    current == ";"
                    and not paren_depth
                    and not bracket_depth
                    and not brace_depth
                ):
                    expression = code_text[start:cursor].strip()
                    if expression:
                        yield expression
                    index = cursor + 1
                    break
                cursor += 1
            else:
                return
            continue
        index += 1


def _terminal_output_has_taint(
    code_text: str,
    tainted_variables: Iterable[str],
    wildcard_used: bool = False,
) -> bool:
    for name in ("die", "exit", "wp_die"):
        for _called, arguments in iter_named_function_calls(code_text, {name}):
            if arguments and _expression_has_taint(
                arguments[0], tainted_variables, wildcard_used
            ):
                return True
    return False


def _sink_for_statement(
    statement: Statement,
    code_text: str,
    analysis: Dict[str, Any],
    shortcode_callbacks: Set[str],
    context: str,
    helper_return_variables: Set[str] | None = None,
    helper_result_is_output: bool = False,
    same_instance_helper_return_variables: Set[str] | None = None,
    attachment_exif_return_accumulators: Set[str] | None = None,
    tainted_variables: Iterable[str] = (),
    wildcard_used: bool = False,
) -> Tuple[List[Tuple[str, str]], str, str]:
    sink_hits = detect_sinks(code_text)
    terminal_patterns = {
        r"\b(?:die|exit)\s*\(",
        r"\bwp_die\s*\(",
    }
    if not _terminal_output_has_taint(code_text, tainted_variables, wildcard_used):
        sink_hits = [hit for hit in sink_hits if hit[1] not in terminal_patterns]
    function_name = str(function_for_line(analysis, statement.end_line).get("name", ""))
    is_shortcode_html_build = (
        function_name in shortcode_callbacks and bool(HTML_BUILD_RE.search(code_text))
    )
    shortcode_return_expression = next(
        (
            expression
            for expression in _iter_return_expressions(code_text)
            if _expression_has_taint(expression, tainted_variables, wildcard_used)
        ),
        None,
    )
    is_shortcode_return = bool(
        function_name in shortcode_callbacks and shortcode_return_expression
    )
    if is_shortcode_return:
        sink_hits.append(("shortcode_return", RETURN_RE.pattern))
    elif is_shortcode_html_build:
        sink_hits.append(("shortcode_return", HTML_BUILD_RE.pattern))

    assignment = ASSIGNMENT_RE.search(code_text)
    is_returned_helper_html_build = bool(
        assignment
        and assignment.group("lhs") in set(helper_return_variables or set())
        and HTML_BUILD_RE.search(code_text)
    )
    if is_returned_helper_html_build:
        sink_hits.append(("helper_return", HTML_BUILD_RE.pattern))
    is_output_consumed_helper_html_return = bool(
        helper_result_is_output and HTML_RETURN_RE.search(code_text)
    )
    if is_output_consumed_helper_html_return:
        sink_hits.append(("helper_return", RETURN_RE.pattern))
    same_instance_return_variables = set(same_instance_helper_return_variables or set())
    is_same_instance_helper_html_return = bool(
        same_instance_return_variables
        and HTML_RETURN_RE.search(code_text)
        and any(variable in extract_php_variables(code_text) for variable in same_instance_return_variables)
    )
    if is_same_instance_helper_html_return:
        sink_hits.append(("helper_return", RETURN_RE.pattern))
    is_attachment_exif_return_accumulator = bool(
        assignment
        and assignment.group("lhs") in set(attachment_exif_return_accumulators or set())
        and any(
            variable != assignment.group("lhs")
            for variable in extract_php_variables(assignment.group("rhs"))
        )
    )
    if is_attachment_exif_return_accumulator:
        sink_hits.append(("html_output", "attachment_exif_return_accumulator"))

    if not sink_hits:
        return [], "", ""

    preferred_kind = ""
    if is_same_instance_helper_html_return:
        # This synthetic sink is admitted only for the bounded method-return
        # model.  Prefer it over contextual pattern matches on the same
        # literal HTML return so the finding does not look like generic output.
        preferred_kind = "helper_return"
    elif is_attachment_exif_return_accumulator:
        preferred_kind = "html_output"
    elif context == "javascript":
        preferred_kind = "js_context"
    elif context in {"url_attribute", "html_attribute"}:
        preferred_kind = "dom_attr_like"
    elif function_name in shortcode_callbacks and (
        is_shortcode_return or is_shortcode_html_build
    ):
        preferred_kind = "shortcode_return"
    elif is_returned_helper_html_build:
        preferred_kind = "helper_return"
    elif is_output_consumed_helper_html_return:
        preferred_kind = "helper_return"

    selected = next((hit for hit in sink_hits if hit[0] == preferred_kind), sink_hits[0])
    return sink_hits, selected[0], selected[1]


def _finding_line(statement: Statement, pattern: str, search_text: str = "") -> int:
    if not pattern:
        return statement.start_line
    target = search_text or statement.text
    match = re.search(pattern, target, re.IGNORECASE)
    if not match:
        return statement.start_line
    return statement.start_line + target[: match.start()].count("\n")


def _dedupe_hits(hits: Sequence[Tuple[str, str]]) -> List[Tuple[str, str]]:
    return list(dict.fromkeys(hits))


def _update_parse_extract_state(
    code_text: str,
    scope_state: Dict[str, TaintInfo],
    wildcard_scopes: Set[str],
    scope: str,
) -> None:
    names = {"parse_str", "wp_parse_str", "extract"}
    for name, arguments in iter_named_function_calls(code_text, names):
        if not arguments:
            continue
        input_text = arguments[0]
        input_vars = extract_php_variables(input_text)
        input_sources = detect_sources(input_text)
        tainted_inputs = [variable for variable in input_vars if variable in scope_state]
        input_tainted = bool(input_sources) or bool(tainted_inputs)
        if not input_tainted:
            continue

        if name in {"parse_str", "wp_parse_str"} and len(arguments) >= 2:
            targets = extract_php_variables(arguments[1])
            if targets:
                scope_state[targets[0]] = TaintInfo(
                    origin_kind="parse_str_scope",
                    origin_match=name,
                    sanitizers=[],
                )
                continue
        if name == "extract":
            literal_keys = {
                match.group("key") for match in LITERAL_ARRAY_KEY_RE.finditer(input_text)
            }
            if literal_keys:
                if input_sources:
                    origin_kind, origin_match = input_sources[0]
                elif tainted_inputs:
                    origin = scope_state[tainted_inputs[0]]
                    origin_kind, origin_match = origin.origin_kind, origin.origin_match
                else:  # pragma: no cover - guarded by input_tainted
                    origin_kind, origin_match = "parse_str_scope", name
                for key in literal_keys:
                    scope_state[f"${key}"] = TaintInfo(
                        origin_kind=origin_kind,
                        origin_match=origin_match,
                        sanitizers=[],
                    )
                continue
        wildcard_scopes.add(scope)


def _expression_taint(
    expression: str,
    scope_state: Dict[str, TaintInfo],
    wildcard_used: bool = False,
) -> TaintInfo | None:
    """Resolve taint for one positional argument without widening call targets."""
    sources = detect_sources(expression)
    if sources:
        origin_kind, origin_match = sources[0]
        return TaintInfo(
            origin_kind=origin_kind,
            origin_match=origin_match,
            sanitizers=detect_sanitizers(expression),
            flow_evidence="unique_helper_argument",
        )

    references = _tainted_references(expression, scope_state)
    if references:
        origin = scope_state[references[0]]
        return TaintInfo(
            origin_kind=origin.origin_kind,
            origin_match=origin.origin_match,
            sanitizers=_dedupe_hits(
                [*origin.sanitizers, *detect_sanitizers(expression)]
            ),
            flow_evidence="unique_helper_argument",
        )

    if wildcard_used and extract_php_variables(expression):
        return TaintInfo(
            origin_kind="parse_str_scope",
            origin_match="scope-created variable",
            sanitizers=detect_sanitizers(expression),
            flow_evidence="unique_helper_argument",
        )
    return None


def _literal_class_constants(source_text: str) -> List[Tuple[str, str]]:
    """Return non-inherited ``Class::CONST`` literal keys from one plugin file."""
    headers = list(CLASS_HEADER_RE.finditer(source_text))
    constants: List[Tuple[str, str]] = []
    for index, header in enumerate(headers):
        if re.search(r"\bextends\b", header.group("header"), re.IGNORECASE):
            continue
        end = headers[index + 1].start() if index + 1 < len(headers) else len(source_text)
        class_name = header.group("class").casefold()
        for constant in CLASS_LITERAL_CONST_RE.finditer(source_text, header.end(), end):
            if "}" in source_text[header.end() : constant.start()]:
                continue
            constants.append(
                (f"{class_name}::{constant.group('name').casefold()}", constant.group("key"))
            )
    return constants


def _literal_rest_post_object_callback(
    namespace: str, route: str, options: str
) -> str:
    """Return a bare object callback for one closed POST route options array."""
    normalized = options.strip()
    if not (
        STATIC_REST_ROUTE_EXPRESSION_RE.fullmatch(namespace)
        and _static_key(route)
        and normalized.startswith("array(")
        and normalized.endswith(")")
        and not REST_PERMISSION_CALLBACK_RE.search(normalized)
    ):
        return ""
    methods = REST_POST_METHOD_RE.findall(normalized)
    callbacks = list(REST_OBJECT_CALLBACK_RE.finditer(normalized))
    if len(methods) != 1 or len(callbacks) != 1:
        return ""
    return callbacks[0].group("method").casefold()


SANITIZER_FUNCTIONS = {
    "sanitize_text_field",
    "sanitize_key",
    "sanitize_email",
    "sanitize_file_name",
    "absint",
    "intval",
    "floatval",
    "boolval",
    "wp_kses",
    "wp_kses_post",
    "esc_html",
    "wp_specialchars",
    "_wp_specialchars",
    "esc_attr",
    "attribute_escape",
    "esc_url",
    "clean_url",
    "esc_js",
    "js_escape",
    "esc_textarea",
}


def _sanitizers_for_tainted_variables(
    text: str, tainted_variables: Sequence[str]
) -> List[Tuple[str, str]]:
    """Return only sanitizer calls whose first argument uses tainted data."""
    tainted = set(tainted_variables)
    hits: List[Tuple[str, str]] = []
    for name, arguments in iter_named_function_calls(text, SANITIZER_FUNCTIONS):
        if not arguments:
            continue
        if tainted.intersection(extract_php_variables(arguments[0])):
            hits.extend(detect_sanitizers(f"{name}("))
    return _dedupe_hits(hits)


def _is_unset_default_assignment(text: str, variable: str) -> bool:
    """Return True for ``if (!isset($var)) $var = <default>`` statements.

    When ``variable`` already carries taint, this branch cannot be assumed to
    execute and overwrite it.  The path-insensitive state therefore retains
    the incoming value at the join.
    """
    normalized = FUNCTION_HEADER_RE.sub("", text, count=1)
    pattern = re.compile(
        rf"^\s*(?:<\?(?:php|=)?\s*)?if\s*\(\s*!\s*isset\s*\(\s*"
        rf"{re.escape(variable)}\s*\)\s*\)",
        re.IGNORECASE | re.DOTALL,
    )
    return bool(pattern.search(normalized))


def _direct_helper_return_taint(
    definition: Dict[str, Any],
) -> TaintInfo | None:
    """Return direct source taint from a uniquely resolved helper return."""
    helper_path = Path(definition["path"])
    helper_name = str(definition.get("name", "")).casefold()
    text = safe_read_text(helper_path)
    analysis = analyze_entrypoints(text, helper_path)
    for statement in _iter_statements(text):
        function_name = str(
            function_for_line(analysis, statement.end_line).get("name", "")
        ).casefold()
        if function_name != helper_name:
            continue
        code_text = _strip_php_comments(statement.text)
        for match in RETURN_EXPRESSION_RE.finditer(code_text):
            expression = match.group("expression")
            sources = detect_sources(expression)
            if not sources:
                continue
            origin_kind, origin_match = sources[0]
            return TaintInfo(
                origin_kind=origin_kind,
                origin_match=origin_match,
                sanitizers=detect_sanitizers(expression),
                flow_evidence="unique_helper_return",
            )
    return None


def _local_source_helper_return_taint(
    definition: Dict[str, Any],
) -> TaintInfo | None:
    """Summarize only a parameterless helper's local source-to-return flow."""
    if definition.get("parameters"):
        return None

    helper_path = Path(definition["path"])
    helper_name = str(definition.get("name", "")).casefold()
    text = safe_read_text(helper_path)
    analysis = analyze_entrypoints(text, helper_path)
    scope_state: Dict[str, TaintInfo] = {}

    for statement in _iter_statements(text):
        function_name = str(
            function_for_line(analysis, statement.end_line).get("name", "")
        ).casefold()
        if function_name != helper_name:
            continue
        code_text = _strip_php_comments(statement.text)
        body_text = FUNCTION_HEADER_RE.sub("", code_text, count=1)

        for foreach_match in FOREACH_VALUE_RE.finditer(code_text):
            iterable = foreach_match.group("iterable")
            sources = detect_sources(iterable)
            references = _tainted_references(iterable, scope_state)
            if sources:
                origin_kind, origin_match = sources[0]
                origin_sanitizers = detect_sanitizers(iterable)
            elif references:
                origin = scope_state[references[0]]
                origin_kind, origin_match = origin.origin_kind, origin.origin_match
                origin_sanitizers = origin.sanitizers
            else:
                continue
            scope_state[foreach_match.group("value")] = TaintInfo(
                origin_kind=origin_kind,
                origin_match=origin_match,
                sanitizers=origin_sanitizers,
            )

        assignment = HELPER_ASSIGNMENT_RE.search(body_text)
        if assignment:
            lhs = assignment.group("lhs")
            rhs = assignment.group("rhs")
            sources = detect_sources(rhs)
            references = _tainted_references(rhs, scope_state)
            if sources:
                origin_kind, origin_match = sources[0]
                sanitizers = detect_sanitizers(rhs)
            elif references:
                origin = scope_state[references[0]]
                origin_kind, origin_match = origin.origin_kind, origin.origin_match
                sanitizers = _dedupe_hits(
                    [*origin.sanitizers, *detect_sanitizers(rhs)]
                )
            else:
                if assignment.group("operator") == "=":
                    scope_state.pop(lhs, None)
                continue
            scope_state[lhs] = TaintInfo(
                origin_kind=origin_kind,
                origin_match=origin_match,
                sanitizers=sanitizers,
            )

        for return_match in RETURN_EXPRESSION_RE.finditer(body_text):
            expression = return_match.group("expression")
            sources = detect_sources(expression)
            references = _tainted_references(expression, scope_state)
            if sources:
                origin_kind, origin_match = sources[0]
                sanitizers = detect_sanitizers(expression)
            elif references:
                origin = scope_state[references[0]]
                origin_kind, origin_match = origin.origin_kind, origin.origin_match
                sanitizers = _dedupe_hits(
                    [*origin.sanitizers, *detect_sanitizers(expression)]
                )
            else:
                continue
            return TaintInfo(
                origin_kind=origin_kind,
                origin_match=origin_match,
                sanitizers=sanitizers,
                flow_evidence="unique_helper_return",
            )
    return None


def _same_instance_local_source_return_taint(
    definition: Dict[str, Any],
) -> TaintInfo | None:
    """Summarize a direct local source-to-return method within one class only."""
    helper_path = Path(definition["path"])
    helper_name = str(definition.get("name", "")).casefold()
    helper_class = str(definition.get("class_name", "")).casefold()
    if not helper_name or not helper_class:
        return None
    text = safe_read_text(helper_path)
    analysis = analyze_entrypoints(text, helper_path)
    scope_state: Dict[str, TaintInfo] = {}
    parameters = set(definition.get("parameters", []))

    for statement in _iter_statements(text):
        function = function_for_line(analysis, statement.end_line)
        if (
            str(function.get("name", "")).casefold() != helper_name
            or str(function.get("class_name", "")).casefold() != helper_class
            or int(function.get("line", 0)) != int(definition.get("line", 0))
        ):
            continue
        code_text = _strip_php_comments(statement.text)
        body_text = FUNCTION_HEADER_RE.sub("", code_text, count=1)
        assignment = HELPER_ASSIGNMENT_RE.search(body_text)
        if assignment:
            lhs, rhs = assignment.group("lhs"), assignment.group("rhs")
            sources = detect_sources(rhs)
            references = _tainted_references(rhs, scope_state)
            if sources:
                origin_kind, origin_match = sources[0]
                scope_state[lhs] = TaintInfo(origin_kind, origin_match, detect_sanitizers(rhs))
            elif references:
                origin = scope_state[references[0]]
                scope_state[lhs] = TaintInfo(
                    origin.origin_kind,
                    origin.origin_match,
                    _dedupe_hits([*origin.sanitizers, *detect_sanitizers(rhs)]),
                )
            elif assignment.group("operator") == "=":
                scope_state.pop(lhs, None)

        for return_match in RETURN_EXPRESSION_RE.finditer(body_text):
            expression = return_match.group("expression")
            # The source must reach a local return value.  Parameters and
            # properties are intentionally excluded from this summary.
            if "$this->" in expression or parameters & set(extract_php_variables(expression)):
                continue
            sources = detect_sources(expression)
            references = _tainted_references(expression, scope_state)
            if sources:
                origin_kind, origin_match = sources[0]
                sanitizers = detect_sanitizers(expression)
            elif references:
                origin = scope_state[references[0]]
                origin_kind, origin_match = origin.origin_kind, origin.origin_match
                sanitizers = _dedupe_hits([*origin.sanitizers, *detect_sanitizers(expression)])
            else:
                continue
            return TaintInfo(
                origin_kind=origin_kind,
                origin_match=origin_match,
                sanitizers=sanitizers,
                flow_evidence="same_instance_helper_return",
            )
    return None


def _output_consumed_no_argument_helper_assignment(
    code_text: str,
) -> re.Match[str] | None:
    """Find a no-argument helper assignment whose value is output here."""
    for match in NO_ARGUMENT_HELPER_ASSIGNMENT_RE.finditer(code_text):
        output_text = code_text[match.end() :]
        if (
            match.group("lhs") in extract_php_variables(output_text)
            and detect_sinks(output_text)
        ):
            return match
    return None


def analyze_php_file(
    path: Path,
    shortcode_callbacks: Set[str] | None = None,
    tainted_storage_keys: Set[Tuple[str, str, str]] | None = None,
    registered_callbacks: Set[str] | None = None,
    unique_function_definitions: Dict[str, Dict[str, Any]] | None = None,
    _discovered_storage_keys: Set[Tuple[str, str, str]] | None = None,
    _emit_findings: bool = True,
    _inherited_scope_taint: Dict[str, TaintInfo] | None = None,
    _include_stack: Set[Path] | None = None,
    _loaded_include_targets: Set[Path] | None = None,
    _target_function: str = "",
    _seeded_function_taint: Dict[str, TaintInfo] | None = None,
    _helper_depth: int = 0,
    _helper_stack: Set[Tuple[Path, str]] | None = None,
    _inherited_entrypoint_meta: Dict[str, Any] | None = None,
    _helper_result_is_output: bool = False,
    _custom_unique_zero_arg_helpers: Set[str] | None = None,
    _custom_zero_arg_helper_summaries: Dict[str, TaintInfo] | None = None,
    _option_constant_keys: Dict[str, str] | None = None,
    _option_setter_keys: Dict[str, str] | None = None,
    _option_getter_keys: Dict[str, str] | None = None,
    _rest_post_object_callbacks: Set[Tuple[str, str]] | None = None,
    _post_meta_class_constant_keys: Dict[str, str] | None = None,
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    resolved_path = path.resolve()
    include_stack = set(_include_stack or set())
    if resolved_path in include_stack:
        return findings
    include_stack.add(resolved_path)
    loaded_include_targets = (
        _loaded_include_targets if _loaded_include_targets is not None else set()
    )
    text = safe_read_text(path)
    lines = text.splitlines()
    entrypoint_analysis = analyze_entrypoints(text, path)
    statements = list(_iter_statements(text))

    shortcode_callbacks = set(shortcode_callbacks or set()) | {
        str(entry.get("callback", ""))
        for entry in entrypoint_analysis.get("entries", [])
        if entry.get("kind") == "shortcode" and entry.get("callback")
    }
    registered_callbacks = {
        callback.casefold() for callback in (registered_callbacks or set())
    }
    unique_function_definitions = unique_function_definitions or {}
    helper_stack = set(_helper_stack or set())
    taint_by_scope: Dict[str, Dict[str, TaintInfo]] = {}
    if _inherited_scope_taint:
        taint_by_scope["<global>"] = _literal_include_scope_taint(
            _inherited_scope_taint
        )
    wildcard_scopes: Set[str] = set()
    literal_keys_by_scope: Dict[str, Dict[str, Set[str]]] = {}
    custom_table_aliases_by_scope: Dict[str, Dict[str, Tuple[str, int]]] = {}
    custom_sql_aliases_by_scope: Dict[str, Dict[str, str]] = {}
    custom_result_fields_by_scope: Dict[str, Dict[str, Set[Tuple[str, str, str]]]] = {}
    custom_zero_arg_helper_values: Dict[str, Dict[str, TaintInfo]] = {}
    storage_array_fields_by_scope: Dict[str, Dict[str, Set[str]]] = {}
    attachment_metadata_variables_by_scope: Dict[str, Dict[str, Set[str]]] = {}
    plugin_tainted_storage = set(tainted_storage_keys or set())
    option_constant_keys = {
        key[1]: key[2]
        for key in plugin_tainted_storage
        if key[0] == OPTION_CONSTANT_DOMAIN
    }
    option_setter_keys = {
        key[1]: key[2]
        for key in plugin_tainted_storage
        if key[0] == OPTION_SETTER_DOMAIN
    }
    option_getter_keys = {
        key[1]: key[2]
        for key in plugin_tainted_storage
        if key[0] == OPTION_GETTER_DOMAIN
    }
    same_instance_output_methods = {
        key[1]
        for key in plugin_tainted_storage
        if key[0] == SAME_INSTANCE_OUTPUT_METHOD_DOMAIN
    }
    attachment_exif_metadata_fields = {
        key[2]
        for key in plugin_tainted_storage
        if key[0] == ATTACHMENT_EXIF_METADATA_DOMAIN
    }
    attachment_exif_output_accumulators = {
        key[1]: key[2]
        for key in plugin_tainted_storage
        if key[0] == ATTACHMENT_EXIF_OUTPUT_CALLBACK_DOMAIN and key[2]
    }
    rest_post_object_callbacks = {
        (key[1], key[2])
        for key in plugin_tainted_storage
        if key[0] == REST_POST_OBJECT_CALLBACK_DOMAIN and key[1] and key[2]
    }
    post_meta_class_constant_keys = {
        key[1]: key[2]
        for key in plugin_tainted_storage
        if key[0] == POST_META_CLASS_CONSTANT_DOMAIN and key[1] and key[2]
    }
    if _option_constant_keys is not None:
        option_constant_keys = dict(_option_constant_keys)
    if _option_setter_keys is not None:
        option_setter_keys = dict(_option_setter_keys)
    if _option_getter_keys is not None:
        option_getter_keys = dict(_option_getter_keys)
    if _rest_post_object_callbacks is not None:
        rest_post_object_callbacks = set(_rest_post_object_callbacks)
    if _post_meta_class_constant_keys is not None:
        post_meta_class_constant_keys = dict(_post_meta_class_constant_keys)
    custom_constants = {
        match.group("name"): f"wpdb_prefix:{match.group('suffix')}"
        for match in CUSTOM_TABLE_DEFINE_RE.finditer(text)
    }
    custom_constants.update(
        {key[1]: key[2] for key in plugin_tainted_storage if key[0] == CUSTOM_SQL_CONSTANT_DOMAIN}
    )
    local_tainted_storage: Set[Tuple[str, str]] = set()
    # When a plugin index is supplied, only its plugin-wide unique names are
    # eligible.  Falling back to local recognition is retained solely for
    # direct single-file callers that do not use the storage prepass.
    custom_wrapper_names = {
        key[1] for key in plugin_tainted_storage
        if key[0] == CUSTOM_SQL_WRAPPER_DOMAIN
    }
    if tainted_storage_keys is None:
        custom_wrapper_names |= _thin_custom_sql_wrappers(text)
    custom_unique_helper_names = {
        key[1] for key in plugin_tainted_storage
        if key[0] == CUSTOM_SQL_HELPER_DOMAIN
    }
    custom_helper_summaries: Dict[str, TaintInfo] = {}
    for key in plugin_tainted_storage:
        if key[0] != CUSTOM_SQL_HELPER_DOMAIN or "\x1f" not in key[2]:
            continue
        origin_kind, origin_match = key[2].split("\x1f", 1)
        custom_helper_summaries[key[1]] = TaintInfo(
            origin_kind, origin_match, [], "unique_helper_return"
        )
    if _custom_unique_zero_arg_helpers is not None:
        custom_unique_helper_names = set(_custom_unique_zero_arg_helpers)
    if _custom_zero_arg_helper_summaries is not None:
        custom_helper_summaries = dict(_custom_zero_arg_helper_summaries)
    custom_registered_roots = {
        str(entry.get("callback", "")).casefold()
        for entry in entrypoint_analysis.get("entries", [])
        if entry.get("callback")
    } | registered_callbacks
    custom_registered_roots.update(
        match.group("callback").casefold()
        for match in re.finditer(
            r"\badd_(?:action|filter)\s*\(\s*['\"][^'\"]+['\"]\s*,\s*['\"](?P<callback>[A-Za-z_][A-Za-z0-9_]*)['\"]",
            text,
            re.I,
        )
    )
    tainted_top_level_option_globals = _tainted_top_level_option_globals(
        plugin_tainted_storage
    )

    for scope, parameters in _shortcode_scopes(
        entrypoint_analysis, shortcode_callbacks
    ).items():
        scope_state = taint_by_scope.setdefault(scope, {})
        for parameter in parameters:
            scope_state[parameter] = TaintInfo(
                origin_kind="shortcode_attrs",
                origin_match=parameter,
                sanitizers=[],
            )

    if _target_function:
        target = next(
            (
                function
                for function in entrypoint_analysis.get("functions", [])
                if str(function.get("name", "")).casefold() == _target_function
            ),
            None,
        )
        if target is None:
            return findings
        target_scope = f"{target.get('name', '')}@{target.get('line', '')}"
        taint_by_scope.setdefault(target_scope, {}).update(
            _seeded_function_taint or {}
        )

    helper_return_variables: Set[str] = set()
    same_instance_helper_return_variables: Dict[str, Set[str]] = {}
    if _target_function and _helper_result_is_output:
        for target_statement in statements:
            target_name = str(
                function_for_line(
                    entrypoint_analysis, target_statement.end_line
                ).get("name", "")
            ).casefold()
            if target_name != _target_function:
                continue
            target_code = _strip_php_comments(target_statement.text)
            helper_return_variables.update(
                match.group("variable")
                for match in RETURN_VARIABLE_RE.finditer(target_code)
            )

    for statement_index, statement in enumerate(statements):
        code_text = _strip_php_comments(statement.text)
        same_instance_assignment_lhs = ""
        current_function = function_for_line(entrypoint_analysis, statement.end_line)
        current_function_name = str(current_function.get("name", "")).casefold()
        current_class_name = str(current_function.get("class_name", "")).casefold()
        if _target_function and current_function_name != _target_function:
            continue
        scope = _scope_id(entrypoint_analysis, statement.end_line)
        scope_state = taint_by_scope.setdefault(scope, {})
        key_aliases = literal_keys_by_scope.setdefault(scope, {})
        custom_table_aliases = custom_table_aliases_by_scope.setdefault(scope, {})
        custom_sql_aliases = custom_sql_aliases_by_scope.setdefault(scope, {})
        custom_result_fields = custom_result_fields_by_scope.setdefault(scope, {})
        custom_helper_values = custom_zero_arg_helper_values.setdefault(scope, {})
        storage_array_fields = storage_array_fields_by_scope.setdefault(scope, {})
        attachment_metadata_variables = attachment_metadata_variables_by_scope.setdefault(
            scope, {}
        )
        attachment_html_accumulators = (
            {attachment_exif_output_accumulators[current_function_name]}
            if current_function_name in attachment_exif_output_accumulators
            else set()
        )
        if (current_class_name, current_function_name) in rest_post_object_callbacks:
            parameters = list(current_function.get("parameters", []))
            if parameters:
                scope_state.setdefault(
                    str(parameters[0]),
                    TaintInfo(
                        origin_kind="rest_request",
                        origin_match="literal POST object callback",
                        sanitizers=[],
                        flow_evidence="rest_post_request",
                    ),
                )
        if current_function_name in custom_registered_roots:
            for declaration in GLOBAL_DECLARATION_RE.finditer(code_text):
                for global_name in extract_php_variables(declaration.group("variables")):
                    for field, info in tainted_top_level_option_globals.get(
                        global_name, {}
                    ).items():
                        scope_state[_array_taint_key(global_name, field)] = info
        define_match = CUSTOM_TABLE_DEFINE_RE.search(code_text)
        if define_match:
            custom_constants[define_match.group("name")] = (
                f"wpdb_prefix:{define_match.group('suffix')}"
            )
        custom_code_text = re.sub(r"^\s*<\?(?:php|=)?\s*", "", code_text, flags=re.I)
        custom_code_text = FUNCTION_HEADER_RE.sub("", custom_code_text, count=1)
        simple_assignment = CUSTOM_SQL_ASSIGNMENT_RE.match(custom_code_text.rstrip(";"))
        if simple_assignment:
            custom_lhs, custom_rhs = simple_assignment.group("lhs"), simple_assignment.group("rhs")
            table_value = _custom_table_value(custom_rhs, custom_constants, custom_table_aliases)
            if table_value and table_value[1] == 0:
                # Direct/constant expressions have depth 0; one variable
                # binding is allowed and an alias-of-alias is rejected.
                custom_table_aliases[custom_lhs] = (table_value[0], table_value[1] + 1)
            else:
                custom_table_aliases.pop(custom_lhs, None)
            flattened_sql = _flatten_php_concat(custom_rhs)
            if flattened_sql and re.search(r"\b(?:INSERT|UPDATE|SELECT)\b", flattened_sql, re.I):
                custom_sql_aliases[custom_lhs] = flattened_sql
            else:
                custom_sql_aliases.pop(custom_lhs, None)
            helper_call = re.fullmatch(r"\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(\s*\)\s*", custom_rhs)
            if (
                helper_call
                and current_function_name in custom_registered_roots
                and helper_call.group("name").casefold() in custom_unique_helper_names
            ):
                helper_taint = (
                    custom_helper_summaries.get(helper_call.group("name").casefold())
                    or _local_zero_arg_helper_source(text, helper_call.group("name"))
                )
                if helper_taint:
                    custom_helper_values[custom_lhs] = helper_taint
            else:
                # Preserve an already summarized helper value through a local
                # fixed transformation such as esc_sql($value). This state is
                # consumed only by exact custom-SQL write values and never
                # becomes a general output source.
                helper_references = _tainted_references(
                    custom_rhs, custom_helper_values
                )
                propagated_helper = (
                    _expression_taint(custom_rhs, custom_helper_values)
                    if helper_references
                    else None
                )
                if propagated_helper:
                    custom_helper_values[custom_lhs] = TaintInfo(
                        propagated_helper.origin_kind,
                        propagated_helper.origin_match,
                        propagated_helper.sanitizers,
                        "unique_helper_return",
                    )
                else:
                    custom_helper_values.pop(custom_lhs, None)
        is_registered_root = (
            _helper_depth == 0
            and current_function_name
            and current_function_name in registered_callbacks
        )
        if is_registered_root:
            helper_assignment = _output_consumed_no_argument_helper_assignment(
                code_text
            )
            if helper_assignment:
                helper_definition = unique_function_definitions.get(
                    helper_assignment.group("name").casefold()
                )
                if helper_definition:
                    helper_return_taint = _local_source_helper_return_taint(
                        helper_definition
                    )
                    if helper_return_taint:
                        scope_state[helper_assignment.group("lhs")] = (
                            helper_return_taint
                        )
        # This is intentionally separate from generic helper summaries. It
        # accepts only $this->fixedMethod(...) in a class method whose own
        # fixed name has a direct object-method output use in this plugin.
        if current_class_name and current_function_name in same_instance_output_methods:
            assignment = HELPER_ASSIGNMENT_RE.search(
                FUNCTION_HEADER_RE.sub("", code_text, count=1)
            )
            if assignment:
                helper_match = SAME_INSTANCE_HELPER_RHS_RE.fullmatch(assignment.group("rhs"))
                if helper_match:
                    helper_name = helper_match.group("name").casefold()
                    same_class_definitions = [
                        function
                        for function in entrypoint_analysis.get("functions", [])
                        if str(function.get("name", "")).casefold() == helper_name
                        and str(function.get("class_name", "")).casefold() == current_class_name
                    ]
                    if len(same_class_definitions) == 1:
                        definition = dict(same_class_definitions[0])
                        definition["path"] = path.resolve()
                        helper_return_taint = _same_instance_local_source_return_taint(definition)
                        if helper_return_taint:
                            same_instance_assignment_lhs = assignment.group("lhs")
                            scope_state[assignment.group("lhs")] = helper_return_taint
                            same_instance_helper_return_variables.setdefault(scope, set()).add(
                                assignment.group("lhs")
                            )
        for foreach_match in FOREACH_VALUE_RE.finditer(code_text):
            container = foreach_match.group("container")
            iterable = foreach_match.group("iterable")
            container_keys = key_aliases.get(container, set())
            if (
                iterable == container
                and container_keys
                and foreach_match.group("key")
            ):
                key_aliases[foreach_match.group("key")] = set(container_keys)
            iterable_sources = detect_sources(iterable)
            tainted_iterable = _tainted_references(iterable, scope_state)
            element_taint = [
                (key, scope_state[key])
                for key in tainted_iterable
            ]
            if iterable_sources:
                source_kind, source_match = iterable_sources[0]
                element_taint.insert(
                    0,
                    (
                        iterable,
                        TaintInfo(
                            origin_kind=source_kind,
                            origin_match=source_match,
                            sanitizers=detect_sanitizers(iterable),
                        ),
                    ),
                )
            if element_taint:
                origin = element_taint[0][1]
                scope_state[foreach_match.group("value")] = TaintInfo(
                    origin_kind=origin.origin_kind,
                    origin_match=origin.origin_match,
                    sanitizers=_dedupe_hits(
                        sanitizer
                        for _key, info in element_taint
                        for sanitizer in info.sanitizers
                    ),
                    flow_evidence=origin.flow_evidence,
                )
            custom_fields = custom_result_fields.get(iterable, set())
            if custom_fields and iterable == container:
                row = foreach_match.group("value")
                for _domain, _table, column in custom_fields:
                    info = TaintInfo(
                        origin_kind="plugin_stored_read",
                        origin_match=f"{CUSTOM_SQL_DOMAIN}:{_table}:{column}",
                        sanitizers=[],
                        flow_evidence="plugin_literal_sql_storage",
                    )
                    scope_state[_custom_sql_field_key(row, column, False)] = info
                    scope_state[_custom_sql_field_key(row, column, True)] = info
        flow_text = _output_expression_flow_text(_foreach_body_text(code_text))
        statement_body_text = (
            FUNCTION_HEADER_RE.sub("", code_text, count=1)
            if _target_function
            else code_text
        )
        if _target_function:
            # A helper's first semicolon-delimited statement also contains its
            # declaration header.  Parameters named in that header are not
            # data reads and must not taint an unrelated sink in the body.
            flow_text = FUNCTION_HEADER_RE.sub("", flow_text, count=1)
        variables = extract_php_variables(flow_text)
        direct_sources = detect_sources(flow_text)
        tainted_variables = _tainted_references(flow_text, scope_state)
        wildcard_used = scope in wildcard_scopes and bool(variables)

        matched_reads = _matched_storage_reads(
            flow_text,
            local_tainted_storage,
            plugin_tainted_storage,
            key_aliases,
            option_constant_keys,
            option_getter_keys,
            post_meta_class_constant_keys,
        )
        storage_writes = _storage_writes(
            code_text,
            key_aliases,
            option_constant_keys,
            option_setter_keys,
            post_meta_class_constant_keys,
        )
        custom_calls = list(_iter_custom_sql_calls(custom_code_text))
        custom_writes: List[Tuple[Tuple[str, str, str], str]] = []
        custom_reads: List[Tuple[str, Set[Tuple[str, str, str]], bool]] = []
        for api, argument, call_start in custom_calls:
            alias = STATIC_VARIABLE_RE.match(argument)
            query = custom_sql_aliases.get(alias.group(1), "") if alias else _flatten_php_concat(argument)
            if not query:
                continue
            table = _custom_sql_table(query, custom_table_aliases, custom_constants)
            if api == "query":
                custom_writes.extend(_custom_sql_write_values(query, table))
            elif api in {"get_results", "get_row"}:
                columns = _custom_sql_select_columns(query)
                if columns is None or not table:
                    continue
                matched_columns = {
                    key for key in plugin_tainted_storage
                    if key[0] == CUSTOM_SQL_DOMAIN and key[1] == table
                    and ("*" in columns or key[2] in columns)
                }
                assignment_match = re.search(
                    r"(?P<lhs>\$[A-Za-z_][A-Za-z0-9_]*)\s*=\s*$",
                    custom_code_text[:call_start],
                )
                if assignment_match and matched_columns:
                    custom_reads.append((assignment_match.group("lhs"), matched_columns, api == "get_row"))
        for _api, arguments in _iter_custom_sql_data_writes(custom_code_text):
            custom_writes.extend(_custom_sql_array_data_values(arguments, custom_table_aliases, custom_constants))
        # A recognized thin wrapper is a read only when its first argument is
        # a known SQL alias or a closed concat expression.  No accessor,
        # property, dynamic dispatch, or non-literal flag is allowed.
        for wrapper in custom_wrapper_names:
            for match in re.finditer(rf"\b{re.escape(wrapper)}\s*\(", custom_code_text, re.I):
                arguments = _split_call_arguments(custom_code_text, match.end() - 1)
                if len(arguments) not in {1, 2} or (len(arguments) == 2 and arguments[1].strip() not in {"0", "1"}):
                    continue
                alias = STATIC_VARIABLE_RE.match(arguments[0])
                query = custom_sql_aliases.get(alias.group(1), "") if alias else _flatten_php_concat(arguments[0])
                table = _custom_sql_table(query, custom_table_aliases, custom_constants)
                columns = _custom_sql_select_columns(query)
                if not table or columns is None:
                    continue
                matched_columns = {key for key in plugin_tainted_storage if key[0] == CUSTOM_SQL_DOMAIN and key[1] == table and ("*" in columns or key[2] in columns)}
                assignment_match = re.search(
                    r"(?P<lhs>\$[A-Za-z_][A-Za-z0-9_]*)\s*=\s*$",
                    code_text[:match.start()],
                )
                if assignment_match and matched_columns:
                    custom_reads.append((assignment_match.group("lhs"), matched_columns, False))
        write_hits = (
            [hit for hit in detect_storage(code_text) if hit[0] == "writes"]
            if _emit_findings
            else []
        )

        snippet_lines: List[str] = []
        snippet_text = ""
        context = ""
        sink_hits: List[Tuple[str, str]] = []
        sink_kind = ""
        sink_match = ""
        if _emit_findings:
            snippet_start = max(0, statement.start_line - 1 - WINDOW_BEFORE)
            snippet_end = min(len(lines), statement.end_line + WINDOW_AFTER)
            snippet_lines = lines[snippet_start:snippet_end]
            snippet_text = "\n".join(snippet_lines)
            context = _context_for(f"{snippet_text}\n{statement.text}")
            # JSONP has no HTML <script> wrapper in the PHP statement itself.
            # Apply JavaScript context only to the exact callback(payload)
            # construction, not to neighboring statements in the snippet.
            if re.search(JSONP_CALLBACK_PATTERN, statement.text, re.IGNORECASE):
                context = "javascript"
            sink_hits, sink_kind, sink_match = _sink_for_statement(
                statement,
                code_text,
                entrypoint_analysis,
                shortcode_callbacks,
                context,
                helper_return_variables,
                _helper_result_is_output,
                same_instance_helper_return_variables.get(scope, set()),
                attachment_html_accumulators,
                tainted_variables,
                wildcard_used,
            )

        if tainted_variables:
            stronger_tainted_variables = [
                variable
                for variable in tainted_variables
                if scope_state[variable].flow_evidence
                not in {
                    "plugin_dynamic_subject_storage",
                    "plugin_literal_sql_storage",
                }
            ]
            if direct_sources or stronger_tainted_variables:
                tainted_variables = stronger_tainted_variables

        has_flow = bool(direct_sources or tainted_variables or matched_reads or wildcard_used)
        if has_flow and (sink_hits or write_hits):
            if direct_sources:
                source_kind, source_match = direct_sources[0]
                flow_evidence = "same_statement"
                confidence = "high"
                source_origin = source_kind
            elif matched_reads and not (
                matched_reads[0][2] == "dynamic_subject" and tainted_variables
            ):
                matched_key = matched_reads[0][0]
                plugin_match_kind = matched_reads[0][2]
                if plugin_match_kind:
                    source_kind = "plugin_stored_read"
                    if plugin_match_kind == "dynamic_subject":
                        source_match = (
                            "plugin matched dynamic-subject stored key: "
                            f"{matched_key[0]}:{matched_key[1]}"
                        )
                        flow_evidence = "plugin_dynamic_subject_storage"
                        confidence = "low"
                    else:
                        source_match = (
                            "plugin matched stored key: "
                            f"{matched_key[0]}:{matched_key[1]}"
                        )
                        flow_evidence = "plugin_literal_storage"
                        confidence = "medium"
                else:
                    source_kind = "stored_read"
                    source_match = (
                        f"matched stored key: {matched_key[0]}:{matched_key[1]}"
                    )
                    flow_evidence = "matched_stored_key"
                    confidence = "high"
                source_origin = source_kind
            elif tainted_variables:
                source_match = ", ".join(tainted_variables)
                flow_evidence = next(
                    (
                        scope_state[var].flow_evidence
                        for var in tainted_variables
                        if scope_state[var].flow_evidence
                        in {
                            "literal_include_scope",
                            "unique_helper_argument",
                            "unique_helper_return",
                            "plugin_dynamic_subject_storage",
                            "plugin_literal_sql_storage",
                            "attachment_exif_metadata_filter",
                        }
                    ),
                    "variable_assignment",
                )
                if flow_evidence == "variable_assignment":
                    flow_evidence = next(
                        (
                            scope_state[var].flow_evidence
                            for var in tainted_variables
                            if scope_state[var].flow_evidence == "same_instance_helper_return"
                        ),
                        flow_evidence,
                    )
                if flow_evidence == "plugin_literal_sql_storage":
                    source_kind = "plugin_stored_read"
                    source_origin = source_kind
                    confidence = "low"
                else:
                    source_kind = "variable_flow"
                    confidence = (
                        "low"
                        if flow_evidence == "plugin_dynamic_subject_storage"
                        else "medium"
                    )
                    source_origin = " | ".join(
                        sorted({scope_state[var].origin_kind for var in tainted_variables})
                    )
            else:
                source_kind = "parse_str_scope"
                source_match = "variables created by parse_str/extract"
                flow_evidence = "scope_created_variables"
                confidence = "low"
                source_origin = source_kind

            sanitizer_hits = (
                _sanitizers_for_tainted_variables(code_text, tainted_variables)
                if tainted_variables
                else detect_sanitizers(code_text)
            )
            for variable in tainted_variables:
                sanitizer_hits.extend(scope_state[variable].sanitizers)
            sanitizer_hits = _dedupe_hits(sanitizer_hits)
            security_hits = detect_security_checks(snippet_text)

            storage_kind = "writes" if write_hits else ""
            storage_match = write_hits[0][1] if write_hits else ""
            score, severity = score_finding(
                source_kind=source_kind,
                source_origin=source_origin,
                sink_kind=sink_kind,
                storage_kind=storage_kind,
                sanitizer_hits=sanitizer_hits,
                security_hits=security_hits,
                snippet=statement.text,
                context=context,
                flow_evidence=flow_evidence,
            )

            finding_type = "REFLECTED_XSS_CANDIDATE"
            if storage_kind == "writes":
                finding_type = "STORED_XSS_CANDIDATE"
            elif matched_reads:
                finding_type = "STORED_XSS_READ_TO_OUTPUT"
            elif sink_kind == "shortcode_return":
                finding_type = "SHORTCODE_XSS_CANDIDATE"
            elif context == "javascript":
                finding_type = "JS_CONTEXT_XSS_CANDIDATE"
            elif context in {"url_attribute", "html_attribute"}:
                finding_type = "ATTRIBUTE_CONTEXT_XSS_CANDIDATE"

            finding_line = _finding_line(
                statement,
                sink_match or storage_match,
                code_text,
            )
            entrypoint_meta = summarize_entrypoints_for_line(
                entrypoint_analysis,
                finding_line,
                snippet_text,
            )
            if _inherited_entrypoint_meta:
                entrypoint_meta = dict(_inherited_entrypoint_meta)

            findings.append(
                {
                    "plugin": plugin_name_from_path(path),
                    "file": str(path),
                    "line": finding_line,
                    "type": finding_type,
                    "severity": severity,
                    "score": score,
                    "confidence": confidence,
                    "flow_evidence": flow_evidence,
                    "source_kind": source_kind,
                    "source_origin": source_origin,
                    "source_match": source_match,
                    "sink_kind": sink_kind,
                    "sink_match": sink_match,
                    "storage_kind": storage_kind,
                    "storage_match": storage_match,
                    "sanitizer_matches": " | ".join(
                        f"{kind}:{pattern}" for kind, pattern in sanitizer_hits
                    ),
                    "security_checks": " | ".join(
                        f"{kind}:{pattern}" for kind, pattern in security_hits
                    ),
                    "tainted_vars": ", ".join(tainted_variables),
                    **entrypoint_meta,
                    "context": context,
                    "snippet": normalize_snippet(snippet_lines),
                }
            )

        # A tainted write marks only its statically known key.  Reads are not
        # considered sources unless a matching write was observed in this file.
        if storage_writes:
            for key, value_text, _api, plugin_key in storage_writes:
                value_variables = extract_php_variables(value_text)
                if detect_sources(value_text) or _tainted_references(
                    value_text, scope_state
                ) or (scope in wildcard_scopes and bool(value_variables)):
                    local_tainted_storage.add(key)
                    if _discovered_storage_keys is not None and plugin_key:
                        _discovered_storage_keys.add(plugin_key)
                        if plugin_key[0] == "option":
                            value_variable = STATIC_VARIABLE_RE.match(value_text.strip())
                            if value_variable:
                                for field in storage_array_fields.get(
                                    value_variable.group(1), set()
                                ):
                                    _discovered_storage_keys.add(
                                        (
                                            GLOBAL_OPTION_FIELD_DOMAIN,
                                            plugin_key[2],
                                            field,
                                        )
                                    )
                elif (
                    _discovered_storage_keys is not None
                    and plugin_key
                    and (current_class_name, current_function_name)
                    in rest_post_object_callbacks
                ):
                    # This narrow REST model is path-insensitive except for a
                    # later unconditional clean write to the exact same
                    # resolved post-meta key in its callback.  Do not retain a
                    # stale source when the callback overwrites it.
                    _discovered_storage_keys.discard(plugin_key)

        # Only an executed query can populate the plugin-wide custom-SQL
        # index.  Each key is an exact (table, column) pair, so siblings in an
        # INSERT/UPDATE neither inherit taint nor become readable sources.
        for custom_key, value_text in custom_writes:
            helper_taint = next(
                (custom_helper_values[var] for var in extract_php_variables(value_text) if var in custom_helper_values),
                None,
            )
            if detect_sources(value_text) or _tainted_references(value_text, scope_state) or helper_taint:
                if _discovered_storage_keys is not None:
                    _discovered_storage_keys.add(custom_key)

        for result_variable, matched_columns, is_row in custom_reads:
            if is_row:
                for _domain, table, column in matched_columns:
                    info = TaintInfo(
                        origin_kind="plugin_stored_read",
                        origin_match=f"{CUSTOM_SQL_DOMAIN}:{table}:{column}",
                        sanitizers=[],
                        flow_evidence="plugin_literal_sql_storage",
                    )
                    scope_state[_custom_sql_field_key(result_variable, column, False)] = info
                    scope_state[_custom_sql_field_key(result_variable, column, True)] = info
            else:
                custom_result_fields[result_variable] = set(matched_columns)

        assignment_pattern = HELPER_ASSIGNMENT_RE if _target_function else ASSIGNMENT_RE
        assignment_text = statement_body_text
        function_header = FUNCTION_HEADER_RE.search(assignment_text)
        if function_header:
            first_body_text = assignment_text[function_header.end() :]
            if any(
                source_kind == "acf_field_value"
                for source_kind, _source_match in detect_sources(first_body_text)
            ):
                # The tolerant splitter can keep a default-argument function
                # declaration and its first body assignment together.  Apply
                # the header skip only when that body contains the fixed ACF
                # persisted-field source; changing every function header
                # alters unrelated seeded shortcode scopes.
                assignment_text = first_body_text
        assignment = assignment_pattern.search(assignment_text)
        if assignment:
            lhs = assignment.group("lhs")
            operator = assignment.group("operator")
            rhs = assignment.group("rhs")
            rhs_sources = detect_sources(rhs)
            rhs_variables = extract_php_variables(rhs)
            rhs_tainted = _tainted_references(rhs, scope_state)
            attachment_read_taint = _attachment_exif_metadata_read_taint(
                rhs, attachment_metadata_variables
            )
            stronger_rhs_tainted = [
                variable
                for variable in rhs_tainted
                if scope_state[variable].flow_evidence
                != "plugin_dynamic_subject_storage"
            ]
            if stronger_rhs_tainted:
                rhs_tainted = stronger_rhs_tainted
            rhs_matched_reads = _matched_storage_reads(
                rhs,
                local_tainted_storage,
                plugin_tainted_storage,
                key_aliases,
                option_constant_keys,
                option_getter_keys,
                post_meta_class_constant_keys,
            )
            helper_return_taint = None
            fixed_helper_match = FIXED_HELPER_RHS_RE.fullmatch(rhs)
            if (
                fixed_helper_match
                and _helper_depth == 0
                and current_function_name in registered_callbacks
            ):
                helper_definition = unique_function_definitions.get(
                    fixed_helper_match.group("name").casefold()
                )
                if helper_definition:
                    helper_return_taint = _direct_helper_return_taint(
                        helper_definition
                    )

            if rhs_sources or rhs_tainted or rhs_matched_reads or attachment_read_taint or helper_return_taint or (
                scope in wildcard_scopes and bool(rhs_variables)
            ):
                if rhs_sources:
                    origin_kind, origin_match = rhs_sources[0]
                    origin_flow_evidence = "variable_assignment"
                elif rhs_matched_reads and not (
                    rhs_matched_reads[0][2] == "dynamic_subject" and rhs_tainted
                ):
                    origin_kind = (
                        "plugin_stored_read"
                        if rhs_matched_reads[0][2]
                        else "stored_read"
                    )
                    origin_match = f"{rhs_matched_reads[0][0][0]}:{rhs_matched_reads[0][0][1]}"
                    origin_flow_evidence = (
                        "plugin_dynamic_subject_storage"
                        if rhs_matched_reads[0][2] == "dynamic_subject"
                        else "variable_assignment"
                    )
                elif rhs_tainted:
                    origin = scope_state[rhs_tainted[0]]
                    origin_kind, origin_match = origin.origin_kind, origin.origin_match
                    origin_flow_evidence = origin.flow_evidence
                elif attachment_read_taint:
                    origin_kind = attachment_read_taint.origin_kind
                    origin_match = attachment_read_taint.origin_match
                    origin_flow_evidence = attachment_read_taint.flow_evidence
                elif helper_return_taint:
                    origin_kind = helper_return_taint.origin_kind
                    origin_match = helper_return_taint.origin_match
                    origin_flow_evidence = helper_return_taint.flow_evidence
                else:
                    origin_kind, origin_match = "parse_str_scope", "scope-created variable"
                    origin_flow_evidence = "scope_created_variables"
                if (
                    operator == "="
                    and not ALTERNATIVE_BRANCH_RE.search(code_text)
                    and not _is_unset_default_assignment(code_text, lhs)
                ):
                    _clear_array_element_taint(lhs, scope_state)
                same_instance_variables = same_instance_helper_return_variables.setdefault(
                    scope, set()
                )
                if origin_flow_evidence == "same_instance_helper_return":
                    same_instance_variables.add(lhs)
                elif lhs != same_instance_assignment_lhs:
                    same_instance_variables.discard(lhs)
                scope_state[lhs] = TaintInfo(
                    origin_kind=origin_kind,
                    origin_match=origin_match,
                    sanitizers=_dedupe_hits(
                        [
                            *detect_sanitizers(rhs),
                            *(helper_return_taint.sanitizers if helper_return_taint else []),
                        ]
                    ),
                    flow_evidence=origin_flow_evidence,
                )
                if not _emit_findings and operator == "=":
                    fields = set(_tainted_literal_array_fields(rhs, scope_state))
                    if fields:
                        storage_array_fields[lhs] = fields
                    else:
                        storage_array_fields.pop(lhs, None)
            elif (
                operator == "="
                and not ALTERNATIVE_BRANCH_RE.search(code_text)
                and not _is_unset_default_assignment(code_text, lhs)
            ):
                # A clean assignment in an ``else``/``elseif`` arm does not
                # invalidate the tainted value from another feasible arm.  A
                # path-insensitive analysis must retain the union at the join.
                preserve_attachment_exif_taint = (
                    current_function_name in attachment_exif_output_accumulators
                    and lhs in scope_state
                    and scope_state[lhs].origin_kind == "external_structured_data"
                    and scope_state[lhs].flow_evidence
                    == "attachment_exif_metadata_filter"
                    and _is_attachment_exif_optional_clean_assignment(code_text, lhs)
                )
                if lhs != same_instance_assignment_lhs and not preserve_attachment_exif_taint:
                    same_instance_helper_return_variables.setdefault(scope, set()).discard(lhs)
                    _clear_array_element_taint(lhs, scope_state)
                    scope_state.pop(lhs, None)
                    if not _emit_findings:
                        storage_array_fields.pop(lhs, None)

            if (
                operator == "="
                and ATTACHMENT_METADATA_READ_RE.fullmatch(rhs)
                and attachment_exif_metadata_fields
            ):
                attachment_metadata_variables[lhs] = set(attachment_exif_metadata_fields)
            elif operator == "=" and not ALTERNATIVE_BRANCH_RE.search(code_text):
                attachment_metadata_variables.pop(lhs, None)

            static_storage_key = _static_key(rhs)
            literal_array_keys = {
                match.group("key")
                for match in STORAGE_LITERAL_ARRAY_KEY_RE.finditer(rhs)
            }
            if static_storage_key:
                key_aliases[lhs] = {static_storage_key}
            elif literal_array_keys:
                key_aliases[lhs] = literal_array_keys
            elif operator == "=" and not ALTERNATIVE_BRANCH_RE.search(code_text):
                key_aliases.pop(lhs, None)

        # Normal analysis tracks exact local fields and append elements.  The
        # storage prepass deliberately keeps its established container summary
        # so dynamic-field storage paths from the frozen baseline are retained.
        array_assignment = ARRAY_ELEMENT_ASSIGNMENT_RE.search(statement_body_text)
        if array_assignment:
            container = array_assignment.group("lhs")
            index = array_assignment.group("index")
            operator = array_assignment.group("operator")
            rhs = array_assignment.group("rhs")
            rhs_sources = detect_sources(rhs)
            rhs_variables = extract_php_variables(rhs)
            rhs_tainted = _tainted_references(rhs, scope_state)
            field = _static_key(index)
            local_target = (
                _array_taint_key(container, field)
                if field
                else _array_wildcard_taint_key(container)
                if not index.strip()
                else ""
            )
            if rhs_sources or rhs_tainted or (
                scope in wildcard_scopes and bool(rhs_variables)
            ):
                if rhs_sources:
                    origin_kind, origin_match = rhs_sources[0]
                    origin_flow_evidence = "variable_assignment"
                elif rhs_tainted:
                    origin = scope_state[rhs_tainted[0]]
                    origin_kind, origin_match = origin.origin_kind, origin.origin_match
                    origin_flow_evidence = origin.flow_evidence
                else:
                    origin_kind, origin_match = "parse_str_scope", "scope-created variable"
                    origin_flow_evidence = "scope_created_variables"
                dynamic_external_structured_target = (
                    not local_target
                    and bool(index.strip())
                    and origin_kind == "external_structured_data"
                )
                target = (
                    _array_wildcard_taint_key(container)
                    if _emit_findings and dynamic_external_structured_target
                    else local_target if _emit_findings else container
                )
                if target:
                    scope_state[target] = TaintInfo(
                        origin_kind=origin_kind,
                        origin_match=origin_match,
                        sanitizers=detect_sanitizers(rhs),
                        flow_evidence=origin_flow_evidence,
                    )
                    if not _emit_findings and field:
                        storage_array_fields.setdefault(container, set()).add(field)
            elif operator == "=" and not ALTERNATIVE_BRANCH_RE.search(code_text):
                target = local_target if _emit_findings else container
                if target:
                    scope_state.pop(target, None)
                if not _emit_findings and field:
                    storage_array_fields.setdefault(container, set()).discard(field)

        list_assignment = LIST_ASSIGNMENT_RE.search(statement_body_text)
        if list_assignment:
            targets = extract_php_variables(list_assignment.group("targets"))
            rhs = list_assignment.group("rhs")
            rhs_sources = detect_sources(rhs)
            rhs_variables = extract_php_variables(rhs)
            rhs_tainted = _tainted_references(rhs, scope_state)
            if rhs_sources or rhs_tainted or (
                scope in wildcard_scopes and bool(rhs_variables)
            ):
                if rhs_sources:
                    origin_kind, origin_match = rhs_sources[0]
                    origin_flow_evidence = "variable_assignment"
                elif rhs_tainted:
                    origin = scope_state[rhs_tainted[0]]
                    origin_kind, origin_match = origin.origin_kind, origin.origin_match
                    origin_flow_evidence = origin.flow_evidence
                else:
                    origin_kind, origin_match = "parse_str_scope", "scope-created variable"
                    origin_flow_evidence = "scope_created_variables"
                for target in targets:
                    scope_state[target] = TaintInfo(
                        origin_kind=origin_kind,
                        origin_match=origin_match,
                        sanitizers=detect_sanitizers(rhs),
                        flow_evidence=origin_flow_evidence,
                    )

        _update_parse_extract_state(
            code_text,
            scope_state,
            wildcard_scopes,
            scope,
        )

        # Follow only fixed-name, positional calls rooted in a registered
        # callback.  Every target name must have exactly one definition in the
        # plugin.  A second helper boundary is allowed only when each return
        # value remains on an output-consumed chain; a third boundary is never
        # followed.
        is_seeded_helper = (
            _helper_depth > 0
            and current_function_name
            and current_function_name == _target_function
        )
        if (
            _emit_findings
            and unique_function_definitions
            and _helper_depth < MAX_HELPER_HANDOFF_DEPTH
            and (is_registered_root or is_seeded_helper)
        ):
            for helper_name, arguments in iter_function_calls(code_text):
                helper_name = helper_name.casefold()
                if helper_name == current_function_name:
                    continue
                definition = unique_function_definitions.get(helper_name)
                if not definition:
                    continue
                helper_path = Path(definition["path"]).resolve()
                helper_key = (helper_path, helper_name)
                if helper_key in helper_stack:
                    continue

                seeded_taint: Dict[str, TaintInfo] = {}
                for parameter, argument in zip(
                    definition.get("parameters", []), arguments
                ):
                    argument_taint = _expression_taint(
                        argument,
                        scope_state,
                        wildcard_used=scope in wildcard_scopes,
                    )
                    if argument_taint:
                        seeded_taint[str(parameter)] = argument_taint
                if not seeded_taint:
                    continue

                helper_result_is_output = bool(detect_sinks(code_text)) or bool(
                    _helper_result_is_output
                    and RETURN_EXPRESSION_RE.search(code_text)
                )
                if _helper_depth == 1 and not helper_result_is_output:
                    continue

                inherited_entrypoint_meta = _inherited_entrypoint_meta
                if not inherited_entrypoint_meta:
                    inherited_entrypoint_meta = summarize_entrypoints_for_line(
                        entrypoint_analysis,
                        statement.end_line,
                        snippet_text,
                    )
                helper_findings = analyze_php_file(
                    helper_path,
                    shortcode_callbacks=shortcode_callbacks,
                    tainted_storage_keys=tainted_storage_keys,
                    registered_callbacks=registered_callbacks,
                    unique_function_definitions=unique_function_definitions,
                    _target_function=helper_name,
                    _seeded_function_taint=seeded_taint,
                    _helper_depth=_helper_depth + 1,
                    _helper_stack=helper_stack | {helper_key},
                    _inherited_entrypoint_meta=inherited_entrypoint_meta,
                    _helper_result_is_output=helper_result_is_output,
                )
                existing_keys = {
                    (
                        finding["file"],
                        finding["line"],
                        finding["sink_kind"],
                        finding["tainted_vars"],
                        finding["source_origin"],
                    )
                    for finding in findings
                }
                for finding in helper_findings:
                    key = (
                        finding["file"],
                        finding["line"],
                        finding["sink_kind"],
                        finding["tainted_vars"],
                        finding["source_origin"],
                    )
                    if key not in existing_keys:
                        findings.append(finding)
                        existing_keys.add(key)

        # Storage indexing is deliberately file-local.  Only normal finding
        # analysis follows literal includes, so the prepass cannot amplify a
        # cross-file storage relationship.
        if _emit_findings:
            include_target = _literal_include_target(code_text, path)
            is_once_include = _is_include_once(code_text)
            if (
                include_target
                and include_target not in include_stack
                and scope_state
                and not (is_once_include and include_target in loaded_include_targets)
            ):
                loaded_include_targets.add(include_target)
                include_findings = analyze_php_file(
                    include_target,
                    shortcode_callbacks=shortcode_callbacks,
                    tainted_storage_keys=tainted_storage_keys,
                    registered_callbacks=registered_callbacks,
                    unique_function_definitions=unique_function_definitions,
                    _inherited_scope_taint=_literal_include_scope_taint(scope_state),
                    _include_stack=include_stack,
                    _loaded_include_targets=loaded_include_targets,
                )
                existing_scope_keys = {
                    (
                        finding["file"],
                        finding["line"],
                        finding["sink_kind"],
                        finding["sink_match"],
                        finding["tainted_vars"],
                        finding["source_origin"],
                    )
                    for finding in findings
                    if finding["flow_evidence"] == "literal_include_scope"
                }
                for finding in include_findings:
                    key = (
                        finding["file"],
                        finding["line"],
                        finding["sink_kind"],
                        finding["sink_match"],
                        finding["tainted_vars"],
                        finding["source_origin"],
                    )
                    if (
                        finding["flow_evidence"] != "literal_include_scope"
                        or key not in existing_scope_keys
                    ):
                        findings.append(finding)
                        if finding["flow_evidence"] == "literal_include_scope":
                            existing_scope_keys.add(key)

    return findings


def collect_tainted_storage_keys(
    path: Path,
    shortcode_callbacks: Set[str] | None = None,
    custom_unique_zero_arg_helpers: Set[str] | None = None,
    custom_zero_arg_helper_summaries: Dict[str, TaintInfo] | None = None,
    option_constant_keys: Dict[str, str] | None = None,
    option_setter_keys: Dict[str, str] | None = None,
    option_getter_keys: Dict[str, str] | None = None,
    rest_post_object_callbacks: Set[Tuple[str, str]] | None = None,
    post_meta_class_constant_keys: Dict[str, str] | None = None,
) -> Set[Tuple[str, str, str]]:
    """Collect literal WordPress storage keys written from local taint.

    This is a conservative plugin prepass: it does not seed reads from other
    files and therefore cannot recursively amplify an uncertain cross-file
    storage match into another write.
    """

    discovered: Set[Tuple[str, str, str]] = set()
    analyze_php_file(
        path,
        shortcode_callbacks,
        _discovered_storage_keys=discovered,
        _emit_findings=False,
        _custom_unique_zero_arg_helpers=custom_unique_zero_arg_helpers,
        _custom_zero_arg_helper_summaries=custom_zero_arg_helper_summaries,
        _option_constant_keys=option_constant_keys,
        _option_setter_keys=option_setter_keys,
        _option_getter_keys=option_getter_keys,
        _rest_post_object_callbacks=rest_post_object_callbacks,
        _post_meta_class_constant_keys=post_meta_class_constant_keys,
    )
    return discovered


def build_tainted_storage_index(
    paths: Sequence[Path],
    plugin_root: Path,
    shortcode_callbacks: Dict[str, Set[str]] | None = None,
) -> Dict[str, Set[Tuple[str, str, str]]]:
    """Build a per-plugin index of tainted writes with static storage keys."""

    callback_index = shortcode_callbacks or {}
    result: Dict[str, Set[Tuple[str, str, str]]] = {}
    source_by_path: Dict[Path, str] = {}
    plugin_by_path: Dict[Path, str] = {}
    sources_by_plugin: Dict[str, List[Tuple[Path, str]]] = {}
    function_counts: Dict[str, Dict[str, int]] = {}
    zero_arg_helpers: Dict[str, Set[str]] = {}
    zero_arg_helper_definition_paths: Dict[str, Dict[str, Path]] = {}
    wrapper_candidates: Dict[str, Set[str]] = {}
    option_constant_candidates: Dict[str, Dict[str, List[str]]] = {}
    output_consumed_object_methods: Dict[str, Set[str]] = {}
    top_level_assignment_counts: Dict[str, Dict[str, int]] = {}
    top_level_option_candidates: Dict[str, Dict[str, List[str]]] = {}
    attachment_filter_callbacks: Dict[str, Set[str]] = {}
    content_filter_callbacks: Dict[str, Set[str]] = {}
    function_definitions: Dict[str, Dict[str, List[Tuple[Path, Dict[str, Any]]]]] = {}
    rest_route_candidates: Dict[str, Set[Tuple[str, str]]] = {}
    post_meta_class_constant_candidates: Dict[str, Dict[str, List[str]]] = {}
    post_meta_class_constant_references: Dict[str, Set[str]] = {}

    for path in paths:
        plugin = plugin_name_from_path(path, plugin_root)
        plugin_by_path[path] = plugin
        try:
            source_text = safe_read_text(path)
        except Exception:
            continue
        source_by_path[path] = source_text
        sources_by_plugin.setdefault(plugin, []).append((path, source_text))
        source_analysis = analyze_entrypoints(source_text, path)
        for constant, key in _literal_class_constants(source_text):
            post_meta_class_constant_candidates.setdefault(plugin, {}).setdefault(
                constant, []
            ).append(key)
        attachment_filter_callbacks.setdefault(plugin, set()).update(
            match.group("callback").casefold()
            for match in ATTACHMENT_EXIF_FILTER_RE.finditer(source_text)
        )
        content_filter_callbacks.setdefault(plugin, set()).update(
            match.group("callback").casefold()
            for match in CONTENT_FILTER_RE.finditer(source_text)
        )
        for statement in _iter_statements(source_text):
            statement_text = _strip_php_comments(statement.text)
            for api, arguments in iter_named_function_calls(
                statement_text, STORAGE_API_NAMES
            ):
                domain, key_index = (
                    WRITE_SPECS[api][:2] if api in WRITE_SPECS else READ_SPECS[api]
                )
                if domain != "post_meta" or len(arguments) <= key_index:
                    continue
                reference = CLASS_CONSTANT_REFERENCE_RE.fullmatch(
                    arguments[key_index]
                )
                if reference:
                    post_meta_class_constant_references.setdefault(
                        plugin, set()
                    ).add(
                        f"{reference.group('class').casefold()}::"
                        f"{reference.group('constant').casefold()}"
                    )
            current_function = function_for_line(source_analysis, statement.end_line)
            current_class = str(current_function.get("class_name", "")).casefold()
            if current_class:
                for _name, arguments in iter_named_function_calls(
                    statement_text, {"register_rest_route"}
                ):
                    if len(arguments) != 3:
                        continue
                    callback = _literal_rest_post_object_callback(
                        arguments[0], arguments[1], arguments[2]
                    )
                    if callback:
                        rest_route_candidates.setdefault(plugin, set()).add(
                            (current_class, callback)
                        )
            if not function_for_line(source_analysis, statement.end_line):
                assignment = ASSIGNMENT_RE.search(statement_text)
                if assignment:
                    name = assignment.group("lhs")
                    counts = top_level_assignment_counts.setdefault(plugin, {})
                    counts[name] = counts.get(name, 0) + 1
                option_assignment = TOP_LEVEL_LITERAL_OPTION_ASSIGNMENT_RE.fullmatch(
                    statement_text
                )
                if option_assignment:
                    top_level_option_candidates.setdefault(plugin, {}).setdefault(
                        option_assignment.group("global"), []
                    ).append(option_assignment.group("key"))
            if not detect_sinks(statement_text):
                continue
            output_consumed_object_methods.setdefault(plugin, set()).update(
                match.group("name").casefold()
                for match in DIRECT_OBJECT_METHOD_CALL_RE.finditer(statement_text)
            )
        for match in OPTION_CONSTANT_DEFINE_RE.finditer(source_text):
            option_constant_candidates.setdefault(plugin, {}).setdefault(
                match.group("name"), []
            ).append(match.group("key"))
        counts = function_counts.setdefault(plugin, {})
        for function in source_analysis.get("functions", []):
            name = str(function.get("name", "")).casefold()
            if not name:
                continue
            counts[name] = counts.get(name, 0) + 1
            function_definitions.setdefault(plugin, {}).setdefault(name, []).append(
                (path, function)
            )
            if not function.get("parameters"):
                zero_arg_helpers.setdefault(plugin, set()).add(name)
                zero_arg_helper_definition_paths.setdefault(plugin, {})[name] = path
        wrapper_candidates.setdefault(plugin, set()).update(_thin_custom_sql_wrappers(source_text))

    unique_helpers = {
        plugin: {name for name in names if function_counts.get(plugin, {}).get(name) == 1}
        for plugin, names in zero_arg_helpers.items()
    }
    unique_wrappers = {
        plugin: {name for name in names if function_counts.get(plugin, {}).get(name) == 1}
        for plugin, names in wrapper_candidates.items()
    }
    rest_post_object_callbacks: Dict[str, Set[Tuple[str, str]]] = {}
    for plugin, candidates in rest_route_candidates.items():
        for class_name, method_name in candidates:
            definitions = function_definitions.get(plugin, {}).get(method_name, [])
            if (
                len(definitions) == 1
                and str(definitions[0][1].get("class_name", "")).casefold()
                == class_name
            ):
                rest_post_object_callbacks.setdefault(plugin, set()).add(
                    (class_name, method_name)
                )
    post_meta_class_constant_keys = {
        plugin: {
            constant: values[0]
            for constant, values in candidates.items()
            if len(values) == 1
            and constant in post_meta_class_constant_references.get(plugin, set())
        }
        for plugin, candidates in post_meta_class_constant_candidates.items()
        if rest_post_object_callbacks.get(plugin)
    }
    option_constant_keys = {
        plugin: {
            name: values[0]
            for name, values in candidates.items()
            if len(values) == 1
        }
        for plugin, candidates in option_constant_candidates.items()
    }
    option_setter_candidates: Dict[str, Dict[str, str]] = {}
    option_getter_candidates: Dict[str, Dict[str, str]] = {}
    for plugin, sources in sources_by_plugin.items():
        constants = option_constant_keys.get(plugin, {})
        if not constants:
            continue
        for _path, source_text in sources:
            setters, getters = _thin_option_wrappers(source_text, constants)
            option_setter_candidates.setdefault(plugin, {}).update(setters)
            option_getter_candidates.setdefault(plugin, {}).update(getters)
    unique_option_setters = {
        plugin: {
            name: key
            for name, key in candidates.items()
            if function_counts.get(plugin, {}).get(name) == 1
        }
        for plugin, candidates in option_setter_candidates.items()
    }
    unique_option_getters = {
        plugin: {
            name: key
            for name, key in candidates.items()
            if function_counts.get(plugin, {}).get(name) == 1
        }
        for plugin, candidates in option_getter_candidates.items()
    }
    attachment_exif_metadata_fields: Dict[str, Set[str]] = {}
    for plugin, callbacks in attachment_filter_callbacks.items():
        for callback in callbacks:
            definitions = function_definitions.get(plugin, {}).get(callback, [])
            if len(definitions) != 1:
                continue
            definition_path, definition = definitions[0]
            if definition.get("class_name"):
                continue
            source_text = source_by_path.get(definition_path)
            if source_text is None:
                continue
            fields = _attachment_exif_metadata_fields(source_text, definition)
            if fields:
                attachment_exif_metadata_fields.setdefault(plugin, set()).update(fields)
    attachment_exif_output_accumulators: Dict[str, Dict[str, str]] = {}
    for plugin, fields in attachment_exif_metadata_fields.items():
        if not fields:
            continue
        for outer_callback in content_filter_callbacks.get(plugin, set()):
            outer_definitions = function_definitions.get(plugin, {}).get(
                outer_callback, []
            )
            if len(outer_definitions) != 1:
                continue
            outer_path, outer_definition = outer_definitions[0]
            if outer_definition.get("class_name"):
                continue
            outer_source = source_by_path.get(outer_path)
            if outer_source is None:
                continue
            start = int(outer_definition.get("start_line", outer_definition.get("line", 0)))
            end = int(outer_definition.get("end_line", 0))
            if start <= 0 or end < start:
                continue
            outer_body = "\n".join(outer_source.splitlines()[start - 1 : end])
            for callback_match in PREG_REPLACE_CALLBACK_RETURN_RE.finditer(outer_body):
                inner_callback = callback_match.group("callback").casefold()
                inner_definitions = function_definitions.get(plugin, {}).get(
                    inner_callback, []
                )
                if len(inner_definitions) != 1:
                    continue
                inner_path, inner_definition = inner_definitions[0]
                if inner_definition.get("class_name"):
                    continue
                inner_source = source_by_path.get(inner_path)
                if inner_source is None:
                    continue
                accumulator = _attachment_exif_return_accumulator(
                    inner_source, inner_definition
                )
                if accumulator:
                    attachment_exif_output_accumulators.setdefault(plugin, {})[
                        inner_callback
                    ] = accumulator
    # Keep the existing storage-index contract free of unrelated helper
    # metadata.  A helper name is published only when the plugin actually has
    # custom-SQL handling and a zero-argument assignment call to that helper.
    active_unique_helpers: Dict[str, Set[str]] = {}
    for plugin, names in unique_helpers.items():
        plugin_sources = [source for _path, source in sources_by_plugin.get(plugin, [])]
        combined = "\n".join(plugin_sources)
        if not re.search(r"\$wpdb\s*->\s*(?:query|insert|update)\s*\(", combined, re.I):
            continue
        called = {
            match.group("name").casefold()
            for match in re.finditer(
                r"\$[A-Za-z_][A-Za-z0-9_]*\s*=\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(\s*\)",
                combined,
            )
        }
        active_unique_helpers[plugin] = names & called
    helper_summaries: Dict[str, Dict[str, TaintInfo]] = {}
    for plugin, names in active_unique_helpers.items():
        summaries: Dict[str, TaintInfo] = {}
        for name in names:
            definition_path = zero_arg_helper_definition_paths.get(plugin, {}).get(name)
            if definition_path is None:
                continue
            source_text = source_by_path.get(definition_path)
            if source_text is None:
                continue
            summary = _local_zero_arg_helper_source(source_text, name)
            if summary:
                summaries[name] = summary
        helper_summaries[plugin] = summaries
    for path in paths:
        plugin = plugin_by_path[path]
        try:
            source_text = source_by_path.get(path)
            if source_text is None:
                source_text = safe_read_text(path)
            wrappers = unique_wrappers.get(plugin, set())
            constants = {
                (CUSTOM_SQL_CONSTANT_DOMAIN, match.group("name"), f"wpdb_prefix:{match.group('suffix')}")
                for match in CUSTOM_TABLE_DEFINE_RE.finditer(source_text)
            }
        except Exception:
            wrappers = set()
            constants = set()
        if wrappers:
            result.setdefault(plugin, set()).update(
                (CUSTOM_SQL_WRAPPER_DOMAIN, wrapper, "") for wrapper in wrappers
            )
        if helper_summaries.get(plugin):
            result.setdefault(plugin, set()).update(
                (
                    CUSTOM_SQL_HELPER_DOMAIN,
                    helper,
                    f"{summary.origin_kind}\x1f{summary.origin_match}",
                )
                for helper, summary in helper_summaries[plugin].items()
            )
        if constants:
            result.setdefault(plugin, set()).update(constants)
        if output_consumed_object_methods.get(plugin):
            result.setdefault(plugin, set()).update(
                (SAME_INSTANCE_OUTPUT_METHOD_DOMAIN, name, "")
                for name in output_consumed_object_methods[plugin]
            )
        try:
            keys = collect_tainted_storage_keys(
                path,
                callback_index.get(plugin, set()),
                set(helper_summaries.get(plugin, {})),
                helper_summaries.get(plugin, {}),
                # Literal option constants are used only to recognize the
                # bounded thin wrappers above.  Do not resolve arbitrary
                # direct update_option(CONST, ...)/get_option(CONST) calls:
                # that broader model materially expands unrelated candidates.
                {},
                unique_option_setters.get(plugin, {}),
                unique_option_getters.get(plugin, {}),
                rest_post_object_callbacks.get(plugin, set()),
                post_meta_class_constant_keys.get(plugin, {}),
            )
        except Exception:
            # The normal scan records the file-level error.  A failed prepass
            # must not abort every other plugin or create an unverified key.
            continue
        if keys:
            result.setdefault(plugin, set()).update(keys)
            result[plugin].update(
                (OPTION_SETTER_DOMAIN, name, key)
                for name, key in unique_option_setters.get(plugin, {}).items()
            )
            result[plugin].update(
                (OPTION_GETTER_DOMAIN, name, key)
                for name, key in unique_option_getters.get(plugin, {}).items()
            )
        if rest_post_object_callbacks.get(plugin):
            result.setdefault(plugin, set()).update(
                (REST_POST_OBJECT_CALLBACK_DOMAIN, class_name, method_name)
                for class_name, method_name in rest_post_object_callbacks[plugin]
            )
        if post_meta_class_constant_keys.get(plugin):
            result.setdefault(plugin, set()).update(
                (POST_META_CLASS_CONSTANT_DOMAIN, constant, key)
                for constant, key in post_meta_class_constant_keys[plugin].items()
            )
    for plugin, candidates in top_level_option_candidates.items():
        plugin_index = result.get(plugin, set())
        for global_name, keys in candidates.items():
            if (
                len(keys) != 1
                or top_level_assignment_counts.get(plugin, {}).get(global_name) != 1
            ):
                continue
            key = keys[0]
            if ("option", "", key) not in plugin_index:
                continue
            if not any(
                domain == GLOBAL_OPTION_FIELD_DOMAIN and option_key == key
                for domain, option_key, _field in plugin_index
            ):
                continue
            result.setdefault(plugin, set()).add(
                (GLOBAL_OPTION_BINDING_DOMAIN, global_name, key)
            )
    for plugin, fields in attachment_exif_metadata_fields.items():
        result.setdefault(plugin, set()).update(
            (ATTACHMENT_EXIF_METADATA_DOMAIN, "", field) for field in fields
        )
    for plugin, callbacks in attachment_exif_output_accumulators.items():
        result.setdefault(plugin, set()).update(
            (ATTACHMENT_EXIF_OUTPUT_CALLBACK_DOMAIN, callback, accumulator)
            for callback, accumulator in callbacks.items()
        )
    return result
