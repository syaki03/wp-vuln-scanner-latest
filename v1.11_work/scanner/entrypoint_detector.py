import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Set

from scanner.legacy_models import iter_named_function_calls
from scanner.utils import plugin_name_from_path, safe_read_text


FUNCTION_RE = re.compile(
    r"\bfunction\s+&?\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^)]*)\)",
    re.IGNORECASE,
)
CLASS_RE = re.compile(
    r"^\s*(?:<\?(?:php)?\s*)?(?:(?:abstract|final)\s+)?"
    r"class\s+(?P<name>[a-zA-Z_][a-zA-Z0-9_]*)"
    r"(?:\s+extends\s+(?P<parent>[a-zA-Z_][a-zA-Z0-9_\\]*))?",
    re.IGNORECASE,
)
ADD_ACTION_RE = re.compile(r"\badd_action\s*\(\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
ADD_FILTER_RE = re.compile(r"\badd_filter\s*\(\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
REST_ROUTE_RE = re.compile(
    r"\bregister_rest_route\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*['\"]([^'\"]+)['\"]",
    re.IGNORECASE,
)

ADMIN_PAGE_FUNCTIONS = {
    "add_options_page",
    "add_management_page",
    "add_menu_page",
    "add_submenu_page",
    "add_dashboard_page",
    "add_theme_page",
    "add_plugins_page",
    "add_users_page",
    "add_profile_page",
    "add_media_page",
    "add_comments_page",
}

CALLBACK_STRING_RE = re.compile(r"['\"]([a-zA-Z_][a-zA-Z0-9_]*)['\"]")

PUBLIC_HOOKS = {
    "init",
    "wp",
    "wp_loaded",
    "parse_request",
    "template_redirect",
    "the_content",
    "wp_enqueue_scripts",
}

ADMIN_HOOKS = {
    "admin_init",
    "admin_menu",
    "admin_post",
    "admin_enqueue_scripts",
    "admin_notices",
}

ADMIN_ONLY_MARKERS = (
    "current_user_can('manage_options'",
    'current_user_can("manage_options"',
    "current_user_can( 'manage_options'",
    'current_user_can( "manage_options"',
    "is_admin()",
    "admin_menu",
    "admin_init",
)

RISKY_DIRECT_FILE_NAMES = re.compile(
    r"(?:ajax|download|upload|export|import|popup|preview|connector|endpoint|gateway|proxy|callback)",
    re.IGNORECASE,
)
ABSPATH_GUARD_RE = re.compile(
    r"\bdefined\s*\(\s*['\"]ABSPATH['\"]\s*\)",
    re.IGNORECASE,
)
WP_BOOTSTRAP_RE = re.compile(r"(?:wp-load|wp-blog-header)\.php", re.IGNORECASE)
AUTH_MARKER_RE = re.compile(
    r"\b(?:current_user_can|is_user_logged_in|wp_verify_nonce|"
    r"check_(?:admin|ajax)_referer)\s*\(",
    re.IGNORECASE,
)
DIRECT_EXECUTION_MARKER_RE = re.compile(r"\bSCRIPT_FILENAME\b|\b__FILE__\b", re.IGNORECASE)
ADMIN_CAPABILITIES = {
    "activate_plugins",
    "delete_plugins",
    "delete_themes",
    "edit_plugins",
    "edit_themes",
    "manage_options",
    "update_core",
    "update_plugins",
    "update_themes",
}


def _line_at(lines: List[str], index: int, span: int = 8) -> str:
    end = min(len(lines), index + span)
    return "\n".join(lines[index:end])


def _extract_callback(line: str, skip: int = 1) -> str:
    names = CALLBACK_STRING_RE.findall(line)
    if len(names) > skip:
        return names[skip]
    return ""


def _static_argument(value: str) -> str:
    match = re.fullmatch(r"\s*['\"]([^'\"]*)['\"]\s*", value)
    return match.group(1) if match else ""


def _callable_name(value: str) -> str:
    names = CALLBACK_STRING_RE.findall(value)
    return names[-1] if names else _static_argument(value)


def _capability_exposure(capability: str) -> str:
    normalized = capability.strip().lower()
    if not normalized:
        return "unknown"
    if normalized in ADMIN_CAPABILITIES:
        return "admin"
    return "authenticated"


def _has_abspath_guard(text: str) -> bool:
    """Return True only when ABSPATH is used to block direct execution."""
    if not ABSPATH_GUARD_RE.search(text):
        return False

    guard_patterns = (
        re.compile(
            r"if\s*\(\s*!\s*defined\s*\(\s*['\"]ABSPATH['\"]\s*\)\s*\)"
            r"\s*(?:\{\s*)?(?:exit|die)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        re.compile(
            r"\bdefined\s*\(\s*['\"]ABSPATH['\"]\s*\)\s*or\s*(?:exit|die)\b",
            re.IGNORECASE,
        ),
    )
    return any(pattern.search(text) for pattern in guard_patterns)


def _has_direct_execution_guard(text: str) -> bool:
    """Detect common SCRIPT_FILENAME/FILE guards without parsing PHP."""
    if not DIRECT_EXECUTION_MARKER_RE.search(text):
        return False
    for marker in re.finditer(r"\bSCRIPT_FILENAME\b", text, re.IGNORECASE):
        window = text[max(0, marker.start() - 180) : marker.end() + 360]
        if "__FILE__" in window and re.search(r"\b(?:exit|die)\b", window, re.IGNORECASE):
            return True
    return False


def _looks_like_include_only_template(text: str, path: Path | None) -> bool:
    """Identify view-like files that should not be called public endpoints."""
    if _has_abspath_guard(text) or _has_direct_execution_guard(text) or WP_BOOTSTRAP_RE.search(text):
        return False
    if re.search(
        r"\b(?:add_action|add_filter|register_rest_route|add_shortcode|wp_ajax(?:_nopriv)?_)\b",
        text,
        re.IGNORECASE,
    ):
        return False

    has_markup = bool(
        re.search(r"<(?:a|div|form|h[1-6]|input|label|select|table|textarea)\b", text, re.IGNORECASE)
    )
    has_view_binding = bool(re.search(r"\$this\s*->|\bself::|\$hook_suffix\b", text, re.IGNORECASE))
    normalized_path = str(path or "").replace("\\", "/").lower()
    path_hint = bool(
        re.search(
            r"/(?:admin|include|includes|pages|templates?|views?)/|"
            r"(?:admin|settings|panel|template|view|include)[^/]*\.php$",
            normalized_path,
        )
    )
    return has_markup and (has_view_binding or path_hint)


def _direct_file_info(text: str, path: Path | None) -> Dict[str, Any]:
    has_abspath_guard = _has_abspath_guard(text)
    has_direct_execution_guard = _has_direct_execution_guard(text)
    loads_wordpress = bool(WP_BOOTSTRAP_RE.search(text))
    has_auth_marker = bool(AUTH_MARKER_RE.search(text))
    include_only = _looks_like_include_only_template(text, path)
    risky_name = bool(path and RISKY_DIRECT_FILE_NAMES.search(path.name))

    if has_abspath_guard or has_direct_execution_guard:
        kind = "guarded_include"
        exposure = "unknown"
        candidate = True
    elif include_only:
        kind = "include_only"
        exposure = "unknown"
        candidate = True
    elif loads_wordpress or risky_name:
        kind = "direct_php"
        exposure = "authenticated" if has_auth_marker else "unauthenticated"
        candidate = True
    else:
        kind = "direct_php"
        exposure = "unknown"
        candidate = False

    return {
        "kind": kind,
        "name": path.name if path else "",
        "callback": "",
        "exposure": exposure,
        "line": 1,
        "raw": "direct PHP file candidate",
        "candidate": candidate,
        "has_abspath_guard": has_abspath_guard,
        "has_direct_execution_guard": has_direct_execution_guard,
        "loads_wordpress": loads_wordpress,
        "include_only": include_only,
    }


def _classify_hook(hook: str) -> tuple[str, str]:
    hook_lower = hook.lower()

    if hook_lower.startswith("wp_ajax_nopriv_"):
        return "ajax_nopriv", "unauthenticated"
    if hook_lower.startswith("wp_ajax_"):
        return "ajax", "authenticated"
    if hook_lower.startswith("admin_post_nopriv_"):
        return "admin_post_nopriv", "unauthenticated"
    if hook_lower.startswith("admin_post_"):
        return "admin_post", "authenticated"
    if hook_lower in PUBLIC_HOOKS:
        return "public_hook", "public"
    if hook_lower in ADMIN_HOOKS or hook_lower.startswith("admin_"):
        return "admin_hook", "admin"
    return "hook", "unknown"


def _classify_rest(block: str) -> tuple[str, str]:
    lower = block.lower()
    if "permission_callback" not in lower:
        return "rest_route", "unknown"
    if "__return_true" in lower:
        return "rest_route", "unauthenticated"
    if "current_user_can" in lower and "manage_options" in lower:
        return "rest_route", "admin"
    if "current_user_can" in lower:
        return "rest_route", "authenticated"
    return "rest_route", "unknown"


def _admin_only_hint(text: str) -> bool:
    lower = text.lower().replace(" ", "")
    compact_markers = tuple(marker.lower().replace(" ", "") for marker in ADMIN_ONLY_MARKERS)
    return any(marker in lower for marker in compact_markers)


def _find_function_end(lines: List[str], start_index: int) -> int:
    """Find a named function's closing brace while ignoring strings/comments."""
    depth = 0
    started = False
    quote = ""
    escaped = False
    in_block_comment = False

    for line_index in range(start_index, len(lines)):
        line = lines[line_index]
        char_index = 0
        while char_index < len(line):
            char = line[char_index]
            pair = line[char_index : char_index + 2]

            if in_block_comment:
                if pair == "*/":
                    in_block_comment = False
                    char_index += 2
                else:
                    char_index += 1
                continue
            if quote:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = ""
                char_index += 1
                continue
            if pair == "/*":
                in_block_comment = True
                char_index += 2
                continue
            if pair == "//" or char == "#":
                break
            if char in ("'", '"'):
                quote = char
            elif char == "{":
                depth += 1
                started = True
            elif char == "}" and started:
                depth -= 1
                if depth == 0:
                    return line_index + 1
            char_index += 1

    return len(lines)


def function_for_line(analysis: Dict[str, Any], line_no: int) -> Dict[str, Any]:
    for function in analysis.get("functions", []):
        if function["line"] <= line_no <= function.get("end_line", line_no):
            return function
    return {}


def analyze_entrypoints(text: str, path: Path | None = None) -> Dict[str, Any]:
    lines = text.splitlines()
    entries: List[Dict[str, Any]] = []
    functions: List[Dict[str, Any]] = []
    classes: List[Dict[str, Any]] = []

    for idx, line in enumerate(lines, start=1):
        class_match = CLASS_RE.search(line)
        if class_match:
            classes.append(
                {
                    "name": class_match.group("name"),
                    "parent": class_match.group("parent") or "",
                    "line": idx,
                }
            )
        function_match = FUNCTION_RE.search(line)
        if function_match:
            functions.append(
                {
                    "name": function_match.group(1),
                    "line": idx,
                    "parameters": re.findall(
                        r"\$[a-zA-Z_][a-zA-Z0-9_]*",
                        function_match.group(2),
                    ),
                }
            )

        action_match = ADD_ACTION_RE.search(line)
        if action_match:
            hook = action_match.group(1)
            kind, exposure = _classify_hook(hook)
            entries.append(
                {
                    "kind": kind,
                    "name": hook,
                    "callback": _extract_callback(line, skip=1),
                    "exposure": exposure,
                    "line": idx,
                    "raw": line.strip(),
                }
            )

        filter_match = ADD_FILTER_RE.search(line)
        if filter_match:
            hook = filter_match.group(1)
            kind, exposure = _classify_hook(hook)
            entries.append(
                {
                    "kind": "filter" if kind == "hook" else kind,
                    "name": hook,
                    "callback": _extract_callback(line, skip=1),
                    "exposure": exposure,
                    "line": idx,
                    "raw": line.strip(),
                }
            )

        for _name, arguments in iter_named_function_calls(line, {"add_shortcode"}):
            if len(arguments) < 2:
                continue
            entries.append(
                {
                    "kind": "shortcode",
                    "name": _static_argument(arguments[0]) or arguments[0].strip(),
                    "callback": _callable_name(arguments[1]),
                    "exposure": "contributor",
                    "line": idx,
                    "raw": line.strip(),
                }
            )

        for page_function, arguments in iter_named_function_calls(line, ADMIN_PAGE_FUNCTIONS):
            if page_function == "add_submenu_page":
                if len(arguments) < 6:
                    continue
                capability_index = 3
                name_index = 4
                callback_index = 5
            else:
                if len(arguments) < 5:
                    continue
                capability_index = 2
                name_index = 3
                callback_index = 4
            capability = _static_argument(arguments[capability_index])
            callback = _callable_name(arguments[callback_index])
            entries.append(
                {
                    "kind": "admin_page",
                    "name": _static_argument(arguments[name_index]) or page_function,
                    "callback": callback,
                    "capability": capability,
                    "exposure": _capability_exposure(capability),
                    "line": idx,
                    "raw": line.strip(),
                }
            )

        rest_match = REST_ROUTE_RE.search(_line_at(lines, idx - 1))
        if rest_match:
            block = _line_at(lines, idx - 1)
            kind, exposure = _classify_rest(block)
            entries.append(
                {
                    "kind": kind,
                    "name": f"{rest_match.group(1)}{rest_match.group(2)}",
                    "callback": _extract_callback(block, skip=2),
                    "exposure": exposure,
                    "line": idx,
                    "raw": line.strip(),
                }
            )

    for function in functions:
        function["end_line"] = _find_function_end(lines, function["line"] - 1)
    for class_record in classes:
        class_record["end_line"] = _find_function_end(lines, class_record["line"] - 1)
    for function in functions:
        owner = next(
            (
                class_record
                for class_record in classes
                if class_record["line"] <= function["line"] <= class_record["end_line"]
            ),
            None,
        )
        if owner:
            function["class_name"] = owner["name"]
            function["class_parent"] = owner["parent"]

    file_path = Path(path) if path is not None else None
    direct_file = _direct_file_info(text, file_path)

    return {
        "entries": entries,
        "functions": functions,
        "text": text,
        "direct_file": direct_file,
    }


def build_shortcode_callback_index(
    paths: Iterable[Path], plugin_root: Path
) -> Dict[str, Set[str]]:
    """Return uniquely defined registered shortcode callbacks per plugin.

    A callback is shared across files only when the plugin registers it and
    exactly one named function/method with that name exists in that plugin.
    Ambiguous callback names are intentionally omitted.
    """
    registrations: Dict[str, Set[str]] = defaultdict(set)
    definitions: Dict[str, Counter[str]] = defaultdict(Counter)
    for path in paths:
        plugin = plugin_name_from_path(path, plugin_root)
        analysis = analyze_entrypoints(safe_read_text(path), path)
        registrations[plugin].update(
            str(entry.get("callback", "")).casefold()
            for entry in analysis.get("entries", [])
            if entry.get("kind") == "shortcode" and entry.get("callback")
        )
        definitions[plugin].update(
            str(function.get("name", ""))
            for function in analysis.get("functions", [])
            if function.get("name")
        )
    return {
        plugin: {
            callback
            for callback in callbacks
            if definitions[plugin].get(callback, 0) == 1
        }
        for plugin, callbacks in registrations.items()
    }


def build_helper_handoff_index(
    paths: Iterable[Path], plugin_root: Path
) -> tuple[Dict[str, Set[str]], Dict[str, Dict[str, Dict[str, Any]]]]:
    """Return registered callbacks and uniquely defined named helpers per plugin.

    The index deliberately resolves only a bare function/method name that has
    exactly one definition in the plugin.  Dynamic callables, inherited
    methods, and ambiguous duplicate names are therefore outside this model.
    """
    registrations: Dict[str, Set[str]] = defaultdict(set)
    definitions: Dict[str, Dict[str, List[Dict[str, Any]]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for path in paths:
        plugin = plugin_name_from_path(path, plugin_root)
        analysis = analyze_entrypoints(safe_read_text(path), path)
        registrations[plugin].update(
            str(entry.get("callback", ""))
            for entry in analysis.get("entries", [])
            if entry.get("callback")
        )
        for function in analysis.get("functions", []):
            name = str(function.get("name", "")).casefold()
            if not name:
                continue
            definitions[plugin][name].append(
                {
                    "name": name,
                    "path": path.resolve(),
                    "line": int(function.get("line", 0)),
                    "end_line": int(function.get("end_line", 0)),
                    "parameters": list(function.get("parameters", [])),
                }
            )

    unique_definitions = {
        plugin: {
            name: records[0]
            for name, records in named_definitions.items()
            if len(records) == 1
        }
        for plugin, named_definitions in definitions.items()
    }
    unique_registrations = {
        plugin: {
            callback
            for callback in callbacks
            if callback in unique_definitions.get(plugin, {})
        }
        for plugin, callbacks in registrations.items()
    }
    return unique_registrations, unique_definitions


def build_scanner_indexes(
    paths: Iterable[Path], plugin_root: Path
) -> tuple[
    Dict[str, Set[str]],
    Dict[str, Set[str]],
    Dict[str, Dict[str, Dict[str, Any]]],
]:
    """Build shortcode and helper-handoff indexes in one source pass.

    This preserves the public outputs of ``build_shortcode_callback_index``
    and ``build_helper_handoff_index`` while avoiding a second complete parse
    of every plugin file in normal scanner and benchmark runs.
    """
    shortcode_registrations: Dict[str, Set[str]] = defaultdict(set)
    registered_callbacks: Dict[str, Set[str]] = defaultdict(set)
    shortcode_definition_counts: Dict[str, Counter[str]] = defaultdict(Counter)
    helper_definitions: Dict[str, Dict[str, List[Dict[str, Any]]]] = defaultdict(
        lambda: defaultdict(list)
    )

    for path in paths:
        plugin = plugin_name_from_path(path, plugin_root)
        # The separate builders materialize empty per-plugin entries while
        # visiting files.  Keep that observable mapping shape unchanged.
        shortcode_registrations[plugin]
        registered_callbacks[plugin]
        shortcode_definition_counts[plugin]
        helper_definitions[plugin]
        analysis = analyze_entrypoints(safe_read_text(path), path)
        for entry in analysis.get("entries", []):
            callback = str(entry.get("callback", ""))
            if not callback:
                continue
            # Preserve the established index contract exactly.  Callback
            # capitalization normalization is a separate scanner behavior
            # change and must be benchmarked independently.
            registered_callbacks[plugin].add(callback)
            if entry.get("kind") == "shortcode":
                shortcode_registrations[plugin].add(callback.casefold())

        for function in analysis.get("functions", []):
            original_name = str(function.get("name", ""))
            if not original_name:
                continue
            shortcode_definition_counts[plugin][original_name] += 1
            helper_name = original_name.casefold()
            helper_definitions[plugin][helper_name].append(
                {
                    "name": helper_name,
                    "path": path.resolve(),
                    "line": int(function.get("line", 0)),
                    "end_line": int(function.get("end_line", 0)),
                    "parameters": list(function.get("parameters", [])),
                }
            )

    shortcode_callbacks = {
        plugin: {
            callback
            for callback in callbacks
            if shortcode_definition_counts[plugin].get(callback, 0) == 1
        }
        for plugin, callbacks in shortcode_registrations.items()
    }
    unique_function_definitions = {
        plugin: {
            name: records[0]
            for name, records in named_definitions.items()
            if len(records) == 1
        }
        for plugin, named_definitions in helper_definitions.items()
    }
    unique_registered_callbacks = {
        plugin: {
            callback
            for callback in callbacks
            if callback in unique_function_definitions.get(plugin, {})
        }
        for plugin, callbacks in registered_callbacks.items()
    }
    return (
        shortcode_callbacks,
        unique_registered_callbacks,
        unique_function_definitions,
    )


def _current_function(analysis: Dict[str, Any], line_no: int) -> str:
    return str(function_for_line(analysis, line_no).get("name", ""))


def _pick_entries(analysis: Dict[str, Any], line_no: int) -> List[Dict[str, Any]]:
    entries = analysis.get("entries", [])
    function_name = _current_function(analysis, line_no)

    if function_name:
        callback_entries = [entry for entry in entries if entry.get("callback") == function_name]
        if callback_entries:
            return callback_entries[:3]

    direct_file = analysis.get("direct_file", {})
    if not function_name and direct_file.get("candidate"):
        return [direct_file]

    nearby = [entry for entry in entries if abs(int(entry.get("line", 0)) - line_no) <= 80]
    if nearby:
        return sorted(nearby, key=lambda entry: abs(int(entry.get("line", 0)) - line_no))[:3]

    before = [entry for entry in entries if int(entry.get("line", 0)) <= line_no]
    if before:
        return sorted(before, key=lambda entry: int(entry.get("line", 0)), reverse=True)[:1]

    return []


def summarize_entrypoints_for_line(
    analysis: Dict[str, Any],
    line_no: int,
    snippet: str,
) -> Dict[str, str]:
    entries = _pick_entries(analysis, line_no)
    function_name = _current_function(analysis, line_no)

    kinds = sorted({str(entry.get("kind", "")) for entry in entries if entry.get("kind")})
    names = sorted({str(entry.get("name", "")) for entry in entries if entry.get("name")})
    exposures = sorted({str(entry.get("exposure", "")) for entry in entries if entry.get("exposure")})
    lines = sorted({str(entry.get("line", "")) for entry in entries if entry.get("line")})

    entry_raw = "\n".join(str(entry.get("raw", "")) for entry in entries)
    local_text = f"{snippet}\n{entry_raw}"
    admin_page_entries = [entry for entry in entries if entry.get("kind") == "admin_page"]
    if admin_page_entries:
        admin_only = any(entry.get("exposure") == "admin" for entry in admin_page_entries)
        admin_only = admin_only or _admin_only_hint(local_text.replace("admin_menu", ""))
    else:
        admin_only = _admin_only_hint(local_text) or "admin" in exposures

    if "unauthenticated" in exposures:
        poc_priority = "high_unauthenticated"
    elif "public" in exposures:
        poc_priority = "high_public"
    elif "contributor" in exposures:
        poc_priority = "medium_contributor"
    elif "authenticated" in exposures and not admin_only:
        poc_priority = "medium_authenticated"
    elif admin_only:
        poc_priority = "skip_admin_only"
    else:
        poc_priority = "review_unknown"

    return {
        "entrypoint_kind": " | ".join(kinds),
        "entrypoint_name": " | ".join(names),
        "entrypoint_exposure": " | ".join(exposures),
        "entrypoint_role": "admin" if admin_only else "",
        "entrypoint_line": " | ".join(lines),
        "entrypoint_function": function_name,
        "admin_only_hint": str(bool(admin_only)),
        "poc_priority": poc_priority,
    }
