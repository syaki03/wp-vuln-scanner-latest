JSONP_CALLBACK_PATTERN = (
    r"\$_(?:GET|POST|REQUEST|COOKIE)\s*\[\s*['\"]callback['\"]\s*\]\s*"
    r"\.\s*(?:['\"]\s*\(\s*\$[a-zA-Z_][a-zA-Z0-9_]*\s*\)\s*['\"]"
    r"|['\"]\s*\(\s*['\"]\s*\.\s*\$[a-zA-Z_][a-zA-Z0-9_]*\s*"
    r"\.\s*['\"]\s*\)\s*['\"])"
)


SINKS = {
    "html_output": [
        r"\becho\b",
        r"\bprint\b",
        r"\bprintf\s*\(",
        r"\b(?:die|exit)\s*\(",
        r"\bwp_die\s*\(",
        r"<\?=",
        # BuddyPress' bare template helper echoes the group name internally.
        # Keep this on a statement-leading global call so similarly named
        # getters, methods, and declarations do not become generic sinks.
        r"(?:<\?php\s+|\A\s*)bp_group_name\s*\(",
    ],
    "dom_attr_like": [
        r"(href|src|value|title|alt|data-[a-zA-Z0-9_-]+)\s*=\s*['\"][^'\"]*\$[a-zA-Z_][a-zA-Z0-9_]*",
    ],
    "js_context": [
        r"<script\b",
        r"onclick\s*=",
        r"onchange\s*=",
        r"onmouseover\s*=",
        r"\bwp_add_inline_script\s*\(",
        # JSONP executes the caller-controlled callback as JavaScript.  Keep
        # this intentionally limited to a request ``callback`` key followed
        # immediately by a parenthesized PHP payload construction; ordinary
        # JSON encoders and unrelated concatenations are not JavaScript sinks.
        JSONP_CALLBACK_PATTERN,
    ],
}
