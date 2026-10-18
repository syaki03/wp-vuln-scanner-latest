SOURCE_SCORES = {
    "legacy_url_input": 30,
    "legacy_implicit_request_uri": 30,
    "legacy_superglobals": 28,
    "raw_request_body": 28,
    "input_api": 25,
    "superglobals": 25,
    "rest": 22,
    "shortcode_attrs": 22,
    # CSV fields and EXIF headers are external structured data, but are less
    # directly attributable to a request than the usual WordPress sources.
    "external_structured_data": 2,
    "wordpress_post_title": 18,
    "acf_field_value": 18,
    "content_cards_data": 18,
    "wordpress_comment_content": 18,
    "pretty_link_click_referer": 18,
    "buddypress_group_name": 18,
    "stored_read": 22,
    "plugin_stored_read": 6,
    "parse_str_scope": 16,
    "variable_flow": 16,
}

SINK_SCORES = {
    "html_output": 25,
    "shortcode_return": 30,
    "helper_return": 30,
    "dom_attr_like": 35,
    "js_context": 40,
}

CONTEXT_ESCAPES = {
    "html": {"escape_html", "html_allowlist"},
    "html_attribute": {"escape_attr"},
    "url_attribute": {"escape_url"},
    "textarea": {"escape_textarea"},
    "javascript": {"escape_js"},
}


def score_finding(
    source_kind: str,
    source_origin: str,
    sink_kind: str,
    storage_kind: str,
    sanitizer_hits: list,
    security_hits: list,
    snippet: str,
    context: str = "general",
    flow_evidence: str = "",
):
    score = SOURCE_SCORES.get(source_kind, 12)
    if source_kind == "variable_flow" and flow_evidence in {
        "unique_helper_argument",
        "unique_helper_return",
    }:
        origin_scores = [
            SOURCE_SCORES[origin]
            for origin in (part.strip() for part in source_origin.split("|"))
            if origin in SOURCE_SCORES
        ]
        if origin_scores:
            # A uniquely resolved helper boundary preserves the known source
            # provenance; do not collapse it to the generic variable score.
            score = max(origin_scores)
    elif source_kind == "variable_flow" and source_origin in {
        "acf_field_value",
        "content_cards_data",
        "external_structured_data",
        "pretty_link_click_referer",
        "wordpress_comment_content",
    }:
        # Preserve the deliberately lower source priority through existing
        # same-scope assignment/array/foreach propagation.
        score = SOURCE_SCORES[source_origin]
    score += SINK_SCORES.get(sink_kind, 0)

    if storage_kind == "writes":
        # A write is necessary evidence for stored XSS, but it is not the
        # user-visible sink.  Keep write-only candidates reviewable without
        # routinely ranking them above a matched read-to-output path.
        score += 25 if sink_kind else 10

    if flow_evidence == "same_statement":
        score += 12
    elif flow_evidence in {
        "variable_assignment",
        "literal_include_scope",
        "unique_helper_argument",
        "unique_helper_return",
    }:
        score += 8
    elif flow_evidence == "matched_stored_key":
        score += 10
    elif flow_evidence == "plugin_literal_storage":
        # Matching a plugin-wide literal key creates a reviewable candidate,
        # not proof that the write and read execute on the same runtime path.
        score += 0
    elif flow_evidence == "plugin_literal_sql_storage":
        # A literal custom table and column match is useful review evidence,
        # but it does not establish row identity or runtime reachability.
        score -= 4
    elif flow_evidence == "plugin_dynamic_subject_storage":
        # Both sides use a dynamic object identifier.  The literal meta key
        # and storage family match, but object identity remains unproven.
        score -= 3
    elif flow_evidence == "scope_created_variables":
        score -= 5

    sanitizer_kinds = {kind for kind, _ in sanitizer_hits}
    expected = CONTEXT_ESCAPES.get(context, set())
    if "numeric_cast" in sanitizer_kinds:
        score -= 45
    if expected.intersection(sanitizer_kinds):
        score -= 50
    elif any(kind.startswith("escape_") or kind == "html_allowlist" for kind in sanitizer_kinds):
        # An escape for the wrong context is evidence of intent, not mitigation.
        score -= 3

    # Input sanitizers and nonce/capability checks do not replace output
    # encoding, so neither lowers the XSS score.
    _ = security_hits, snippet

    if score >= 65:
        severity = "HIGH"
    elif score >= 40:
        severity = "MEDIUM"
    elif score >= 20:
        severity = "LOW"
    else:
        severity = "INFO"

    return score, severity
