SANITIZERS = {
    # Input normalization is useful evidence, but it is not output encoding.
    "input_sanitize": [
        r"\bsanitize_text_field\s*\(",
        r"\bsanitize_key\s*\(",
        r"\bsanitize_email\s*\(",
        r"\bsanitize_file_name\s*\(",
    ],
    "numeric_cast": [
        r"\babsint\s*\(",
        r"\bintval\s*\(",
        r"\bfloatval\s*\(",
        r"\bboolval\s*\(",
    ],
    "html_allowlist": [
        r"\bwp_kses\s*\(",
        r"\bwp_kses_post\s*\(",
    ],
    "escape_html": [
        r"\besc_html\s*\(",
        r"\b(?:wp_specialchars|_wp_specialchars)\s*\(",
    ],
    "escape_attr": [
        r"\besc_attr\s*\(",
        r"\battribute_escape\s*\(",
    ],
    "escape_url": [
        r"\besc_url\s*\(",
        r"\bclean_url\s*\(",
    ],
    "escape_js": [
        r"\besc_js\s*\(",
        r"\bjs_escape\s*\(",
    ],
    "escape_textarea": [
        r"\besc_textarea\s*\(",
    ],
    "security_checks": [
        r"\bcheck_admin_referer\s*\(",
        r"\bcheck_ajax_referer\s*\(",
        r"\bwp_verify_nonce\s*\(",
        r"\bcurrent_user_can\s*\(",
    ],
}
