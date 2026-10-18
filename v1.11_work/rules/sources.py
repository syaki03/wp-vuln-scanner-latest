SOURCES = {
    # High-value request sources found frequently in older plugins.  Keep these
    # before the generic superglobal rules so reports retain the useful subtype.
    "legacy_url_input": [
        r"\$_SERVER\s*\[\s*['\"](?:PHP_SELF|REQUEST_URI|HTTP_HOST|QUERY_STRING|PATH_INFO|ORIG_PATH_INFO|HTTP_[A-Z0-9_]+)['\"]\s*\]",
    ],
    "legacy_superglobals": [
        r"\$HTTP_(?:GET|POST|REQUEST|COOKIE|SERVER|ENV|FILES|SESSION)_VARS\b",
        r"\$HTTP_RAW_POST_DATA\b",
    ],
    "raw_request_body": [
        r"\bfile_get_contents\s*\(\s*['\"]php://input['\"]\s*\)",
        r"['\"]php://input['\"]",
    ],
    "input_api": [
        r"\bfilter_input(?:_array)?\s*\(",
    ],
    "superglobals": [
        r"\$_GET\b",
        r"\$_POST\b",
        r"\$_REQUEST\b",
        r"\$_COOKIE\b",
        r"\$_SERVER\b",
        r"\$_FILES\b",
    ],
    "rest": [
        r"\bWP_REST_Request\b",
        r"\$request->get_param\s*\(",
        r"\$request->get_params\s*\(",
        r"\$request->get_(?:body|query|url)_params\s*\(",
        r"\$request->get_json_params\s*\(",
        r"\$request->get_(?:body|header|headers)\s*\(",
    ],
    "shortcode_attrs": [
        r"\bshortcode_atts\s*\(",
    ],
    # These APIs return structured fields read from local attacker-supplied
    # artifacts.  They are intentionally narrower than generic file reads:
    # SplFileObject::fgetcsv()/fgetcsv() return CSV fields and
    # exif_read_data() returns image EXIF headers.
    "external_structured_data": [
        r"(?:\$[a-zA-Z_][a-zA-Z0-9_]*\s*->\s*)?fgetcsv\s*\(",
        r"\bexif_read_data\s*\(",
    ],
    # Post titles are persisted author-controlled content, not request input.
    # Keep this separate and lower-confidence so direct unescaped output is
    # reviewable without treating every WordPress storage read as tainted.
    "wordpress_post_title": [
        r"\bget_the_title\s*\(",
    ],
    # ACF's global get_field() API returns a persisted field value.  Limit the
    # heuristic to call-expression positions so the function declaration,
    # object/static methods, and similarly named helpers are not classified as
    # stored content sources.
    "acf_field_value": [
        r"(?:<\?php\s+|\A\s*|[=(,]\s*|\breturn\s+|\becho\s+)get_field\s*\(",
    ],
    # Content Cards exposes remote OpenGraph values, including values persisted
    # in post meta, through this global getter.  Limit the heuristic to
    # call-expression positions so its definition, methods, and similarly named
    # helpers are not classified as stored remote-content sources.
    "content_cards_data": [
        r"(?:<\?php\s+|\A\s*|[=(,]\s*|\breturn\s+|\becho\s+)get_cc_data\s*\(",
    ],
    # WordPress templates conventionally expose the current WP_Comment as
    # ``$comment``.  Without object type inference, keep this persisted-content
    # heuristic on that exact receiver and property instead of treating every
    # object's similarly named field as a WordPress comment.
    "wordpress_comment_content": [
        r"\$comment\s*->\s*comment_content\b(?!\s*\()",
    ],
    # Pretty Links 2.1.9 stores a visitor-controlled HTTP Referer in each click
    # record and its click-list template exposes that persisted value through
    # this exact object/property shape.  Keep the heuristic on the concrete
    # receiver so generic objects with a similarly named field are not sources.
    "pretty_link_click_referer": [
        r"\$click\s*->\s*referer\b(?!\s*\()",
    ],
    # BuddyPress 1.9.x template code uses this bare global helper to echo the
    # current persisted group name.  Match only a PHP template statement that
    # starts with the helper call; do not treat the getter, a method, or the
    # function declaration as this persisted-content source.
    "buddypress_group_name": [
        r"(?:<\?php\s+|\A\s*)bp_group_name\s*\(",
    ],
}
