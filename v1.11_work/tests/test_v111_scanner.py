import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from scanner import taint_engine
from scanner.sanitizer_detector import detect_sanitizers
from scanner.sink_detector import detect_sinks
from scanner.source_detector import detect_sources
from scanner.entrypoint_detector import (
    analyze_entrypoints,
    build_helper_handoff_index,
    build_scanner_indexes,
    build_shortcode_callback_index,
)
from scanner.taint_engine import analyze_php_file, build_tainted_storage_index
from scanner.utils import plugin_name_from_path


class RuleModelTests(unittest.TestCase):
    def test_nested_file_uses_top_level_plugin_name(self):
        root = Path("C:/plugins")
        path = root / "old-plugin" / "includes" / "admin" / "page.php"
        self.assertEqual("old-plugin", plugin_name_from_path(path, root))

    def test_removed_false_positive_sinks(self):
        text = "return $value; wp_send_json($value); wp_localize_script('h', 'o', $value);"
        self.assertEqual([], detect_sinks(text))

    def test_new_output_sinks(self):
        kinds = {
            kind
            for kind, _ in detect_sinks(
                "<?= $value ?> wp_add_inline_script('h', $value); wp_die($value);"
            )
        }
        self.assertIn("html_output", kinds)
        self.assertIn("js_context", kinds)

    def test_jsonp_request_callback_payload_is_a_javascript_sink(self):
        kinds = {
            kind
            for kind, _ in detect_sinks(
                '$_GET[\'callback\']."($return)";'
            )
        }
        self.assertEqual({"js_context"}, kinds)

    def test_jsonp_rule_rejects_non_callback_json_and_concatenation(self):
        for text in (
            "wp_send_json($_GET['callback']);",
            "json_encode($_GET['callback']);",
            "$_GET['other'] . \"($return)\";",
            "$fixed_callback . \"($return)\";",
        ):
            self.assertEqual([], detect_sinks(text), text)

    def test_unslash_is_not_a_sanitizer(self):
        self.assertEqual([], detect_sanitizers("wp_unslash($value)"))

    def test_legacy_escape_aliases_are_contextual(self):
        hits = detect_sanitizers(
            "wp_specialchars($a); attribute_escape($b); clean_url($c); js_escape($d);"
        )
        self.assertEqual(
            {"escape_html", "escape_attr", "escape_url", "escape_js"},
            {kind for kind, _ in hits},
        )

    def test_legacy_request_sources(self):
        text = (
            "$a = $HTTP_GET_VARS['x']; "
            "$b = filter_input(INPUT_GET, 'x'); "
            "$c = file_get_contents('php://input');"
        )
        kinds = {kind for kind, _ in detect_sources(text)}
        self.assertTrue({"legacy_superglobals", "input_api", "raw_request_body"} <= kinds)

    def test_query_arg_implicit_uri_is_a_source(self):
        kinds = {kind for kind, _ in detect_sources("add_query_arg('page', 'old')")}
        self.assertIn("legacy_implicit_request_uri", kinds)

    def test_query_arg_explicit_array_url_is_not_a_source(self):
        hits = detect_sources("add_query_arg(array('page' => 'old'), 'https://example.test/')")
        self.assertNotIn("legacy_implicit_request_uri", {kind for kind, _ in hits})

    def test_get_the_title_is_a_persisted_content_source(self):
        kinds = {kind for kind, _ in detect_sources("get_the_title( $post_id )")}
        self.assertIn("wordpress_post_title", kinds)

    def test_acf_get_field_is_a_persisted_content_source(self):
        kinds = {kind for kind, _ in detect_sources("$value = get_field( $selector );")}
        self.assertIn("acf_field_value", kinds)

    def test_acf_get_field_rule_rejects_non_global_call_shapes(self):
        for text in (
            "function get_field( $selector ) { return 'clean'; }",
            "$object->get_field( $selector );",
            "FieldStore::get_field( $selector );",
            "$value = get_fields( $selector );",
            "$value = my_get_field( $selector );",
        ):
            with self.subTest(text=text):
                kinds = {kind for kind, _ in detect_sources(text)}
                self.assertNotIn("acf_field_value", kinds)

    def test_content_cards_getter_is_a_persisted_remote_data_source(self):
        kinds = {
            kind for kind, _ in detect_sources("$value = get_cc_data( 'title' );")
        }
        self.assertIn("content_cards_data", kinds)

    def test_content_cards_getter_rule_rejects_non_global_call_shapes(self):
        for text in (
            "function get_cc_data( $key ) { return 'clean'; }",
            "$object->get_cc_data( $key );",
            "Content_Cards::get_cc_data( $key );",
            "$value = get_cc_datas( $key );",
            "$value = my_get_cc_data( $key );",
        ):
            with self.subTest(text=text):
                kinds = {kind for kind, _ in detect_sources(text)}
                self.assertNotIn("content_cards_data", kinds)

    def test_buddypress_group_name_bare_template_call_is_source_and_sink(self):
        text = "<?php bp_group_name( $group );"
        source_kinds = {kind for kind, _ in detect_sources(text)}
        sink_kinds = {kind for kind, _ in detect_sinks(text)}
        self.assertIn("buddypress_group_name", source_kinds)
        self.assertIn("html_output", sink_kinds)

    def test_buddypress_group_name_rule_rejects_non_output_shapes(self):
        for text in (
            "<?php bp_get_group_name();",
            "<?php echo bp_get_group_name();",
            "<?php $object->bp_group_name();",
            "<?php function bp_group_name() { echo 'clean'; }",
        ):
            with self.subTest(text=text):
                source_kinds = {kind for kind, _ in detect_sources(text)}
                self.assertNotIn("buddypress_group_name", source_kinds)

    def test_wordpress_comment_content_is_an_exact_object_property_source(self):
        kinds = {
            kind
            for kind, _ in detect_sources(
                "$comment->comment_content;"
            )
        }
        self.assertIn("wordpress_comment_content", kinds)

        non_sources = (
            "$comment['comment_content'];",
            "$comment->comment_content_filtered;",
            "$comment->comment_author;",
            "comment_content;",
            "$comment->comment_content();",
            "$note->comment_content;",
            "$latest_note->comment_content;",
        )
        for text in non_sources:
            with self.subTest(text=text):
                kinds = {kind for kind, _ in detect_sources(text)}
                self.assertNotIn("wordpress_comment_content", kinds)

    def test_pretty_link_click_referer_is_an_exact_object_property_source(self):
        kinds = {kind for kind, _ in detect_sources("$click->referer;")}
        self.assertIn("pretty_link_click_referer", kinds)

        non_sources = (
            "$click['referer'];",
            "$click->referer_url;",
            "$click->referer();",
            "$click->host;",
            "$clicks->referer;",
            "$row->referer;",
            "referer;",
        )
        for text in non_sources:
            with self.subTest(text=text):
                kinds = {kind for kind, _ in detect_sources(text)}
                self.assertNotIn("pretty_link_click_referer", kinds)

    def test_external_structured_data_sources_are_narrow(self):
        text = "$row = $csv->fgetcsv(','); $meta = exif_read_data($image);"
        kinds = {kind for kind, _ in detect_sources(text)}
        self.assertIn("external_structured_data", kinds)
        self.assertNotIn(
            "external_structured_data",
            {kind for kind, _ in detect_sources("$value = ordinary_reader($file);")},
        )

    def test_add_submenu_page_uses_submenu_argument_positions(self):
        source = (
            "<?php add_submenu_page('mfmain', 'User Groups', 'User Groups', "
            "'administrator', 'mfgroups', array(&$wpfa, 'usergroups'));"
        )
        entries = analyze_entrypoints(source)["entries"]
        self.assertEqual(1, len(entries))
        self.assertEqual("mfgroups", entries[0]["name"])
        self.assertEqual("usergroups", entries[0]["callback"])
        self.assertEqual("administrator", entries[0]["capability"])
        self.assertEqual("authenticated", entries[0]["exposure"])

    def test_entrypoint_functions_record_lexical_class_ownership(self):
        functions = analyze_entrypoints(
            "<?php\n// class Fake {\nfinal class Child extends ParentClass { function render() {} }\nfunction plain() {}"
        )["functions"]
        self.assertEqual("Child", functions[0]["class_name"])
        self.assertEqual("ParentClass", functions[0]["class_parent"])
        self.assertNotIn("class_name", functions[1])


class FlowModelTests(unittest.TestCase):
    def analyze(self, php: str, name: str = "plugin.php"):
        with tempfile.TemporaryDirectory() as directory:
            plugin = Path(directory) / "old-plugin"
            plugin.mkdir()
            path = plugin / name
            path.write_text(php, encoding="utf-8")
            return analyze_php_file(path)

    def analyze_handoff_plugin(self, sources: dict[str, str]):
        with tempfile.TemporaryDirectory() as directory:
            plugin_root = Path(directory)
            plugin = plugin_root / "old-plugin"
            plugin.mkdir()
            paths = []
            for name, source in sources.items():
                path = plugin / name
                path.write_text(source, encoding="utf-8")
                paths.append(path)
            registered, definitions = build_helper_handoff_index(paths, plugin_root)
            findings = []
            for path in paths:
                findings.extend(
                    analyze_php_file(
                        path,
                        registered_callbacks=registered.get("old-plugin", set()),
                        unique_function_definitions=definitions.get("old-plugin", {}),
                    )
                )
            return findings

    def analyze_custom_sql_plugin(self, sources: dict[str, str]):
        with tempfile.TemporaryDirectory() as directory:
            plugin_root = Path(directory)
            plugin = plugin_root / "old-plugin"
            plugin.mkdir()
            paths = []
            for name, source in sources.items():
                path = plugin / name
                path.write_text(source, encoding="utf-8")
                paths.append(path)
            index = build_tainted_storage_index(paths, plugin_root, {})
            findings = []
            for path in paths:
                findings.extend(
                    analyze_php_file(path, tainted_storage_keys=index.get("old-plugin", set()))
                )
            return findings, index

    def analyze_attachment_metadata_plugin(self, sources: dict[str, str]):
        with tempfile.TemporaryDirectory() as directory:
            plugin_root = Path(directory)
            plugin = plugin_root / "old-plugin"
            plugin.mkdir()
            paths = []
            for name, source in sources.items():
                path = plugin / name
                path.write_text(source, encoding="utf-8")
                paths.append(path)
            index = build_tainted_storage_index(paths, plugin_root, {})
            findings = []
            for path in paths:
                findings.extend(
                    analyze_php_file(
                        path,
                        tainted_storage_keys=index.get("old-plugin", set()),
                    )
                )
            return findings, index

    def analyze_same_instance_plugin(self, sources: dict[str, str]):
        with tempfile.TemporaryDirectory() as directory:
            plugin_root = Path(directory)
            plugin = plugin_root / "old-plugin"
            plugin.mkdir()
            paths = []
            for name, source in sources.items():
                path = plugin / name
                path.write_text(source, encoding="utf-8")
                paths.append(path)
            index = build_tainted_storage_index(paths, plugin_root, {})
            findings = []
            for path in paths:
                findings.extend(
                    analyze_php_file(path, tainted_storage_keys=index.get("old-plugin", set()))
                )
            return findings, index

    def analyze_indexed_plugin(self, sources: dict[str, str]):
        with tempfile.TemporaryDirectory() as directory:
            plugin_root = Path(directory)
            plugin = plugin_root / "old-plugin"
            plugin.mkdir()
            paths = []
            for name, source in sources.items():
                path = plugin / name
                path.write_text(source, encoding="utf-8")
                paths.append(path)
            shortcodes, registered, definitions = build_scanner_indexes(paths, plugin_root)
            index = build_tainted_storage_index(paths, plugin_root, shortcodes)
            findings = []
            for path in paths:
                findings.extend(
                    analyze_php_file(
                        path,
                        shortcode_callbacks=shortcodes.get("old-plugin", set()),
                        tainted_storage_keys=index.get("old-plugin", set()),
                        registered_callbacks=registered.get("old-plugin", set()),
                        unique_function_definitions=definitions.get("old-plugin", {}),
                    )
                )
            return findings, index

    def test_same_instance_helper_return_requires_exact_lexical_boundaries(self):
        positive = """<?php
class Field {
 function getValue($name) { $value = $_REQUEST[$name]; return $value; }
 function getInput($name) { $value = $this->getValue($name); return '<input value="' . $value . '">'; }
}
$field = new Field(); echo $field->getInput('name');
"""
        findings, index = self.analyze_same_instance_plugin({"field.php": positive})
        self.assertIn(("same_instance_output_method", "getinput", ""), index["old-plugin"])
        self.assertEqual(1, len(findings))
        self.assertEqual("helper_return", findings[0]["sink_kind"])
        self.assertEqual("same_instance_helper_return", findings[0]["flow_evidence"])
        self.assertEqual("medium", findings[0]["confidence"])

        cases = {
            "no_output_consumed_call": positive.replace("echo $field->getInput('name');", "$field->getInput('name');"),
            "other_receiver": positive.replace("$this->getValue($name)", "$other->getValue($name)"),
            "dynamic_method": positive.replace("$this->getValue($name)", "$this->$method($name)"),
            "duplicate_same_class_method": positive.replace(
                " function getInput",
                " function getValue($name) { $value = $_REQUEST[$name]; return $value; }\n function getInput",
                1,
            ),
            "parameter_return": positive.replace("return $value;", "return $name;", 1),
            "property_return": positive.replace("return $value;", "return $this->value;", 1),
            "clean_return": positive.replace("return $value;", "return 'clean';", 1),
            "clean_overwrite": positive.replace(
                "$value = $this->getValue($name);",
                "$value = $this->getValue($name); $value = 'safe';",
            ),
            "non_html_return": positive.replace("return '<input value=\"' . $value . '\">';", "return $value;"),
            "missing_assigned_value": positive.replace(" . $value . '\">';", " . 'safe' . '\">';"),
        }
        inherited = """<?php
class ParentField { function getValue($name) { $value = $_REQUEST[$name]; return $value; } }
class Field extends ParentField { function getInput($name) { $value = $this->getValue($name); return '<input value="' . $value . '">'; } }
$field = new Field(); echo $field->getInput('name');
"""
        cases["inherited_helper"] = inherited
        for name, source in cases.items():
            with self.subTest(name=name):
                findings, _index = self.analyze_same_instance_plugin({"field.php": source})
                self.assertEqual([], findings)

    def test_registered_callback_hands_tainted_positional_argument_to_unique_helper(self):
        findings = self.analyze_handoff_plugin(
            {
                "plugin.php": """<?php
add_action('wp_ajax_nopriv_demo', 'demo_callback');
function demo_callback() { render_value($_GET['name'], 'safe'); }
function render_value($value, $other) { echo $value; }
"""
            }
        )
        self.assertEqual(1, len(findings))
        self.assertEqual("unique_helper_argument", findings[0]["flow_evidence"])
        self.assertEqual("ajax_nopriv", findings[0]["entrypoint_kind"])

    def test_registered_callback_imports_one_tainted_literal_option_global_field(self):
        positive = """<?php
$mcsp_opt = get_option('old_options');
add_action('admin_menu', 'save_options');
add_filter('preprocess_comment', 'check_comment');
function save_options() {
    $options = array('unsafe' => $_POST['unsafe'], 'clean' => 'safe');
    update_option('old_options', $options);
}
function check_comment() {
    global $mcsp_opt;
    render_error($mcsp_opt['unsafe']);
}
function render_error($message) { wp_die($message); }
"""
        findings, index = self.analyze_indexed_plugin({"plugin.php": positive})
        self.assertIn(("option", "", "old_options"), index["old-plugin"])
        self.assertIn(
            ("global_option_field", "old_options", "unsafe"), index["old-plugin"]
        )
        target = [
            finding
            for finding in findings
            if finding["sink_kind"] == "html_output"
            and finding["file"].endswith("plugin.php")
            and finding["line"] == 13
        ]
        self.assertEqual(1, len(target))
        self.assertEqual("unique_helper_argument", target[0]["flow_evidence"])
        self.assertEqual("plugin_stored_read", target[0]["source_origin"])

        cases = {
            "dynamic_key": positive.replace(
                "get_option('old_options')", "get_option($option_key)"
            ),
            "other_global": positive.replace(
                "global $mcsp_opt;\n    render_error($mcsp_opt['unsafe']);",
                "global $other;\n    render_error($other['unsafe']);",
            ),
            "clean_sibling": positive.replace("['unsafe']);", "['clean']);", 1),
            "unregistered_callback": positive.replace(
                "add_filter('preprocess_comment', 'check_comment');\n", ""
            ),
            "top_level_overwrite": positive.replace(
                "$mcsp_opt = get_option('old_options');",
                "$mcsp_opt = get_option('old_options');\n$mcsp_opt = array();",
            ),
            "field_clean_overwrite": positive.replace(
                "global $mcsp_opt;",
                "global $mcsp_opt;\n    $mcsp_opt['unsafe'] = 'safe';",
            ),
        }
        for name, source in cases.items():
            with self.subTest(name=name):
                findings, _index = self.analyze_indexed_plugin({"plugin.php": source})
                self.assertFalse(
                    any(
                        finding["sink_kind"] == "html_output"
                        and finding["flow_evidence"] == "unique_helper_argument"
                        and finding["source_origin"] == "plugin_stored_read"
                        for finding in findings
                    )
                )

        findings, _index = self.analyze_indexed_plugin(
            {
                "plugin.php": positive,
                "overwrite.php": "<?php $mcsp_opt = array();",
            }
        )
        self.assertFalse(
            any(
                finding["sink_kind"] == "html_output"
                and finding["file"].endswith("plugin.php")
                and finding["flow_evidence"] == "unique_helper_argument"
                and finding["source_origin"] == "plugin_stored_read"
                for finding in findings
            )
        )

    def test_helper_handoff_maps_only_matching_positional_parameter(self):
        findings = self.analyze_handoff_plugin(
            {
                "plugin.php": """<?php
add_action('wp_ajax_nopriv_demo', 'demo_callback');
function demo_callback() { render_value('safe', $_GET['name']); }
function render_value($output, $unused) { echo $output; }
"""
            }
        )
        self.assertEqual([], findings)

    def test_helper_handoff_requires_registered_root_callback(self):
        findings = self.analyze_handoff_plugin(
            {
                "plugin.php": """<?php
function ordinary_function() { render_value($_GET['name']); }
function render_value($value) { echo $value; }
"""
            }
        )
        self.assertEqual([], findings)

    def test_helper_handoff_rejects_ambiguous_duplicate_definition(self):
        findings = self.analyze_handoff_plugin(
            {
                "entry.php": """<?php
add_action('wp_ajax_nopriv_demo', 'demo_callback');
function demo_callback() { render_value($_GET['name']); }
""",
                "one.php": "<?php function render_value($value) { echo $value; }",
                "two.php": "<?php function render_value($value) { echo $value; }",
            }
        )
        self.assertEqual([], findings)

    def test_combined_scanner_indexes_match_separate_indexes(self):
        with tempfile.TemporaryDirectory() as directory:
            plugin_root = Path(directory)
            plugin = plugin_root / "old-plugin"
            plugin.mkdir()
            entry = plugin / "entry.php"
            helper = plugin / "helper.php"
            entry.write_text(
                """<?php
add_shortcode('demo', 'ShortcodeHandler');
add_action('wp_ajax_nopriv_demo', 'AjaxHandler');
function ShortcodeHandler($atts) { return $atts['value']; }
function AjaxHandler() { render_value($_GET['value']); }
""",
                encoding="utf-8",
            )
            helper.write_text(
                "<?php function render_value($value) { echo $value; }",
                encoding="utf-8",
            )
            paths = [entry, helper]

            expected_shortcodes = build_shortcode_callback_index(paths, plugin_root)
            expected_registered, expected_definitions = build_helper_handoff_index(
                paths, plugin_root
            )
            shortcodes, registered, definitions = build_scanner_indexes(
                paths, plugin_root
            )

            self.assertEqual(expected_shortcodes, shortcodes)
            self.assertEqual(expected_registered, registered)
            self.assertEqual(expected_definitions, definitions)

    def test_helper_handoff_supports_one_unique_cross_file_boundary(self):
        findings = self.analyze_handoff_plugin(
            {
                "entry.php": """<?php
add_action('wp_ajax_nopriv_demo', 'demo_callback');
function demo_callback() { render_helper($_GET['name']); }
""",
                "sink.php": "<?php function render_helper($value) { echo $value; }",
            }
        )
        self.assertEqual(1, len(findings))
        self.assertTrue(findings[0]["file"].endswith("sink.php"))
        self.assertEqual("unique_helper_argument", findings[0]["flow_evidence"])

    def test_unset_default_does_not_erase_helper_parameter_taint(self):
        findings = self.analyze_handoff_plugin(
            {
                "plugin.php": """<?php
add_action('wp_ajax_nopriv_preview', 'preview_callback');
function preview_callback() { render_width($_POST['width']); }
function render_width($width) {
    if (!isset($width)) $width = '100';
    echo '<object width="' . $width . '">';
}
"""
            }
        )
        self.assertEqual(1, len(findings))
        self.assertEqual("unique_helper_argument", findings[0]["flow_evidence"])

    def test_function_parameter_default_does_not_erase_seeded_taint(self):
        findings = self.analyze_handoff_plugin(
            {
                "plugin.php": """<?php
add_action('wp_ajax_nopriv_preview', 'preview_callback');
function preview_callback() { echo render_markup($_GET['value']); }
function render_markup($value = null) {
    return '<div>' . $value . '</div>';
}
"""
            }
        )
        helper_returns = [
            finding for finding in findings if finding["sink_kind"] == "helper_return"
        ]
        self.assertEqual(1, len(helper_returns))
        self.assertEqual("unique_helper_argument", helper_returns[0]["flow_evidence"])

    def test_unconditional_clean_assignment_still_erases_helper_parameter_taint(self):
        findings = self.analyze_handoff_plugin(
            {
                "plugin.php": """<?php
add_action('wp_ajax_nopriv_preview', 'preview_callback');
function preview_callback() { render_width($_POST['width']); }
function render_width($width) {
    $width = '100';
    echo '<object width="' . $width . '">';
}
"""
            }
        )
        self.assertEqual([], findings)

    def test_output_consumed_helper_marks_returned_html_builder_as_sink(self):
        findings = self.analyze_handoff_plugin(
            {
                "plugin.php": """<?php
add_action('wp_ajax_nopriv_preview', 'preview_callback');
function preview_callback() { echo build_markup($_GET['value']); }
function build_markup($value) {
    $html = '<div>' . $value . '</div>';
    return $html;
}
"""
            }
        )
        helper_returns = [
            finding for finding in findings if finding["sink_kind"] == "helper_return"
        ]
        self.assertEqual(1, len(helper_returns))
        self.assertEqual(
            "unique_helper_argument", helper_returns[0]["flow_evidence"]
        )
        self.assertGreaterEqual(helper_returns[0]["score"], 60)

    def test_unconsumed_helper_return_does_not_make_html_builder_a_sink(self):
        findings = self.analyze_handoff_plugin(
            {
                "plugin.php": """<?php
add_action('wp_ajax_nopriv_preview', 'preview_callback');
function preview_callback() { build_markup($_GET['value']); }
function build_markup($value) {
    $html = '<div>' . $value . '</div>';
    return $html;
}
"""
            }
        )
        self.assertEqual([], findings)

    def test_registered_callback_receives_direct_source_helper_return(self):
        findings = self.analyze_handoff_plugin(
            {
                "plugin.php": """<?php
add_action('wp_head', 'render_meta');
function request_url() { return $_SERVER['REQUEST_URI']; }
function render_meta() {
    $canonical = request_url();
    echo '<link href="' . $canonical . '">';
}
"""
            }
        )
        self.assertEqual(1, len(findings))
        self.assertEqual("unique_helper_return", findings[0]["flow_evidence"])
        self.assertGreaterEqual(findings[0]["score"], 60)

    def test_registered_callback_outputs_no_argument_helper_local_source_return(self):
        findings = self.analyze_handoff_plugin(
            {
                "plugin.php": """<?php
add_action('admin_menu', 'render_admin');
function render_admin() {
    if ($message = $this->build_message()) echo '<div>' . $message . '</div>';
}
function build_message() {
    $names = $_GET['names'];
    foreach ($names as $name) { $message = '<strong>' . $name . '</strong>'; }
    return $message;
}
"""
            }
        )
        self.assertEqual(1, len(findings))
        self.assertEqual("unique_helper_return", findings[0]["flow_evidence"])
        self.assertIn("$message", findings[0]["tainted_vars"])

    def test_no_argument_helper_summarizes_multiline_tainted_return_expression(self):
        findings = self.analyze_handoff_plugin(
            {
                "plugin.php": """<?php
add_action('admin_menu', 'render_admin');
function render_admin() {
    if ($message = build_message()) echo '<div>' . $message . '</div>';
}
function build_message() {
    $names = $_GET['names'];
    foreach ($names as $name) { $msg = '<strong>' . $name . '</strong>'; }
    return '<p>' .
        $msg .
        '</p>';
}
"""
            }
        )
        self.assertEqual(1, len(findings))
        self.assertEqual("unique_helper_return", findings[0]["flow_evidence"])
        self.assertIn("$message", findings[0]["tainted_vars"])

    def test_no_argument_helper_return_requires_same_statement_output(self):
        findings = self.analyze_handoff_plugin(
            {
                "plugin.php": """<?php
add_action('admin_menu', 'render_admin');
function render_admin() {
    $message = build_message();
    echo '<div>' . $message . '</div>';
}
function build_message() { $message = $_GET['message']; return $message; }
"""
            }
        )
        self.assertEqual([], findings)

    def test_no_argument_helper_return_rejects_formal_parameters(self):
        findings = self.analyze_handoff_plugin(
            {
                "plugin.php": """<?php
add_action('admin_menu', 'render_admin');
function render_admin() {
    if ($message = build_message()) echo '<div>' . $message . '</div>';
}
function build_message($unused) { $message = $_GET['message']; return $message; }
"""
            }
        )
        self.assertEqual([], findings)

    def test_no_argument_helper_return_rejects_call_with_arguments(self):
        findings = self.analyze_handoff_plugin(
            {
                "plugin.php": """<?php
add_action('admin_menu', 'render_admin');
function render_admin() {
    if ($message = build_message('safe')) echo '<div>' . $message . '</div>';
}
function build_message() { $message = $_GET['message']; return $message; }
"""
            }
        )
        self.assertEqual([], findings)

    def test_no_argument_helper_return_rejects_unrelated_return_value(self):
        findings = self.analyze_handoff_plugin(
            {
                "plugin.php": """<?php
add_action('admin_menu', 'render_admin');
function render_admin() {
    if ($message = build_message()) echo '<div>' . $message . '</div>';
}
function build_message() {
    $input = $_GET['message'];
    $message = 'safe';
    return $message;
}
"""
            }
        )
        self.assertEqual([], findings)

    def test_no_argument_helper_return_rejects_unregistered_root(self):
        findings = self.analyze_handoff_plugin(
            {
                "plugin.php": """<?php
function render_admin() {
    if ($message = build_message()) echo '<div>' . $message . '</div>';
}
function build_message() { $message = $_GET['message']; return $message; }
"""
            }
        )
        self.assertEqual([], findings)

    def test_no_argument_helper_return_rejects_duplicate_helper_definition(self):
        findings = self.analyze_handoff_plugin(
            {
                "entry.php": """<?php
add_action('admin_menu', 'render_admin');
function render_admin() {
    if ($message = build_message()) echo '<div>' . $message . '</div>';
}
""",
                "one.php": "<?php function build_message() { $message = $_GET['message']; return $message; }",
                "two.php": "<?php function build_message() { $message = $_GET['message']; return $message; }",
            }
        )
        self.assertEqual([], findings)

    def test_unrelated_escape_in_same_output_does_not_discount_tainted_variable(self):
        findings = self.analyze(
            "<?php\n"
            "$canonical = $_SERVER['REQUEST_URI'];\n"
            "$description = 'safe';\n"
            "echo '<link href=\"' . $canonical . '\">' . esc_html($description);"
        )
        self.assertEqual(1, len(findings))
        self.assertNotIn("escape_html", findings[0]["sanitizer_matches"])

    def test_escape_applied_to_tainted_variable_still_discounts_output(self):
        findings = self.analyze(
            "<?php $canonical = $_SERVER['REQUEST_URI']; "
            "echo esc_html($canonical);"
        )
        self.assertEqual(1, len(findings))
        self.assertIn("escape_html", findings[0]["sanitizer_matches"])
        self.assertEqual("INFO", findings[0]["severity"])

    def test_unregistered_caller_does_not_receive_helper_return_taint(self):
        findings = self.analyze_handoff_plugin(
            {
                "plugin.php": """<?php
function request_url() { return $_SERVER['REQUEST_URI']; }
function render_meta() {
    $canonical = request_url();
    echo '<link href="' . $canonical . '">';
}
"""
            }
        )
        self.assertEqual([], findings)

    def test_output_consumed_helper_handoff_supports_second_boundary(self):
        findings = self.analyze_handoff_plugin(
            {
                "entry.php": """<?php
add_action('wp_ajax_nopriv_demo', 'demo_callback');
function demo_callback() { echo first_helper($_GET['name']); }
""",
                "one.php": "<?php function first_helper($value) { return second_helper('safe', $value); }",
                "two.php": """<?php
function second_helper($safe, $value) {
    $part = '';
    if ($value) { $part = '&amp;error=' . $value; }
    return '<script src="/challenge?' . $part . '"></script>';
}
""",
            }
        )
        second_boundary = [
            finding
            for finding in findings
            if finding["file"].endswith("two.php")
            and finding["flow_evidence"] == "unique_helper_argument"
        ]
        self.assertEqual(1, len(second_boundary))
        self.assertIn(second_boundary[0]["sink_kind"], {"helper_return", "js_context"})

    def test_helper_handoff_stops_before_third_boundary(self):
        findings = self.analyze_handoff_plugin(
            {
                "entry.php": """<?php
add_action('wp_ajax_nopriv_demo', 'demo_callback');
function demo_callback() { echo first_helper($_GET['name']); }
""",
                "one.php": "<?php function first_helper($value) { return second_helper($value); }",
                "two.php": "<?php function second_helper($value) { return third_helper($value); }",
                "three.php": "<?php function third_helper($value) { return '<b>' . $value . '</b>'; }",
            }
        )
        self.assertFalse(
            any(
                finding["file"].endswith("three.php")
                for finding in findings
            )
        )

    def test_second_boundary_return_requires_output_consumption(self):
        findings = self.analyze_handoff_plugin(
            {
                "entry.php": """<?php
add_action('wp_ajax_nopriv_demo', 'demo_callback');
function demo_callback() { first_helper($_GET['name']); }
""",
                "one.php": "<?php function first_helper($value) { return second_helper($value); }",
                "two.php": "<?php function second_helper($value) { return '<b>' . $value . '</b>'; }",
            }
        )
        self.assertEqual([], findings)

    def test_second_boundary_side_effect_sink_is_not_followed_off_output_chain(self):
        findings = self.analyze_handoff_plugin(
            {
                "entry.php": """<?php
add_action('wp_ajax_nopriv_demo', 'demo_callback');
function demo_callback() { first_helper($_GET['name']); }
""",
                "one.php": "<?php function first_helper($value) { second_helper($value); }",
                "two.php": "<?php function second_helper($value) { echo '<b>' . $value . '</b>'; }",
            }
        )
        self.assertEqual([], findings)

    def test_same_statement_source_to_echo(self):
        findings = self.analyze("<?php echo $_GET['name'];")
        self.assertEqual(1, len(findings))
        self.assertEqual("same_statement", findings[0]["flow_evidence"])

    def test_tainted_empty_guard_does_not_flow_to_clean_echo_expression(self):
        findings = self.analyze(
            "<?php\n"
            "$errors[] = $_GET['error'];\n"
            "if (empty($errors)) { echo '<div>clean</div>'; }"
        )

        self.assertEqual([], findings)

    def test_tainted_echo_expression_is_not_suppressed_by_clean_output_filter(self):
        findings = self.analyze(
            "<?php\n"
            "$show = $_GET['show'];\n"
            "$name = $_GET['name'];\n"
            "if ($show) { echo '<div>' . $name . '</div>'; }"
        )

        self.assertEqual(1, len(findings))
        self.assertIn("$name", findings[0]["tainted_vars"])

    def test_condition_assignment_source_reaches_same_statement_echo(self):
        findings = self.analyze(
            "<?php if ($name = $_GET['name']) { echo '<div>' . $name . '</div>'; }"
        )

        self.assertEqual(1, len(findings))
        self.assertEqual("superglobals", findings[0]["source_origin"])

    def test_unescaped_post_title_output_is_reviewable(self):
        findings = self.analyze("<?php echo get_the_title( $post_id );")
        self.assertEqual(1, len(findings))
        self.assertEqual("wordpress_post_title", findings[0]["source_kind"])
        self.assertEqual("same_statement", findings[0]["flow_evidence"])
        self.assertEqual("MEDIUM", findings[0]["severity"])

    def test_acf_get_field_assignment_reaches_unescaped_output(self):
        findings = self.analyze(
            "<?php\n$value = get_field( $selector, $post_id, true );\necho $value;"
        )
        self.assertEqual(1, len(findings))
        self.assertEqual("variable_flow", findings[0]["source_kind"])
        self.assertEqual("acf_field_value", findings[0]["source_origin"])
        self.assertEqual("variable_assignment", findings[0]["flow_evidence"])
        self.assertEqual(51, findings[0]["score"])
        self.assertEqual("MEDIUM", findings[0]["severity"])

    def test_function_defaults_do_not_hide_first_acf_source_assignment(self):
        findings = self.analyze(
            "<?php\n"
            "function the_field( $selector, $post_id = false, $format = true ) {\n"
            "  $value = get_field( $selector, $post_id, $format );\n"
            "  if ( is_array( $value ) ) { $value = @implode( ', ', $value ); }\n"
            "  echo $value;\n"
            "}"
        )
        self.assertEqual(1, len(findings))
        self.assertEqual("acf_field_value", findings[0]["source_origin"])
        self.assertEqual("html_output", findings[0]["sink_kind"])
        self.assertEqual("variable_assignment", findings[0]["flow_evidence"])

    def test_acf_get_field_html_escape_is_deprioritized(self):
        findings = self.analyze(
            "<?php echo esc_html( get_field( $selector ) );"
        )
        self.assertEqual(1, len(findings))
        self.assertEqual("INFO", findings[0]["severity"])
        self.assertIn("escape_html", findings[0]["sanitizer_matches"])

    def test_content_cards_getter_echo_in_helper_definition_is_reviewable(self):
        findings = self.analyze(
            "<?php\n"
            "function the_cc_data( $key, $sanitize = false ) {\n"
            "  echo get_cc_data( $key, $sanitize );\n"
            "}"
        )
        self.assertEqual(1, len(findings))
        self.assertEqual("content_cards_data", findings[0]["source_kind"])
        self.assertEqual("content_cards_data", findings[0]["source_origin"])
        self.assertEqual("same_statement", findings[0]["flow_evidence"])
        self.assertEqual("html_output", findings[0]["sink_kind"])
        self.assertEqual(55, findings[0]["score"])
        self.assertEqual("MEDIUM", findings[0]["severity"])

    def test_content_cards_getter_html_escape_is_deprioritized(self):
        findings = self.analyze("<?php echo esc_html( get_cc_data( 'title' ) );")
        self.assertEqual(1, len(findings))
        self.assertEqual("INFO", findings[0]["severity"])
        self.assertIn("escape_html", findings[0]["sanitizer_matches"])

    def test_content_cards_getter_assignment_preserves_source_score(self):
        findings = self.analyze(
            "<?php\n$value = get_cc_data( 'title' );\necho $value;"
        )
        self.assertEqual(1, len(findings))
        self.assertEqual("variable_flow", findings[0]["source_kind"])
        self.assertEqual("content_cards_data", findings[0]["source_origin"])
        self.assertEqual(51, findings[0]["score"])
        self.assertEqual("MEDIUM", findings[0]["severity"])

    def test_buddypress_group_name_output_helper_is_reviewable(self):
        findings = self.analyze("<?php bp_group_name();")
        self.assertEqual(1, len(findings))
        self.assertEqual("buddypress_group_name", findings[0]["source_kind"])
        self.assertEqual("html_output", findings[0]["sink_kind"])
        self.assertEqual("same_statement", findings[0]["flow_evidence"])
        self.assertEqual(55, findings[0]["score"])
        self.assertEqual("MEDIUM", findings[0]["severity"])

    def test_context_escaped_post_title_is_deprioritized(self):
        findings = self.analyze("<?php echo esc_html( get_the_title( $post_id ) );")
        self.assertEqual(1, len(findings))
        self.assertEqual("INFO", findings[0]["severity"])
        self.assertIn("escape_html", findings[0]["sanitizer_matches"])

    def test_unescaped_comment_content_short_echo_is_reviewable(self):
        findings = self.analyze("<?= $comment->comment_content ?>")
        self.assertEqual(1, len(findings))
        self.assertEqual("wordpress_comment_content", findings[0]["source_kind"])
        self.assertEqual("wordpress_comment_content", findings[0]["source_origin"])
        self.assertEqual("same_statement", findings[0]["flow_evidence"])
        self.assertEqual(55, findings[0]["score"])
        self.assertEqual("MEDIUM", findings[0]["severity"])

    def test_context_escaped_comment_content_short_echo_is_info(self):
        findings = self.analyze("<?= esc_html( $comment->comment_content ) ?>")
        self.assertEqual(1, len(findings))
        self.assertEqual("INFO", findings[0]["severity"])
        self.assertIn("escape_html", findings[0]["sanitizer_matches"])

    def test_comment_content_assignment_preserves_persisted_content_score(self):
        findings = self.analyze(
            "<?php\n$value = $comment->comment_content;\necho $value;"
        )
        self.assertEqual(1, len(findings))
        self.assertEqual("variable_flow", findings[0]["source_kind"])
        self.assertEqual("wordpress_comment_content", findings[0]["source_origin"])
        self.assertEqual(51, findings[0]["score"])
        self.assertEqual("MEDIUM", findings[0]["severity"])

    def test_unrelated_object_property_has_no_comment_content_finding(self):
        findings = self.analyze("<?= $comment->comment_author ?>")
        self.assertEqual([], findings)

    def test_unescaped_pretty_link_referer_attribute_is_reviewable(self):
        findings = self.analyze(
            '<td><a href="<?php echo $click->referer; ?>">link</a></td>'
        )
        self.assertEqual(1, len(findings))
        self.assertEqual("pretty_link_click_referer", findings[0]["source_kind"])
        self.assertEqual("pretty_link_click_referer", findings[0]["source_origin"])
        self.assertEqual("same_statement", findings[0]["flow_evidence"])
        self.assertEqual("url_attribute", findings[0]["context"])

    def test_attribute_only_escape_does_not_clear_url_context(self):
        findings = self.analyze(
            '<td><a href="<?php echo esc_attr( $click->referer ); ?>">link</a></td>'
        )
        self.assertEqual(1, len(findings))
        self.assertEqual("url_attribute", findings[0]["context"])
        self.assertEqual("MEDIUM", findings[0]["severity"])
        self.assertIn("escape_attr", findings[0]["sanitizer_matches"])

    def test_url_escaped_pretty_link_referer_attribute_is_info(self):
        findings = self.analyze(
            '<td><a href="<?php echo esc_url( $click->referer ); ?>">link</a></td>'
        )
        self.assertEqual(1, len(findings))
        self.assertEqual("INFO", findings[0]["severity"])
        self.assertIn("escape_url", findings[0]["sanitizer_matches"])

    def test_pretty_link_referer_assignment_preserves_persisted_content_score(self):
        findings = self.analyze(
            "<?php\n$value = $click->referer;\necho $value;"
        )
        self.assertEqual(1, len(findings))
        self.assertEqual("variable_flow", findings[0]["source_kind"])
        self.assertEqual("pretty_link_click_referer", findings[0]["source_origin"])
        self.assertEqual(51, findings[0]["score"])
        self.assertEqual("MEDIUM", findings[0]["severity"])

    def test_unrelated_statements_are_not_joined(self):
        findings = self.analyze(
            "<?php\n$input = $_GET['name'];\n$clean = 'constant';\necho $clean;"
        )
        self.assertEqual([], findings)

    def test_variable_assignment_reaches_echo(self):
        findings = self.analyze("<?php\n$input = $_GET['name'];\necho $input;")
        self.assertEqual(1, len(findings))
        self.assertEqual("variable_assignment", findings[0]["flow_evidence"])

    def test_helper_assignment_keeps_semicolon_inside_quoted_literal(self):
        findings = self.analyze_handoff_plugin(
            {
                "entry.php": """<?php
add_action('wp_ajax_nopriv_demo', 'demo_callback');
function demo_callback() { echo render_error($_GET['error']); }
""",
                "helper.php": """<?php
function render_error($error) {
    $errorpart = '';
    $errorpart = "&amp;error=" . $error;
    return '<script>' . $errorpart . '</script>';
}
""",
            }
        )
        helper_findings = [
            finding
            for finding in findings
            if finding["file"].endswith("helper.php")
        ]
        self.assertEqual(1, len(helper_findings))
        self.assertEqual(
            "unique_helper_argument", helper_findings[0]["flow_evidence"]
        )
        self.assertIn("$errorpart", helper_findings[0]["tainted_vars"])

    def test_literal_include_hands_taint_to_included_file(self):
        with tempfile.TemporaryDirectory() as directory:
            plugin = Path(directory) / "old-plugin"
            plugin.mkdir()
            source = plugin / "plugin.php"
            included = plugin / "view.php"
            source.write_text(
                "<?php $title = $_GET['title']; include 'view.php';",
                encoding="utf-8",
            )
            included.write_text("<?php echo $title;", encoding="utf-8")

            findings = analyze_php_file(source)

            self.assertEqual(1, len(findings))
            self.assertEqual(str(included.resolve()), findings[0]["file"])
            self.assertEqual(1, findings[0]["line"])
            self.assertEqual("literal_include_scope", findings[0]["flow_evidence"])
            self.assertEqual("medium", findings[0]["confidence"])

    def test_literal_include_inside_named_function_uses_function_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            plugin = Path(directory) / "old-plugin"
            plugin.mkdir()
            source = plugin / "plugin.php"
            included = plugin / "view.php"
            source.write_text(
                "<?php function render_old() {\n"
                "$title = $_GET['title'];\n"
                "include \"view.php\";\n"
                "}",
                encoding="utf-8",
            )
            included.write_text("<?php echo $title;", encoding="utf-8")

            findings = analyze_php_file(source)

            self.assertEqual(1, len(findings))
            self.assertEqual(str(included.resolve()), findings[0]["file"])
            self.assertEqual("literal_include_scope", findings[0]["flow_evidence"])

    def test_nested_literal_include_hands_scope_to_final_file(self):
        with tempfile.TemporaryDirectory() as directory:
            plugin = Path(directory) / "old-plugin"
            plugin.mkdir()
            source = plugin / "plugin.php"
            first = plugin / "first.php"
            final = plugin / "final.php"
            source.write_text(
                "<?php $title = $_GET['title']; include 'first.php';",
                encoding="utf-8",
            )
            first.write_text("<?php include 'final.php';", encoding="utf-8")
            final.write_text("<?php echo $title;", encoding="utf-8")

            findings = analyze_php_file(source)

            self.assertEqual(1, len(findings))
            self.assertEqual(str(final.resolve()), findings[0]["file"])
            self.assertEqual("literal_include_scope", findings[0]["flow_evidence"])

    def test_literal_require_once_hands_taint_to_included_file(self):
        with tempfile.TemporaryDirectory() as directory:
            plugin = Path(directory) / "old-plugin"
            plugin.mkdir()
            source = plugin / "plugin.php"
            included = plugin / "view.php"
            source.write_text(
                "<?php $title = $_GET['title']; require_once 'view.php';",
                encoding="utf-8",
            )
            included.write_text("<?php echo $title;", encoding="utf-8")

            findings = analyze_php_file(source)

            self.assertEqual(1, len(findings))
            self.assertEqual("literal_include_scope", findings[0]["flow_evidence"])

    def test_literal_include_preserves_sanitizer_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            plugin = Path(directory) / "old-plugin"
            plugin.mkdir()
            source = plugin / "plugin.php"
            included = plugin / "view.php"
            source.write_text(
                "<?php $title = esc_html($_GET['title']); include 'view.php';",
                encoding="utf-8",
            )
            included.write_text("<?php echo $title;", encoding="utf-8")

            findings = analyze_php_file(source)

            self.assertEqual(1, len(findings))
            self.assertIn("escape_html", findings[0]["sanitizer_matches"])
            self.assertEqual("INFO", findings[0]["severity"])

    def test_array_element_source_marks_container_for_literal_storage_write(self):
        php = (
            "<?php\n"
            "$options['title'] = $_POST['title'];\n"
            "update_option('old_options', $options);"
        )
        with tempfile.TemporaryDirectory() as directory:
            plugin_root = Path(directory)
            plugin = plugin_root / "old-plugin"
            plugin.mkdir()
            source = plugin / "plugin.php"
            source.write_text(php, encoding="utf-8")

            index = build_tainted_storage_index([source], plugin_root, {})

            self.assertTrue(
                {
                    ("option", "", "old_options"),
                    ("global_option_field", "old_options", "title"),
                }
                <= index["old-plugin"]
            )

    def test_literal_array_field_taint_reaches_same_scope_output(self):
        findings = self.analyze(
            "<?php\n"
            "$data['title'] = $_POST['title'];\n"
            "echo $data['title'];"
        )

        self.assertEqual(1, len(findings))
        self.assertEqual(3, findings[0]["line"])
        self.assertIn("$data['title']", findings[0]["tainted_vars"])

    def test_literal_array_field_taint_does_not_reach_sibling_or_dynamic_field(self):
        sibling = self.analyze(
            "<?php\n"
            "$data['title'] = $_POST['title'];\n"
            "echo $data['safe'];"
        )
        dynamic = self.analyze(
            "<?php\n"
            "$data[$field] = $_POST['title'];\n"
            "echo $data['title'];"
        )

        self.assertEqual([], sibling)
        self.assertEqual([], dynamic)

    def test_clean_array_field_overwrite_clears_local_taint(self):
        findings = self.analyze(
            "<?php\n"
            "$data['title'] = $_POST['title'];\n"
            "$data['title'] = 'constant';\n"
            "echo $data['title'];"
        )

        self.assertEqual([], findings)

    def test_clean_container_overwrite_clears_local_field_taint(self):
        findings = self.analyze(
            "<?php\n"
            "$data['title'] = $_POST['title'];\n"
            "$data = array('safe' => 'constant');\n"
            "echo $data['title'];"
        )

        self.assertEqual([], findings)

    def test_foreach_propagates_array_element_taint_to_value_only(self):
        findings = self.analyze(
            "<?php\n"
            "$rows['title'] = $_POST['title'];\n"
            "foreach ($rows as $key => $value) {\n"
            "echo $value;\n"
            "}"
        )

        self.assertEqual(1, len(findings))
        self.assertEqual(4, findings[0]["line"])
        self.assertEqual("$value", findings[0]["tainted_vars"])

        key_findings = self.analyze(
            "<?php\n"
            "$rows['title'] = $_POST['title'];\n"
            "foreach ($rows as $key => $value) {\n"
            "echo $key;\n"
            "}"
        )
        self.assertEqual([], key_findings)

    def test_foreach_superglobal_array_taints_value(self):
        findings = self.analyze(
            "<?php\n"
            "foreach ($_POST['items'] as $key => $item) {\n"
            "echo $item;\n"
            "}"
        )

        self.assertEqual(1, len(findings))
        self.assertEqual("superglobals", findings[0]["source_origin"])
        self.assertEqual("$item", findings[0]["tainted_vars"])

    def test_array_append_taint_reaches_foreach_and_aggregate_use(self):
        foreach_findings = self.analyze(
            "<?php\n"
            "$items[] = $_GET['item'];\n"
            "foreach ($items as $item) { echo $item; }"
        )
        aggregate_findings = self.analyze(
            "<?php\n"
            "$items[] = $_GET['item'];\n"
            "echo implode(', ', $items);"
        )

        self.assertEqual(1, len(foreach_findings))
        self.assertEqual(1, len(aggregate_findings))

    def test_array_aggregate_self_assignment_preserves_taint_without_crashing(self):
        findings = self.analyze(
            "<?php\n"
            "$items[] = $_GET['item'];\n"
            "$items = array_unique($items);\n"
            "echo implode(', ', $items);"
        )

        self.assertEqual(1, len(findings))

    def test_include_once_target_is_analyzed_only_once(self):
        with tempfile.TemporaryDirectory() as directory:
            plugin = Path(directory) / "old-plugin"
            plugin.mkdir()
            source = plugin / "plugin.php"
            included = plugin / "view.php"
            source.write_text(
                "<?php $title = $_GET['title']; include_once 'view.php'; "
                "include_once 'view.php';",
                encoding="utf-8",
            )
            included.write_text("<?php echo $title;", encoding="utf-8")

            findings = analyze_php_file(source)

            self.assertEqual(1, len(findings))

    def test_duplicate_literal_include_finding_is_reported_once(self):
        with tempfile.TemporaryDirectory() as directory:
            plugin = Path(directory) / "old-plugin"
            plugin.mkdir()
            source = plugin / "plugin.php"
            included = plugin / "view.php"
            source.write_text(
                "<?php $title = $_GET['title']; include 'view.php'; "
                "include 'view.php';",
                encoding="utf-8",
            )
            included.write_text("<?php echo $title;", encoding="utf-8")

            findings = analyze_php_file(source)

            self.assertEqual(1, len(findings))

    def test_plugin_storage_array_read_flows_into_literal_include(self):
        with tempfile.TemporaryDirectory() as directory:
            plugin_root = Path(directory)
            plugin = plugin_root / "old-plugin"
            plugin.mkdir()
            writer = plugin / "save.php"
            render = plugin / "render.php"
            template = plugin / "template.php"
            writer.write_text(
                "<?php $options['title'] = $_POST['title']; "
                "update_option('old_options', $options);",
                encoding="utf-8",
            )
            render.write_text(
                "<?php $options = get_option('old_options'); "
                "include 'template.php';",
                encoding="utf-8",
            )
            template.write_text("<?php echo $options['title'];", encoding="utf-8")

            index = build_tainted_storage_index(
                [writer, render, template], plugin_root, {}
            )
            findings = analyze_php_file(
                render, tainted_storage_keys=index["old-plugin"]
            )

            self.assertEqual(1, len(findings))
            self.assertEqual(str(template.resolve()), findings[0]["file"])
            self.assertEqual("literal_include_scope", findings[0]["flow_evidence"])

    def test_plugin_meta_dynamic_subject_stays_low_confidence_through_include(self):
        with tempfile.TemporaryDirectory() as directory:
            plugin_root = Path(directory)
            plugin = plugin_root / "old-plugin"
            plugin.mkdir()
            writer = plugin / "save.php"
            render = plugin / "render.php"
            template = plugin / "template.php"
            writer.write_text(
                "<?php update_post_meta($post_id, 'old_caption', $_POST['caption']);",
                encoding="utf-8",
            )
            render.write_text(
                "<?php $caption = get_post_meta($post_id, 'old_caption', true); "
                "include 'template.php';",
                encoding="utf-8",
            )
            template.write_text("<?php echo $caption;", encoding="utf-8")

            index = build_tainted_storage_index(
                [writer, render, template], plugin_root, {}
            )
            findings = analyze_php_file(
                render, tainted_storage_keys=index["old-plugin"]
            )

            self.assertEqual(1, len(findings))
            self.assertEqual(str(template.resolve()), findings[0]["file"])
            self.assertEqual(
                "plugin_dynamic_subject_storage", findings[0]["flow_evidence"]
            )
            self.assertEqual("low", findings[0]["confidence"])

    def test_include_does_not_follow_dynamic_or_parent_path_or_clean_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            plugin = Path(directory) / "old-plugin"
            plugin.mkdir()
            source = plugin / "plugin.php"
            dynamic = plugin / "dynamic.php"
            clean = plugin / "clean.php"
            parent = Path(directory) / "parent.php"
            source.write_text(
                "<?php $title = $_GET['title']; $template = 'dynamic.php'; include $template;"
                " include '../parent.php'; include 'clean.php';",
                encoding="utf-8",
            )
            dynamic.write_text("<?php echo $title;", encoding="utf-8")
            clean.write_text("<?php echo $safe;", encoding="utf-8")
            parent.write_text("<?php echo $title;", encoding="utf-8")

            self.assertEqual([], analyze_php_file(source))

    def test_storage_prepass_does_not_follow_literal_include(self):
        with tempfile.TemporaryDirectory() as directory:
            plugin_root = Path(directory)
            plugin = plugin_root / "old-plugin"
            plugin.mkdir()
            source = plugin / "plugin.php"
            included = plugin / "save.php"
            source.write_text(
                "<?php $title = $_POST['title']; include 'save.php';",
                encoding="utf-8",
            )
            included.write_text(
                "<?php update_option('old_title', $title);",
                encoding="utf-8",
            )

            self.assertEqual(
                {}, build_tainted_storage_index([source], plugin_root, {})
            )

    def test_literal_include_cycle_is_not_followed_indefinitely(self):
        with tempfile.TemporaryDirectory() as directory:
            plugin = Path(directory) / "old-plugin"
            plugin.mkdir()
            source = plugin / "plugin.php"
            included = plugin / "view.php"
            source.write_text(
                "<?php $title = $_GET['title']; include 'view.php';",
                encoding="utf-8",
            )
            included.write_text(
                "<?php echo $title; include 'plugin.php';", encoding="utf-8"
            )

            findings = analyze_php_file(source)

            self.assertEqual(1, len(findings))
            self.assertEqual(str(included.resolve()), findings[0]["file"])

    def test_alternative_clean_branch_does_not_erase_tainted_path(self):
        findings = self.analyze(
            "<?php\n"
            "if (isset($_GET['name'])) { $value = $_GET['name']; }\n"
            "else { $value = 'safe'; }\n"
            "?>\n<input value=\"<?php echo $value; ?>\">"
        )
        self.assertEqual(1, len(findings))
        self.assertEqual("variable_assignment", findings[0]["flow_evidence"])
        self.assertEqual("html_attribute", findings[0]["context"])

    def test_later_php_block_sanitizer_does_not_apply_to_earlier_output(self):
        findings = self.analyze(
            "<?php $value = $_GET['name']; ?>\n"
            "<div><?php echo $value; ?></div>\n"
            "<?php $page = intval($_GET['page']); ?>"
        )
        value_findings = [
            finding for finding in findings if "$value" in finding["tainted_vars"]
        ]
        self.assertEqual(1, len(value_findings))
        self.assertNotIn("numeric_cast", value_findings[0]["sanitizer_matches"])
        self.assertEqual("MEDIUM", value_findings[0]["severity"])

    def test_die_is_an_output_sink(self):
        findings = self.analyze("<?php die($_REQUEST['message']);")
        self.assertEqual(1, len(findings))
        self.assertEqual("REFLECTED_XSS_CANDIDATE", findings[0]["type"])

    def test_terminal_output_requires_taint_in_the_printed_argument(self):
        for terminal in ("die()", "exit()", "wp_die('fixed message')"):
            with self.subTest(terminal=terminal):
                findings = self.analyze(
                    "<?php if (!empty($_REQUEST['message'])) { "
                    f"{terminal}; }}"
                )
                self.assertEqual([], findings)

        for terminal in (
            "die($_REQUEST['message'])",
            "exit($_REQUEST['message'])",
            "wp_die($_REQUEST['message'])",
        ):
            with self.subTest(terminal=terminal):
                findings = self.analyze(f"<?php {terminal};")
                self.assertEqual(1, len(findings))
                self.assertEqual("html_output", findings[0]["sink_kind"])

    def test_variable_free_output_detaches_leading_control_sources(self):
        clean_outputs = (
            "if (!empty($_GET['name'])) { echo 'fixed'; }",
            "if ($_GET['name']) { print 'fixed'; }",
            "if (isset($_GET['name'])) { printf('%s', 'fixed'); }",
            "if ($_GET['name']) { ?><?= esc_html__('fixed') ?><?php }",
        )
        for code in clean_outputs:
            with self.subTest(code=code):
                self.assertEqual([], self.analyze("<?php " + code))

        tainted_outputs = (
            "echo $_GET['name']",
            "print($_GET['name'])",
            "printf('%s', $_GET['name'])",
            "?><?= $_GET['name'] ?>",
        )
        for code in tainted_outputs:
            with self.subTest(code=code):
                findings = self.analyze("<?php " + code + ";")
                self.assertEqual(1, len(findings))
                self.assertEqual("html_output", findings[0]["sink_kind"])

    def test_dynamic_output_is_preserved_when_local_taint_is_not_yet_known(self):
        findings = self.analyze(
            "<?php if (($name = $_GET['name'])) { echo $name; }"
        )
        self.assertEqual(1, len(findings))

    def test_taint_does_not_cross_named_functions(self):
        findings = self.analyze(
            "<?php\n"
            "function collect_old() { $value = $_GET['name']; }\n"
            "function render_old() { echo $value; }"
        )
        self.assertEqual([], findings)

    def test_normal_return_is_not_an_output_sink(self):
        findings = self.analyze(
            "<?php\nfunction helper($value) { return $value; }\nhelper($_GET['name']);"
        )
        self.assertEqual([], findings)

    def test_registered_shortcode_return_is_an_output_sink(self):
        findings = self.analyze(
            "<?php\n"
            "add_shortcode('old_box', 'render_old_box');\n"
            "function render_old_box($atts) { return '<div>' . $atts['title'] . '</div>'; }"
        )
        self.assertEqual(1, len(findings))
        self.assertEqual("SHORTCODE_XSS_CANDIDATE", findings[0]["type"])
        self.assertEqual("shortcode_return", findings[0]["sink_kind"])

    def test_registered_shortcode_return_requires_taint_in_return_expression(self):
        for return_statement in ("return;", "return 'fixed';"):
            with self.subTest(return_statement=return_statement):
                findings = self.analyze(
                    "<?php\n"
                    "add_shortcode('old_box', 'render_old_box');\n"
                    "function render_old_box($atts) {\n"
                    f"if (!empty($atts['title'])) {{ {return_statement} }}\n"
                    "}"
                )
                self.assertEqual([], findings)

        findings = self.analyze(
            "<?php\n"
            "add_shortcode('old_box', 'render_old_box');\n"
            "function render_old_box($atts) { return $atts['title']; }"
        )
        self.assertEqual(1, len(findings))
        self.assertEqual("shortcode_return", findings[0]["sink_kind"])

        findings = self.analyze(
            "<?php\n"
            "add_shortcode('old_box', 'render_old_box');\n"
            "function render_old_box($atts) { return render_box($atts); }"
        )
        self.assertEqual(1, len(findings))
        self.assertEqual("shortcode_return", findings[0]["sink_kind"])

        findings = self.analyze(
            "<?php\n"
            "add_shortcode('old_box', 'render_old_box');\n"
            "function render_old_box($atts) {\n"
            "if (!function_exists('render_box')) { return 'fixed message'; }\n"
            "return render_box($atts);\n"
            "}"
        )
        self.assertEqual(1, len(findings))
        self.assertEqual(5, findings[0]["line"])
        self.assertEqual("shortcode_return", findings[0]["sink_kind"])

        findings = self.analyze(
            "<?php\n"
            "add_shortcode('old_box', 'render_old_box');\n"
            "function render_old_box($atts, $content = null) {\n"
            "$style = array();\n"
            "$style[] = 'color:' . $atts['color'];\n"
            "return '<div style=\"' . implode(';', $style) . '\">' . $content . '</div>';\n"
            "}"
        )
        self.assertEqual(1, len(findings))
        self.assertEqual(6, findings[0]["line"])
        self.assertEqual("shortcode_return", findings[0]["sink_kind"])

        findings = self.analyze(
            "<?php\n"
            "add_shortcode('old_box', 'render_old_box');\n"
            "function render_old_box($atts) {\n"
            "if (!empty($atts['title'])) { return implode(';', array('a', 'b')); }\n"
            "}"
        )
        self.assertEqual([], findings)

    def test_dynamic_shortcode_tag_and_array_callback_html_build_is_a_sink(self):
        findings = self.analyze(
            "<?php\n"
            "class Old_Box {\n"
            "function render_old_box($atts) {\n"
            "extract(shortcode_atts(array('class' => ''), $atts));\n"
            "$html = '<div class=\"' . $class . '\">';\n"
            "return $html;\n"
            "}\n}\n"
            "add_shortcode(OLD_BOX_TAG, array(&$old_box, 'render_old_box'));"
        )
        build_findings = [finding for finding in findings if finding["line"] == 5]
        self.assertEqual(1, len(build_findings))
        self.assertEqual("SHORTCODE_XSS_CANDIDATE", build_findings[0]["type"])
        self.assertEqual("shortcode_return", build_findings[0]["sink_kind"])

    def test_shortcode_extract_taints_literal_attributes_not_unrelated_variables(self):
        findings = self.analyze(
            "<?php\n"
            "add_shortcode('old_box', 'render_old_box');\n"
            "function render_old_box($atts) {\n"
            "extract(shortcode_atts(array('class' => ''), $atts));\n"
            "$safe = 'constant';\n"
            "$safe_html = '<div class=\"' . $safe . '\">';\n"
            "$unsafe_html = '<div class=\"' . $class . '\">';\n"
            "return $unsafe_html;\n}"
        )
        build_lines = {
            finding["line"]
            for finding in findings
            if finding["sink_kind"] == "shortcode_return"
        }
        self.assertIn(7, build_lines)
        self.assertNotIn(6, build_lines)

    def test_list_assignment_propagates_shortcode_attribute_taint(self):
        findings = self.analyze(
            "<?php\n"
            "add_shortcode('old_box', 'render_old_box');\n"
            "function render_old_box($atts) {\n"
            "extract(shortcode_atts(array('show' => ''), $atts));\n"
            "list($minutes, $seconds) = explode(':', $show);\n"
            "$class = 'show-' . $minutes . '-' . $seconds;\n"
            "$html = '<div class=\"' . $class . '\">';\n"
            "return $html;\n}"
        )
        self.assertTrue(any(finding["line"] == 7 for finding in findings))

    def test_plugin_shortcode_index_links_unique_cross_file_callback(self):
        with tempfile.TemporaryDirectory() as directory:
            plugin_root = Path(directory)
            plugin = plugin_root / "old-plugin"
            plugin.mkdir()
            registration = plugin / "plugin.php"
            callback = plugin / "includes.php"
            registration.write_text(
                "<?php add_shortcode('old-box', 'render_old_box');",
                encoding="utf-8",
            )
            callback.write_text(
                "<?php function render_old_box($atts) {\n"
                "extract(shortcode_atts(array('class' => ''), $atts));\n"
                "$html = '<div class=\"' . $class . '\">';\n"
                "return $html;\n}",
                encoding="utf-8",
            )
            paths = [registration, callback]
            index = build_shortcode_callback_index(paths, plugin_root)

            findings = analyze_php_file(callback, index["old-plugin"])

            self.assertIn("render_old_box", index["old-plugin"])
            self.assertTrue(
                any(finding["sink_kind"] == "shortcode_return" for finding in findings)
            )

    def test_unregistered_html_builder_is_not_a_sink(self):
        findings = self.analyze(
            "<?php function helper($atts) { "
            "$html = '<div class=\"' . $atts['class'] . '\">'; return $html; }"
        )
        self.assertEqual([], findings)

    def test_shortcode_docblock_return_is_not_a_sink(self):
        findings = self.analyze(
            "<?php\n"
            "add_shortcode('old_box', 'render_old_box');\n"
            "/** @return unsafe-looking documentation */\n"
            "function render_old_box($atts) { return esc_html($atts['title']); }"
        )
        self.assertEqual(1, len(findings))
        self.assertNotEqual(3, findings[0]["line"])

    def test_unregistered_atts_variable_is_not_a_source(self):
        findings = self.analyze("<?php\nfunction helper($atts) { echo $atts['title']; }")
        self.assertEqual([], findings)

    def test_json_and_localize_are_not_php_xss_sinks(self):
        findings = self.analyze(
            "<?php\nwp_send_json($_GET['x']);\n"
            "wp_localize_script('h', 'OldData', array('x' => $_GET['x']));"
        )
        self.assertEqual([], findings)

    def test_jsonp_request_callback_payload_is_detected_in_same_statement(self):
        findings = self.analyze(
            "<?php\n"
            "$return = json_encode(array('ok' => true));\n"
            "if (isset($_GET['callback'])) {\n"
            "    $return = $_GET['callback'].\"($return)\";\n"
            "}"
        )
        self.assertEqual(1, len(findings))
        self.assertEqual("js_context", findings[0]["sink_kind"])
        self.assertEqual("javascript", findings[0]["context"])
        self.assertEqual("JS_CONTEXT_XSS_CANDIDATE", findings[0]["type"])
        self.assertEqual(4, findings[0]["line"])

    def test_jsonp_context_does_not_reclassify_neighboring_html_output(self):
        findings = self.analyze(
            "<?php\n"
            "$payload = '{}';\n"
            "$jsonp = $_GET['callback'].\"($payload)\";\n"
            "echo $_GET['label'];"
        )
        by_line = {finding["line"]: finding for finding in findings}
        self.assertEqual("javascript", by_line[3]["context"])
        self.assertEqual("JS_CONTEXT_XSS_CANDIDATE", by_line[3]["type"])
        self.assertEqual("html", by_line[4]["context"])
        self.assertEqual("REFLECTED_XSS_CANDIDATE", by_line[4]["type"])

    def test_inline_script_is_a_javascript_sink(self):
        findings = self.analyze("<?php wp_add_inline_script('h', $_GET['code']);")
        self.assertEqual(1, len(findings))
        self.assertEqual("JS_CONTEXT_XSS_CANDIDATE", findings[0]["type"])

    def test_stored_read_requires_matching_tainted_write(self):
        findings = self.analyze(
            "<?php\n"
            "update_option('old_title', $_POST['title']);\n"
            "echo get_option('old_title');\n"
            "echo get_option('unrelated_title');"
        )
        self.assertEqual(2, len(findings))
        self.assertEqual(
            {"STORED_XSS_CANDIDATE", "STORED_XSS_READ_TO_OUTPUT"},
            {finding["type"] for finding in findings},
        )
        by_type = {finding["type"]: finding for finding in findings}
        self.assertEqual(
            "matched_stored_key",
            by_type["STORED_XSS_READ_TO_OUTPUT"]["flow_evidence"],
        )
        self.assertEqual(
            "high", by_type["STORED_XSS_READ_TO_OUTPUT"]["confidence"]
        )
        self.assertLess(
            by_type["STORED_XSS_CANDIDATE"]["score"],
            by_type["STORED_XSS_READ_TO_OUTPUT"]["score"],
        )

    def test_plugin_storage_index_links_cross_file_literal_option(self):
        with tempfile.TemporaryDirectory() as directory:
            plugin_root = Path(directory)
            plugin = plugin_root / "old-plugin"
            plugin.mkdir()
            write_path = plugin / "save.php"
            read_path = plugin / "render.php"
            write_path.write_text(
                "<?php update_option('old_title', $_POST['title']);",
                encoding="utf-8",
            )
            read_path.write_text(
                "<?php echo get_option('old_title');",
                encoding="utf-8",
            )

            index = build_tainted_storage_index(
                [read_path, write_path], plugin_root, {}
            )
            findings = analyze_php_file(
                read_path, tainted_storage_keys=index["old-plugin"]
            )

            self.assertEqual({("option", "", "old_title")}, index["old-plugin"])
            self.assertEqual(1, len(findings))
            self.assertEqual("STORED_XSS_READ_TO_OUTPUT", findings[0]["type"])
            self.assertEqual("plugin_literal_storage", findings[0]["flow_evidence"])
            self.assertEqual("medium", findings[0]["confidence"])

    def test_plugin_option_constant_thin_wrappers_reach_output(self):
        with tempfile.TemporaryDirectory() as directory:
            plugin_root = Path(directory)
            plugin = plugin_root / "old-plugin"
            plugin.mkdir()
            source = plugin / "plugin.php"
            source.write_text(
                "<?php\n"
                "define('OLD_OPTION', 'old_title');\n"
                "function save_title($value) { return update_option(OLD_OPTION, $value); }\n"
                "function read_title() { $value = get_option(OLD_OPTION); return $value; }\n"
                "function save() { save_title($_GET['title']); }\n"
                "function render() { $title = read_title(); echo $title; }\n",
                encoding="utf-8",
            )
            index = build_tainted_storage_index([source], plugin_root, {})
            findings = analyze_php_file(source, tainted_storage_keys=index["old-plugin"])

            self.assertIn(("option", "", "old_title"), index["old-plugin"])
            output = [finding for finding in findings if finding["line"] == 6]
            self.assertEqual(1, len(output))
            self.assertEqual("ATTRIBUTE_CONTEXT_XSS_CANDIDATE", output[0]["type"])
            self.assertEqual("variable_assignment", output[0]["flow_evidence"])
            self.assertEqual("stored_read", output[0]["source_origin"])
            self.assertEqual("medium", output[0]["confidence"])

    def test_plugin_option_constant_model_rejects_non_thin_or_ambiguous_forms(self):
        cases = {
            "direct_constant_apis": "<?php\ndefine('OLD_OPTION', 'old_title');\nfunction save() { update_option(OLD_OPTION, $_GET['title']); }\nfunction render() { echo get_option(OLD_OPTION); }\n",
            "duplicate_wrapper": "<?php\ndefine('OLD_OPTION', 'old_title');\nfunction save_title($value) { return update_option(OLD_OPTION, $value); }\nfunction save_title($value) { return update_option(OLD_OPTION, $value); }\nfunction read_title() { return get_option(OLD_OPTION); }\nfunction save() { save_title($_GET['title']); }\nfunction render() { $title = read_title(); echo $title; }\n",
            "mismatched_constant": "<?php\ndefine('WRITE_OPTION', 'old_title'); define('READ_OPTION', 'other_title');\nfunction save_title($value) { return update_option(WRITE_OPTION, $value); }\nfunction read_title() { return get_option(READ_OPTION); }\nfunction save() { save_title($_GET['title']); }\nfunction render() { $title = read_title(); echo $title; }\n",
            "dynamic_definition": "<?php\ndefine('OLD_OPTION', 'old_' . $suffix);\nfunction save_title($value) { return update_option(OLD_OPTION, $value); }\nfunction read_title() { return get_option(OLD_OPTION); }\nfunction save() { save_title($_GET['title']); }\nfunction render() { $title = read_title(); echo $title; }\n",
            "clean_write": "<?php\ndefine('OLD_OPTION', 'old_title');\nfunction save_title($value) { return update_option(OLD_OPTION, $value); }\nfunction read_title() { return get_option(OLD_OPTION); }\nfunction save() { save_title('clean'); }\nfunction render() { $title = read_title(); echo $title; }\n",
            "extra_logic": "<?php\ndefine('OLD_OPTION', 'old_title');\nfunction save_title($value) { $value = trim($value); return update_option(OLD_OPTION, $value); }\nfunction read_title() { $value = get_option(OLD_OPTION); return trim($value); }\nfunction save() { save_title($_GET['title']); }\nfunction render() { $title = read_title(); echo $title; }\n",
        }
        for name, php in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                plugin_root = Path(directory)
                plugin = plugin_root / "old-plugin"
                plugin.mkdir()
                source = plugin / "plugin.php"
                source.write_text(php, encoding="utf-8")
                index = build_tainted_storage_index([source], plugin_root, {})
                findings = analyze_php_file(
                    source, tainted_storage_keys=index.get("old-plugin", set())
                )
                self.assertFalse(
                    any(
                        finding["source_origin"]
                        in {"stored_read", "plugin_stored_read"}
                        for finding in findings
                    )
                )

    def test_plugin_storage_index_handles_read_before_write(self):
        with tempfile.TemporaryDirectory() as directory:
            plugin_root = Path(directory)
            plugin = plugin_root / "old-plugin"
            plugin.mkdir()
            path = plugin / "plugin.php"
            path.write_text(
                "<?php\n"
                "echo get_option('old_title');\n"
                "update_option('old_title', $_POST['title']);",
                encoding="utf-8",
            )

            index = build_tainted_storage_index([path], plugin_root, {})
            findings = analyze_php_file(
                path, tainted_storage_keys=index["old-plugin"]
            )

            self.assertTrue(
                any(
                    finding["type"] == "STORED_XSS_READ_TO_OUTPUT"
                    and finding["line"] == 2
                    for finding in findings
                )
            )

    def test_plugin_storage_index_does_not_cross_plugin_or_dynamic_key(self):
        with tempfile.TemporaryDirectory() as directory:
            plugin_root = Path(directory)
            writer = plugin_root / "writer-plugin"
            reader = plugin_root / "reader-plugin"
            writer.mkdir()
            reader.mkdir()
            writer_path = writer / "save.php"
            dynamic_path = writer / "dynamic.php"
            reader_path = reader / "render.php"
            writer_path.write_text(
                "<?php update_option('shared_title', $_POST['title']);",
                encoding="utf-8",
            )
            dynamic_path.write_text(
                "<?php update_option($dynamic_key, $_POST['value']);",
                encoding="utf-8",
            )
            reader_path.write_text(
                "<?php echo get_option('shared_title');",
                encoding="utf-8",
            )

            index = build_tainted_storage_index(
                [writer_path, dynamic_path, reader_path], plugin_root, {}
            )
            findings = analyze_php_file(
                reader_path, tainted_storage_keys=index.get("reader-plugin", set())
            )

            self.assertEqual(
                {("option", "", "shared_title")}, index["writer-plugin"]
            )
            self.assertNotIn(
                ("option", "", "dynamic_key"), index["writer-plugin"]
            )
            self.assertEqual([], findings)

    def test_plugin_storage_index_supports_site_option_and_shortcode_write(self):
        with tempfile.TemporaryDirectory() as directory:
            plugin_root = Path(directory)
            plugin = plugin_root / "old-plugin"
            plugin.mkdir()
            registration = plugin / "plugin.php"
            callback = plugin / "save.php"
            reader = plugin / "render.php"
            registration.write_text(
                "<?php add_shortcode('old-save', 'save_old_title');",
                encoding="utf-8",
            )
            callback.write_text(
                "<?php function save_old_title($atts) {\n"
                "update_site_option('old_network_title', $atts['title']);\n}",
                encoding="utf-8",
            )
            reader.write_text(
                "<?php echo get_site_option('old_network_title');",
                encoding="utf-8",
            )
            paths = [registration, callback, reader]
            callbacks = build_shortcode_callback_index(paths, plugin_root)

            index = build_tainted_storage_index(paths, plugin_root, callbacks)
            findings = analyze_php_file(
                reader, tainted_storage_keys=index["old-plugin"]
            )

            self.assertEqual(
                {("site_option", "", "old_network_title")},
                index["old-plugin"],
            )
            self.assertEqual(1, len(findings))
            self.assertEqual("plugin_literal_storage", findings[0]["flow_evidence"])

    def test_plugin_storage_index_ignores_clean_literal_write(self):
        with tempfile.TemporaryDirectory() as directory:
            plugin_root = Path(directory)
            plugin = plugin_root / "old-plugin"
            plugin.mkdir()
            write_path = plugin / "save.php"
            read_path = plugin / "render.php"
            write_path.write_text(
                "<?php update_option('old_title', 'constant');",
                encoding="utf-8",
            )
            read_path.write_text(
                "<?php echo get_option('old_title');",
                encoding="utf-8",
            )

            index = build_tainted_storage_index(
                [write_path, read_path], plugin_root, {}
            )

            self.assertNotIn("old-plugin", index)
            self.assertEqual([], analyze_php_file(read_path))

    def test_plugin_storage_index_resolves_enumerated_foreach_option_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            plugin_root = Path(directory)
            plugin = plugin_root / "old-plugin"
            plugin.mkdir()
            write_path = plugin / "save.php"
            read_path = plugin / "render.php"
            write_path.write_text(
                "<?php function save_old_options() {\n"
                "$options = array('old_title' => '', 'old_subtitle' => '');\n"
                "foreach ($options as $option_name => $default) {\n"
                "if (get_option($option_name) === false) {\n"
                "add_option($option_name, $default);\n"
                "} else {\n"
                "update_option($option_name, $_POST[$option_name]);\n}\n}\n}",
                encoding="utf-8",
            )
            read_path.write_text(
                "<?php echo get_option('old_subtitle');",
                encoding="utf-8",
            )

            index = build_tainted_storage_index(
                [write_path, read_path], plugin_root, {}
            )
            findings = analyze_php_file(
                read_path, tainted_storage_keys=index["old-plugin"]
            )

            self.assertEqual(
                {
                    ("option", "", "old_title"),
                    ("option", "", "old_subtitle"),
                },
                index["old-plugin"],
            )
            self.assertEqual(1, len(findings))

    def test_plugin_storage_index_rejects_interpolated_key(self):
        with tempfile.TemporaryDirectory() as directory:
            plugin_root = Path(directory)
            plugin = plugin_root / "old-plugin"
            plugin.mkdir()
            path = plugin / "save.php"
            path.write_text(
                '<?php update_option("old_$suffix", $_POST["value"]);',
                encoding="utf-8",
            )

            self.assertEqual(
                {}, build_tainted_storage_index([path], plugin_root, {})
            )

    def test_plugin_meta_literal_subject_and_key_match_is_medium_confidence(self):
        with tempfile.TemporaryDirectory() as directory:
            plugin_root = Path(directory)
            plugin = plugin_root / "old-plugin"
            plugin.mkdir()
            write_path = plugin / "save.php"
            read_path = plugin / "render.php"
            write_path.write_text(
                "<?php update_post_meta(42, 'old_caption', $_POST['caption']);",
                encoding="utf-8",
            )
            read_path.write_text(
                "<?php echo get_post_meta(42, 'old_caption', true);",
                encoding="utf-8",
            )

            index = build_tainted_storage_index(
                [write_path, read_path], plugin_root, {}
            )
            findings = analyze_php_file(
                read_path, tainted_storage_keys=index["old-plugin"]
            )

            self.assertEqual(1, len(findings))
            self.assertEqual("plugin_literal_storage", findings[0]["flow_evidence"])
            self.assertEqual("medium", findings[0]["confidence"])

    def test_plugin_meta_dynamic_subjects_match_by_literal_key_with_low_confidence(self):
        with tempfile.TemporaryDirectory() as directory:
            plugin_root = Path(directory)
            plugin = plugin_root / "old-plugin"
            plugin.mkdir()
            dynamic_write = plugin / "dynamic-save.php"
            dynamic_read = plugin / "dynamic-render.php"
            paths = [dynamic_write, dynamic_read]
            dynamic_write.write_text(
                "<?php update_post_meta($post_id, 'old_caption', $_POST['caption']);",
                encoding="utf-8",
            )
            dynamic_read.write_text(
                "<?php echo get_post_meta($other_post_id, 'old_caption', true);",
                encoding="utf-8",
            )

            index = build_tainted_storage_index(paths, plugin_root, {})
            findings = analyze_php_file(
                dynamic_read, tainted_storage_keys=index["old-plugin"]
            )

            self.assertEqual(1, len(findings))
            self.assertEqual(
                "plugin_dynamic_subject_storage", findings[0]["flow_evidence"]
            )
            self.assertEqual("low", findings[0]["confidence"])

    def test_plugin_meta_dynamic_subject_does_not_override_existing_variable_flow(self):
        with tempfile.TemporaryDirectory() as directory:
            plugin_root = Path(directory)
            plugin = plugin_root / "old-plugin"
            plugin.mkdir()
            dynamic_write = plugin / "dynamic-save.php"
            dynamic_read = plugin / "dynamic-render.php"
            dynamic_write.write_text(
                "<?php update_post_meta($post_id, 'old_caption', $_POST['caption']);",
                encoding="utf-8",
            )
            dynamic_read.write_text(
                "<?php $title = $_GET['title']; "
                "echo $title . get_post_meta($post_id, 'old_caption', true);",
                encoding="utf-8",
            )

            index = build_tainted_storage_index(
                [dynamic_write, dynamic_read], plugin_root, {}
            )
            findings = analyze_php_file(
                dynamic_read, tainted_storage_keys=index["old-plugin"]
            )

            self.assertEqual(1, len(findings))
            self.assertEqual("variable_assignment", findings[0]["flow_evidence"])
            self.assertEqual("medium", findings[0]["confidence"])

    def test_plugin_meta_dynamic_subject_does_not_override_assignment_origin(self):
        with tempfile.TemporaryDirectory() as directory:
            plugin_root = Path(directory)
            plugin = plugin_root / "old-plugin"
            plugin.mkdir()
            dynamic_write = plugin / "dynamic-save.php"
            dynamic_read = plugin / "dynamic-render.php"
            dynamic_write.write_text(
                "<?php update_post_meta($post_id, 'old_caption', $_POST['caption']);",
                encoding="utf-8",
            )
            dynamic_read.write_text(
                "<?php $title = $_GET['title']; "
                "$combined = $title . get_post_meta($post_id, 'old_caption', true); "
                "echo $combined;",
                encoding="utf-8",
            )

            index = build_tainted_storage_index(
                [dynamic_write, dynamic_read], plugin_root, {}
            )
            findings = analyze_php_file(
                dynamic_read, tainted_storage_keys=index["old-plugin"]
            )

            self.assertEqual(1, len(findings))
            self.assertEqual("variable_assignment", findings[0]["flow_evidence"])
            self.assertEqual("medium", findings[0]["confidence"])

    def test_plugin_meta_dynamic_subject_is_omitted_from_mixed_sink_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            plugin_root = Path(directory)
            plugin = plugin_root / "old-plugin"
            plugin.mkdir()
            dynamic_write = plugin / "dynamic-save.php"
            dynamic_read = plugin / "dynamic-render.php"
            dynamic_write.write_text(
                "<?php update_post_meta($post_id, 'old_caption', $_POST['caption']);",
                encoding="utf-8",
            )
            dynamic_read.write_text(
                "<?php $stored = get_post_meta($post_id, 'old_caption', true); "
                "$title = $_GET['title']; echo $title . $stored;",
                encoding="utf-8",
            )

            index = build_tainted_storage_index(
                [dynamic_write, dynamic_read], plugin_root, {}
            )
            findings = analyze_php_file(
                dynamic_read, tainted_storage_keys=index["old-plugin"]
            )

            self.assertEqual(1, len(findings))
            self.assertEqual("variable_assignment", findings[0]["flow_evidence"])
            self.assertEqual("$title", findings[0]["tainted_vars"])
            self.assertEqual("medium", findings[0]["confidence"])

    def test_plugin_meta_dynamic_subject_does_not_override_mixed_rhs_origin(self):
        with tempfile.TemporaryDirectory() as directory:
            plugin_root = Path(directory)
            plugin = plugin_root / "old-plugin"
            plugin.mkdir()
            dynamic_write = plugin / "dynamic-save.php"
            dynamic_read = plugin / "dynamic-render.php"
            dynamic_write.write_text(
                "<?php update_post_meta($post_id, 'old_caption', $_POST['caption']);",
                encoding="utf-8",
            )
            dynamic_read.write_text(
                "<?php $stored = get_post_meta($post_id, 'old_caption', true); "
                "$title = $_GET['title']; $combined = $stored . $title; "
                "echo $combined;",
                encoding="utf-8",
            )

            index = build_tainted_storage_index(
                [dynamic_write, dynamic_read], plugin_root, {}
            )
            findings = analyze_php_file(
                dynamic_read, tainted_storage_keys=index["old-plugin"]
            )

            self.assertEqual(1, len(findings))
            self.assertEqual("variable_assignment", findings[0]["flow_evidence"])
            self.assertEqual("medium", findings[0]["confidence"])

    def test_plugin_meta_dynamic_subject_does_not_match_static_subject(self):
        with tempfile.TemporaryDirectory() as directory:
            plugin_root = Path(directory)
            plugin = plugin_root / "old-plugin"
            plugin.mkdir()
            dynamic_write = plugin / "dynamic-save.php"
            literal_write = plugin / "literal-save.php"
            dynamic_read = plugin / "dynamic-render.php"
            different_read = plugin / "different-render.php"
            dynamic_write.write_text(
                "<?php update_post_meta($post_id, 'old_caption', $_POST['caption']);",
                encoding="utf-8",
            )
            literal_write.write_text(
                "<?php update_post_meta(42, 'old_caption', $_POST['caption']);",
                encoding="utf-8",
            )
            dynamic_read.write_text(
                "<?php echo get_post_meta($post_id, 'old_caption', true);",
                encoding="utf-8",
            )
            different_read.write_text(
                "<?php echo get_post_meta(43, 'old_caption', true);",
                encoding="utf-8",
            )

            paths = [dynamic_write, literal_write, dynamic_read, different_read]
            index = build_tainted_storage_index(paths, plugin_root, {})

            self.assertEqual(
                {
                    ("post_meta", "42", "old_caption"),
                    ("post_meta", "<dynamic-subject>", "old_caption"),
                },
                index["old-plugin"],
            )
            literal_only_index = {("post_meta", "42", "old_caption")}
            self.assertEqual(
                [], analyze_php_file(dynamic_read, tainted_storage_keys=literal_only_index)
            )
            dynamic_only_index = {
                ("post_meta", "<dynamic-subject>", "old_caption")
            }
            self.assertEqual(
                [],
                analyze_php_file(
                    different_read, tainted_storage_keys=dynamic_only_index
                ),
            )

    def test_plugin_storage_index_keeps_storage_families_separate(self):
        with tempfile.TemporaryDirectory() as directory:
            plugin_root = Path(directory)
            plugin = plugin_root / "old-plugin"
            plugin.mkdir()
            write_path = plugin / "save.php"
            read_path = plugin / "render.php"
            write_path.write_text(
                "<?php update_option('old_title', $_POST['title']);",
                encoding="utf-8",
            )
            read_path.write_text(
                "<?php echo get_post_meta($post_id, 'old_title', true);",
                encoding="utf-8",
            )

            index = build_tainted_storage_index(
                [write_path, read_path], plugin_root, {}
            )
            findings = analyze_php_file(
                read_path, tainted_storage_keys=index["old-plugin"]
            )

            self.assertEqual([], findings)

    def test_parse_str_without_result_taints_created_variables(self):
        findings = self.analyze(
            "<?php\nparse_str($_SERVER['QUERY_STRING']);\necho $page;"
        )
        self.assertEqual(1, len(findings))
        self.assertEqual("scope_created_variables", findings[0]["flow_evidence"])

    def test_contextual_legacy_escape_lowers_severity(self):
        findings = self.analyze("<?php echo wp_specialchars($_GET['name']);")
        self.assertEqual(1, len(findings))
        self.assertEqual("INFO", findings[0]["severity"])

    def test_fgetcsv_fields_flow_through_foreach_to_html_output(self):
        findings = self.analyze(
            "<?php\n"
            "$row = $csv->fgetcsv(',');\n"
            "foreach ($row as $field) { echo '<td>' . $field . '</td>'; }"
        )
        self.assertEqual(1, len(findings))
        self.assertEqual("external_structured_data", findings[0]["source_origin"])
        self.assertEqual("LOW", findings[0]["severity"])

    def test_exif_values_flow_through_array_and_foreach_to_html_output(self):
        findings = self.analyze(
            "<?php\n"
            "$exif = exif_read_data($image, 0, true);\n"
            "$img_info[] = $exif['IFD0']['Title'];\n"
            "foreach ($img_info as $value) { echo '<td>' . $value . '</td>'; }"
        )
        self.assertEqual(1, len(findings))
        self.assertEqual("external_structured_data", findings[0]["source_origin"])
        self.assertEqual("LOW", findings[0]["severity"])

    def test_exif_values_with_translated_dynamic_key_flow_to_foreach_output(self):
        findings = self.analyze(
            "<?php\n"
            "$exif = exif_read_data($image, 0, true);\n"
            "$img_info[__('Make', 'gallery')] = $exif['IFD0']['Make'];\n"
            "foreach ($img_info as $value) { echo '<td>' . $value . '</td>'; }"
        )
        self.assertEqual(1, len(findings))
        self.assertEqual("external_structured_data", findings[0]["source_origin"])
        self.assertEqual("LOW", findings[0]["severity"])

    def test_external_dynamic_array_key_does_not_taint_fixed_sibling_output(self):
        findings = self.analyze(
            "<?php\n"
            "$exif = exif_read_data($image, 0, true);\n"
            "$img_info[__('Make', 'gallery')] = $exif['IFD0']['Make'];\n"
            "$img_info['safe'] = 'clean';\n"
            "echo '<td>' . $img_info['safe'] . '</td>';"
        )
        self.assertEqual([], findings)

    def test_attachment_metadata_exif_filter_flows_exact_field_to_output(self):
        findings, index = self.analyze_attachment_metadata_plugin(
            {
                "metadata.php": "<?php\n"
                "add_filter('wp_read_image_metadata', 'capture_image_make', 10, 3);\n"
                "function capture_image_make($metadata, $file, $type) {\n"
                "  $exif = exif_read_data($file);\n"
                "  $metadata['make'] = $exif['Make'];\n"
                "  return $metadata;\n"
                "}\n",
                "render.php": "<?php\n"
                "add_filter('the_content', 'render_image_metadata');\n"
                "function render_image_metadata($content) {\n"
                "  return preg_replace_callback('/<img[^>]*>/', 'render_image_match', $content);\n"
                "}\n"
                "function render_image_match($matches) {\n"
                "  $image_metadata = wp_get_attachment_metadata($attachment_id);\n"
                "  $make = $image_metadata['image_meta']['make'];\n"
                "  if (strlen($make) == 20) $make = 'RICOH';\n"
                "  $result = $matches[0] . '<span class=\"image-meta\">';\n"
                "  $result = $result . $make;\n"
                "  $result = $result . '</span>';\n"
                "  return $result;\n"
                "}\n",
            }
        )
        self.assertIn(
            ("attachment_exif_metadata", "", "make"), index["old-plugin"]
        )
        self.assertEqual(1, len(findings))
        self.assertEqual("external_structured_data", findings[0]["source_origin"])
        self.assertEqual(
            "attachment_exif_metadata_filter", findings[0]["flow_evidence"]
        )

    def test_attachment_metadata_exif_filter_rejects_unbounded_shapes(self):
        cases = {
            "dynamic_hook": "<?php\n"
            "$hook = 'wp_read_image_metadata';\n"
            "add_filter($hook, 'capture_image_make', 10, 3);\n"
            "function capture_image_make($metadata, $file, $type) { $exif = exif_read_data($file); $metadata['make'] = $exif['Make']; return $metadata; }\n",
            "dynamic_callback": "<?php\n"
            "$callback = 'capture_image_make';\n"
            "add_filter('wp_read_image_metadata', $callback, 10, 3);\n"
            "function capture_image_make($metadata, $file, $type) { $exif = exif_read_data($file); $metadata['make'] = $exif['Make']; return $metadata; }\n",
            "unregistered_callback": "<?php\n"
            "function capture_image_make($metadata, $file, $type) { $exif = exif_read_data($file); $metadata['make'] = $exif['Make']; return $metadata; }\n",
            "method_callback": "<?php\n"
            "class MetadataCapture { function capture_image_make($metadata, $file, $type) { $exif = exif_read_data($file); $metadata['make'] = $exif['Make']; return $metadata; } }\n"
            "add_filter('wp_read_image_metadata', array('MetadataCapture', 'capture_image_make'), 10, 3);\n",
            "exif_absent": "<?php\n"
            "add_filter('wp_read_image_metadata', 'capture_image_make', 10, 3);\n"
            "function capture_image_make($metadata, $file, $type) { $metadata['make'] = ordinary_reader($file); return $metadata; }\n",
        }
        for name, metadata_source in cases.items():
            with self.subTest(name=name):
                findings, index = self.analyze_attachment_metadata_plugin(
                    {
                        "metadata.php": metadata_source,
                        "render.php": "<?php\n"
                        "$image_metadata = wp_get_attachment_metadata($attachment_id);\n"
                        "$make = $image_metadata['image_meta']['make'];\n"
                        "echo $make;\n",
                    }
                )
                self.assertNotIn(
                    ("attachment_exif_metadata", "", "make"),
                    index.get("old-plugin", set()),
                )
                self.assertEqual([], findings)

    def test_attachment_metadata_exif_filter_rejects_unconditional_clean_overwrite(self):
        findings, _index = self.analyze_attachment_metadata_plugin(
            {
                "metadata.php": "<?php\n"
                "add_filter('wp_read_image_metadata', 'capture_image_make', 10, 3);\n"
                "function capture_image_make($metadata, $file, $type) {\n"
                "  $exif = exif_read_data($file);\n"
                "  $metadata['make'] = $exif['Make'];\n"
                "  return $metadata;\n}\n",
                "render.php": "<?php\n"
                "add_filter('the_content', 'render_image_metadata');\n"
                "function render_image_metadata($content) {\n"
                "  return preg_replace_callback('/<img[^>]*>/', 'render_image_match', $content);\n"
                "}\n"
                "function render_image_match($matches) {\n"
                "  $image_metadata = wp_get_attachment_metadata($attachment_id);\n"
                "  $make = $image_metadata['image_meta']['make'];\n"
                "  $make = 'RICOH';\n"
                "  $result = $matches[0] . '<span class=\"image-meta\">';\n"
                "  $result = $result . $make;\n"
                "  $result = $result . '</span>';\n"
                "  return $result;\n"
                "}\n",
            }
        )
        self.assertEqual([], findings)

    def test_attachment_metadata_exif_filter_rejects_other_or_clean_fields(self):
        metadata_source = "<?php\n"
        metadata_source += "add_filter('wp_read_image_metadata', 'capture_image_make', 10, 3);\n"
        metadata_source += "function capture_image_make($metadata, $file, $type) {\n"
        metadata_source += "  $exif = exif_read_data($file);\n"
        metadata_source += "  $metadata['make'] = $exif['Make'];\n"
        metadata_source += "  $metadata['safe'] = 'clean';\n"
        metadata_source += "  return $metadata;\n}\n"
        cases = {
            "other_field": "$model = $image_metadata['image_meta']['model']; echo $model;",
            "clean_sibling": "$safe = $image_metadata['image_meta']['safe']; echo $safe;",
            "other_nested_shape": "$make = $image_metadata['sizes']['make']; echo $make;",
        }
        for name, render_body in cases.items():
            with self.subTest(name=name):
                findings, _index = self.analyze_attachment_metadata_plugin(
                    {
                        "metadata.php": metadata_source,
                        "render.php": "<?php\n"
                        "$image_metadata = wp_get_attachment_metadata($attachment_id);\n"
                        + render_body,
                    }
                )
                self.assertEqual([], findings)

    def test_attachment_metadata_exif_filter_rejects_unbounded_return_accumulators(self):
        metadata_source = "<?php\n"
        metadata_source += "add_filter('wp_read_image_metadata', 'capture_image_make', 10, 3);\n"
        metadata_source += "function capture_image_make($metadata, $file, $type) {\n"
        metadata_source += "  $exif = exif_read_data($file);\n"
        metadata_source += "  $metadata['make'] = $exif['Make'];\n"
        metadata_source += "  return $metadata;\n}\n"
        render_cases = {
            "other_output_filter": "<?php\n"
            "add_filter('the_title', 'render_image_metadata');\n"
            "function render_image_metadata($content) { return preg_replace_callback('/<img[^>]*>/', 'render_image_match', $content); }\n"
            "function render_image_match($matches) { $image_metadata = wp_get_attachment_metadata($attachment_id); $make = $image_metadata['image_meta']['make']; $result = $matches[0] . '<span>'; $result = $result . $make; return $result; }\n",
            "dynamic_replacement_callback": "<?php\n"
            "add_filter('the_content', 'render_image_metadata');\n"
            "function render_image_metadata($content) { $callback = 'render_image_match'; return preg_replace_callback('/<img[^>]*>/', $callback, $content); }\n"
            "function render_image_match($matches) { $image_metadata = wp_get_attachment_metadata($attachment_id); $make = $image_metadata['image_meta']['make']; $result = $matches[0] . '<span>'; $result = $result . $make; return $result; }\n",
            "non_html_initializer": "<?php\n"
            "add_filter('the_content', 'render_image_metadata');\n"
            "function render_image_metadata($content) { return preg_replace_callback('/<img[^>]*>/', 'render_image_match', $content); }\n"
            "function render_image_match($matches) { $image_metadata = wp_get_attachment_metadata($attachment_id); $make = $image_metadata['image_meta']['make']; $result = $matches[0]; $result = $result . $make; return $result; }\n",
            "wrong_return_accumulator": "<?php\n"
            "add_filter('the_content', 'render_image_metadata');\n"
            "function render_image_metadata($content) { return preg_replace_callback('/<img[^>]*>/', 'render_image_match', $content); }\n"
            "function render_image_match($matches) { $image_metadata = wp_get_attachment_metadata($attachment_id); $make = $image_metadata['image_meta']['make']; $result = $matches[0] . '<span>'; $result = $result . $make; return $other; }\n",
        }
        for name, render_source in render_cases.items():
            with self.subTest(name=name):
                findings, _index = self.analyze_attachment_metadata_plugin(
                    {"metadata.php": metadata_source, "render.php": render_source}
                )
                self.assertEqual([], findings)

    def test_clean_and_unrelated_function_data_are_not_sources(self):
        self.assertEqual(
            [],
            self.analyze(
                "<?php $row = ordinary_reader($file); "
                "foreach ($row as $field) { echo '<td>' . $field . '</td>'; }"
            ),
        )
        self.assertEqual(
            [],
            self.analyze(
                "<?php $meta = array('Title' => 'clean'); "
                "foreach ($meta as $value) { echo '<td>' . $value . '</td>'; }"
            ),
        )

    def test_wrong_url_escape_does_not_hide_finding(self):
        findings = self.analyze(
            "<?php echo '<a href=\"' . esc_attr($_GET['url']) . '\">open</a>';"
        )
        self.assertEqual(1, len(findings))
        self.assertIn(findings[0]["severity"], {"MEDIUM", "HIGH"})

    def test_direct_php_entrypoint_is_recorded(self):
        findings = self.analyze("<?php echo $_REQUEST['value'];", name="ajax.php")
        self.assertEqual("direct_php", findings[0]["entrypoint_kind"])
        self.assertEqual("unauthenticated", findings[0]["entrypoint_exposure"])

    def test_custom_sql_native_object_read_is_low_confidence(self):
        findings, index = self.analyze_custom_sql_plugin({
            "write.php": "<?php $table = $wpdb->prefix . 'events'; $payload = $_GET['x']; $wpdb->query(\"UPDATE $table SET payload='$payload', clean='ok' WHERE id=1\");",
            "read.php": "<?php $table = $wpdb->prefix . 'events'; $rows = $wpdb->get_results(\"SELECT payload, count(*) AS total FROM $table\"); foreach ($rows as $row) { echo $row->payload; echo $row->total; }",
        })
        self.assertIn(("custom_sql", "wpdb_prefix:events", "payload"), index["old-plugin"])
        self.assertEqual(1, len(findings))
        self.assertEqual("plugin_literal_sql_storage", findings[0]["flow_evidence"])
        self.assertEqual("low", findings[0]["confidence"])

    def test_custom_sql_does_not_override_stronger_same_sink_evidence(self):
        findings, _index = self.analyze_custom_sql_plugin({
            "write.php": "<?php $table=$wpdb->prefix.'events'; $value=$_GET['x']; $wpdb->query(\"UPDATE $table SET payload='$value' WHERE id=1\");",
            "read.php": "<?php $table=$wpdb->prefix.'events'; $row=$wpdb->get_row(\"SELECT payload FROM $table WHERE id=\".$_GET['id']); echo $row->payload;",
        })
        self.assertEqual(1, len(findings))
        self.assertEqual("variable_assignment", findings[0]["flow_evidence"])
        self.assertEqual("medium", findings[0]["confidence"])

    def test_custom_sql_exact_field_can_flow_through_local_accumulator(self):
        findings, _index = self.analyze_custom_sql_plugin({
            "write.php": "<?php $table=$wpdb->prefix.'events'; $value=$_GET['x']; $wpdb->query(\"UPDATE $table SET payload='$value' WHERE id=1\");",
            "read.php": "<?php $table=$wpdb->prefix.'events'; $rows=$wpdb->get_results(\"SELECT payload,count(*) AS total FROM $table\"); $html=''; foreach($rows as $row){$html .= $row->payload;} echo $html;",
        })
        self.assertEqual(1, len(findings))
        self.assertEqual("plugin_literal_sql_storage", findings[0]["flow_evidence"])

    def test_custom_sql_thin_array_a_wrapper_and_update_alias(self):
        findings, _index = self.analyze_custom_sql_plugin({
            "write.php": "<?php define('LOG_TABLE', $wpdb->prefix . 'logs'); $table = LOG_TABLE; $value = $_POST['x']; $sql = \"UPDATE $table SET payload='$value', clean='ok' WHERE id=1\"; $wpdb->query($sql);",
            "read.php": "<?php\nfunction lz_selectquery($query, $array=0) {\nglobal $wpdb;\n$result = $wpdb->get_results($query, 'ARRAY_A');\nif (empty($array)) { return current($result); } else { return $result; }\n}\n$table = LOG_TABLE;\n$sql = \"SELECT payload FROM $table\";\n$rows = lz_selectquery($sql, 1);\nforeach ($rows as $row) { print $row['payload']; }",
        })
        self.assertEqual(1, len(findings))
        self.assertEqual("plugin_literal_sql_storage", findings[0]["flow_evidence"])

    def test_custom_sql_insert_data_and_registered_zero_arg_helper_are_limited_to_write(self):
        findings, index = self.analyze_custom_sql_plugin({
            "write.php": "<?php\nfunction local_source() { return $_GET['x']; }\nadd_action('init', 'save');\nfunction save() {\n$table=$wpdb->prefix.'events';\n$value=local_source();\n$wpdb->insert($table, array('payload' => $value, 'clean' => 'ok'));\n$wpdb->update($table, array('payload' => $value), array('id' => 1));\n}",
            "read.php": "<?php $table=$wpdb->prefix.'events'; $row=$wpdb->get_row(\"SELECT payload FROM $table\"); echo $row->payload;",
        })
        self.assertIn(("custom_sql", "wpdb_prefix:events", "payload"), index["old-plugin"])
        self.assertEqual(1, len(findings))
        self.assertEqual("low", findings[0]["confidence"])
        # The helper result must not be treated as a general output source.
        self.assertEqual([], self.analyze("<?php\nfunction local_source() { return $_GET['x']; }\nadd_action('init', 'save');\nfunction save() {\n$value=local_source();\necho $value;\n}"))

    def test_custom_sql_flattens_legacy_concat_and_helper_return(self):
        findings, index = self.analyze_custom_sql_plugin({
            "helper.php": "<?php\nfunction nsp_URL() {\n$x = (isset($_SERVER['QUERY_STRING']) ? $_SERVER['QUERY_STRING'] : '');\nif (empty($x)) { $x = (isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : ''); }\nif (substr($x, 0, 1) === '?') { $x = substr($x, 1); }\nreturn $x;\n}",
            "write.php": "<?php\nadd_action('init', 'save');\nfunction save() {\n$table = $wpdb->prefix . 'cn_social_icon';\n$value = nsp_URL();\n$value = esc_sql($value);\n$update = \"UPDATE \" . $table . \" SET image_url='\" . $value . \"', clean='ok' WHERE id=1\";\n$wpdb->query($update);\n}",
            "read.php": "<?php\n$table = $wpdb->prefix . 'cn_social_icon';\n$rows = $wpdb->get_results(\"SELECT image_url FROM \" . $table);\nforeach ($rows as $row) { echo $row->image_url; }",
        })
        self.assertIn(("custom_sql", "wpdb_prefix:cn_social_icon", "image_url"), index["old-plugin"])
        self.assertEqual(1, len(findings))

    def test_custom_sql_direct_prefix_concat_and_rejections(self):
        findings, _index = self.analyze_custom_sql_plugin({
            "write.php": "<?php $url=$_SERVER['REQUEST_URI']; $wpdb->query(\"INSERT INTO `\" . $wpdb->prefix . \"loginizer_logs` SET url='\" . $url . \"'\");",
            "read.php": "<?php $rows=$wpdb->get_results(\"SELECT url FROM `\" . $wpdb->prefix . \"loginizer_logs`\"); foreach($rows as $row){ echo $row->url; }",
        })
        self.assertEqual(1, len(findings))
        negatives = {
            "alias_of_alias": "<?php $a=$wpdb->prefix.'a'; $b=$a; $c=$b; $x=$_GET['x']; $wpdb->query(\"INSERT INTO $c (payload) VALUES ('$x')\");",
            "malformed_concat": "<?php $a=$wpdb->prefix.'a'; $x=$_GET['x']; $sql=\"INSERT INTO $a (payload) VALUES ('$x); $wpdb->query($sql);",
            "duplicate_helper": "<?php function source(){return $_GET['x'];} function source(){return $_GET['x'];} add_action('init','save'); function save(){ $a=$wpdb->prefix.'a'; $x=source(); $wpdb->query(\"INSERT INTO $a (payload) VALUES ('$x')\");}",
            "bad_wrapper": "<?php function rows($q,$flag=0){ $result=$wpdb->get_results($q,'ARRAY_A'); if($flag){return $result;} return other($result); }",
        }
        for name, source in negatives.items():
            with self.subTest(name=name):
                findings, _index = self.analyze_custom_sql_plugin({"write.php": source, "read.php": "<?php $a=$wpdb->prefix.'a'; $rows=$wpdb->get_results(\"SELECT payload FROM $a\"); foreach($rows as $row){echo $row->payload;}"})
                self.assertEqual([], findings)

    def test_custom_sql_wrapper_accepts_direct_concat_with_static_terms(self):
        findings, _index = self.analyze_custom_sql_plugin({
            "write.php": "<?php $url = $_SERVER['REQUEST_URI']; $loginizer=array('current_ip'=>'clean'); $wpdb->query(\"INSERT INTO `\" . $wpdb->prefix . \"loginizer_logs` SET username='clean', time='\".time().\"', ip='\".$loginizer['current_ip'].\"', url='\" . $url . \"'\");",
            "read.php": "<?php\nfunction lz_selectquery($query,$array=0) {\nglobal $wpdb;\n$result=$wpdb->get_results($query,'ARRAY_A');\nif(empty($array)){return current($result);}else{return $result;}\n}\n$lz_env=array('cur_page'=>0,'res_len'=>10);\n$loginizer=array('current_ip'=>'clean');\n$filter=new stdClass(); $filter->kind='ip';\n$rows=lz_selectquery(\"SELECT * FROM `\".$wpdb->prefix.\"loginizer_logs` WHERE current_ip='\".$loginizer['current_ip'].\"' AND kind='\".$filter->kind.\"' LIMIT \".$lz_env['cur_page'].\", \".$lz_env['res_len'].\"\",1);\nforeach($rows as $row){echo $row['url'];}",
        })
        self.assertEqual(1, len(findings))
        self.assertEqual("plugin_literal_sql_storage", findings[0]["flow_evidence"])

    def test_custom_sql_rejects_dynamic_concat_terms(self):
        cases = {
            "dynamic_key": "<?php $a=$wpdb->prefix.'a'; $x=$_GET['x']; $key=$_GET['key']; $wpdb->query(\"INSERT INTO $a (payload) VALUES ('\".$data[$key].\"')\");",
            "dynamic_property": "<?php $a=$wpdb->prefix.'a'; $x=$_GET['x']; $field=$_GET['field']; $wpdb->query(\"INSERT INTO $a (payload) VALUES ('\".$data->$field.\"')\");",
            "dynamic_call": "<?php $a=$wpdb->prefix.'a'; $x=$_GET['x']; $fn='source'; $wpdb->query(\"INSERT INTO $a (payload) VALUES ('\".$fn().\"')\");",
        }
        reader = "<?php $a=$wpdb->prefix.'a'; $rows=$wpdb->get_results(\"SELECT payload FROM $a\"); foreach($rows as $row){echo $row->payload;}"
        for name, writer in cases.items():
            with self.subTest(name=name):
                findings, _index = self.analyze_custom_sql_plugin({"write.php": writer, "read.php": reader})
                self.assertEqual([], findings)

    def test_custom_sql_rejects_duplicate_wrapper(self):
        findings, _index = self.analyze_custom_sql_plugin({
            "write.php": "<?php $a=$wpdb->prefix.'a'; $x=$_GET['x']; $wpdb->query(\"INSERT INTO $a (payload) VALUES ('$x')\");",
            "read.php": "<?php function rows($q){$r=$wpdb->get_results($q,'ARRAY_A');return $r;} function rows($q){$r=$wpdb->get_results($q,'ARRAY_A');return $r;} $a=$wpdb->prefix.'a'; $q=\"SELECT payload FROM $a\"; $rows=rows($q); foreach($rows as $row){echo $row['payload'];}",
        })
        self.assertEqual([], findings)

    def test_custom_sql_rejects_plugin_wide_duplicate_helper_or_wrapper(self):
        reader = "<?php $a=$wpdb->prefix.'a'; $rows=$wpdb->get_results(\"SELECT payload FROM $a\"); foreach($rows as $row){echo $row->payload;}"
        helper_findings, _index = self.analyze_custom_sql_plugin({
            "helper-one.php": "<?php function source(){ return $_GET['x']; }",
            "helper-two.php": "<?php function source(){ return $_GET['x']; }",
            "write.php": "<?php add_action('init','save'); function save(){ $a=$wpdb->prefix.'a'; $x=source(); $wpdb->query(\"INSERT INTO $a (payload) VALUES ('$x')\"); }",
            "read.php": reader,
        })
        self.assertEqual([], helper_findings)
        wrapper_findings, _index = self.analyze_custom_sql_plugin({
            "write.php": "<?php $a=$wpdb->prefix.'a'; $x=$_GET['x']; $wpdb->query(\"INSERT INTO $a (payload) VALUES ('$x')\");",
            "wrapper-one.php": "<?php function rows($q){global $wpdb; $r=$wpdb->get_results($q,'ARRAY_A'); return $r;}",
            "wrapper-two.php": "<?php function rows($q){global $wpdb; $r=$wpdb->get_results($q,'ARRAY_A'); return $r;}",
            "read.php": "<?php $a=$wpdb->prefix.'a'; $q=\"SELECT payload FROM $a\"; $rows=rows($q); foreach($rows as $row){echo $row['payload'];}",
        })
        self.assertEqual([], wrapper_findings)

    def test_custom_sql_unique_helper_summary_uses_its_definition_source(self):
        with tempfile.TemporaryDirectory() as directory:
            plugin_root = Path(directory)
            plugin = plugin_root / "old-plugin"
            plugin.mkdir()
            helper = plugin / "helper.php"
            writer = plugin / "write.php"
            helper.write_text(
                "<?php function local_source() { return $_GET['x']; }",
                encoding="utf-8",
            )
            writer.write_text(
                "<?php add_action('init', 'save'); function save() { "
                "$table=$wpdb->prefix.'events'; $value=local_source(); "
                "$wpdb->query(\"UPDATE $table SET payload='$value'\"); }",
                encoding="utf-8",
            )
            filler_paths = []
            for number in range(4):
                filler = plugin / f"filler-{number}.php"
                filler.write_text("<?php $unused = 'value';", encoding="utf-8")
                filler_paths.append(filler)

            with patch.object(
                taint_engine,
                "_local_zero_arg_helper_source",
                wraps=taint_engine._local_zero_arg_helper_source,
            ) as summarize:
                index = build_tainted_storage_index(
                    [helper, writer, *filler_paths], plugin_root, {}
                )

            self.assertEqual(1, summarize.call_count)
            self.assertEqual(
                {
                    ("custom_sql", "wpdb_prefix:events", "payload"),
                    (
                        "custom_sql_zero_arg_helper",
                        "local_source",
                        "superglobals\x1f\\$_GET\\b",
                    ),
                },
                index["old-plugin"],
            )

    def test_custom_sql_rejects_mismatches_and_unexecuted_alias(self):
        cases = {
            "table": ("$a = $wpdb->prefix . 'a'; $x=$_GET['x']; $wpdb->query(\"INSERT INTO $a (payload) VALUES ('$x')\");", "$b = $wpdb->prefix . 'b'; $rows=$wpdb->get_results(\"SELECT payload FROM $b\"); foreach($rows as $row){echo $row->payload;}"),
            "column": ("$a = $wpdb->prefix . 'a'; $x=$_GET['x']; $wpdb->query(\"INSERT INTO $a (payload) VALUES ('$x')\");", "$a = $wpdb->prefix . 'a'; $rows=$wpdb->get_results(\"SELECT clean FROM $a\"); foreach($rows as $row){echo $row->clean;}"),
            "clean_sibling": ("$a = $wpdb->prefix . 'a'; $x=$_GET['x']; $wpdb->query(\"INSERT INTO $a (payload, clean) VALUES ('$x', 'ok')\");", "$a = $wpdb->prefix . 'a'; $rows=$wpdb->get_results(\"SELECT * FROM $a\"); foreach($rows as $row){echo $row->clean;}"),
            "clean_write": ("$a = $wpdb->prefix . 'a'; $wpdb->query(\"INSERT INTO $a (payload) VALUES ('ok')\");", "$a = $wpdb->prefix . 'a'; $rows=$wpdb->get_results(\"SELECT payload FROM $a\"); foreach($rows as $row){echo $row->payload;}"),
            "dynamic_table": ("$a = $wpdb->prefix . $_GET['table']; $x=$_GET['x']; $wpdb->query(\"INSERT INTO $a (payload) VALUES ('$x')\");", "$a = $wpdb->prefix . 'a'; $rows=$wpdb->get_results(\"SELECT payload FROM $a\"); foreach($rows as $row){echo $row->payload;}"),
            "dynamic_column": ("$a = $wpdb->prefix . 'a'; $x=$_GET['x']; $col=$_GET['col']; $wpdb->query(\"UPDATE $a SET $col='$x'\");", "$a = $wpdb->prefix . 'a'; $rows=$wpdb->get_results(\"SELECT payload FROM $a\"); foreach($rows as $row){echo $row->payload;}"),
            "unexecuted": ("$a = $wpdb->prefix . 'a'; $x=$_GET['x']; $sql=\"INSERT INTO $a (payload) VALUES ('$x')\";", "$a = $wpdb->prefix . 'a'; $rows=$wpdb->get_results(\"SELECT payload FROM $a\"); foreach($rows as $row){echo $row->payload;}"),
        }
        for name, (writer, reader) in cases.items():
            with self.subTest(name=name):
                findings, _index = self.analyze_custom_sql_plugin({"write.php": "<?php " + writer, "read.php": "<?php " + reader})
                self.assertEqual([], findings)

    def test_custom_sql_does_not_cross_plugins(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, second = root / "first", root / "second"
            first.mkdir(); second.mkdir()
            writer = first / "write.php"; reader = second / "read.php"
            writer.write_text("<?php $a=$wpdb->prefix.'a'; $x=$_GET['x']; $wpdb->query(\"INSERT INTO $a (payload) VALUES ('$x')\");", encoding="utf-8")
            reader.write_text("<?php $a=$wpdb->prefix.'a'; $rows=$wpdb->get_results(\"SELECT payload FROM $a\"); foreach($rows as $row){echo $row->payload;}", encoding="utf-8")
            index = build_tainted_storage_index([writer, reader], root, {})
            self.assertEqual([], analyze_php_file(reader, tainted_storage_keys=index.get("second", set())))

    def test_rest_post_object_callback_class_constant_post_meta_reaches_html_attribute(self):
        with tempfile.TemporaryDirectory() as directory:
            plugin_root = Path(directory)
            plugin = plugin_root / "old-plugin"
            plugin.mkdir()
            constants = plugin / "Plugin.php"
            writer = plugin / "Block.php"
            reader = plugin / "Data.php"
            constants.write_text(
                "<?php class Old_Plugin { const CF_SOURCE = 'old-source'; const UNUSED = 'unused'; }",
                encoding="utf-8",
            )
            writer.write_text(
                "<?php\nclass Old_Block {\nfunction routes() {\n"
                "register_rest_route('old/v1', '/update', array("
                "'methods' => 'POST', 'callback' => array($this, 'save')));\n}\n"
                "function save($data) {\n"
                "update_post_meta($data['id'], Old_Plugin::CF_SOURCE, "
                "$data['old-source']);\n}\n}",
                encoding="utf-8",
            )
            reader.write_text(
                "<?php\nclass Old_Data {\nfunction render() {\n"
                "$source = strtolower(get_post_meta($this->chart->ID, "
                "Old_Plugin::CF_SOURCE, true));\n"
                "echo '<span data-source=\"' . $source . '\"></span>';\n}\n}",
                encoding="utf-8",
            )
            paths = [constants, writer, reader]

            index = build_tainted_storage_index(paths, plugin_root, {})
            findings = analyze_php_file(
                reader, tainted_storage_keys=index["old-plugin"]
            )

            self.assertIn(
                ("post_meta", "<dynamic-subject>", "old-source"),
                index["old-plugin"],
            )
            self.assertNotIn(
                ("post_meta_class_constant", "old_plugin::unused", "unused"),
                index["old-plugin"],
            )
            self.assertTrue(
                any(
                    finding["source_origin"] == "plugin_stored_read"
                    and finding["sink_kind"] == "html_output"
                    for finding in findings
                ),
                findings,
            )

    def test_rest_post_object_callback_model_rejects_unbounded_shapes(self):
        cases = {
            "get": "'methods' => 'GET', 'callback' => array($this, 'save')",
            "permission": "'methods' => 'POST', 'callback' => array($this, 'save'), 'permission_callback' => '__return_true'",
            "bare": "'methods' => 'POST', 'callback' => 'save'",
            "static": "'methods' => 'POST', 'callback' => array('Old_Block', 'save')",
            "dynamic_callback": "'methods' => 'POST', 'callback' => array($this, $callback)",
            "dynamic_options": "$options",
            "clean_overwrite": "'methods' => 'POST', 'callback' => array($this, 'save')",
        }
        for name, options in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                plugin_root = Path(directory)
                plugin = plugin_root / "old-plugin"
                plugin.mkdir()
                constants = plugin / "Plugin.php"
                writer = plugin / "Block.php"
                reader = plugin / "Data.php"
                constants.write_text(
                    "<?php class Old_Plugin { const CF_SOURCE = 'old-source'; }",
                    encoding="utf-8",
                )
                overwrite = (
                    " update_post_meta($data['id'], Old_Plugin::CF_SOURCE, 'clean');"
                    if name == "clean_overwrite"
                    else ""
                )
                writer.write_text(
                    "<?php\nclass Old_Block {\nfunction routes() {\n"
                    f"register_rest_route('old/v1', '/update', array({options}));\n}}\n"
                    "function save($data) {\n"
                    "update_post_meta($data['id'], Old_Plugin::CF_SOURCE, "
                    "$data['old-source']);"
                    f"{overwrite}\n}}",
                    encoding="utf-8",
                )
                reader.write_text(
                    "<?php $source = get_post_meta($chart_id, "
                    "Old_Plugin::CF_SOURCE, true); echo $source;",
                    encoding="utf-8",
                )
                paths = [constants, writer, reader]
                index = build_tainted_storage_index(paths, plugin_root, {})
                findings = analyze_php_file(
                    reader, tainted_storage_keys=index.get("old-plugin", set())
                )
                self.assertEqual([], findings)

        for name, namespace, route in (
            ("dynamic_namespace", "$namespace", "'/update'"),
            ("called_namespace", "make_namespace()", "'/update'"),
            ("dynamic_route", "'old/v1'", "$route"),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                plugin_root = Path(directory)
                plugin = plugin_root / "old-plugin"
                plugin.mkdir()
                constants = plugin / "Plugin.php"
                writer = plugin / "Block.php"
                reader = plugin / "Data.php"
                constants.write_text(
                    "<?php class Old_Plugin { const CF_SOURCE = 'old-source'; }",
                    encoding="utf-8",
                )
                writer.write_text(
                    "<?php class Old_Block { function routes() { "
                    f"register_rest_route({namespace}, {route}, array("
                    "'methods'=>'POST','callback'=>array($this,'save'))); } "
                    "function save($data) { update_post_meta($data['id'], "
                    "Old_Plugin::CF_SOURCE, $data['old-source']); } }",
                    encoding="utf-8",
                )
                reader.write_text(
                    "<?php $source=get_post_meta($chart_id, Old_Plugin::CF_SOURCE, true); echo $source;",
                    encoding="utf-8",
                )
                paths = [constants, writer, reader]
                index = build_tainted_storage_index(paths, plugin_root, {})
                self.assertEqual(
                    [],
                    analyze_php_file(
                        reader, tainted_storage_keys=index.get("old-plugin", set())
                    ),
                )

    def test_rest_post_object_callback_model_rejects_duplicate_inherited_dynamic_or_other_constants(self):
        cases = {
            "duplicate_method": (
                "class Old_Block { function routes() { register_rest_route('old/v1', '/update', array('methods'=>'POST','callback'=>array($this,'save'))); } function save($data) { update_post_meta($data['id'], Old_Plugin::CF_SOURCE, $data['old-source']); } } class Other_Block { function save($data) {} }",
                "Old_Plugin::CF_SOURCE",
            ),
            "inherited": (
                "class Parent_Block {} class Old_Block extends Parent_Block { function routes() { register_rest_route('old/v1', '/update', array('methods'=>'POST','callback'=>array($this,'save'))); } function save($data) { update_post_meta($data['id'], Old_Plugin::CF_SOURCE, $data['old-source']); } }",
                "Old_Plugin::CF_SOURCE",
            ),
            "dynamic_constant": (
                "class Old_Block { function routes() { register_rest_route('old/v1', '/update', array('methods'=>'POST','callback'=>array($this,'save'))); } function save($data) { update_post_meta($data['id'], Old_Plugin::$CF_SOURCE, $data['old-source']); } }",
                "Old_Plugin::CF_SOURCE",
            ),
            "other_constant": (
                "class Old_Block { function routes() { register_rest_route('old/v1', '/update', array('methods'=>'POST','callback'=>array($this,'save'))); } function save($data) { update_post_meta($data['id'], Other_Plugin::CF_SOURCE, $data['old-source']); } }",
                "Old_Plugin::CF_SOURCE",
            ),
            "other_storage": (
                "class Old_Block { function routes() { register_rest_route('old/v1', '/update', array('methods'=>'POST','callback'=>array($this,'save'))); } function save($data) { update_option(Old_Plugin::CF_SOURCE, $data['old-source']); } }",
                "Old_Plugin::CF_SOURCE",
            ),
        }
        for name, (writer_text, reader_constant) in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                plugin_root = Path(directory)
                plugin = plugin_root / "old-plugin"
                plugin.mkdir()
                constants = plugin / "Plugin.php"
                writer = plugin / "Block.php"
                reader = plugin / "Data.php"
                constants.write_text(
                    "<?php class Old_Plugin { const CF_SOURCE = 'old-source'; } "
                    "class Other_Plugin { const CF_SOURCE = 'other-source'; }",
                    encoding="utf-8",
                )
                writer.write_text("<?php " + writer_text, encoding="utf-8")
                reader.write_text(
                    "<?php $source = get_post_meta($chart_id, "
                    f"{reader_constant}, true); echo $source;",
                    encoding="utf-8",
                )
                paths = [constants, writer, reader]
                index = build_tainted_storage_index(paths, plugin_root, {})
                findings = analyze_php_file(
                    reader, tainted_storage_keys=index.get("old-plugin", set())
                )
                self.assertEqual([], findings)

        for name, constants_text in (
            (
                "inherited_constant_class",
                "class Base_Plugin {} class Old_Plugin extends Base_Plugin { const CF_SOURCE = 'old-source'; }",
            ),
            (
                "global_constant_after_class",
                "class Old_Plugin {} const CF_SOURCE = 'old-source';",
            ),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                plugin_root = Path(directory)
                plugin = plugin_root / "old-plugin"
                plugin.mkdir()
                constants = plugin / "Plugin.php"
                writer = plugin / "Block.php"
                reader = plugin / "Data.php"
                constants.write_text("<?php " + constants_text, encoding="utf-8")
                writer.write_text(
                    "<?php class Old_Block { function routes() { "
                    "register_rest_route('old/v1','/update',array('methods'=>'POST',"
                    "'callback'=>array($this,'save'))); } function save($data) { "
                    "update_post_meta($data['id'], Old_Plugin::CF_SOURCE, "
                    "$data['old-source']); } }",
                    encoding="utf-8",
                )
                reader.write_text(
                    "<?php $source=get_post_meta($chart_id, Old_Plugin::CF_SOURCE, true); echo $source;",
                    encoding="utf-8",
                )
                paths = [constants, writer, reader]
                index = build_tainted_storage_index(paths, plugin_root, {})
                self.assertEqual(
                    [],
                    analyze_php_file(
                        reader, tainted_storage_keys=index.get("old-plugin", set())
                    ),
                )


if __name__ == "__main__":
    unittest.main()
