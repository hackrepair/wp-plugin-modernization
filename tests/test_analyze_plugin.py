import json
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app" / "analyze_plugin.py"


PLUGIN = """<?php
/**
 * Plugin Name: Fixture Plugin
 * Version: 1.0.0
 */
defined( 'ABSPATH' ) || exit;
function fixture_save() {
    $value = $_POST['value'];
    global $wpdb;
    $wpdb->query( "SELECT 1" );
    echo $value;
}
"""


class AnalyzePluginTests(unittest.TestCase):
    def run_app(self, input_path: Path, output: Path):
        return subprocess.run(["python3", str(APP), str(input_path), "--output", str(output)], text=True, capture_output=True, check=False)

    def test_directory_scan_preserves_source_and_writes_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plugin = root / "fixture-plugin"
            plugin.mkdir()
            source = plugin / "fixture-plugin.php"
            source.write_text(PLUGIN)
            before = source.read_bytes()
            output = root / "report"
            result = self.run_app(plugin, output)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual(before, source.read_bytes())
            report = json.loads((output / "report.json").read_text())
            self.assertEqual(64, len(report["input"]["sha256"]))
            self.assertEqual(1, report["inventory"]["php_files"])
            self.assertEqual("Fixture Plugin", report["plugin_headers"][0]["headers"]["Plugin Name"])
            self.assertEqual({"input", "output"}, {item["category"] for item in report["findings"] if item["category"] != "syntax"})

    def test_excludes_embedded_tooling_worktrees(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plugin = root / "fixture-plugin"
            plugin.mkdir()
            (plugin / "fixture.php").write_text(PLUGIN)
            duplicate = plugin / ".claude" / "worktrees" / "copy.php"
            duplicate.parent.mkdir(parents=True)
            duplicate.write_text("<?php echo $_POST['duplicate'];")
            output = root / "report"
            result = self.run_app(plugin, output)
            self.assertEqual(0, result.returncode, result.stderr)
            report = json.loads((output / "report.json").read_text())
            self.assertEqual(1, report["inventory"]["php_files"])
            self.assertFalse(any(".claude" in item["path"] for item in report["findings"]))

    def test_recognizes_guarded_input_and_constrained_deserialization(self):
        guarded = """<?php
function save_setting() {
    current_user_can( 'manage_options' );
    check_ajax_referer( 'fixture', 'nonce' );
    $value = absint( wp_unslash( $_POST['value'] ) );
    global $wpdb;
    $wpdb->get_row( $wpdb->prepare( 'SELECT id FROM %i WHERE id = %d', $wpdb->posts, $value ) );
    echo esc_html( $value );
    $caps = unserialize( $stored, array( 'allowed_classes' => false ) );
    if ( ! is_array( $caps ) ) { return; }
}
"""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plugin = root / "fixture-plugin"
            plugin.mkdir()
            (plugin / "fixture.php").write_text(guarded)
            result = self.run_app(plugin, root / "report")
            self.assertEqual(0, result.returncode, result.stderr)
            report = json.loads((root / "report" / "report.json").read_text())
            titles = {item["title"] for item in report["findings"]}
            self.assertIn("Request input has local controls", titles)
            self.assertIn("Constrained deserialization observed", titles)
            self.assertTrue(any(item["title"] == "Request input has local controls" and item["severity"] == "info" for item in report["findings"]))
            self.assertNotIn("Dynamic database query needs parameterization review", titles)
            self.assertNotIn("Dynamic output needs escaping-context review", titles)

    def test_structured_wpdb_delete_and_documented_stream_output_are_not_actionable(self):
        safe_patterns = """<?php
function remove_row( $id ) {
    global $wpdb;
    $wpdb->delete( $wpdb->options, array( 'option_id' => $id ), array( '%d' ) );
    // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Binary response body.
    echo fread( $handle, 1024 );
}
"""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plugin = root / "fixture-plugin"
            plugin.mkdir()
            (plugin / "fixture.php").write_text(safe_patterns)
            result = self.run_app(plugin, root / "report")
            self.assertEqual(0, result.returncode, result.stderr)
            report = json.loads((root / "report" / "report.json").read_text())
            self.assertFalse(any(item["category"] == "database" for item in report["findings"]))
            self.assertTrue(any(item["title"] == "Documented unescaped output observed" and item["severity"] == "info" for item in report["findings"]))

    def test_zip_scan_creates_report_without_modifying_archive(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "fixture.zip"
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr("fixture/fixture.php", PLUGIN)
            before = archive.read_bytes()
            result = self.run_app(archive, root / "report")
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual(before, archive.read_bytes())

    def test_rejects_unsafe_zip_member(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "unsafe.zip"
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr("../escape.php", "<?php")
            result = self.run_app(archive, root / "report")
            self.assertEqual(2, result.returncode)
            self.assertIn("unsafe path", result.stderr)

    def test_refuses_to_overwrite_existing_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plugin = root / "fixture-plugin"
            plugin.mkdir()
            (plugin / "fixture.php").write_text(PLUGIN)
            output = root / "report"
            output.mkdir()
            result = self.run_app(plugin, output)
            self.assertNotEqual(0, result.returncode)
            self.assertIn("must not already exist", result.stderr)


if __name__ == "__main__":
    unittest.main()
