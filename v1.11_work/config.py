import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent

# Set WP_PLUGIN_ROOT to a directory that contains one subdirectory per plugin.
PLUGIN_ROOT = Path(
    os.environ.get("WP_PLUGIN_ROOT", str(BASE_DIR / "plugins"))
).expanduser().resolve()

# Override with WP_SCANNER_OUTPUT_DIR when results should be written elsewhere.
OUTPUT_DIR = Path(
    os.environ.get("WP_SCANNER_OUTPUT_DIR", str(BASE_DIR / "output"))
).expanduser().resolve()
CSV_NAME = "findings.csv"
JSON_NAME = "findings.json"
HTML_NAME = "report.html"

PHP_EXTENSIONS = {".php", ".inc", ".module"}

WINDOW_BEFORE = 4
WINDOW_AFTER = 10

MAX_SNIPPET_LINES = 20
