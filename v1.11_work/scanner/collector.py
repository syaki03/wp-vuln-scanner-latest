from pathlib import Path
from typing import List
from config import PHP_EXTENSIONS

def collect_php_files(root: Path) -> List[Path]:
    files = []
    for path in root.rglob("*"):
        if path.is_file() and path.suffix.lower() in PHP_EXTENSIONS:
            files.append(path)
    return sorted(files)