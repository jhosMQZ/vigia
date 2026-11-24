"""Shared helpers for source-code modules: safe file walking and language detection."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Iterator

LANG_BY_EXT = {
    ".py": "python", ".pyw": "python", ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".vue": "javascript", ".svelte": "javascript", ".php": "php", ".phtml": "php",
    ".java": "java", ".kt": "java", ".jsp": "java", ".cs": "csharp", ".cshtml": "csharp", ".razor": "csharp",
    ".go": "go", ".rb": "ruby", ".erb": "ruby", ".html": "html", ".htm": "html", ".jinja": "html", ".jinja2": "html",
    ".j2": "html", ".twig": "html", ".hbs": "html", ".ejs": "html", ".blade.php": "php", ".css": "css", ".scss": "css",
    ".sql": "sql", ".config": "config", ".xml": "config", ".yml": "config", ".yaml": "config", ".json": "config",
    ".ini": "config", ".toml": "config", ".properties": "config", ".env": "config", ".tf": "terraform",
}
SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", "target", "bin", "obj", ".next", ".nuxt", "coverage",
             "__pycache__", ".venv", "venv", "env", "site-packages", "bower_components", ".gradle", ".idea", ".vs",
             "migrations", "public/build", "static/dist"}
TEST_HINT = ("/test/", "/tests/", "/spec/", "/__tests__/", "_test.", ".test.", ".spec.", "/fixtures/", "/testdata/",
             "/examples/", "/docs/")


def language(path: Path) -> str | None:
    name = path.name.lower()
    if name.endswith(".blade.php"):
        return "php"
    if name in ("dockerfile",) or name.startswith("dockerfile."):
        return "dockerfile"
    if name.startswith(".env"):
        return "config"
    return LANG_BY_EXT.get(path.suffix.lower())


def iter_files(root: Path, max_files: int = 30000, max_size: int = 1_500_000,
               include_minified: bool = False) -> Iterator[tuple[Path, str]]:
    """Yield (path, relative posix path) without following links, skipping vendored/build dirs."""
    count = 0
    root = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not (Path(dirpath) / d).is_symlink())
        for fn in sorted(filenames):
            p = Path(dirpath) / fn
            if p.is_symlink():
                continue
            try:
                if p.stat().st_size > max_size:
                    continue
            except OSError:
                continue
            if not include_minified and (fn.endswith((".min.js", ".min.css", ".bundle.js", ".map", ".lock")) and
                                         not fn.endswith(("package-lock.json",))):
                continue
            count += 1
            if count > max_files:
                return
            yield p, p.relative_to(root).as_posix()


def read_text(path: Path) -> str | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:4096]:
        return None
    return data.decode("utf-8", errors="replace")


def is_test_path(rel: str) -> bool:
    r = "/" + rel.lower()
    return any(h in r for h in TEST_HINT)
