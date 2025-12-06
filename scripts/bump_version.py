#!/usr/bin/env python
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]  # repo root


def update_pyproject(version: str) -> None:
    pyproject = ROOT / "pyproject.toml"
    text = pyproject.read_text(encoding="utf-8")

    new_text, count = re.subn(
        r'(?m)^(version\s*=\s*")[^"]+(")',
        rf"\g<1>{version}\g<2>",
        text,
    )
    if count == 0:
        raise SystemExit("Could not find version in pyproject.toml")
    pyproject.write_text(new_text, encoding="utf-8")
    print(f"[pyproject.toml] set version = {version}")


def update_init(version: str) -> None:
    init_file = ROOT / "src" / "cyvest" / "__init__.py"
    text = init_file.read_text(encoding="utf-8")

    new_text, count = re.subn(
        r'(?m)^(__version__\s*=\s*")[^"]+(")',
        rf"\g<1>{version}\g<2>",
        text,
    )
    if count == 0:
        raise SystemExit("Could not find __version__ in src/cyvest/__init__.py")
    init_file.write_text(new_text, encoding="utf-8")
    print(f"[src/cyvest/__init__.py] set __version__ = {version}")


def update_js_packages(version: str) -> None:
    package_paths = [
        ROOT / "js" / "packages" / "cyvest-js" / "package.json",
        ROOT / "js" / "packages" / "cyvest-vis" / "package.json",
        ROOT / "js" / "packages" / "cyvest-app" / "package.json",
    ]

    for pkg_path in package_paths:
        if not pkg_path.exists():
            print(f"[WARN] {pkg_path} does not exist, skipping")
            continue

        data = json.loads(pkg_path.read_text(encoding="utf-8"))
        old = data.get("version")
        data["version"] = version
        pkg_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        print(f"[{pkg_path}] {old} -> {version}")


def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: bump_version.py X.Y.Z", file=sys.stderr)
        raise SystemExit(1)

    version = sys.argv[1].strip()

    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise SystemExit(f"Invalid version '{version}', expected X.Y.Z")

    update_pyproject(version)
    update_init(version)
    update_js_packages(version)
    print("Done.")


if __name__ == "__main__":
    main()
