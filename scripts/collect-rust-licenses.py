"""Stage Cargo dependency notices and the Rust runtime license materials."""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess


def copy_notices(source: Path, output: Path, declared: str | None = None) -> None:
    files = {
        file for file in source.iterdir()
        if file.is_file() and re.match(r"^(?:UNLICENSE|LICEN[CS]E|COPYRIGHT|NOTICE)(?:$|[-_.])", file.name, re.I)
    }
    if declared:
        file = (source / declared).resolve(strict=True)
        if not file.is_relative_to(source):
            raise ValueError(f"License file is outside its package: {file}")
        files.add(file)
    if not files:
        raise ValueError(f"No license files found in {source}")
    output.mkdir()
    for file in sorted(files):
        shutil.copyfile(file, output / file.name)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    metadata = json.loads(subprocess.check_output([
        "cargo", "metadata", "--format-version", "1", "--locked",
        "--manifest-path", str(args.manifest), "--filter-platform", args.target,
    ]))
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    root = metadata["resolve"]["root"]
    dependencies = set()
    pending = [root]
    while pending:
        for dependency in nodes[pending.pop()]["deps"]:
            package = dependency["pkg"]
            if package not in dependencies and any(kind["kind"] is None for kind in dependency["dep_kinds"]):
                dependencies.add(package)
                pending.append(package)
    packages = sorted(
        (package for package in metadata["packages"] if package["id"] in dependencies),
        key=lambda package: (package["name"], package["version"]),
    )

    sysroot = Path(subprocess.check_output(["rustc", "--print", "sysroot"], text=True, encoding="utf-8").strip())
    docs = sysroot / "share" / "doc" / "rust"
    copyright_file = docs / "COPYRIGHT-library.html"
    if not copyright_file.is_file():
        copyright_file = docs / "COPYRIGHT.html"
    if not copyright_file.is_file():
        raise ValueError(f"Rust toolchain copyright is missing from {docs}")
    runtime_docs = [
        file for file in (
            copyright_file, docs / "LICENSE-APACHE", docs / "LICENSE-MIT", docs / "COPYRIGHT",
        ) if file.is_file()
    ]

    args.output.mkdir(parents=True)
    runtime = args.output / "rust-runtime"
    runtime.mkdir()
    for file in runtime_docs:
        shutil.copyfile(file, runtime / file.name)
    lines = [
        "License materials for the AntiOS Rust static core",
        f"Rust runtime: {subprocess.check_output(['rustc', '--version'], text=True).strip()}",
        "",
    ]
    for package in packages:
        folder = f"{package['name']}-{package['version']}"
        copy_notices(Path(package["manifest_path"]).resolve().parent, args.output / folder, package["license_file"])
        lines.append(f"{folder}: {package['license'] or package['license_file']}")
    (args.output / "CONTENTS.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
