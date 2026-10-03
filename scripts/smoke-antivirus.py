"""Check the packaged CLI; optionally require a working native AMSI provider.

The detection fixture is ordinary text matched by a temporary local hash rule.
It tests packaging and detection plumbing, not real malware detection quality.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


def validate_benign(code, report, *, require_amsi=False):
    summary = report["summary"]
    if (summary["files_scanned"] != 1 or summary["threats"] != 0
            or summary["reviews"] != 0 or summary["skipped"] != 0
            or summary["cancelled"] or summary["limit_reached"]
            or report["findings"]):
        raise ValueError("Unexpected benign scan result")
    complete = (summary["provider_scanned"] == 1 and summary["errors"] == 0
                and report["coverage"] == "provider-and-signatures"
                and report["verdict"] == "no-threats-found")
    if complete and code == 0:
        return "AMSI benign scan passed"
    if (not require_amsi and code == 3 and summary["provider_scanned"] == 0
            and report["coverage"] == "limited" and report["verdict"] == "incomplete"
            and (summary["errors"] > 0 or not report["engine"]["available"])):
        return "AMSI unavailable: packaging passed; native antivirus validation is still required"
    raise ValueError(f"Invalid or insufficient AMSI coverage (exit {code})")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executable", type=Path)
    parser.add_argument("--require-amsi", action="store_true")
    args = parser.parse_args()
    executable = str(args.executable.resolve())
    with tempfile.TemporaryDirectory(prefix="antios-smoke-") as folder:
        fixture = Path(folder) / "benign.txt"
        content = b"AntiOS harmless packaging smoke fixture\n"
        fixture.write_bytes(content)

        def scan(*extra):
            result = subprocess.run([executable, "virus-scan", str(fixture), "--json", *extra],
                                    capture_output=True, text=True, timeout=60)
            print(result.stdout)
            if result.stderr:
                print(result.stderr)
            return result.returncode, json.loads(result.stdout)

        code, report = scan()
        status = validate_benign(code, report, require_amsi=args.require_amsi)
        print(status)
        if code == 3:
            print(f"::warning::{status}")
        summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary_path:
            with open(summary_path, "a", encoding="utf-8") as stream:
                stream.write(f"- `{Path(executable).name}`: {status}\n")

        signatures = Path(folder) / "signatures.json"
        signatures.write_text(json.dumps({"schema": 1, "sha256": {
            hashlib.sha256(content).hexdigest(): "Harmless smoke fixture"}}), encoding="utf-8")
        code, report = scan("--signatures", str(signatures))
        if (code != 1 or report["verdict"] != "threats-found"
                or report["summary"]["files_scanned"] != 1
                or report["summary"]["threats"] != 1
                or len(report["findings"]) != 1
                or report["findings"][0]["engine"] != "SHA-256"
                or report["findings"][0]["sha256"] != hashlib.sha256(content).hexdigest()):
            raise ValueError("Local signature detection smoke test failed")
        if fixture.read_bytes() != content:
            raise ValueError("Read-only scan modified the fixture")
        print("Local signature detection and read-only scan passed")


if __name__ == "__main__":
    main()
