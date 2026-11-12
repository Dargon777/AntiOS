"""Release-gate regressions: workflow policy and real shell preflight with inert fixtures."""

import io
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tarfile
import zipfile

import pytest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/release.yml"
VERIFIER = ROOT / "scripts/verify-release-provenance.sh"
COMMIT = "a" * 40
VERSION = "3.0.2a1"
REPO = "Dargon777/AntiOS"


def test_unsigned_release_is_explicit_and_fail_closed():
    workflow = WORKFLOW.read_text(encoding="utf-8")
    assert "      unsigned_prerelease:\n" in workflow
    input_block = workflow.split("      unsigned_prerelease:\n", 1)[1].split(
        "      hardened_build:", 1
    )[0]
    assert "type: boolean" in input_block
    assert "default: false" in input_block
    assert "inputs.signed_release == true || github.ref != 'refs/heads/master'" in workflow
    release_job = workflow.split("\n  publish-release:\n", 1)[1].split(
        "\n  hardened-windows:", 1
    )[0]
    assert "github.ref == 'refs/heads/master'" in release_job.split("needs:", 1)[0]
    assert "inputs.unsigned_prerelease == true && inputs.signed_release != true" in release_job
    assert "attestations: read" in release_job
    assert "draft:true,prerelease:true" in release_job
    assert "draft:false" not in release_job.replace(" ", "")
    assert "scripts/verify-release-provenance.sh" in release_job
    assert release_job.index("bash scripts/verify-release-provenance.sh") < release_job.index(
        'gh api --method PATCH "repos/$GITHUB_REPOSITORY/releases/$release_id"'
    )
    assert release_job.index("sha256sum --check AntiOS-Setup.exe.sha256") < release_job.index(
        "bash scripts/verify-release-provenance.sh"
    )
    assert workflow.count("actions/attest@v4") == 3
    assert workflow.count(
        "(inputs.signed_release == true || inputs.unsigned_prerelease == true)"
    ) == 3


def _archives(root: Path, *, win_commit=COMMIT, linux_version=VERSION,
              windows_signing="Unsigned direct-download build"):
    windows = root / "windows"
    linux = root / "linux"
    windows.mkdir(exist_ok=True, parents=True)
    linux.mkdir(exist_ok=True, parents=True)

    win_info = (
        f"AntiOS version: {VERSION}\nCommit: {win_commit}\n"
        f"Code signing: {windows_signing}\n"
    )
    with zipfile.ZipFile(windows / "AntiOS-windows-x64.zip", "w") as zf:
        zf.writestr("BUILD_INFO.txt", win_info)
    linux_info = f"AntiOS version: {linux_version}\nCommit: {COMMIT}\n"
    data = linux_info.encode("utf-8")
    with tarfile.open(linux / "AntiOS-linux-x64.tar.gz", "w:gz") as tf:
        member = tarfile.TarInfo("./BUILD_INFO.txt")
        member.size = len(data)
        tf.addfile(member, io.BytesIO(data))


@pytest.fixture
def assets(tmp_path):
    root = tmp_path / "release-artifacts"
    (root / "windows/python-dist").mkdir(parents=True)
    (root / "windows/AntiOS-Setup.exe").write_bytes(b"inert setup")
    (root / "windows/python-dist/antios.whl").write_bytes(b"inert wheel")
    (root / "windows/python-dist/antios.tar.gz").write_bytes(b"inert sdist")
    _archives(root)

    mock_bin = tmp_path / "bin"
    mock_bin.mkdir()
    gh = mock_bin / "gh"
    gh.write_text(
        '#!/usr/bin/env bash\n'
        'printf "%s\\n" "$*" >> "$MOCK_GH_LOG"\n'
        'if [[ "${MOCK_GH_FAIL:-false}" == "true" ]]; then exit 7; fi\n',
        encoding="utf-8",
    )
    gh.chmod(0o755)
    return root, mock_bin, tmp_path / "gh.log"


def _verify(assets, *, fail=False, commit=COMMIT):
    root, mock_bin, log = assets
    env = os.environ.copy()
    env["PATH"] = str(mock_bin) + os.pathsep + env.get("PATH", "")
    env["MOCK_GH_LOG"] = str(log)
    env["MOCK_GH_FAIL"] = "true" if fail else "false"
    proc = subprocess.run(
        ["bash", str(VERIFIER), REPO, commit, VERSION, str(root)],
        env=env, capture_output=True, text=True, check=False,
    )
    commands = [shlex.split(line) for line in log.read_text(encoding="utf-8").splitlines()] if log.exists() else []
    return proc, commands


@pytest.mark.skipif(os.name == "nt" or shutil.which("bash") is None, reason="Release gate executes on POSIX runners")
def test_verified_unsigned_assets_match_exact_build_source(assets):
    proc, commands = _verify(assets)
    assert proc.returncode == 0, proc.stderr
    assert len(commands) == 5
    for command in commands:
        assert command[:2] == ["attestation", "verify"]
        assert command[command.index("--repo") + 1] == REPO
        assert command[command.index("--signer-workflow") + 1] == (
            REPO + "/.github/workflows/release.yml"
        )
        assert command[command.index("--source-digest") + 1] == COMMIT
        assert command[command.index("--source-ref") + 1] == "refs/heads/master"


@pytest.mark.skipif(os.name == "nt" or shutil.which("bash") is None, reason="Release gate executes on POSIX runners")
@pytest.mark.parametrize("failure", ["commit", "linux_version", "signature"])
def test_modified_metadata_is_rejected_before_verification(assets, failure):
    root, _, _ = assets
    changes = {
        "commit": {"win_commit": "b" * 40},
        "linux_version": {"linux_version": "9.9.9a1"},
        "signature": {"windows_signing": "Valid Authenticode"},
    }
    _archives(root, **changes[failure])
    proc, commands = _verify(assets)
    assert proc.returncode != 0
    assert commands == []


@pytest.mark.skipif(os.name == "nt" or shutil.which("bash") is None, reason="Release gate executes on POSIX runners")
def test_attestation_failure_aborts_before_other_verifications(assets):
    proc, commands = _verify(assets, fail=True)
    assert proc.returncode != 0
    assert len(commands) == 1


@pytest.mark.skipif(os.name == "nt" or shutil.which("bash") is None, reason="Release gate executes on POSIX runners")
def test_invalid_commit_rejected_before_attestation(assets):
    proc, commands = _verify(assets, commit="not-a-commit")
    assert proc.returncode != 0
    assert commands == []
