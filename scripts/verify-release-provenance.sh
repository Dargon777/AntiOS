#!/usr/bin/env bash
# Reject unsigned prerelease assets whose metadata or signed provenance
# cannot be tied to the current master build.
set -euo pipefail

if [[ "$#" -ne 4 ]]; then
  echo "Usage: bash scripts/verify-release-provenance.sh OWNER/REPO COMMIT VERSION ARTIFACT_DIR" >&2
  exit 2
fi

repo="$1"
commit="$2"
version="$3"
root="$4"

if [[ ! "$repo" =~ ^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$ ||
      ! "$commit" =~ ^[0-9a-f]{40}$ ||
      -z "$version" || ! -d "$root" ]]; then
  echo "Invalid release provenance arguments" >&2
  exit 2
fi

win_zip="$root/windows/AntiOS-windows-x64.zip"
linux_tgz="$root/linux/AntiOS-linux-x64.tar.gz"
setup="$root/windows/AntiOS-Setup.exe"
shopt -s nullglob
wheels=("$root"/windows/python-dist/*.whl)
sdists=("$root"/windows/python-dist/*.tar.gz)
if [[ "${#wheels[@]}" -ne 1 || "${#sdists[@]}" -ne 1 ]]; then
  echo "Expected exactly one wheel and one sdist" >&2
  exit 1
fi

# Fail closed when either archive lacks its expected BUILD_INFO file.
win_info="$(unzip -p "$win_zip" BUILD_INFO.txt | tr -d '\r')"
linux_info="$(tar -xOzf "$linux_tgz" ./BUILD_INFO.txt | tr -d '\r')"
for info in "$win_info" "$linux_info"; do
  grep -Fqx "Commit: $commit" <<<"$info"
  grep -Fqx "AntiOS version: $version" <<<"$info"
done
grep -Fqx "Code signing: Unsigned direct-download build" <<<"$win_info"

# Metadata alone is untrusted. Verify cryptographically signed provenance
# for each released executable/archive/distribution against this exact ref
# and commit; GitHub Attestations are not publisher code signing.
for artifact in "$setup" "$win_zip" "${wheels[0]}" "${sdists[0]}" "$linux_tgz"; do
  if [[ ! -s "$artifact" || -L "$artifact" ]]; then
    echo "Missing or unsafe artifact: $artifact" >&2
    exit 1
  fi
  gh attestation verify "$artifact" \
    --repo "$repo" \
    --signer-workflow "$repo/.github/workflows/release.yml" \
    --source-digest "$commit" \
    --source-ref "refs/heads/master" >/dev/null
done

echo "All five unsigned release artifacts match commit $commit and master provenance."
