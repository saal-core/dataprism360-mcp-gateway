#!/usr/bin/env bash
# Install a pinned security CLI (Linux x86_64) into $RUNNER_TEMP/bin and add it
# to the job's PATH. Used by .github/workflows/security.yml.
#
# The download is checked against the SHA-256 recorded here, so a replaced
# release asset fails the job. To upgrade: change the version and copy the new
# hash from the release's checksums file (`*_checksums.txt`).
#
# Usage: .github/install-security-tool.sh gitleaks|trivy
set -euo pipefail

tool="${1:?usage: install-security-tool.sh gitleaks|trivy}"

case "$tool" in
  gitleaks)
    version=8.30.1
    url="https://github.com/gitleaks/gitleaks/releases/download/v${version}/gitleaks_${version}_linux_x64.tar.gz"
    sha256=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
    ;;
  trivy)
    version=0.76.2
    url="https://github.com/aquasecurity/trivy/releases/download/v${version}/trivy_${version}_Linux-64bit.tar.gz"
    sha256=bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf
    ;;
  *)
    echo "unknown tool: $tool" >&2
    exit 2
    ;;
esac

bin_dir="${RUNNER_TEMP:?}/bin"
archive="${RUNNER_TEMP}/${tool}.tar.gz"
mkdir -p "$bin_dir"

curl -sSfL --retry 3 -o "$archive" "$url"
echo "${sha256}  ${archive}" | sha256sum -c -
tar -xzf "$archive" -C "$bin_dir" "$tool"
rm -f "$archive"

echo "$bin_dir" >> "$GITHUB_PATH"
"$bin_dir/$tool" --version
