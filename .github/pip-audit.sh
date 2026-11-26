#!/usr/bin/env bash
# pip-audit with the accepted vulnerabilities in .github/security-ignore.txt
# skipped. Extra arguments go to pip-audit, e.g.:
#   .github/pip-audit.sh                    # the installed environment
#   .github/pip-audit.sh -r file.txt --no-deps --disable-pip
set -euo pipefail

ignore_file="$(dirname "$0")/security-ignore.txt"
args=()
while read -r id _; do
    [[ -z "$id" || "$id" == \#* ]] && continue
    args+=(--ignore-vuln "$id")
done < "$ignore_file"

exec pip-audit --progress-spinner off "${args[@]}" "$@"
