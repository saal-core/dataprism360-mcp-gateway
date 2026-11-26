#!/usr/bin/env python3
"""Turn a scanner's JSON report into a short Markdown table for the job summary.

Usage (from .github/workflows/security.yml):
    security-summary.py semgrep  <report.json>
    security-summary.py gitleaks <report.json>
    security-summary.py trivy    <report.json> [title]

Prints Markdown to stdout. Never prints secret values: the gitleaks report is
written with --redact and only file, line, rule and commit are shown here.
"""

import json
import sys
from collections import Counter

SEVERITY_ORDER = ["CRITICAL", "HIGH", "ERROR", "MEDIUM", "WARNING", "LOW", "INFO", "UNKNOWN"]


def _sev_key(sev):
    return SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else len(SEVERITY_ORDER)


def _table(header, rows):
    lines = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    lines += ["| " + " | ".join(str(c) for c in row) + " |" for row in rows]
    return "\n".join(lines)


def semgrep(report):
    results = report.get("results", [])
    out = [f"### Semgrep: {len(results)} finding(s)"]
    if not results:
        return "\n".join(out)
    sev = Counter(r["extra"]["severity"] for r in results)
    out.append(_table(["Severity", "Count"], sorted(sev.items(), key=lambda kv: _sev_key(kv[0]))))
    rules = Counter((r["extra"]["severity"], r["check_id"].rsplit(".", 1)[-1]) for r in results)
    rows = sorted(((s, rule, n) for (s, rule), n in rules.items()), key=lambda r: (_sev_key(r[0]), -r[2]))
    out.append("")
    out.append(_table(["Severity", "Rule", "Count"], rows))
    return "\n".join(out)


def gitleaks(report):
    out = [f"### gitleaks: {len(report)} finding(s) (values redacted)"]
    if report:
        rows = sorted(
            {(f["File"], f["StartLine"], f["RuleID"], f["Commit"][:8]) for f in report}
        )
        out.append(_table(["File", "Line", "Rule", "Commit"], rows))
    return "\n".join(out)


def trivy(report, title):
    vulns, misconfigs = Counter(), []
    for result in report.get("Results") or []:
        for v in result.get("Vulnerabilities") or []:
            vulns[v.get("Severity", "UNKNOWN")] += 1
        for m in result.get("Misconfigurations") or []:
            misconfigs.append((m.get("Severity", "UNKNOWN"), m["ID"], result["Target"], m.get("Title", "")))
    out = [f"### {title or report.get('ArtifactName', 'trivy')}"]
    if not vulns and not misconfigs:
        out.append("No findings.")
    if vulns:
        out.append(_table(["Severity", "Vulnerabilities"], sorted(vulns.items(), key=lambda kv: _sev_key(kv[0]))))
    if misconfigs:
        out.append(_table(["Severity", "ID", "Target", "Title"], sorted(misconfigs, key=lambda m: _sev_key(m[0]))))
    return "\n".join(out)


def main(argv):
    if len(argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    kind, path = argv[1], argv[2]
    with open(path, encoding="utf-8") as fh:
        report = json.load(fh)
    if kind == "semgrep":
        print(semgrep(report))
    elif kind == "gitleaks":
        print(gitleaks(report))
    elif kind == "trivy":
        print(trivy(report, argv[3] if len(argv) > 3 else ""))
    else:
        print(__doc__, file=sys.stderr)
        return 2
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
