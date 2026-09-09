from __future__ import annotations

from collections import Counter

from .analyzer import posture_score
from .models import Finding


def summarize(findings: list[Finding]) -> dict[str, object]:
    severity = Counter(f.severity for f in findings)
    controls = Counter(f.control_id for f in findings)
    principals = sorted({f.principal_id for f in findings})
    return {
        "posture_score": posture_score(findings),
        "finding_count": len(findings),
        "affected_principals": len(principals),
        "severity": dict(sorted(severity.items())),
        "controls": dict(sorted(controls.items())),
    }


def to_markdown(findings: list[Finding]) -> str:
    summary = summarize(findings)
    lines = [
        "# Cloud IAM Review Report",
        "",
        "> Synthetic lab output. This report does not represent a production tenant.",
        "",
        f"**Posture score:** {summary['posture_score']}/100",
        f"**Findings:** {summary['finding_count']}",
        f"**Affected principals:** {summary['affected_principals']}",
        "",
        "## Findings",
        "",
        "| Severity | Control | Principal | Finding | ATT&CK |",
        "|---|---|---|---|---|",
    ]
    for finding in findings:
        attacks = ", ".join(finding.attack_ids) or "—"
        lines.append(
            f"| {finding.severity.upper()} | {finding.control_id} | {finding.principal_id} | {finding.title} | {attacks} |"
        )

    lines.extend(["", "## Remediation guidance", ""])
    for finding in findings:
        lines.append(f"- **{finding.control_id} / {finding.principal_id}:** {finding.remediation}")
    return "\n".join(lines) + "\n"
