from __future__ import annotations

from collections import defaultdict

from .models import Finding, Grant, Principal

SEVERITY_WEIGHT = {"low": 1, "medium": 3, "high": 7, "critical": 10}


def analyze(principals: list[Principal], grants: list[Grant]) -> list[Finding]:
    principal_map = {p.principal_id: p for p in principals}
    if len(principal_map) != len(principals):
        raise ValueError("duplicate principal_id detected")

    for principal in principals:
        principal.validate()
    for grant in grants:
        grant.validate()
        if grant.principal_id not in principal_map:
            raise ValueError(f"grant references unknown principal: {grant.principal_id}")

    findings: list[Finding] = []
    grants_by_principal: dict[str, list[Grant]] = defaultdict(list)
    for grant in grants:
        grants_by_principal[grant.principal_id].append(grant)

    for principal in principals:
        principal_grants = grants_by_principal.get(principal.principal_id, [])
        privileged = [g for g in principal_grants if g.privileged]
        wildcard = [g for g in principal_grants if g.wildcard]
        standing = [g for g in privileged if g.standing_access]

        if principal.enabled and privileged and principal.principal_type == "user" and principal.mfa_enabled is False:
            findings.append(Finding(
                "IAM-001", principal.principal_id, "critical",
                "Privileged user without MFA",
                "A human identity has privileged cloud permissions without a second authentication factor.",
                "Enforce phishing-resistant MFA and revalidate privileged sign-in controls.",
                ("T1078.004",), tuple(g.grant_id for g in privileged),
            ))

        if wildcard:
            findings.append(Finding(
                "IAM-002", principal.principal_id, "high",
                "Wildcard privilege assignment",
                "One or more grants use wildcard permissions or resource scope, increasing blast radius.",
                "Replace wildcard grants with task-specific actions and narrowly scoped resources.",
                ("T1098",), tuple(g.grant_id for g in wildcard),
            ))

        if principal.enabled and standing:
            findings.append(Finding(
                "IAM-003", principal.principal_id, "high",
                "Standing privileged access",
                "Privileged permissions are continuously active instead of time-bound or eligible-only.",
                "Move human privileged access to just-in-time activation with approval and expiration.",
                ("T1078.004",), tuple(g.grant_id for g in standing),
            ))

        if principal.enabled and principal.last_used_days is not None and principal.last_used_days >= 90 and privileged:
            findings.append(Finding(
                "IAM-004", principal.principal_id, "high",
                "Dormant privileged identity",
                f"Privileged identity has not been used for {principal.last_used_days} days.",
                "Disable or remove privileged grants after owner validation; monitor for attempted reuse.",
                ("T1078.004",), (),
            ))

        if principal.enabled and principal.principal_type == "service_account" and principal.credential_age_days is not None and principal.credential_age_days >= 180:
            findings.append(Finding(
                "IAM-005", principal.principal_id, "medium",
                "Aged non-human credential",
                f"Service-account credential age is {principal.credential_age_days} days.",
                "Rotate the credential and migrate to workload identity or short-lived federation where possible.",
                ("T1552.001",), (),
            ))

        if principal.enabled and privileged and not principal.owner:
            findings.append(Finding(
                "IAM-006", principal.principal_id, "medium",
                "Privileged identity without accountable owner",
                "Privileged access cannot be tied to a named service or business owner.",
                "Assign an accountable owner and require recurring access certification.",
                ("T1098",), (),
            ))

        if principal.enabled and principal.external and privileged:
            findings.append(Finding(
                "IAM-007", principal.principal_id, "high",
                "External principal with privileged access",
                "An external identity has privileged access to cloud resources.",
                "Validate business need, reduce scope, enforce strong authentication, and set an expiry date.",
                ("T1078.004",), tuple(g.grant_id for g in privileged),
            ))

    return sorted(findings, key=lambda f: (-SEVERITY_WEIGHT[f.severity], f.principal_id, f.control_id))


def posture_score(findings: list[Finding]) -> int:
    penalty = sum(SEVERITY_WEIGHT[f.severity] for f in findings)
    return max(0, round(100 - min(100, penalty * 2.5)))
