# Example Cloud IAM Assessment

> Synthetic demonstration output. No production tenant or employer data is represented.

## Executive summary

The sample environment contains multiple IAM conditions that materially increase privilege risk: a privileged human user without MFA, wildcard administrative access, dormant standing privilege, an aged service-account credential, and external privileged access. The recommended remediation sequence prioritizes authentication strength and removal of excessive standing privilege before credential lifecycle and governance improvements.

## Priority findings

| Priority | Control | Synthetic principal | Risk | Recommended action |
|---|---|---|---|---|
| P0 | IAM-001 | usr-finops-admin | Privileged cloud user lacks MFA | Enforce phishing-resistant MFA and revalidate privileged sign-in |
| P1 | IAM-002 | usr-finops-admin | Wildcard administrative grant | Replace with task-specific permissions and scoped resources |
| P1 | IAM-004 | usr-legacy-ops | Privileged identity dormant for >90 days | Validate owner need; disable or remove elevation |
| P1 | IAM-007 | usr-vendor-support | External principal has standing privilege | Reduce scope, enforce expiry, document business justification |
| P2 | IAM-005 | svc-build-bot | Long-lived service credential | Rotate and migrate toward short-lived workload identity |

## Remediation sequence

1. Protect privileged human identities with strong MFA.
2. Remove wildcard and unnecessary standing privilege.
3. Disable or downgrade dormant privileged identities after owner validation.
4. Constrain external privileged relationships with expiry and narrow scope.
5. Rotate aged non-human credentials and adopt federation where possible.
6. Run a fresh export and re-assess the resulting effective-access state.

## Validation criteria

Closure requires evidence that the risky state no longer exists in the source-of-truth IAM configuration. Ticket closure alone is insufficient.
