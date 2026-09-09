# Assessment Methodology

## Review objective

Identify cloud identities and permission grants whose configuration increases the probability or blast radius of account misuse, privilege escalation, or unauthorized persistence.

## Review sequence

1. Normalize principal and grant data into a provider-neutral schema.
2. Validate identifiers, provider names, scopes, and relationship integrity.
3. Evaluate privileged identities for MFA coverage, standing access, dormancy, ownership, external trust, wildcard permissions, and credential age.
4. Assign findings by control with evidence references.
5. Aggregate severity into a transparent posture score.
6. Produce remediation guidance and define revalidation criteria.

## Control rationale

- **IAM-001 Privileged user without MFA:** high-value identities should require a strong second factor.
- **IAM-002 Wildcard privilege:** unrestricted actions/resources increase blast radius.
- **IAM-003 Standing privileged access:** permanent elevation should be replaced with eligible/time-bound access where feasible.
- **IAM-004 Dormant privileged identity:** unused elevated identities increase unnecessary exposure.
- **IAM-005 Aged non-human credential:** long-lived static secrets increase credential-theft persistence risk.
- **IAM-006 Missing owner:** access without accountable ownership weakens certification and remediation governance.
- **IAM-007 External privileged principal:** third-party trust requires explicit business justification, narrow scope, and expiry.

## MITRE ATT&CK context

Mappings are contextual, not evidence that an adversary performed the technique:

- **T1078.004 – Valid Accounts: Cloud Accounts**
- **T1098 – Account Manipulation**
- **T1552.001 – Unsecured Credentials: Credentials In Files**

## Remediation and revalidation

A finding should not be closed solely because a ticket was resolved. Revalidation should confirm the resulting identity state:

- MFA is enforced and tested for privileged human users.
- wildcard grants are replaced with least-privilege actions and resource constraints.
- standing privilege is converted to eligible/JIT access where supported.
- dormant access is disabled or removed after owner validation.
- non-human credentials are rotated or replaced by workload federation.
- ownership metadata is populated and tied to recurring certification.
- external privileged access has documented justification, expiry, strong authentication, and limited scope.

## Limitations

This lab uses normalized synthetic data and does not evaluate every provider-specific IAM condition, deny policy, nested group, resource policy, permission boundary, service control policy, custom role, or workload identity relationship. A production review must account for effective permissions and provider-specific inheritance semantics.
