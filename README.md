# Cloud IAM Review Lab

A defensive, provider-neutral **Cloud Identity & Access Management security review project** for identifying excessive privilege, weak authentication, stale access, risky external trust, and long-lived non-human credentials across normalized AWS, Azure, and GCP identity data.

This repository is intentionally built as a security-engineering portfolio project rather than a collection of screenshots or provider-specific notes. It demonstrates how cloud IAM data can be normalized, evaluated with deterministic controls, translated into explainable risk, and driven through remediation and revalidation.

> **Safety and scope:** all identities, permissions, resources, and reports in this repository are synthetic. The project performs no live tenant access, permission changes, credential collection, or offensive account activity.

## Problem statement

Cloud IAM risk is difficult to manage because effective privilege is distributed across users, roles, groups, service identities, resource policies, inherited scopes, and provider-specific control planes. A useful review must go beyond asking whether an identity is an administrator. It should identify combinations such as:

- privileged human identities without strong MFA;
- broad or wildcard grants that unnecessarily increase blast radius;
- standing privileged access that should be time-bound;
- dormant privileged identities that remain enabled;
- long-lived service-account credentials;
- privileged identities without accountable ownership; and
- external principals with elevated access.

This lab implements that review pattern in code.

## Architecture

```text
Synthetic IAM Inventory
        |
        v
+-------------------+
| JSON Loader       |
| src/io.py         |
+-------------------+
        |
        v
+-------------------+
| Canonical Models  |
| principals/grants |
+-------------------+
        |
        v
+-------------------+
| IAM Analyzer      |
| 7 controls        |
+-------------------+
        |
        +------------------+
        |                  |
        v                  v
+-------------------+  +-------------------+
| Posture Metrics   |  | Evidence Findings |
+-------------------+  +-------------------+
        \                  /
         \                /
          v              v
          Markdown Report
```

See [`docs/architecture.md`](docs/architecture.md) for component boundaries, trust boundaries, and production extension points.

## Implemented controls

| Control | Condition | Default severity | Defensive objective |
|---|---|---:|---|
| IAM-001 | Privileged human user without MFA | Critical | Strengthen authentication for high-value cloud accounts |
| IAM-002 | Wildcard privilege assignment | High | Reduce unnecessary permission/resource scope |
| IAM-003 | Standing privileged access | High | Encourage eligible/JIT privilege models |
| IAM-004 | Privileged identity dormant ≥90 days | High | Remove stale elevated access |
| IAM-005 | Service credential age ≥180 days | Medium | Reduce long-lived credential exposure |
| IAM-006 | Privileged identity without owner | Medium | Improve accountability and access certification |
| IAM-007 | External principal with privilege | High | Govern third-party trust and expiry |

## MITRE ATT&CK context

ATT&CK mappings are used only to explain why specific identity weaknesses matter. A configuration finding is **not** evidence that an adversary executed a technique.

- **T1078.004 – Valid Accounts: Cloud Accounts**
- **T1098 – Account Manipulation**
- **T1552.001 – Unsecured Credentials: Credentials In Files**

## Repository structure

```text
.
├── .github/workflows/ci.yml
├── data/
│   └── synthetic_inventory.json
├── docs/
│   ├── architecture.md
│   └── methodology.md
├── reports/
│   └── example-assessment.md
├── src/
│   ├── analyzer.py
│   ├── cli.py
│   ├── io.py
│   ├── models.py
│   └── reporting.py
└── tests/
    └── test_analyzer.py
```

## Usage

Requires Python 3.11+ and no third-party runtime dependencies.

```bash
python -m unittest discover -s tests -v
python -m src.cli data/synthetic_inventory.json --output iam-review.md
```

The CLI validates the inventory, runs deterministic controls, and generates a Markdown assessment containing posture metrics, affected principals, evidence-backed findings, ATT&CK context, and remediation guidance.

## Example workflow

1. Export or assemble IAM data using read-only access.
2. Normalize identities and grants into the canonical schema.
3. Reject malformed data and broken principal/grant relationships.
4. Evaluate risky privilege patterns.
5. Prioritize findings based on severity and affected identity.
6. Remediate in the source cloud platform.
7. Collect a new export.
8. Re-run the assessment and verify the risky state is gone.

The important distinction is that **ticket closure is not treated as security validation**. A finding should be closed only when the resulting IAM state has been re-observed and confirmed.

## Design decisions

### Provider-neutral core

The analyzer uses normalized concepts—principal, grant, scope, privilege, wildcard access—so the security logic is not tied to one vendor. Provider adapters can be added separately.

### Deterministic findings

Each control has an explicit condition and evidence reference. This makes the output auditable and suitable for remediation discussions instead of opaque scoring.

### Severity and posture scoring

The project assigns severity per control and produces a simple posture score. The score is intentionally transparent and should be treated as a prioritization aid, not a compliance certification or quantitative probability of compromise.

### Fail-closed relationships

Grants referencing unknown principals and duplicate principal IDs are rejected. Data quality failures should not silently produce misleading IAM conclusions.

## Testing

The unit suite validates:

- critical detection of privileged users without MFA;
- wildcard privilege detection;
- dormant privileged identity detection;
- aged service-account credentials;
- external privileged principals;
- rejection of grants with missing principals;
- rejection of duplicate principal IDs; and
- posture-score degradation when findings exist.

GitHub Actions runs the unit suite and a synthetic CLI smoke assessment on pushes and pull requests.

## Remediation strategy

Recommended order of operations:

1. enforce phishing-resistant MFA for privileged human identities;
2. remove wildcard permissions and narrow resource scope;
3. convert standing privileged access to eligible/JIT models;
4. disable or downgrade dormant privileged identities after owner validation;
5. constrain external privilege with business justification, expiry, and strong authentication;
6. rotate or eliminate aged static service credentials;
7. assign accountable owners and introduce recurring access certification; and
8. re-export effective access and re-run the assessment.

See [`docs/methodology.md`](docs/methodology.md) for validation criteria and limitations.

## Example assessment

[`reports/example-assessment.md`](reports/example-assessment.md) shows an executive-style synthetic review with priority findings, remediation sequence, and closure criteria.

## Skills demonstrated

- cloud IAM security engineering
- least-privilege analysis
- identity governance
- privileged access management concepts
- multi-cloud normalization
- secure Python data modeling
- deterministic control design
- defensive ATT&CK mapping
- evidence-based remediation
- revalidation workflow design
- security reporting
- unit testing and CI

## Limitations

This lab does not attempt to calculate complete provider-specific effective permissions. It does not yet resolve nested groups, AWS SCPs/permission boundaries/resource policies, Azure management-group inheritance/PIM state, GCP organization policies/custom roles, workload-identity federation graphs, conditional policy expressions, or every cross-account trust path.

Those are deliberate extension points rather than hidden assumptions.

## Roadmap

- add provider-specific read-only adapter interfaces;
- model nested group and role inheritance;
- add effective-permission graph analysis;
- support policy-condition and expiry evaluation;
- add access-review campaign metrics;
- export JSON/SARIF findings for security pipelines;
- add policy-as-code mappings to CIS/cloud-provider benchmarks; and
- add historical trend comparison for remediation validation.

## Professional use

This repository is designed to demonstrate defensive cloud IAM review methodology and security-engineering implementation. It should be used only with authorized, appropriately scoped identity data.
