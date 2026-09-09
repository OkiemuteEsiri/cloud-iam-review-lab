# Architecture

## Purpose

This project models a defensive cloud IAM review pipeline that can consume normalized identity and permission data from AWS, Azure, or GCP exports without requiring live tenant access.

## Components

1. **Inventory loader (`src/io.py`)** validates and loads synthetic JSON input.
2. **Canonical models (`src/models.py`)** define cloud principals, grants, and findings.
3. **Analysis engine (`src/analyzer.py`)** evaluates risky privilege conditions deterministically.
4. **Reporting (`src/reporting.py`)** produces fleet-level metrics and human-readable Markdown findings.
5. **CLI (`src/cli.py`)** provides a repeatable batch execution path.
6. **Tests (`tests/`)** validate control behavior and fail-closed input handling.

## Trust boundaries

- Input data is treated as untrusted until schema validation completes.
- The analyzer does not execute cloud API calls or modify permissions.
- Findings are advisory and require owner validation before remediation.
- Synthetic data is isolated from any employer or production tenant.

## Production extension points

A production implementation could add read-only adapters for AWS IAM Access Analyzer / IAM APIs, Microsoft Graph and Azure Resource Manager, and Google Cloud IAM APIs. Those adapters should use least-privilege read-only credentials, explicit tenant scoping, audit logging, secret management, and pagination/error handling.
