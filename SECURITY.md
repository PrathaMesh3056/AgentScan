# Security Policy

AgentScan is an open-source security scanner and red-teaming toolkit designed to identify vulnerabilities in autonomous AI agents and LLM-powered applications. We take the security of our own software seriously.

## Supported Versions

We provide security updates and bug fixes for the following versions:

| Version | Supported | Notes |
| :--- | :---: | :--- |
| `0.1.x` | ✅ | Current active development release. |
| `< 0.1.0` | ❌ | Pre-release alpha builds. Please upgrade. |

---

## Reporting a Vulnerability

If you believe you have discovered a security vulnerability in AgentScan, **please do not open a public GitHub issue**. Instead, follow our responsible disclosure process:

### 1. Preferred Method: GitHub Private Vulnerability Reporting
Submit a report through GitHub's Private Vulnerability Reporting feature:
1. Navigate to the [AgentScan Security Advisories](https://github.com/PrathaMesh3056/AgentScan/security/advisories) page.
2. Click **"Report a vulnerability"**.
3. Provide a clear description, reproduction steps, proof-of-concept, and potential impact.

### 2. Alternative Method: Email
If GitHub Private Vulnerability Reporting is unavailable, email our security team directly at:
- **Email**: `security@agentscan.dev` (or reach out to the project maintainer via [GitHub profile](https://github.com/PrathaMesh3056)).
- If possible, encrypt sensitive details using PGP.

---

## What to Include in Your Report

To help us triage and resolve the issue quickly, please include:
- A clear summary of the vulnerability and its potential impact.
- Exact reproduction steps, including CLI commands, configuration options, or minimal sample code.
- Environment details: Python version, operating system, and installed AgentScan version (`agentscan --version` or Git commit hash).
- Any proposed remediation or patch, if available.

---

## Response & Resolution SLA

When you submit a vulnerability report:
1. **Initial Acknowledgment**: We will acknowledge receipt of your report within **48 hours**.
2. **Triage & Assessment**: Within **5 business days**, we will confirm whether the vulnerability is valid and provide an estimated timeline for remediation.
3. **Fix & Release**: We aim to release a patch within **14 business days** of confirmation, depending on complexity.
4. **Public Disclosure**: We coordinate disclosure dates with the reporter and publish a GitHub Security Advisory with appropriate credit.

---

## Security Scope & Threat Model

### In-Scope
- Vulnerabilities in the AgentScan CLI, runners, core parsers, or evaluation engines.
- Remote code execution, arbitrary file write, or privilege escalation in the local dashboard (`agentscan ui`).
- Security bypasses in the automated self-healing engine (`agentscan fix`).
- Insecure deserialization or dangerous execution patterns within AgentScan's own codebase.

### Out-of-Scope
- Vulnerabilities in third-party targets scanned by AgentScan (e.g., if a tested agent endpoint is vulnerable to prompt injection, that is the expected behavior of a scanner finding).
- Denial of Service against local machines resulting from scanning extremely large files without memory limits.
- Attacks requiring physical access to an unlocked developer workstation.
- Social engineering attacks against maintainers or users.

---

## Responsible Use Notice

AgentScan is intended solely for authorized security evaluations of systems you own or have explicit, documented permission to test. Unauthorized testing of third-party systems is illegal and strictly prohibited.
