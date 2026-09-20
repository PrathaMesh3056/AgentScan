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

### 1. Direct Email (Recommended)
Email our security team directly:
- **Email**: `security@agentscan.dev` or `prathameshpatil300804@gmail.com`
- **Maintainer**: Contact the maintainer directly via [GitHub Profile](https://github.com/PrathaMesh3056).
- If desired, you may encrypt sensitive vulnerability details using PGP.

### 2. GitHub Private Vulnerability Reporting
You can also submit an advisory draft directly through GitHub:
1. Navigate to the repository's **[Security](https://github.com/PrathaMesh3056/AgentScan/security)** tab.
2. If Private Vulnerability Reporting is enabled, click **"Report a vulnerability"** under the Advisories section to open a confidential report.
3. If the button is not visible or the page is unavailable, please use the direct email contact above.

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
