# AgentScan: website product brief

**Suggested headline:** Find security gaps in AI agents before they reach users.

**Suggested subheading:** AgentScan tests how your AI agent handles adversarial requests, sensitive information and tool access. Review the evidence, see which checks completed and decide what to fix.

**Short product description:** Security testing for AI agents, with evidence you can review and findings you can act on.

## What AgentScan is

AgentScan is an open-source security testing product for AI agents and applications built with large language models. Teams can assess an agent they operate, audit a code repository and review the results in a local dashboard or terminal report.

It is designed for developers and security teams who need to understand an agent's behavior before release and after changes to its prompts, tools or dependencies.

## What teams can do

- **Test a running agent:** Send controlled checks for prompt injection, jailbreaks, sensitive-data disclosure and tool-use risks to an authorized agent endpoint.
- **Audit the application:** Inspect source code, dependencies and configuration for selected security issues.
- **Understand your results:** Review findings alongside completed checks, unavailable checks and request errors. Clear coverage and error states help you judge what the scan established.
- **Explore the evidence visually:** View charts of evaluated coverage, finding severity, module status and scan duration, with a table of module scopes and reasons.
- **Share results:** Export reports in JSON, HTML or SARIF for review and development workflows.

## How it works

1. Connect an agent endpoint you own or have permission to test, or choose a repository to audit.
2. Run the relevant checks from the local dashboard or command line.
3. Review the evidence and coverage, then use the findings to guide changes to the agent or application.

## Use cases for the website

- **Before release:** Assess an agent's responses to adversarial inputs and review the application for selected security issues.
- **After an update:** Repeat relevant checks when prompts, tools, dependencies or configuration change.
- **During a security review:** Share exported findings and evidence with the team responsible for fixing them.

## Data handling

Deterministic analysis is the default. Teams can optionally use a model running on their own machine. External model analysis is available only when a client explicitly designates a scan as non-sensitive and configures a provider key locally. Sensitive scans stay with deterministic or local analysis. Live checks send test requests to the target agent selected by the operator.

## Current product scope

AgentScan currently offers a command-line tool, a local dashboard and optional service APIs for teams that deploy the service themselves. Scan results describe observed behavior and coverage for the checks run. Their scope and limits should be visible wherever the website describes protection or security outcomes.

## Website calls to action

- **Primary button: Get started** — link to the starting guide.
- **Secondary button: Explore the checks** — link to the supported attack modules in the starting guide.
- **Privacy link: Understand data handling** — link to the data policy.

**Publishing note:** Describe the currently available local and self-hosted workflows. Hosted accounts, subscription plans, billing and automatic continuous monitoring need confirmed product support before they appear as available features. The available charts describe scan observations; attack-success percentages and overall agent-security guarantees require additional evidence.

For the technical product README, see [the repository overview](../../README.md). For setup and supported attack modules, see [the starting guide](../START_HERE.md). For details on model-provider choices and sensitive data, see [the data policy](../DATA_POLICY.md).
