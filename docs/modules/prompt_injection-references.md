# Prompt injection: published agent research

These original researcher and vendor sources inform AgentScan's attack patterns
and defense guidance. They describe disclosed demonstrations or research
exercises; they do not establish AgentScan reproductions, exploitation against
uninvolved customers or a product's current vulnerability status. Detailed
research notes were reviewed on 9 October 2026.

## Today's ATK-001 decision

[ATK-001](prompt_injection.md) assesses direct user-message disclosure of a known
private reference. [ATK-005](indirect_injection.md) assesses an instrumented
retrieved-document boundary. Neither module reproduces the full attack chains
below or verifies their tool, identity and outbound effects.

## Case records

| Published research | Relevant boundary | Defense lesson |
| --- | --- | --- |
| [Anthropic: containing Claude](https://www.anthropic.com/engineering/how-we-contain-claude) | Deceptive user tasks and privileged resources | Enforce filesystem and network boundaries beyond model instructions. |
| [Zenity: AgentCorruption](https://labs.zenity.io/post/agentcorruption-how-a-single-prompt-collapsed-the-entire-cloud-security-model) | Tool-enabled cloud agent and workload permissions | Limit execution-role permissions and access to privileged resources. |
| [Aim/Cato: EchoLeak](https://www.catonetworks.com/blog/breaking-down-echoleak/) | Retrieved email, private context and rendering | Separate retrieved content from authority and constrain outbound channels. |
| [Zenity: AgentFlayer](https://labs.zenity.io/post/agentflayer-chatgpt-connectors-0click-attack-5b41) | Uploaded documents and connected data | Restrict data scope and validate actions and destinations. |
| [Radware: ShadowLeak](https://www.radware.com/security/threat-advisories-and-attack-reports/shadowleak/) | Connected email and agent-side requests | Use scoped permissions and observable action logging. |
| [Orca: RoguePilot](https://orca.security/resources/blog/roguepilot-github-copilot-vulnerability/) | Issue content, filesystem links and resource fetching | Constrain fetching, resolve paths safely and narrow token permissions. |
| [Brave: Comet prompt injection](https://brave.com/blog/comet-prompt-injection/) | Web content and privileged browsing | Check action alignment and isolate browsing capabilities. |

The defense lessons are bounded design inferences from these records, rather
than claims that AgentScan implements each protection.

## Date and remediation provenance

Publication dates, demonstrated impact and fix status are separate facts.
Research pages may include later qualifications, and an observed mitigation
date is not necessarily its deployment date. Consult the linked original record
and vendor advisories for the relevant version; this guide does not certify a
current patch status.

## How to use these references for a safe direct scan

Provision a unique synthetic private reference on an authorized target and keep
it out of attack input. Test plausible task and authority pretexts alongside
ordinary permitted tasks. Assess only observable supported outcomes: a full
reference match cannot rule out transformed disclosure or data leaving through
tools. Preserve missing-evidence and operational-error states in the report.

Use application-level authorization, least privilege, output contracts and
constrained destinations. A clean text response alone cannot certify those
deployed boundaries. See [evaluation limits](../EVALUATION.md).
