# AgentScan Roadmap

This document outlines completed milestones and planned initiatives for AgentScan.

---

## Current Status: Alpha (`v0.1.0-alpha`)

AgentScan is under active development. Core scanning, static auditing, reporting, and CLI workflows are functional and backed by an automated test suite.

---

## Completed Milestones

- [x] **OWASP Top 10 for LLMs (2025)**: Dedicated heuristic and behavioral test suites for all 10 risk categories.
- [x] **Universal Connectors**: Support for HTTP endpoints, cURL replay, headless Playwright browsers, WebSockets, and Model Context Protocol (MCP) servers.
- [x] **Static Auditing**: AI software supply chain analysis via OSV.dev, Python AST dangerous call inspection, and CycloneDX 1.6 AIBOM generation.
- [x] **Identity & RBAC Graphs**: Graph-based analysis of tool permissions and multi-hop privilege escalation pathways via NetworkX.
- [x] **Local Neural Activation Probing (DEEP Mode)**: Latent representation shift inspection on CPU reference models (`Qwen2.5-0.5B`).
- [x] **Remediation Diff Generation (`agentscan fix`)**: Automated synthesis of unified git diff patches and NeMo Guardrail policies.
- [x] **Local Web Dashboard (`agentscan ui`)**: Real-time SSE dashboard for visual review of findings and session trajectories.
- [x] **REST API & Worker Stack**: Optional multi-tenant FastAPI server with JWT authentication and Redis Streams job queue.

---

## Planned Milestones

- [ ] **eBPF Agent Sandbox**: Real-time kernel syscall inspection and sandboxing for tool-executing agents.
- [ ] **Live AI Gateway Exporters**: Automated export of detected defense rules to LiteLLM Proxy, Cloudflare AI Gateway, and AWS Bedrock.
- [ ] **Expanded MCP Security Auditing**: Extended validation of custom MCP tools, prompt injection via dynamic resources, and cross-server communication.
- [ ] **Community Attack Registry**: Standardized format for community-contributed attack modules and threat scenarios.
