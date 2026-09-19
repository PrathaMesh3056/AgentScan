# Contributing to AgentScan

Thank you for your interest in contributing to **AgentScan**! Whether you are writing a new attack module, improving documentation, fixing a bug, or optimizing performance, your help is appreciated.

---

## Code of Conduct

All contributors are expected to adhere to our [Code of Conduct](CODE_OF_CONDUCT.md). Please treat others with respect and professionalism.

---

## Getting Started

### 1. Prerequisites
- **Python**: 3.12 or higher
- **Package Manager**: [`uv`](https://github.com/astral-sh/uv) (recommended) or `pip`
- **Git**

### 2. Setting Up Your Development Environment

```bash
# Fork and clone the repository
git clone https://github.com/YOUR_USERNAME/AgentScan.git
cd AgentScan

# Sync dependencies and development tools
uv sync --all-extras
```

### 3. Running the Test Suite

Before writing code, verify that the existing test suite passes:

```bash
# Run the fast test suite (skips slow model downloads)
uv run pytest tests/ -m "not slow"

# Run the complete test suite
uv run pytest tests/ -q
```

---

## Code Quality Standards

We enforce strict linting, formatting, and type-checking standards:

```bash
# Check code style with Ruff
uv run ruff check .

# Format code with Ruff
uv run ruff format .

# Check static types with mypy
uv run mypy agentscan/
```

We also recommend installing pre-commit hooks:
```bash
uv run pre-commit install
```

---

## Adding a New Attack Module

Adding a new security evaluation module to AgentScan requires minimal boilerplate:

1. **Choose the Module Category**:
   - `agentscan/attacks/scan/`: Passive single-turn or multi-turn behavioral evaluations.
   - `agentscan/attacks/exploit/`: Active blast-radius proofs (exfiltration, tool hijack, memory poisoning).
   - `agentscan/attacks/deep/`: Local CPU neural activation and model representation probes.

2. **Create the Python Module**:
   Subclass `AttackModule` from `agentscan.attacks.base`:

```python
from __future__ import annotations

from agentscan.attacks.base import AttackModule
from agentscan.core.models import Finding, ScanMode, Severity, Target


class MyCustomAttack(AttackModule):
    attack_id = "ATK-099"
    attack_name = "Custom Vulnerability Probe"
    owasp_id = "LLM01"
    supported_modes = [ScanMode.SCAN]

    async def run(self, target: Target) -> list[Finding]:
        # Implement your evaluation logic here
        findings: list[Finding] = []

        # Example finding emission:
        # findings.append(
        #     self.make_finding(
        #         severity=Severity.HIGH,
        #         description="Target exhibited unauthorized behavior.",
        #         evidence="Evidence snippet...",
        #         payload_used="Payload string...",
        #     )
        # )
        return findings
```

3. **Add Tests**:
   Add a unit test in `tests/test_attacks/` to verify finding emission and behavior on mock responses.

4. **Automatic Discovery**:
   The registry in `agentscan.attacks.registry` automatically discovers and registers any `AttackModule` subclass placed in the attacks directory.

---

## Pull Request Guidelines

1. **Branch Naming**: Use descriptive branch names:
   - `feat/add-atk-099`
   - `fix/connector-timeout`
   - `docs/update-manual`
2. **Commit Messages**: Follow Conventional Commits:
   - `feat: add ATK-099 custom probe`
   - `fix: resolve socket timeout in http connector`
   - `docs: update quick start instructions`
3. **Checklist Before Submitting**:
   - [ ] All tests pass (`uv run pytest tests/ -q`).
   - [ ] Linting and formatting pass (`uv run ruff check . && uv run ruff format --check .`).
   - [ ] Type checking passes (`uv run mypy agentscan/`).
   - [ ] Documentation is updated where applicable.
