# agentscan/swarm/presets.py
#
# Preconfigured swarm red-team compositions and YAML profile loaders.

from __future__ import annotations

from pathlib import Path

import yaml

from agentscan.swarm.models import (
    AgentRole,
    SwarmAgentConfig,
    SwarmStrategy,
    SwarmTeamConfig,
)

PRESETS: dict[str, SwarmTeamConfig] = {
    "trio": SwarmTeamConfig(
        name="Default Red-Team Trio",
        strategy=SwarmStrategy.PIPELINE,
        default_model="ollama/llama3.2",
        max_rounds=2,
        agents=[
            SwarmAgentConfig(name="Recon-Alpha", role=AgentRole.RECON),
            SwarmAgentConfig(name="Bypass-Echo", role=AgentRole.BYPASS),
            SwarmAgentConfig(name="Exploit-Omega", role=AgentRole.EXPLOIT),
            SwarmAgentConfig(name="Judge-Delta", role=AgentRole.JUDGE),
        ],
    ),
    "agency": SwarmTeamConfig(
        name="Excessive Agency Hunter",
        strategy=SwarmStrategy.COLLABORATIVE,
        default_model="ollama/llama3.2",
        max_rounds=2,
        agents=[
            SwarmAgentConfig(name="Tool-Scanner", role=AgentRole.RECON),
            SwarmAgentConfig(name="Privilege-Escalator", role=AgentRole.EXPLOIT),
            SwarmAgentConfig(name="HITL-Auditor", role=AgentRole.JUDGE),
        ],
    ),
    "stealth": SwarmTeamConfig(
        name="Stealth Evasion Swarm",
        strategy=SwarmStrategy.ADAPTIVE,
        default_model="ollama/llama3.2",
        max_rounds=2,
        agents=[
            SwarmAgentConfig(name="Boundary-Prober", role=AgentRole.RECON),
            SwarmAgentConfig(name="Obfuscation-Specialist", role=AgentRole.BYPASS),
            SwarmAgentConfig(name="Exfil-Runner", role=AgentRole.EXPLOIT),
            SwarmAgentConfig(name="Compliance-Judge", role=AgentRole.JUDGE),
        ],
    ),
}


def list_presets() -> list[str]:
    """Return available preset team names."""
    return sorted(PRESETS.keys())


def load_team_preset(name: str) -> SwarmTeamConfig:
    """Load a built-in swarm team by preset name."""
    preset_key = name.lower().strip()
    if preset_key in PRESETS:
        return PRESETS[preset_key]
    raise ValueError(f"Unknown swarm preset: '{name}'. Available presets: {list_presets()}")


def load_team_from_yaml(path: Path) -> SwarmTeamConfig:
    """Load a custom swarm team configuration from a YAML file."""
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return SwarmTeamConfig.model_validate(data)


def resolve_team(preset_or_file: str) -> SwarmTeamConfig:
    """Resolve a team configuration from either a preset name or file path."""
    p = Path(preset_or_file)
    if p.exists() and p.is_file():
        return load_team_from_yaml(p)
    return load_team_preset(preset_or_file)
