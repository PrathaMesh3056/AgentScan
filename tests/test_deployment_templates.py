"""Check fail-closed source defaults without starting or deploying workloads."""

from __future__ import annotations

import ipaddress
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def documents(name: str) -> list[dict]:
    return list(yaml.safe_load_all((ROOT / "deploy/k8s" / name).read_text(encoding="utf-8")))


@pytest.mark.parametrize("name", ["Dockerfile", "Dockerfile.deep"])
def test_runtime_images_use_locked_profiles_and_non_root_execution(name):
    source = (ROOT / name).read_text(encoding="utf-8")
    assert "COPY pyproject.toml uv.lock README.md LICENSE CHANGELOG.md" in source
    assert "ghcr.io/astral-sh/uv:0.12.3" in source and ":latest" not in source
    assert "uv sync --locked --no-dev --no-install-project" in source
    assert all(f"--extra {extra}" in source for extra in ("ui", "api", "telemetry"))
    assert "--no-deps /dist/*.whl" in source
    assert "USER 10001:10001" in source.split(" AS runner", 1)[1]
    assert "COPY . " not in source and "COPY .env" not in source
    if name.endswith(".deep"):
        assert "--extra deep" in source
        assert "HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1" in source
        assert "ollama pull" not in source and "snapshot_download" not in source


def test_dashboard_compose_port_is_loopback_only():
    config = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    assert config["services"]["agentscan-ui"]["ports"] == ["127.0.0.1:8765:8765"]
    assert config["services"]["agentscan-ui"]["environment"]["AGENTSCAN_UI_TOKEN"].startswith(
        "${AGENTSCAN_UI_TOKEN:?"
    )


@pytest.mark.parametrize(
    "name", ["api-deployment.yaml", "worker-deployment.yaml", "deep-worker-deployment.yaml"]
)
def test_deployment_requires_operator_image_and_runtime_has_no_host_privileges(name):
    deployment = next(doc for doc in documents(name) if doc["kind"] == "Deployment")
    pod = deployment["spec"]["template"]["spec"]
    assert pod["securityContext"]["runAsNonRoot"] is True
    assert pod["securityContext"]["runAsUser"] == 10001
    assert pod["securityContext"]["seccompProfile"]["type"] == "RuntimeDefault"
    assert not any(pod.get(name) for name in ("hostNetwork", "hostPID", "hostIPC"))
    for container in pod["containers"]:
        assert "@sha256:REPLACE_WITH_VERIFIED_RELEASE_DIGEST" in container["image"]
        assert container["securityContext"]["allowPrivilegeEscalation"] is False
        assert container["securityContext"]["capabilities"]["drop"] == ["ALL"]
        assert container["resources"]["limits"]["memory"]
    assert not any("hostPath" in volume for volume in pod.get("volumes", []))


def test_dedicated_deep_pool_uses_offline_cache_and_actual_deep_stream():
    docs = documents("deep-worker-deployment.yaml")
    deployment = next(doc for doc in docs if doc["kind"] == "Deployment")
    container = deployment["spec"]["template"]["spec"]["containers"][0]
    env = {entry["name"]: entry.get("value") for entry in container["env"]}
    assert env["AGENTSCAN_DEEP_WORKER"] == "true"
    assert env["HF_HUB_OFFLINE"] == env["TRANSFORMERS_OFFLINE"] == "1"
    assert all(mount["readOnly"] for mount in container["volumeMounts"])
    scaler = next(doc for doc in docs if doc["kind"] == "ScaledObject")
    assert scaler["spec"]["scaleTargetRef"]["name"] == deployment["metadata"]["name"]
    assert scaler["spec"]["triggers"][0]["metadata"]["stream"] == "agentscan:scan:deep"


def test_each_queue_scaler_references_separate_redis_authentication():
    docs = documents("worker-deployment.yaml") + documents("deep-worker-deployment.yaml")
    auth = next(doc for doc in docs if doc["kind"] == "TriggerAuthentication")
    assert auth["spec"]["secretTargetRef"] == [
        {"parameter": "password", "name": "agentscan-secrets", "key": "redis-scaler-password"}
    ]
    streams = set()
    for doc in docs:
        if doc["kind"] == "ScaledObject":
            for trigger in doc["spec"]["triggers"]:
                streams.add(trigger["metadata"]["stream"])
                assert trigger["authenticationRef"]["name"] == auth["metadata"]["name"]
    assert streams == {"agentscan:scan:normal", "agentscan:scan:high", "agentscan:scan:deep"}


def test_network_templates_deny_target_egress_until_explicit_enrollment():
    policies = documents("network-policy.yaml")
    default = next(
        doc for doc in policies if doc["metadata"]["name"] == "agentscan-workload-boundaries"
    )
    assert set(default["spec"]["policyTypes"]) == {"Ingress", "Egress"}
    assert default["spec"]["ingress"] == []
    selector = default["spec"]["podSelector"]["matchExpressions"][0]
    assert set(selector["values"]) == {"agentscan-api", "agentscan-worker", "agentscan-deep-worker"}
    approved = next(
        doc for doc in policies if doc["metadata"]["name"] == "agentscan-approved-target-egress"
    )
    assert approved["spec"]["egress"] == []
    ports = set()
    for rule in default["spec"]["egress"]:
        assert rule["to"]
        assert rule["ports"]
        for peer in rule["to"]:
            assert peer
            if "ipBlock" in peer:
                assert ipaddress.ip_network(peer["ipBlock"]["cidr"]).prefixlen > 0
        ports.update(port["port"] for port in rule["ports"])
    assert ports == {53, 5432, 6379}


def test_api_ingress_is_limited_to_a_named_controller_and_api_port():
    policy = next(
        doc
        for doc in documents("network-policy.yaml")
        if doc["metadata"]["name"] == "agentscan-api-ingress"
    )
    rule = policy["spec"]["ingress"][0]
    assert rule["ports"] == [{"protocol": "TCP", "port": 8080}]
    assert rule["from"][0]["namespaceSelector"]["matchLabels"]
    assert rule["from"][0]["podSelector"]["matchLabels"]


def test_context_allowlist_reapplies_secret_exclusions_after_runtime_inclusion():
    rules = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    rules = [line for line in rules if line and not line.startswith("#")]
    assert rules[0] == "**"
    package_index = rules.index("!agentscan/**")
    assert all(
        rules.index(pattern) > package_index
        for pattern in (
            "**/.env",
            "**/.env.*",
            "**/*.key",
            "**/*.pem",
            "**/internal_docs/**",
            "**/.agentscan-recovery/**",
            "**/__pycache__/**",
        )
    )


@pytest.mark.parametrize(
    "path", [".env.production", "deploy/k8s/secrets.yaml", "deploy/k8s/secrets.production.yaml"]
)
def test_filled_local_environment_and_cluster_secret_files_are_git_ignored(path):
    result = subprocess.run(
        ["git", "check-ignore", "--no-index", "--quiet", "--", path],
        cwd=ROOT,
        capture_output=True,
        timeout=5,
    )
    assert result.returncode == 0
