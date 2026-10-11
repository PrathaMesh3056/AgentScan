#!/usr/bin/env bash
# Install outside the source tree, so imports cannot fall back to this checkout.
set -euo pipefail
shopt -s nullglob

wheels=(dist/*.whl)
sdists=(dist/*.tar.gz)
if [[ ${#wheels[@]} -ne 1 || ${#sdists[@]} -ne 1 ]]; then
  printf '%s\n' 'Expected exactly one wheel and one sdist.' >&2
  exit 1
fi
wheel="$PWD/${wheels[0]}"
sdist="$PWD/${sdists[0]}"
uv run --no-sync python .github/scripts/check_artifact_contents.py "$wheel" "$sdist"
scratch="$(mktemp -d "${RUNNER_TEMP:?}/agentscan-artifacts.XXXXXX")"

for profile in wheel sdist service; do
  smoke_env="$scratch/$profile"
  uv venv "$smoke_env" --python "${PYTHON_VERSION:?}"
  case "$profile" in
    wheel) requirement="$wheel" ;;
    sdist) requirement="$sdist" ;;
    service) requirement="$wheel[ui,api]" ;;
  esac
  uv pip install --python "$smoke_env/bin/python" "$requirement"
  (
    cd "$scratch"
    "$smoke_env/bin/agentscan" --version
    "$smoke_env/bin/python" -c 'from agentscan.core.models import ScanMode, ScanReport; from agentscan.reporting.sarif_report import to_sarif; assert to_sarif(ScanReport(target_url="http://fixture.test", scan_mode=ScanMode.SCAN))["version"] == "2.1.0"'
    if [[ "$profile" == service ]]; then
      "$smoke_env/bin/python" -c 'from agentscan.api.server import create_api_app; from agentscan.api import worker; from agentscan.ui.app import create_app; assert create_api_app(); assert create_app()'
    fi
  )
done
