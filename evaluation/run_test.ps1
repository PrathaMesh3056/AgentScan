$ErrorActionPreference = "Continue"

$evalDir = $PSScriptRoot
$repoDir = (Resolve-Path "$evalDir\..").Path
$canary = "SYNTHETIC_CANARY_REF_DEV_20261012_A9B8C7"

Write-Host "=== 1. Building multi-agent target Docker image ==="
docker build -t atk005-target:local $evalDir

Write-Host "`n=== 2. Creating isolated Docker network ==="
docker network rm atk005-net 2>$null
docker network create atk005-net

Write-Host "`n=== 3. Running Phase 1: Baseline Test (Vulnerable) ==="
docker rm -f atk005-target 2>$null
docker run -d --name atk005-target --network atk005-net atk005-target:local --port 8000 --reference $canary --mode baseline
Start-Sleep -Seconds 2

Write-Host "Running AgentScan against baseline target..."
docker run --rm --network atk005-net `
    -v "${repoDir}:/workspace:ro" `
    -v "${evalDir}:/test:rw" `
    -e "PYTHONPATH=/workspace" `
    --entrypoint python `
    agentscan-agentscan-api:latest `
    -m agentscan.cli scan --config /test/scan_config.yaml --output /test/baseline_report.json --transcript /test/baseline_transcript.txt -v

docker rm -f atk005-target 2>$null

Write-Host "`n=== 4. Running Phase 2: Defended Test (Mitigated) ==="
docker run -d --name atk005-target --network atk005-net atk005-target:local --port 8000 --reference $canary --mode defended
Start-Sleep -Seconds 2

Write-Host "Running AgentScan against defended target..."
docker run --rm --network atk005-net `
    -v "${repoDir}:/workspace:ro" `
    -v "${evalDir}:/test:rw" `
    -e "PYTHONPATH=/workspace" `
    --entrypoint python `
    agentscan-agentscan-api:latest `
    -m agentscan.cli scan --config /test/scan_config.yaml --output /test/defended_report.json --transcript /test/defended_transcript.txt -v

docker rm -f atk005-target 2>$null

Write-Host "`n=== 5. Cleaning up Docker network ==="
docker network rm atk005-net 2>$null

Write-Host "`n=== Execution Complete ==="
