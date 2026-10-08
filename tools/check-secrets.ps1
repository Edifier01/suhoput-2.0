$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
$taskScan = Join-Path $taskRoot ('.cache/secret-scan/' + [Guid]::NewGuid().ToString())
New-Item -ItemType Directory -Force -Path $taskScan | Out-Null
$taskPaths = & git -C $taskRoot -c core.quotepath=false ls-files --cached --others --exclude-standard
if ($LASTEXITCODE -ne 0) { throw 'Could not list versioned inputs.' }
foreach ($taskRelative in $taskPaths) {
    $taskSource = [IO.Path]::GetFullPath((Join-Path $taskRoot $taskRelative))
    if (-not $taskSource.StartsWith($taskRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Unexpected file outside workspace.'
    }
    if (-not (Test-Path -LiteralPath $taskSource -PathType Leaf)) { continue }
    $taskTarget = Join-Path $taskScan $taskRelative
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $taskTarget) | Out-Null
    Copy-Item -LiteralPath $taskSource -Destination $taskTarget
}
# Ignored local config and caches are not copied or read. Findings are redacted.
& docker run --rm --network none --mount "type=bind,source=$taskScan,target=/scan,readonly" zricethezav/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f dir /scan --redact --no-banner
if ($LASTEXITCODE -ne 0) { throw 'Secret scan failed; values are redacted.' }
