$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
$taskConfig = Join-Path $PSScriptRoot '.env.local'
if (-not (Test-Path -LiteralPath $taskConfig)) {
    $taskRandom = [System.Security.Cryptography.RandomNumberGenerator]
    $taskValues = @('LOCAL_DB_PASSWORD', 'LOCAL_DB_ROOT_PASSWORD', 'LOCAL_ADMIN_PASSWORD') | ForEach-Object {
        $_ + '=' + [Convert]::ToHexString($taskRandom::GetBytes(32))
    }
    [IO.File]::WriteAllText($taskConfig, ($taskValues -join "`n") + "`n", [Text.UTF8Encoding]::new($false))
}
& git -C $taskRoot check-ignore --quiet -- $taskConfig
if ($LASTEXITCODE -ne 0) { throw 'Local configuration must be ignored by Git.' }
Write-Output 'Local configuration exists and is ignored. Values were not printed.'
