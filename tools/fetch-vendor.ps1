$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
$taskCache = Join-Path $taskRoot '.cache/packages'
New-Item -ItemType Directory -Force -Path $taskCache | Out-Null
$taskArchive = Join-Path $taskCache 'woocommerce.11.2.0.zip'
$taskExpected = '66E91B45B057B64C73D4521111CEA5BDC78C4C89DE8FA2CA4B18B9422706D722'
if (-not (Test-Path -LiteralPath $taskArchive)) {
    Invoke-WebRequest -Uri 'https://downloads.wordpress.org/plugin/woocommerce.11.2.0.zip' -OutFile $taskArchive
}
if ((Get-FileHash -LiteralPath $taskArchive -Algorithm SHA256).Hash -ne $taskExpected) {
    throw 'WooCommerce archive checksum mismatch; do not install.'
}
Write-Output 'WooCommerce 11.2.0 archive SHA-256 verified.'
