$ErrorActionPreference = 'Stop'
$taskLib = Join-Path (Split-Path -Parent $PSScriptRoot) 'tools/moysklad-probe-lib.ps1'
if (Test-Path -LiteralPath $taskLib) { . $taskLib }
$taskPassed = 0
function Assert-Probe($Condition, [string]$Message) {
    if (-not $Condition) { throw ('FAIL: ' + $Message) }
    $script:taskPassed++
}
function Assert-Rejected([scriptblock]$Action, [string]$Message) {
    $taskRejected = $false
    try { & $Action | Out-Null } catch { $taskRejected = $true }
    Assert-Probe $taskRejected $Message
}
Assert-Probe ([bool](Get-Command Get-ProbeCodeEvidence -ErrorAction SilentlyContinue)) 'Code evidence analyzer must exist'
$taskGs = [string][char]29
$taskCodeA = '010000000000000121SYNTHETIC0001' + $taskGs + '91ABCD' + $taskGs + '92SYNTHETIC_SIGNATURE_A'
$taskCodeB = '010000000000000121SYNTHETIC0002' + $taskGs + '91ABCD' + $taskGs + '92SYNTHETIC_SIGNATURE_B'
$taskPositions = @(@{id='position-a';quantity=2;assortment=@{meta=@{href='variant-a'}};trackingCodes=@(@{type='transportpack';cis='synthetic-pack';trackingCodes=@(@{type='trackingcode';cis=$taskCodeA},@{type='trackingcode';cis=$taskCodeB})})})
$taskEvidence = Get-ProbeCodeEvidence $taskPositions
Assert-Probe ($taskEvidence.unit_codes -eq 2 -and $taskEvidence.packages -eq 1) 'Packages must not count as units'
Assert-Probe ($taskEvidence.quantity_matches -eq 1 -and $taskEvidence.gs_codes -eq 2 -and $taskEvidence.crypto_candidates -eq 2) 'Two units map to one variant without stripping GS'
Assert-Probe ($taskEvidence.full_code_proven -eq $false) 'Structure alone cannot prove original full scanned bytes'
$taskJson = $taskEvidence | ConvertTo-Json -Depth 10
Assert-Probe (-not $taskJson.Contains('SYNTHETIC') -and -not $taskJson.Contains('variant-a')) 'Evidence output must contain neither raw codes nor source IDs'
$taskPositions[0].trackingCodes[0].trackingCodes[1].cis = $taskCodeA
Assert-Probe ((Get-ProbeCodeEvidence $taskPositions).duplicate_codes -eq 1) 'Repeated code cannot represent two units'
$taskPositions[0].trackingCodes = @(@{type='trackingcode';cis='010000000000000121SHORT'})
$taskEvidence = Get-ProbeCodeEvidence $taskPositions
Assert-Probe ($taskEvidence.quantity_mismatches -eq 1 -and $taskEvidence.crypto_candidates -eq 0) 'Short CIS and missing unit remain unproven'
Assert-Probe ((Get-ProbeCodeEvidence @(@{quantity=1})).missing_variant_or_position -eq 1) 'Unknown instance locator is detected'
$taskPositions[0].trackingCodes = @(@{type='transportpack';cis='empty-pack'})
Assert-Probe ((Get-ProbeCodeEvidence $taskPositions).unexpanded_packages -eq 1) 'Unexpanded package is not complete unit evidence'
$taskPositions[0].trackingCodes = @(@{type='trackingcode';cis=$taskCodeA})
$taskPositions[0].trackingCodes_1162 = @(@{type='trackingcode';cis_1162='synthetic-tag'})
Assert-Probe ((Get-ProbeCodeEvidence $taskPositions).tag1162_codes -eq 1) 'Tag 1162 is counted separately from original bytes'

$taskPages = @{
    0=@{meta=@{size=3};rows=@(@{id='a'},@{id='b'})}
    2=@{meta=@{size=3};rows=@(@{id='c'})}
}
$taskRead = { param([int]$Offset) $taskPages[$Offset] }
$taskState = New-ProbePageState
Add-ProbePage $taskState (& $taskRead 0)
# Serialize the checkpoint, then resume with a new state object.
$taskRestored = $taskState | ConvertTo-Json -Depth 10 | ConvertFrom-Json -AsHashtable
Add-ProbePage $taskRestored (& $taskRead $taskRestored.offset)
Assert-Probe ($taskRestored.offset -eq 3 -and $taskRestored.ids.Count -eq 3) 'Resume retains all distinct IDs'
Assert-Rejected { Add-ProbePage $taskRestored @{meta=@{size=4};rows=@(@{id='d'})} } 'Changing size cannot claim completeness'
Assert-Rejected { Add-ProbePage (New-ProbePageState) @{meta=@{size=2};rows=@()} } 'Empty intermediate page must fail'
Assert-Rejected { Add-ProbePage (New-ProbePageState) @{meta=@{size=2};rows=@(@{id='a'},@{id='a'})} } 'Duplicate IDs must fail'
Assert-Rejected { Add-ProbePage (New-ProbePageState) @{rows=@(@{id='a'})} } 'Missing size is unknown, not zero'
Assert-Rejected { Add-ProbePage (New-ProbePageState) @{meta=@{size=1;offset=100};rows=@(@{id='a'})} } 'Wrong server offset cannot claim complete collection'

$taskIntention = @{externalCode='synthetic-operation';organization='org';store='store';positions=@(@{variant='v';quantity=2;price=1300000;reserve=2})}
$taskDocument = @{id='d';externalCode='synthetic-operation';organization='org';store='store';positions=@(@{variant='v';quantity=2;price=1300000;reserve=2})}
Assert-Probe ((Resolve-ProbeDocument @($taskDocument) $taskIntention) -eq 'confirmed') 'Lost response resolves by stable locator and complete composition'
Assert-Probe ((Resolve-ProbeDocument @() $taskIntention) -eq 'unknown') 'Empty search does not permit another POST'
Assert-Probe ((Resolve-ProbeDocument @($taskDocument,$taskDocument) $taskIntention) -eq 'conflict') 'Ambiguous locator is a conflict'
$taskDocument.positions[0].reserve = 1
Assert-Probe ((Resolve-ProbeDocument @($taskDocument) $taskIntention) -eq 'conflict') 'Partial reserve cannot confirm full order'
$taskDocument.positions[0].reserve = 2
$taskDocument.store = 'other'
Assert-Probe ((Resolve-ProbeDocument @($taskDocument) $taskIntention) -eq 'conflict') 'Other warehouse cannot confirm operation'
$taskDocument.store = 'store'
$taskDocument.positions += @{variant='extra';quantity=1;price=1;reserve=1}
Assert-Probe ((Resolve-ProbeDocument @($taskDocument) $taskIntention) -eq 'conflict') 'Extra line cannot confirm saved composition'
Assert-Probe ((Resolve-ProbeDocument @(@{positions=@()}) @{positions=@()}) -ne 'confirmed') 'Missing locator and document ID cannot confirm operation'
$taskDocument.positions=@(@{variant='v';quantity=2;price=1300000;reserve=2})
$taskDocument.Remove('id')
Assert-Probe ((Resolve-ProbeDocument @($taskDocument) $taskIntention) -ne 'confirmed') 'Matched locator without document ID cannot confirm operation'
$taskMetadata=Get-ProbeMetadataEvidence @{ok=$false;status=403}
Assert-Probe ($null -eq $taskMetadata.states -and $null -eq $taskMetadata.attributes) 'Metadata denial is unknown, not absence'
$taskMetadata=Get-ProbeMetadataEvidence @{ok=$true;status=200;data=@{states=@();attributes=@{meta=@{size=6}}}}
Assert-Probe ($taskMetadata.states -eq 0 -and $taskMetadata.attributes -eq 6) 'Explicit array and metadata size have distinct shapes'
$taskMetadata=Get-ProbeMetadataEvidence @{ok=$true;status=200;data=@{attributes=@{meta=@{href='private-ref'}}}}
Assert-Probe ($null -eq $taskMetadata.states -and $null -eq $taskMetadata.attributes) 'Unexpanded reference does not become one attribute'

Write-Output ('PASS ' + $taskPassed + ' independent probe scenarios; no external mutations; simulated API only.')
