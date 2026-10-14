$ErrorActionPreference='Stop'
$taskLib=Join-Path (Split-Path -Parent $PSScriptRoot) 'tools/moysklad-control-lib.ps1'
if (Test-Path -LiteralPath $taskLib) { . $taskLib }
$taskPassed=0
function Assert-Control($Condition,[string]$Message) { if (-not $Condition) { throw ('FAIL: '+$Message) }; $script:taskPassed++ }
function Reject-Control([scriptblock]$Action,[string]$Message) { $taskRejected=$false; try { & $Action | Out-Null } catch { $taskRejected=$true }; Assert-Control $taskRejected $Message }
Assert-Control ([bool](Get-Command Assert-ControlMutation -ErrorAction SilentlyContinue)) 'Mutation guard must exist'
$taskCode='MS-PROBE-20261008-A-P'
$taskManifest=@{package='MS-PROBE-20261008-A';objects=@{P=@{entity='product';code=$taskCode;id=$null;state='prepared'}}}
Assert-ControlMutation $taskManifest 'POST' 'product' 'P' @{name=$taskCode;externalCode=$taskCode;trackingType='NOT_TRACKED';salePrices=@()}
Assert-Control ($true) 'Approved unmarked new product is allowed'
Reject-Control { Assert-ControlMutation $taskManifest 'POST' 'product' 'P' @{name='foreign';externalCode='foreign'} } 'Cannot create foreign object'
Reject-Control { Assert-ControlMutation $taskManifest 'POST' 'product' 'P' @{name=$taskCode;externalCode=$taskCode;trackingType='LP_CLOTHES'} } 'Cannot create marked product'
$taskManifest.objects.P.id='11111111-1111-1111-1111-111111111111'; $taskManifest.objects.P.state='confirmed'
Reject-Control { Assert-ControlMutation $taskManifest 'POST' 'product' 'P' @{name=$taskCode;externalCode=$taskCode} } 'Confirmed create cannot be repeated'
Reject-Control { Assert-ControlMutation $taskManifest 'PUT' 'product' 'P' @{name='replacement'} } 'Cannot change unapproved fields'
Reject-Control { Assert-ControlMutation $taskManifest 'PUT' 'product' 'P' @{salePrices=@();trackingCodes=@()} } 'Cannot send marking fields'
Reject-Control { Assert-ControlMutation $taskManifest 'DELETE' 'product' 'foreign' $null } 'Cannot delete unrecorded ID'
$taskManifest.objects.P.state='unknown'
Reject-Control { Assert-ControlMutation $taskManifest 'DELETE' 'product' 'P' $null } 'Unknown object cannot be blindly deleted'
$taskManifest.objects.P.state='confirmed'
Assert-ControlMutation $taskManifest 'DELETE' 'product' 'P' $null
Assert-Control ($true) 'Confirmed package object can be removed'
$taskManifest.objects.P.entity='variant'
Reject-Control { Assert-ControlMutation $taskManifest 'DELETE' 'product' 'P' $null } 'Entity mismatch cannot target another resource'
Reject-Control { Get-ControlCreateDecision @{state='unknown';id=$null} @() } 'Empty read after lost response cannot authorize another create'
Assert-Control ((Get-ControlCreateDecision @{state='prepared';id=$null;intention=@{name='synthetic'}} @()) -ceq 'continue_prepared') 'Durable prepared intention resumes before any committed send'
Reject-Control { Get-ControlCreateDecision @{state='prepared';id=$null;intention=@{name='synthetic'}} @(@{id='unexpected'}) } 'Prepared intent with an existing locator stops for reconciliation'
Assert-Control ((Get-ControlCreateDecision $null @()) -eq 'create') 'Only no saved intention and empty preflight allow initial create'
Reject-Control { Get-ControlCreateDecision $null @(@{id='existing'}) } 'Existing object without ownership cannot be adopted'
$taskOwned=@{state='confirmed';id='owned'}
Assert-Control ((Get-ControlCreateDecision $taskOwned @(@{id='owned'})) -eq 'reuse') 'Confirmed ID can be reused without POST'
$taskOwned.pending=@{method='PUT';body=@{salePrices=@()}}
Reject-Control { Get-ControlCreateDecision $taskOwned @(@{id='owned'}) } 'Pending update cannot resume a fresh price sequence'
Reject-Control { Assert-ControlMutation @{package='MS-PROBE-20261008-A';objects=@{P=@{entity='product';code=$taskCode;id='11111111-1111-1111-1111-111111111111';state='confirmed';pending=@{method='PUT'}}}} 'PUT' 'product' 'P' @{salePrices=@()} } 'Unknown PUT cannot be sent again'
$taskOwned.Remove('pending')
Reject-Control { Get-ControlCreateDecision $taskOwned @(@{id='foreign'}) } 'Changed locator cannot be adopted'
$taskManifest.objects.P=@{entity='product';code=$taskCode;id='11111111-1111-1111-1111-111111111111';state='confirmed'}
Reject-Control { Assert-ControlOwned $taskManifest 'P' @{id='11111111-1111-1111-1111-111111111111';externalCode=$taskCode;trackingType='LP_CLOTHES'} } 'Changed marking type stops further catalog mutations'
Assert-ControlOwned $taskManifest 'P' @{id='11111111-1111-1111-1111-111111111111';externalCode=$taskCode;trackingType='NOT_TRACKED'}
Assert-Control $true 'Owned unmarked product can be read'
Reject-Control { Assert-ControlCatalogLinks $taskManifest @(@{id='foreign-variant'}) } 'Foreign child link stops all cleanup'
Assert-ControlCatalogLinks $taskManifest @()
Assert-Control $true 'Empty child list allows deleting owned parent'
Assert-Control ([bool](Get-Command Get-ControlVariantPath -ErrorAction SilentlyContinue)) 'Parent-child collection query builder exists'
Assert-Control ((Get-ControlVariantPath '11111111-1111-1111-1111-111111111111') -ceq '/entity/variant?limit=1000&filter=productid%3D11111111-1111-1111-1111-111111111111') 'Parent ID uses supported productid filter, not unsupported href product'
Reject-Control { Get-ControlVariantPath 'id;foreign=true' } 'Parent filter cannot inject another scope'
Assert-Control ([bool](Get-Command Save-ControlAtomic -ErrorAction SilentlyContinue)) 'Durable manifest writer handles temporary filesystem locks'
$taskAtomicDir=Join-Path (Split-Path -Parent $PSScriptRoot) '.cache/control-tests'
New-Item -ItemType Directory -Force -Path $taskAtomicDir | Out-Null
$taskAtomicFile=Join-Path $taskAtomicDir ([Guid]::NewGuid().ToString()+'.json')
try {
    [IO.File]::WriteAllText($taskAtomicFile,'{"state":"prepared"}')
    $taskCommitCalls=0
    $taskCommit={ param($Source,$Target) $script:taskCommitCalls++; if ($script:taskCommitCalls -eq 1) { if ([IO.File]::ReadAllText($Target) -cne '{"state":"prepared"}') { throw 'Old manifest was changed before commit.' }; throw [IO.IOException]::new('Synthetic temporary lock') }; [IO.File]::Move($Source,$Target,$true) }
    Save-ControlAtomic $taskAtomicFile @{state='unknown'} $taskCommit
    $taskSaved=[IO.File]::ReadAllText($taskAtomicFile) | ConvertFrom-Json -AsHashtable
    Assert-Control ($taskCommitCalls -eq 2 -and $taskSaved.state -ceq 'unknown') 'Transient lock retries file commit while preserving old durable intent'
    $taskNeverCommit={param($Source,$Target) throw [IO.IOException]::new('Synthetic permanent lock')}
    Reject-Control { Save-ControlAtomic $taskAtomicFile @{state='confirmed'} $taskNeverCommit 2 } 'Persistent write failure stops before another external action'
    $taskSaved=[IO.File]::ReadAllText($taskAtomicFile) | ConvertFrom-Json -AsHashtable
    Assert-Control ($taskSaved.state -ceq 'unknown') 'Failed file commit cannot report a confirmed durable result'
} finally {
    Remove-Item -LiteralPath $taskAtomicFile
    if (Test-Path -LiteralPath ($taskAtomicFile+'.tmp')) { Remove-Item -LiteralPath ($taskAtomicFile+'.tmp') }
}
Write-Output ('PASS '+$taskPassed+' control safety scenarios; no network.')
