$ErrorActionPreference='Stop'
$taskLib=Join-Path (Split-Path -Parent $PSScriptRoot) 'tools/moysklad-document-control-lib.ps1'
if (Test-Path -LiteralPath $taskLib) { . $taskLib }
$taskPassed=0
function Assert-Doc($Value,[string]$Message) { if (-not $Value) { throw ('FAIL: '+$Message) }; $script:taskPassed++ }
function Reject-Doc([scriptblock]$Action,[string]$Message) { $taskBad=$false; try { & $Action | Out-Null } catch { $taskBad=$true }; Assert-Doc $taskBad $Message }
Assert-Doc ([bool](Get-Command Assert-DocumentControl -ErrorAction SilentlyContinue)) 'Document scope guard exists'
$taskManifest=@{package='MS-PROBE-20261008-A';organization_href='org';store_href='store';retail_href='retail';wholesale_href='wholesale';objects=@{CHANNEL=@{href='channel'};SIMPLE=@{entity='product';id='simple';state='confirmed';href='simple'};DELIVERY=@{entity='service';id='service';state='confirmed';href='service'};RACE_A=@{entity='customerorder';code='MS-PROBE-20261008-A-RACE-A';state='prepared';id=$null};STOCK=@{entity='enter';code='MS-PROBE-20261008-A-STOCK';state='prepared';id=$null}}}
$taskBody=@{name='MS-PROBE-20261008-A-RACE-A';externalCode='MS-PROBE-20261008-A-RACE-A';syncId='11111111-1111-1111-1111-111111111111';organization=@{meta=@{href='org'}};store=@{meta=@{href='store'}};agent=@{meta=@{href='retail'}};salesChannel=@{meta=@{href='channel'}};positions=@(@{assortment=@{meta=@{href='simple'}};quantity=1;price=1300000;reserve=1})}
Assert-DocumentControl $taskManifest 'POST' 'RACE_A' $taskBody
Assert-Doc $true 'Last synthetic unit can be reserved'
$taskManifest.objects.INHERIT=@{state='confirmed';href='inherit'}; $taskManifest.objects.OWN=@{state='confirmed';href='own'}
Assert-DocumentControl $taskManifest 'POST' 'STOCK' @{name='MS-PROBE-20261008-A-STOCK';externalCode='MS-PROBE-20261008-A-STOCK';syncId='11111111-1111-1111-1111-111111111111';organization=@{meta=@{href='org'}};store=@{meta=@{href='store'}};positions=@(@{assortment=@{meta=@{href='inherit'}};quantity=1;price=100},@{assortment=@{meta=@{href='own'}};quantity=2;price=100},@{assortment=@{meta=@{href='simple'}};quantity=1;price=100})}
Assert-Doc $true 'Approved stock entry has no reserve field and does not compare null as a negative number'
$taskNoLinks=$taskBody | ConvertTo-Json -Depth 15 | ConvertFrom-Json -AsHashtable
$taskNoLinks.Remove('agent'); $taskNoLinks.Remove('salesChannel')
Reject-Doc { Assert-DocumentControl $taskManifest 'POST' 'RACE_A' $taskNoLinks } 'Missing agent/channel cannot pass as null equals null'
Reject-Doc { Assert-DocumentControl $taskManifest 'POST' 'STOCK' @{name='MS-PROBE-20261008-A-STOCK';externalCode='MS-PROBE-20261008-A-STOCK';syncId='11111111-1111-1111-1111-111111111111';organization=@{meta=@{href='org'}};store=@{meta=@{href='store'}}} } 'Stock entry cannot omit its full composition'
$taskNoLinks=$taskBody | ConvertTo-Json -Depth 15 | ConvertFrom-Json -AsHashtable
$taskNoLinks.agent.meta.href='wholesale'
Reject-Doc { Assert-DocumentControl $taskManifest 'POST' 'RACE_A' $taskNoLinks } 'Retail race cannot change to existing wholesale agent'
$taskBody.store.meta.href='foreign'
Reject-Doc { Assert-DocumentControl $taskManifest 'POST' 'RACE_A' $taskBody } 'Foreign warehouse cannot be mutated'
$taskBody.store.meta.href='store'; $taskBody.positions[0].assortment.meta.href='foreign'
Reject-Doc { Assert-DocumentControl $taskManifest 'POST' 'RACE_A' $taskBody } 'Foreign SKU cannot be reserved'
$taskBody.positions[0].assortment.meta.href='simple'; $taskBody.positions[0].quantity=2
Reject-Doc { Assert-DocumentControl $taskManifest 'POST' 'RACE_A' $taskBody } 'Race cannot use more than one test unit'
$taskBody.positions[0].quantity=1; $taskBody.positions[0].trackingCodes=@('fake')
Reject-Doc { Assert-DocumentControl $taskManifest 'POST' 'RACE_A' $taskBody } 'Marking fields cannot enter control request'
$taskBody.positions[0].Remove('trackingCodes'); $taskBody.positions[0].assortment.meta.href='service'
Reject-Doc { Assert-DocumentControl $taskManifest 'POST' 'RACE_A' $taskBody } 'Delivery cannot reserve physical stock'
$taskBody.positions[0].assortment.meta.href='simple'; $taskManifest.objects.RACE_A.state='unknown'
Reject-Doc { Assert-DocumentControl $taskManifest 'POST' 'RACE_A' $taskBody } 'Unknown send cannot trigger another POST'
$taskManifest.objects.RACE_A.state='confirmed'; $taskManifest.objects.RACE_A.id='11111111-1111-1111-1111-111111111111'; $taskManifest.objects.RACE_A.pending=@{method='PUT'}
Reject-Doc { Assert-DocumentControl $taskManifest 'PUT' 'RACE_A' @{positions=@()} } 'Unknown update cannot be resent'
$taskManifest.objects.RACE_A.Remove('pending')
Reject-Doc { Assert-DocumentControl $taskManifest 'PUT' 'RACE_A' @{agent=@{meta=@{href='foreign'}}} } 'Existing counterparty fields or links cannot be changed'
$taskManifest.objects.RACE_A.state='prepared'; $taskManifest.objects.RACE_A.id=$null
$taskBody.positions[0].reserve=1; $taskBody.positions+=@{assortment=@{meta=@{href='simple'}};quantity=1;price=1300000;reserve=1}
Reject-Doc { Assert-DocumentControl $taskManifest 'POST' 'RACE_A' $taskBody } 'Duplicate rows cannot exceed approved quantity'
Assert-Doc ([bool](Get-Command Assert-ControlLinkedRows -ErrorAction SilentlyContinue)) 'Linked graph ownership guard exists'
Reject-Doc { Assert-ControlLinkedRows $taskManifest @(@{id='foreign-document'}) } 'Foreign link stops cleanup before mutation'
Assert-ControlLinkedRows $taskManifest @()
Assert-Doc $true 'Empty complete linked collection is safe'
Assert-Doc ([bool](Get-Command Test-ControlRejectedChannel -ErrorAction SilentlyContinue)) 'Rejected channel reconciliation exists'
Assert-Doc (Test-ControlRejectedChannel @{entity='saleschannel';state='unknown';id=$null} 412 @()) 'Explicit 412 and no matching channel allow recording rejection without DELETE'
Assert-Doc (-not (Test-ControlRejectedChannel @{entity='saleschannel';state='unknown';id=$null} 500 @())) 'Transport/server uncertainty and empty read remain unknown'
Assert-Doc (-not (Test-ControlRejectedChannel @{entity='saleschannel';state='unknown';id=$null} 412 @(@{id='unexpected'}))) 'Existing unexpected channel cannot be classified absent'
Assert-Doc ([bool](Get-Command Convert-ControlErrors -ErrorAction SilentlyContinue)) 'Safe error evidence converter exists'
$taskErrors=@(Convert-ControlErrors @(@{code=3000;error="Не указан параметр 'type'; test@example.com Bearer SYNTHETIC_SECRET";parameter='type'}) @('SYNTHETIC_SECRET'))
Assert-Doc ($taskErrors[0].code -eq 3000 -and $taskErrors[0].parameter -ceq 'type') 'Error code and field survive sanitization'
Assert-Doc (-not ($taskErrors | ConvertTo-Json).Contains('SYNTHETIC_SECRET') -and -not ($taskErrors | ConvertTo-Json).Contains('test@example.com')) 'Error evidence cannot reveal credentials or email'
$taskManifest.objects.CHANNEL=@{entity='saleschannel';code='MS-PROBE-20261008-A-CHANNEL';state='prepared';id=$null}
Reject-Doc { Assert-DocumentControl $taskManifest 'POST' 'CHANNEL' @{name='MS-PROBE-20261008-A-CHANNEL';externalCode='MS-PROBE-20261008-A-CHANNEL'} } 'Missing required channel type is rejected before send'
Assert-DocumentControl $taskManifest 'POST' 'CHANNEL' @{name='MS-PROBE-20261008-A-CHANNEL';externalCode='MS-PROBE-20261008-A-CHANNEL';type='OTHER'}
Assert-Doc $true 'Corrected synthetic channel type is permitted'
Assert-Doc ([bool](Get-Command Get-ControlStockReadMode -ErrorAction SilentlyContinue)) 'Deleted SKU recovery requires saved zero-stock evidence'
Assert-Doc ((Get-ControlStockReadMode @{state='deleted'} @{stock=0;reserve=0;inTransit=0}) -ceq 'skip_deleted') 'Confirmed deletion with earlier zero proof needs no impossible live stock row'
Reject-Doc { Get-ControlStockReadMode @{state='deleted'} $null } 'Deletion without zero proof cannot report clean stock'
Reject-Doc { Get-ControlStockReadMode @{state='deleted'} @{stock=0;reserve=1;inTransit=0} } 'Saved nonzero reserve cannot confirm cleanup'
# Execute the real stock reader with hand-authored API replies, without executing script startup.
$taskParseTokens=$null; $taskParseErrors=$null
$taskAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path (Split-Path -Parent $PSScriptRoot) 'tools/control-moysklad-documents.ps1'),[ref]$taskParseTokens,[ref]$taskParseErrors)
$taskFunction=$taskAst.Find({param($Node) $Node -is [Management.Automation.Language.FunctionDefinitionAst] -and $Node.Name -ceq 'Read-TestStock'},$true)
. ([scriptblock]::Create($taskFunction.Extent.Text))
$taskManifest=@{store_href='selected-store';objects=@{INHERIT=@{state='confirmed';entity='variant';href='v-inherit'};OWN=@{state='confirmed';entity='variant';href='v-own'};SIMPLE=@{state='confirmed';entity='product';href='p-simple'}};evidence=@{}}
$taskStockFixtures=@(
    @{meta=@{size=1};rows=@(@{meta=@{href='v-inherit'};stockByStore=@(@{meta=@{href='selected-store'};stock=1;reserve=0;inTransit=10})})},
    @{meta=@{size=1};rows=@(@{meta=@{href='v-own'};stockByStore=@(@{meta=@{href='selected-store'};stock=2;reserve=0;inTransit=0})})},
    @{meta=@{size=1};rows=@(@{meta=@{href='p-simple'};stockByStore=@(@{meta=@{href='selected-store'};stock=1;reserve=0;inTransit=0})})}
)
$taskStockCalls=0
function Read-Doc([string]$Path) { $taskReply=$taskStockFixtures[$script:taskStockCalls]; $script:taskStockCalls++; return $taskReply }
function Save-DocControl {} # The tested consumer retains evidence; file persistence is not this scenario.
$taskFirst=Read-TestStock 'after_enter'
Assert-Doc ($taskStockCalls -eq 3 -and $taskFirst.INHERIT.stock -eq 1 -and $taskFirst.OWN.stock -eq 2 -and $taskFirst.SIMPLE.stock -eq 1) 'First live stock read requires no previous cleanup evidence'
Assert-Doc ($taskFirst.INHERIT.available -eq 1) 'Expected arrivals do not increase available physical test stock'
$taskManifest.evidence.cleanup_stock=@{stock=@{INHERIT=@{stock=0;reserve=0;inTransit=0};OWN=@{stock=0;reserve=0;inTransit=0};SIMPLE=@{stock=0;reserve=0;inTransit=0}}}
foreach ($taskObject in $taskManifest.objects.Values) { $taskObject.state='deleted' }
$taskStockCalls=0; $taskDeleted=Read-TestStock 'reconciled_cleanup'
Assert-Doc ($taskStockCalls -eq 0 -and $taskDeleted.SIMPLE.stock -eq 0) 'Recovered deleted references finish from saved zero proof without GET'
$taskFunction=$taskAst.Find({param($Node) $Node -is [Management.Automation.Language.FunctionDefinitionAst] -and $Node.Name -ceq 'Read-Positions'},$true)
. ([scriptblock]::Create($taskFunction.Extent.Text))
$taskPositionReply=@{meta=@{size=3};rows=@(
    @{id='goods';assortment=@{meta=@{type='variant';href='goods'}};quantity=2;price=1350000;reserve=0},
    @{id='delivery';assortment=@{meta=@{type='service';href='delivery'}};quantity=1;price=50000},
    @{id='missing';assortment=@{meta=@{type='product';href='missing'}};quantity=1;price=1300000}
)}
function Read-Doc([string]$Path) { return $taskPositionReply }
$taskPositions=@(Read-Positions @{entity='customerorder';id='order'})
Assert-Doc ($taskPositions[1].reserve -eq 0 -and $null -ne $taskPositions[1].reserve) 'Omitted service reserve means no physical reservation'
Assert-Doc ($null -eq $taskPositions[2].reserve) 'Omitted goods reserve remains unknown, never silently zero'
$taskPositionReply.rows[1].reserve=$null
$taskPositions=@(Read-Positions @{entity='customerorder';id='order'})
Assert-Doc ($null -eq $taskPositions[1].reserve) 'Explicit null service reserve is not treated as omission'
Write-Output ('PASS '+$taskPassed+' document control guard scenarios; no network.')
