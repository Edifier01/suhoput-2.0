$ErrorActionPreference='Stop'
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'tools/moysklad-probe-lib.ps1')
$taskTokens=$null; $taskErrors=$null
$taskAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path (Split-Path -Parent $PSScriptRoot) 'tools/find-moysklad-examples.ps1'),[ref]$taskTokens,[ref]$taskErrors)
if ($taskErrors.Count) { throw 'Examples script parse errors.' }
$taskFunction=$taskAst.Find({param($Node) $Node -is [Management.Automation.Language.FunctionDefinitionAst] -and $Node.Name -ceq 'Read-ExamplePositions'},$true)
. ([scriptblock]::Create($taskFunction.Extent.Text))
$taskPassed=0
function Assert-Example($Value) { if (-not $Value) { throw 'FAIL examples full positions.' }; $script:taskPassed++ }
$taskReadCount=0
function Read-Example([string]$Path) { $taskPage=$taskReplies[$script:taskReadCount]; $script:taskReadCount++; return $taskPage }
$taskDoc=@{id='synthetic';positions=@{meta=@{size=2;offset=0};rows=@(@{id='a'},@{id='b'})}}
$taskRows=@(Read-ExamplePositions $taskDoc)
Assert-Example ($taskRows.Count -eq 2 -and $taskReadCount -eq 0)
$taskDoc.positions=@{meta=@{size=3;offset=0};rows=@(@{id='a'})}
$taskReplies=@(@{meta=@{size=3;offset=0};rows=@(@{id='a'},@{id='b'})},@{meta=@{size=3;offset=2};rows=@(@{id='c'})})
$taskRows=@(Read-ExamplePositions $taskDoc)
Assert-Example ($taskRows.Count -eq 3 -and $taskRows[2].id -ceq 'c' -and $taskReadCount -eq 2)
$taskReadCount=0; $taskDoc.Remove('positions')
$taskRows=@(Read-ExamplePositions $taskDoc)
Assert-Example ($taskRows.Count -eq 3 -and $taskReadCount -eq 2)
$taskDoc.positions=@{meta=@{size=2};rows=@(@{id='duplicate'},@{id='duplicate'})}
$taskRejected=$false; try { Read-ExamplePositions $taskDoc | Out-Null } catch { $taskRejected=$true }
Assert-Example $taskRejected
$taskDoc.positions=@{meta=@{href='unexpanded'}}; $taskReadCount=0
$taskReplies=@(@{meta=@{size=3;offset=0};rows=@(@{id='a'})},@{meta=@{size=4;offset=1};rows=@(@{id='b'})})
$taskRejected=$false; try { Read-ExamplePositions $taskDoc | Out-Null } catch { $taskRejected=$true }
Assert-Example $taskRejected
$taskFunction=$taskAst.Find({param($Node) $Node -is [Management.Automation.Language.FunctionDefinitionAst] -and $Node.Name -ceq 'Test-ExampleTrackingPresence'},$true)
if (-not $taskFunction) { throw 'FAIL missing tracking-presence consumer.' }
. ([scriptblock]::Create($taskFunction.Extent.Text))
Assert-Example (Test-ExampleTrackingPresence @(@{trackingCodes_1162=@(@{type='transportpack';cis_1162='SYNTHETIC'})}))
Assert-Example (Test-ExampleTrackingPresence @(@{trackingCodes=@(@{type='future_unknown_type';cis='SYNTHETIC'})}))
Assert-Example (-not (Test-ExampleTrackingPresence @(@{trackingCodes=$null;trackingCodes_1162=@()})))
Assert-Example (-not (Test-ExampleTrackingPresence @(@{trackingCodes=@($null)})))
Write-Output ('PASS '+$taskPassed+' complete-position examples; no network/files/secrets.')
