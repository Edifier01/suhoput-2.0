param([switch]$Resume,[ValidateRange(0,100)][int]$StopAfterDocumentPages=0)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'moysklad-probe-lib.ps1')
. (Join-Path $PSScriptRoot 'moysklad-control-lib.ps1')
$taskRoot=Split-Path -Parent $PSScriptRoot
$taskFile=Join-Path $taskRoot '.cache/moysklad/examples-checkpoint.local.json'
$taskConfig=@{}
foreach ($taskLine in [IO.File]::ReadAllLines((Join-Path $taskRoot 'infra/.env.integrations.local'))) {
    if ($taskLine -match '^([A-Z][A-Z0-9_]*)=(.*)$') { $taskConfig[$Matches[1]]=$Matches[2].Trim().Trim('"',"'") }
}
$taskBase='https://api.moysklad.ru/api/remap/1.2'
if (-not $taskConfig.MOYSKLAD_TOKEN -or ($taskConfig.MOYSKLAD_API_BASE_URL -and $taskConfig.MOYSKLAD_API_BASE_URL -cne $taskBase)) { throw 'Invalid config; values withheld.' }
foreach ($taskKey in @('MOYSKLAD_ORGANIZATION_ID','MOYSKLAD_WAREHOUSE_ID')) {
    if ($taskConfig[$taskKey] -notmatch '^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$') { throw 'Selected ID must be UUID.' }
}
$taskHandler=[Net.Http.HttpClientHandler]::new(); $taskHandler.AllowAutoRedirect=$false
$taskHandler.AutomaticDecompression=[Net.DecompressionMethods]::GZip
$taskClient=[Net.Http.HttpClient]::new($taskHandler); $taskClient.Timeout=[TimeSpan]::FromSeconds(30)
$taskClient.DefaultRequestHeaders.Authorization=[Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer',$taskConfig.MOYSKLAD_TOKEN)
$taskClient.DefaultRequestHeaders.Add('Accept-Encoding','gzip')
$taskRequests=0; $taskLastStatus='not_requested'
function Read-Example([string]$Path) {
    if ($Path -notmatch '^/entity/(organization|store|product|variant|demand)(/[0-9a-f-]{36}(/positions|/images)?)?(\?|$)' -or $Path.Contains('..')) { throw 'GET outside examples scope.' }
    Start-Sleep -Milliseconds 500; $script:taskRequests++; $taskResponse=$null
    try {
        $taskResponse=$taskClient.GetAsync($taskBase+$Path).GetAwaiter().GetResult(); $script:taskLastStatus=[int]$taskResponse.StatusCode
        if (-not $taskResponse.IsSuccessStatusCode) { throw 'GET unsuccessful.' }
        return ($taskResponse.Content.ReadAsStringAsync().GetAwaiter().GetResult() | ConvertFrom-Json -AsHashtable -Depth 100)
    } catch { throw ('Example GET unavailable, status='+$taskLastStatus+'; body/headers/credentials withheld.') }
    finally { if ($taskResponse) { $taskResponse.Dispose() } }
}
function Save-Examples { Save-ControlAtomic $taskFile $taskState }
function Test-ExampleTrackingPresence($Positions) {
    # Presence is broader than recognized unit codes: unknown types and unexpanded
    # 1162 packages must remain candidates, never disappear as a zero-code result.
    foreach ($taskPosition in $Positions) {
        foreach ($taskField in @('trackingCodes','trackingCodes_1162')) {
            if (@($taskPosition[$taskField] | Where-Object { $null -ne $_ }).Count -gt 0) { return $true }
        }
    }
    return $false
}
function Read-ExamplePositions($Document) {
    if ($Document.positions -is [System.Collections.IDictionary] -and $Document.positions.ContainsKey('rows') -and $null -ne $Document.positions.meta.size -and $Document.positions.meta.size -eq @($Document.positions.rows).Count) {
        $taskPositionState=New-ProbePageState; Add-ProbePage $taskPositionState $Document.positions
        return @($Document.positions.rows)
    }
    # An unexpanded/truncated positions collection never becomes an empty sample.
    $taskPositionState=New-ProbePageState; $taskPositions=@()
    do {
        $taskPage=Read-Example ('/entity/demand/'+$Document.id+'/positions?limit=1000&offset='+$taskPositionState.offset)
        Add-ProbePage $taskPositionState $taskPage; $taskPositions+=@($taskPage.rows)
    } while ($taskPositionState.offset -lt $taskPositionState.size)
    return $taskPositions
}
try {
    $taskOrg=Read-Example ('/entity/organization/'+$taskConfig.MOYSKLAD_ORGANIZATION_ID)
    $taskStore=Read-Example ('/entity/store/'+$taskConfig.MOYSKLAD_WAREHOUSE_ID)
    if ($taskOrg.name -cne 'Склад Грозный' -or $taskStore.name -cne 'Основной склад' -or $taskOrg.archived -or $taskStore.archived) { throw 'Selected scope changed.' }
    $taskOrgHref=$taskBase+'/entity/organization/'+$taskOrg.id; $taskStoreHref=$taskBase+'/entity/store/'+$taskStore.id
    $taskScope=$taskOrg.id+'/'+$taskStore.id
    if ($Resume) {
        $taskState=[IO.File]::ReadAllText($taskFile) | ConvertFrom-Json -AsHashtable -Depth 100
        if ($taskState.scope -cne $taskScope -or $taskState.version -ne 1) { throw 'Checkpoint scope/version mismatch.' }
    } else {
        $taskState=@{version=1;scope=$taskScope;started_utc=[DateTime]::UtcNow.ToString('o');product=New-ProbePageState;variant=New-ProbePageState;demand=New-ProbePageState;products=@{};variants=@{};photo_candidates=@();code_candidates=@();positions=0;linked_orders=0}
    }
    foreach ($taskEntity in @('product','variant')) {
        $taskPageState=$taskState[$taskEntity]
        while ($null -eq $taskPageState.size -or $taskPageState.offset -lt $taskPageState.size) {
            $taskPage=Read-Example ('/entity/'+$taskEntity+'?limit=1000&offset='+$taskPageState.offset)
            Add-ProbePage $taskPageState $taskPage
            foreach ($taskRow in $taskPage.rows) {
                # Only field availability and IDs, never names, contacts, descriptions or images.
                $taskState[$taskEntity+'s'][$taskRow.id]=@{id=$taskRow.id;parent=$taskRow.product.meta.href;trackingType=$taskRow.trackingType;images=$taskRow.images.meta.size}
                if ($null -ne $taskRow.images.meta.size -and $taskRow.images.meta.size -gt 0) {
                    $taskImages=Read-Example ('/entity/'+$taskEntity+'/'+$taskRow.id+'/images?limit=1000')
                    if ($null -eq $taskImages.meta.size -or $taskImages.meta.size -ne @($taskImages.rows).Count) { throw 'Image collection incomplete.' }
                    $taskState.photo_candidates+=@(@{entity=$taskEntity;id=$taskRow.id;images=$taskImages.meta.size})
                }
            }
            Save-Examples
        }
        $taskCheck=Read-Example ('/entity/'+$taskEntity+'?limit=1')
        if ($taskCheck.meta.size -ne $taskPageState.size) { throw 'Catalog size changed; no complete result.' }
    }
    $taskFilter=[Uri]::EscapeDataString('organization='+$taskOrgHref+';store='+$taskStoreHref)
    $taskThisRunPages=0; $taskPageState=$taskState.demand
    while ($null -eq $taskPageState.size -or $taskPageState.offset -lt $taskPageState.size) {
        # Documented expand limit is <=100; full positions are checked independently.
        $taskPage=Read-Example ('/entity/demand?limit=100&offset='+$taskPageState.offset+'&order=id&expand=positions&filter='+$taskFilter)
        # Work on a clone: incomplete position read must not advance the durable document checkpoint.
        $taskNext=$taskPageState | ConvertTo-Json -Depth 10 | ConvertFrom-Json -AsHashtable
        Add-ProbePage $taskNext $taskPage
        $taskCandidates=@(); $taskPositionsCount=0; $taskLinkedCount=0
        foreach ($taskDoc in $taskPage.rows) {
            if ($taskDoc.organization.meta.href -cne $taskOrgHref -or $taskDoc.store.meta.href -cne $taskStoreHref) { throw 'Document outside selected warehouse/organization.' }
            $taskPositions=@(Read-ExamplePositions $taskDoc); $taskPositionsCount+=$taskPositions.Count
            if ($taskDoc.customerOrder.meta.href) { $taskLinkedCount++ }
            $taskEvidence=Get-ProbeCodeEvidence $taskPositions
            if (Test-ExampleTrackingPresence $taskPositions) {
                $taskKinds=@{}; $taskPositionEvidence=@()
                foreach ($taskPosition in $taskPositions) {
                    $taskSingle=Get-ProbeCodeEvidence @($taskPosition)
                    if (-not (Test-ExampleTrackingPresence @($taskPosition))) { continue }
                    $taskAssortmentId=($taskPosition.assortment.meta.href -split '/')[-1]
                    $taskProductId=$taskAssortmentId
                    if ($taskPosition.assortment.meta.type -ceq 'variant') {
                        $taskProductId='unknown-parent'
                        if ($taskState.variants[$taskAssortmentId].parent) { $taskProductId=($taskState.variants[$taskAssortmentId].parent -split '/')[-1] }
                    }
                    $taskKind=if ($taskProductId) { $taskState.products[$taskProductId].trackingType } else { $null }
                    if (-not $taskKind) { $taskKind='UNKNOWN' }
                    if (-not $taskKinds.ContainsKey($taskKind)) { $taskKinds[$taskKind]=0 }; $taskKinds[$taskKind]++
                    $taskPositionEvidence+=@(@{id=$taskPosition.id;assortment_id=$taskAssortmentId;assortment_type=$taskPosition.assortment.meta.type;tracking_type=$taskKind;quantity=$taskPosition.quantity;tracking_structure_present=$true;evidence=$taskSingle})
                }
                $taskCandidates+=@(@{id=$taskDoc.id;linked_order_id=if ($taskDoc.customerOrder.meta.href) { ($taskDoc.customerOrder.meta.href -split '/')[-1] } else { $null };evidence=$taskEvidence;kinds=$taskKinds;positions=$taskPositionEvidence})
            }
        }
        $taskState.demand=$taskNext; $taskPageState=$taskNext
        $taskState.positions+=$taskPositionsCount; $taskState.linked_orders+=$taskLinkedCount; $taskState.code_candidates+=@($taskCandidates)
        Save-Examples; $taskThisRunPages++
        if ($taskThisRunPages % 10 -eq 0) { @{result='read_only_progress';documents=$taskPageState.offset;total=$taskPageState.size;code_candidate_documents=$taskState.code_candidates.Count;requests=$taskRequests;mutations=0} | ConvertTo-Json -Compress }
        if ($StopAfterDocumentPages -gt 0 -and $taskThisRunPages -ge $StopAfterDocumentPages) { @{result='checkpoint_stop';documents=$taskPageState.offset;total=$taskPageState.size;requests=$taskRequests;mutations=0} | ConvertTo-Json -Compress; return }
    }
    $taskCheck=Read-Example ('/entity/demand?limit=1&filter='+$taskFilter)
    if ($taskCheck.meta.size -ne $taskPageState.size) { throw 'Document size changed; no complete result.' }
    $taskState.checked_utc=[DateTime]::UtcNow.ToString('o'); Save-Examples
    $taskCatalogRows=@($taskState.products.Values)+@($taskState.variants.Values)
    @{result='examples_search_complete';utc=$taskState.checked_utc;requests=$taskRequests;mutations=0;products=$taskState.product.size;variants=$taskState.variant.size;images_unknown=@($taskCatalogRows | Where-Object { $null -eq $_.images }).Count;photo_candidates=$taskState.photo_candidates.Count;documents=$taskState.demand.offset;document_pages=$taskState.demand.pages;positions=$taskState.positions;linked_orders=$taskState.linked_orders;code_candidate_documents=$taskState.code_candidates.Count;full_code_proven=$false} | ConvertTo-Json -Compress
} catch {
    $taskSafeReason='withheld'
    if ($_.Exception.Message -cin @('Collection size changed; restart read.','Collection count exceeded size.','Missing or invalid collection size.','Response offset differs from requested checkpoint.','Missing or duplicate ID.','Empty intermediate page.','Catalog size changed; no complete result.','Document size changed; no complete result.','Image collection incomplete.','Document outside selected warehouse/organization.')) { $taskSafeReason=$_.Exception.Message }
    throw ('Read-only examples search stopped; source='+[IO.Path]::GetFileName($_.InvocationInfo.ScriptName)+'; line='+$_.InvocationInfo.ScriptLineNumber+'; exception_type='+$_.Exception.GetType().Name+'; status='+$taskLastStatus+'; reason='+$taskSafeReason+'; raw response/PII/codes/credentials withheld. No mutations.')
}
finally { $taskClient.Dispose(); $taskHandler.Dispose(); $taskConfig.Clear() }
