param([switch]$Resume, [ValidateRange(0,100)][int]$StopAfterCatalogPages=0, [ValidateRange(1,500)][int]$MaxDocuments=50)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'moysklad-probe-lib.ps1')
$taskRoot=Split-Path -Parent $PSScriptRoot
$taskCache=Join-Path $taskRoot '.cache/moysklad'
$taskFile=Join-Path $taskCache 'capabilities-checkpoint.local.json'
$taskConfig=@{}
foreach ($taskLine in [IO.File]::ReadAllLines((Join-Path $taskRoot 'infra/.env.integrations.local'))) {
    if ($taskLine -match '^([A-Z][A-Z0-9_]*)=(.*)$') { $taskConfig[$Matches[1]]=$Matches[2].Trim().Trim('"',"'") }
}
$taskBase='https://api.moysklad.ru/api/remap/1.2'
if (-not $taskConfig.MOYSKLAD_TOKEN -or ($taskConfig.MOYSKLAD_API_BASE_URL -and $taskConfig.MOYSKLAD_API_BASE_URL -cne $taskBase)) { throw 'Missing token or unsupported API host; values not printed.' }
foreach ($taskKey in @('MOYSKLAD_WAREHOUSE_ID','MOYSKLAD_ORGANIZATION_ID','MOYSKLAD_RETAIL_PRICE_TYPE_ID','MOYSKLAD_WHOLESALE_PRICE_TYPE_ID')) {
    if ($taskConfig[$taskKey] -notmatch '^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$') { throw 'Missing or invalid selected ID; values not printed.' }
}
$taskHandler=[Net.Http.HttpClientHandler]::new(); $taskHandler.AllowAutoRedirect=$false
$taskHandler.AutomaticDecompression=[Net.DecompressionMethods]::GZip
$taskClient=[Net.Http.HttpClient]::new($taskHandler); $taskClient.Timeout=[TimeSpan]::FromSeconds(30)
$taskClient.DefaultRequestHeaders.Authorization=[Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer',$taskConfig.MOYSKLAD_TOKEN)
$taskClient.DefaultRequestHeaders.Add('Accept-Encoding','gzip')
$taskRequests=0
$taskLastStatus='not_requested'
function Get-ProbeMs([string]$Path) {
    # No response text, headers, redirect location or exception object is logged.
    if ($Path -notmatch '^/entity/(product|variant|store|organization|currency|customerorder|demand|saleschannel|service)(/([0-9a-f-]{36}|metadata)(/positions)?)?(\?|$)' -or $Path.Contains('..')) { throw 'GET path outside probe scope.' }
    Start-Sleep -Milliseconds 500
    $script:taskRequests++
    $taskResponse=$null
    try {
        $taskResponse=$taskClient.GetAsync($taskBase+$Path).GetAwaiter().GetResult()
        $script:taskLastStatus=[int]$taskResponse.StatusCode
        if (-not $taskResponse.IsSuccessStatusCode) { return @{ok=$false;status=[int]$taskResponse.StatusCode} }
        return @{ok=$true;status=[int]$taskResponse.StatusCode;data=($taskResponse.Content.ReadAsStringAsync().GetAwaiter().GetResult() | ConvertFrom-Json -AsHashtable -Depth 100)}
    } catch { $script:taskLastStatus='transport_or_json_error'; return @{ok=$false;status='transport_or_json_error'} }
    finally { if ($null -ne $taskResponse) { $taskResponse.Dispose() } }
}
function Require-ProbeMs([string]$Path) {
    $taskReply=Get-ProbeMs $Path
    if (-not $taskReply.ok) { throw ('Required GET unavailable, status='+$taskReply.status+'; response withheld.') }
    return $taskReply.data
}
function Save-ProbeCheckpoint {
    $taskTmp=$taskFile+'.tmp'
    [IO.File]::WriteAllText($taskTmp,($taskState | ConvertTo-Json -Depth 30),[Text.UTF8Encoding]::new($false))
    [IO.File]::Move($taskTmp,$taskFile,$true)
}
try {
    New-Item -ItemType Directory -Force -Path $taskCache | Out-Null
    $taskStore=Require-ProbeMs ('/entity/store/'+$taskConfig.MOYSKLAD_WAREHOUSE_ID)
    $taskOrg=Require-ProbeMs ('/entity/organization/'+$taskConfig.MOYSKLAD_ORGANIZATION_ID)
    if ($taskStore.name -cne 'Основной склад' -or $taskOrg.name -cne 'Склад Грозный' -or $taskStore.archived -or $taskOrg.archived) { throw 'Selected active organization/warehouse mismatch.' }
    $taskScope=$taskOrg.id+'/'+$taskStore.id+'/'+$taskConfig.MOYSKLAD_RETAIL_PRICE_TYPE_ID+'/'+$taskConfig.MOYSKLAD_WHOLESALE_PRICE_TYPE_ID
    if ($Resume) {
        $taskState=[IO.File]::ReadAllText($taskFile) | ConvertFrom-Json -AsHashtable -Depth 100
        if ($taskState.scope -cne $taskScope -or $taskState.version -ne 1) { throw 'Checkpoint scope/version mismatch.' }
    } else { $taskState=@{version=1;scope=$taskScope;started_utc=[DateTime]::UtcNow.ToString('o');product=New-ProbePageState;variant=New-ProbePageState;products=@{};variants=@{}} }
    $taskThisRunPages=0
    foreach ($taskEntity in @('product','variant')) {
        $taskPageState=$taskState[$taskEntity]
        while ($null -eq $taskPageState.size -or $taskPageState.offset -lt $taskPageState.size) {
            $taskPage=Require-ProbeMs ('/entity/'+$taskEntity+'?limit=1000&offset='+$taskPageState.offset)
            Add-ProbePage $taskPageState $taskPage
            foreach ($taskRow in $taskPage.rows) {
                $taskPrices=@{}
                foreach ($taskPrice in $taskRow.salePrices) {
                    $taskPrices[$taskPrice.priceType.id]=@{value=$taskPrice.value;currency=$taskPrice.currency.meta.href}
                }
                $taskState[$taskEntity+'s'][$taskRow.id]=@{
                    id=$taskRow.id;parent=$taskRow.product.meta.href;prices=$taskPrices;archived=$taskRow.archived
                    images=$taskRow.images.meta.size;trackingType=$taskRow.trackingType
                    characteristics=@($taskRow.characteristics | ForEach-Object { @{id=$_.id;name=$_.name;value=$_.value} })
                }
            }
            Save-ProbeCheckpoint
            $taskThisRunPages++
            if ($StopAfterCatalogPages -gt 0 -and $taskThisRunPages -ge $StopAfterCatalogPages) {
                @{result='checkpoint_stop';catalog_pages_this_process=$taskThisRunPages;requests=$taskRequests;mutations=0} | ConvertTo-Json -Compress
                return
            }
        }
        # Size is checked again after a resume; it still does not prove an atomic snapshot.
        $taskCheck=Require-ProbeMs ('/entity/'+$taskEntity+'?limit=1')
        if ($taskCheck.meta.size -ne $taskPageState.size) { throw 'Catalog size changed; restart probe.' }
    }
    $taskSummary=@{
        checked_utc=[DateTime]::UtcNow.ToString('o');api='remap/1.2';method='GET';mutations=0
        selected_scope_verified=$true;catalog=@{};documents=@{};metadata=@{}
        price_origin='not_proven_by_GET';external_reserve_atomicity='not_proven';permission_check_results='not_proven'
    }
    $taskParents=@{}; $taskCurrencies=@{}; $taskTracking=@{}; $taskCharacteristics=@{}
    foreach ($taskEntity in @('product','variant')) {
        $taskCounters=@{count=$taskState[$taskEntity].ids.Count;pages=$taskState[$taskEntity].pages;with_images=0;retail_13000=0;positive_retail=0;positive_wholesale=0}
        foreach ($taskRow in $taskState[$taskEntity+'s'].Values) {
            if ($taskRow.images -gt 0) { $taskCounters.with_images++ }
            foreach ($taskKind in @(@('retail','MOYSKLAD_RETAIL_PRICE_TYPE_ID'),@('wholesale','MOYSKLAD_WHOLESALE_PRICE_TYPE_ID'))) {
                $taskPrice=$taskRow.prices[$taskConfig[$taskKind[1]]]
                if ($null -ne $taskPrice -and $taskPrice.value -gt 0) { $taskCounters['positive_'+$taskKind[0]]++ }
                if ($taskKind[0] -eq 'retail' -and $taskPrice.value -eq 1300000) { $taskCounters.retail_13000++ }
                if ($taskPrice.currency) { $taskCurrencies[$taskPrice.currency]=$true }
            }
            if ($taskEntity -eq 'variant') {
                $taskParentId=($taskRow.parent -split '/')[-1]
                if (-not $taskState.products.ContainsKey($taskParentId)) { throw 'Variant has no fetched parent.' }
                if (-not $taskParents.ContainsKey($taskParentId)) { $taskParents[$taskParentId]=0 }; $taskParents[$taskParentId]++
                foreach ($taskCharacteristic in $taskRow.characteristics) { if ($taskCharacteristic.id) { $taskCharacteristics[$taskCharacteristic.id]=$taskCharacteristic.name } }
            } elseif ($taskRow.trackingType) {
                if (-not $taskTracking.ContainsKey($taskRow.trackingType)) { $taskTracking[$taskRow.trackingType]=0 }; $taskTracking[$taskRow.trackingType]++
            }
        }
        $taskSummary.catalog[$taskEntity]=$taskCounters
    }
    $taskSummary.catalog.simple_products=$taskState.products.Count-$taskParents.Count
    $taskSummary.catalog.max_variants=($taskParents.Values | Measure-Object -Maximum).Maximum
    $taskSummary.catalog.characteristics=@($taskCharacteristics.Values | Sort-Object -Unique)
    $taskSummary.catalog.tracking_types=$taskTracking
    $taskComparison=@{equal=0;different=0;missing_parent_or_variant=0}
    foreach ($taskVariant in $taskState.variants.Values) {
        $taskParent=$taskState.products[($taskVariant.parent -split '/')[-1]]
        foreach ($taskKey in @('MOYSKLAD_RETAIL_PRICE_TYPE_ID','MOYSKLAD_WHOLESALE_PRICE_TYPE_ID')) {
            $taskV=$taskVariant.prices[$taskConfig[$taskKey]]; $taskP=$taskParent.prices[$taskConfig[$taskKey]]
            if ($null -eq $taskV -or $null -eq $taskP) { $taskComparison.missing_parent_or_variant++ }
            elseif ($taskV.value -eq $taskP.value -and $taskV.currency -ceq $taskP.currency) { $taskComparison.equal++ }
            else { $taskComparison.different++ }
        }
    }
    $taskSummary.catalog.parent_variant_price_pairs=$taskComparison
    $taskCurrencyRows=Require-ProbeMs '/entity/currency?limit=1000'
    $taskRub=@($taskCurrencyRows.rows | Where-Object { $_.isoCode -eq 'RUB' -or $_.code -eq '643' })
    $taskRubHrefs=@($taskRub | ForEach-Object { $_.meta.href })
    $taskSummary.catalog.selected_prices_rub=@($taskCurrencies.Keys | Where-Object { $_ -cnotin $taskRubHrefs }).Count -eq 0 -and $taskCurrencies.Count -gt 0
    $taskFilter=[Uri]::EscapeDataString('organization='+$taskBase+'/entity/organization/'+$taskOrg.id+';store='+$taskBase+'/entity/store/'+$taskStore.id)
    $taskPrivateLocators=@{}
    foreach ($taskEntity in @('customerorder','demand')) {
        $taskReply=Get-ProbeMs ('/entity/'+$taskEntity+'?limit='+$MaxDocuments+'&order=moment,desc&filter='+$taskFilter)
        if (-not $taskReply.ok) { $taskSummary.documents[$taskEntity]=@{status=$taskReply.status;complete=$false}; continue }
        $taskDocs=$taskReply.data
        $taskCounts=@{status=200;total=$taskDocs.meta.size;sampled=@($taskDocs.rows).Count;complete=@($taskDocs.rows).Count -eq $taskDocs.meta.size;positions=0;positive_reserve_positions=0;linked_orders=0;agents=0;codes=@();position_fields=@()}
        $taskAgents=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        $taskFields=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        $taskPrivateLocators[$taskEntity]=@()
        foreach ($taskDoc in $taskDocs.rows) {
            if ($taskDoc.store.meta.href -cne $taskBase+'/entity/store/'+$taskStore.id -or $taskDoc.organization.meta.href -cne $taskBase+'/entity/organization/'+$taskOrg.id) { throw 'Document outside selected scope.' }
            if ($taskDoc.agent.meta.href) { [void]$taskAgents.Add($taskDoc.agent.meta.href) }
            if ($taskDoc.customerOrder.meta.href) { $taskCounts.linked_orders++ }
            $taskPositionState=New-ProbePageState; $taskPositions=@()
            do {
                $taskPage=Require-ProbeMs ('/entity/'+$taskEntity+'/'+$taskDoc.id+'/positions?limit=1000&offset='+$taskPositionState.offset)
                Add-ProbePage $taskPositionState $taskPage
                $taskPositions+=@($taskPage.rows)
            } while ($taskPositionState.offset -lt $taskPositionState.size)
            $taskCounts.positions+=$taskPositions.Count
            $taskCounts.positive_reserve_positions+=@($taskPositions | Where-Object { $_.reserve -gt 0 }).Count
            foreach ($taskPosition in $taskPositions) {
                foreach ($taskField in @('assortment','quantity','price','reserve','shipped','trackingCodes','trackingCodes_1162','things')) { if ($taskPosition.ContainsKey($taskField)) { [void]$taskFields.Add($taskField) } }
            }
            $taskCounts.codes+=@(Get-ProbeCodeEvidence $taskPositions)
            # No names, contact data, document text or raw marking codes are persisted.
            $taskPrivateLocators[$taskEntity]+= @{id=$taskDoc.id;linked_order=$taskDoc.customerOrder.meta.href;position_ids=@($taskPositions | ForEach-Object { $_.id })}
        }
        $taskCounts.agents=$taskAgents.Count; $taskCounts.position_fields=@($taskFields | Sort-Object)
        $taskSummary.documents[$taskEntity]=$taskCounts
        $taskMeta=Get-ProbeMs ('/entity/'+$taskEntity+'/metadata')
        $taskSummary.metadata[$taskEntity]=Get-ProbeMetadataEvidence $taskMeta
    }
    foreach ($taskEntity in @('saleschannel','service')) {
        $taskReply=Get-ProbeMs ('/entity/'+$taskEntity+'?limit=1')
        $taskSummary.metadata[$taskEntity]=@{status=$taskReply.status;total=$taskReply.data.meta.size;chosen='not_selected'}
    }
    $taskSummary.requests=$taskRequests
    [IO.File]::WriteAllText((Join-Path $taskCache 'capabilities.local.json'),($taskSummary | ConvertTo-Json -Depth 20),[Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $taskCache 'document-locators.local.json'),($taskPrivateLocators | ConvertTo-Json -Depth 10),[Text.UTF8Encoding]::new($false))
    # Keep terminal output compact; the private aggregate retains per-document counters.
    $taskOutput=@{checked_utc=$taskSummary.checked_utc;requests=$taskRequests;method='GET';mutations=0;catalog=$taskSummary.catalog;metadata=$taskSummary.metadata;documents=@{};price_origin='not_proven_by_GET';external_reserve_atomicity='not_proven';full_marking_codes='not_proven'}
    foreach ($taskEntity in @('customerorder','demand')) {
        $taskCounts=$taskSummary.documents[$taskEntity]
        $taskOutput.documents[$taskEntity]=@{status=$taskCounts.status;total=$taskCounts.total;sampled=$taskCounts.sampled;positions=$taskCounts.positions;complete=$taskCounts.complete;positive_reserve_positions=$taskCounts.positive_reserve_positions;linked_orders=$taskCounts.linked_orders;unit_codes=($taskCounts.codes.unit_codes | Measure-Object -Sum).Sum;tag1162_codes=($taskCounts.codes.tag1162_codes | Measure-Object -Sum).Sum}
    }
    $taskOutput | ConvertTo-Json -Depth 10 -Compress
} catch { throw ('Read-only capabilities probe failed; line='+$_.InvocationInfo.ScriptLineNumber+'; last_status='+$taskLastStatus+'; secrets, personal data and response text withheld.') }
finally { $taskClient.Dispose(); $taskHandler.Dispose(); $taskConfig.Clear() }
