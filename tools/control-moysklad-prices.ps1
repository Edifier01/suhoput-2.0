param([ValidateSet('Prices','RemoveOwnPrice','Cleanup')][string]$Phase='Prices')
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'moysklad-control-lib.ps1')
$taskRoot=Split-Path -Parent $PSScriptRoot
$taskCache=Join-Path $taskRoot '.cache/moysklad'
$taskFile=Join-Path $taskCache 'control-manifest.local.json'
$taskConfig=@{}
foreach ($taskLine in [IO.File]::ReadAllLines((Join-Path $taskRoot 'infra/.env.integrations.local'))) {
    if ($taskLine -match '^([A-Z][A-Z0-9_]*)=(.*)$') { $taskConfig[$Matches[1]]=$Matches[2].Trim().Trim('"',"'") }
}
$taskBase='https://api.moysklad.ru/api/remap/1.2'
if (-not $taskConfig.MOYSKLAD_TOKEN -or ($taskConfig.MOYSKLAD_API_BASE_URL -and $taskConfig.MOYSKLAD_API_BASE_URL -cne $taskBase)) { throw 'Invalid integration config; values withheld.' }
foreach ($taskKey in @('MOYSKLAD_ORGANIZATION_ID','MOYSKLAD_WAREHOUSE_ID','MOYSKLAD_RETAIL_PRICE_TYPE_ID','MOYSKLAD_WHOLESALE_PRICE_TYPE_ID')) {
    if ($taskConfig[$taskKey] -notmatch '^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$') { throw 'Invalid selected UUID; values withheld.' }
}
$taskHandler=[Net.Http.HttpClientHandler]::new(); $taskHandler.AllowAutoRedirect=$false
$taskHandler.AutomaticDecompression=[Net.DecompressionMethods]::GZip
$taskClient=[Net.Http.HttpClient]::new($taskHandler); $taskClient.Timeout=[TimeSpan]::FromSeconds(30)
$taskClient.DefaultRequestHeaders.Authorization=[Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer',$taskConfig.MOYSKLAD_TOKEN)
$taskClient.DefaultRequestHeaders.Add('Accept-Encoding','gzip')
$taskRequests=0; $taskLastStatus='not_requested'
function Save-Control {
    Save-ControlAtomic $taskFile $taskManifest
}
function Invoke-ControlRequest([string]$Method,[string]$Path,$Body=$null) {
    if ($Path -notmatch '^/entity/(organization|store|currency|variant|product)(/([0-9a-f-]{36}|metadata))?(\?|$)' -or $Path.Contains('..')) { throw 'Path outside control scope.' }
    if ($Method -cne 'GET' -and $Path -notmatch '^/entity/(product|variant)(/[0-9a-f-]{36})?$') { throw 'Mutation path outside catalog.' }
    Start-Sleep -Milliseconds 500
    $script:taskRequests++; $taskResponse=$null; $taskRequest=$null
    try {
        $taskRequest=[Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::new($Method),$taskBase+$Path)
        if ($null -ne $Body) { $taskRequest.Content=[Net.Http.StringContent]::new(($Body | ConvertTo-Json -Depth 30 -Compress),[Text.Encoding]::UTF8,'application/json') }
        $taskResponse=$taskClient.SendAsync($taskRequest).GetAwaiter().GetResult()
        $script:taskLastStatus=[int]$taskResponse.StatusCode
        if (-not $taskResponse.IsSuccessStatusCode) { return @{ok=$false;status=[int]$taskResponse.StatusCode} }
        $taskText=$taskResponse.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        return @{ok=$true;status=[int]$taskResponse.StatusCode;data=if ($taskText) { $taskText | ConvertFrom-Json -AsHashtable -Depth 100 } else { $null }}
    } catch { $script:taskLastStatus='transport_or_json_error'; return @{ok=$false;status='transport_or_json_error'} }
    finally { if ($taskResponse) { $taskResponse.Dispose() }; if ($taskRequest) { $taskRequest.Dispose() } }
}
function Read-Control([string]$Path) {
    $taskReply=Invoke-ControlRequest 'GET' $Path
    if (-not $taskReply.ok) { throw ('Required read failed; status='+$taskReply.status) }
    return $taskReply.data
}
function New-ControlRef([string]$Entity,[string]$Id) { return @{meta=@{href=$taskBase+'/entity/'+$Entity+'/'+$Id;type=$Entity;mediaType='application/json'}} }
function New-ControlPrices([decimal]$Retail,[decimal]$Wholesale) {
    return @(@{value=$Retail;currency=New-ControlRef 'currency' $taskRub.id;priceType=New-ControlRef 'pricetype' $taskConfig.MOYSKLAD_RETAIL_PRICE_TYPE_ID},@{value=$Wholesale;currency=New-ControlRef 'currency' $taskRub.id;priceType=New-ControlRef 'pricetype' $taskConfig.MOYSKLAD_WHOLESALE_PRICE_TYPE_ID})
}
function Find-Control([string]$Entity,[string]$Code) {
    $taskRows=Read-Control ('/entity/'+$Entity+'?limit=100&filter='+[Uri]::EscapeDataString('externalCode='+$Code))
    if ($null -eq $taskRows.meta.size -or $taskRows.meta.size -ne @($taskRows.rows).Count) { throw 'Locator collection incomplete.' }
    foreach ($taskRow in $taskRows.rows) { if ($taskRow.externalCode -cne $Code) { throw 'Locator mismatch.' } }
    return @($taskRows.rows)
}
function Create-Control([string]$Entity,[string]$Key,$Body) {
    $taskCode=$taskManifest.package+'-'+$Key
    $taskRows=@(Find-Control $Entity $taskCode)
    $taskDecision=Get-ControlCreateDecision $taskManifest.objects[$Key] $taskRows
    if ($taskDecision -ceq 'reuse') { Assert-ControlOwned $taskManifest $Key $taskRows[0]; return $taskRows[0] }
    if ($Entity -ceq 'variant') { Assert-ControlOwned $taskManifest 'P' (Read-Control ('/entity/product/'+$taskManifest.objects.P.id)) }
    if ($taskDecision -ceq 'continue_prepared') { $taskObject=$taskManifest.objects[$Key]; $Body=$taskObject.intention }
    else { $taskObject=@{entity=$Entity;code=$taskCode;id=$null;state='prepared';intention=$Body}; $taskManifest.objects[$Key]=$taskObject; Save-Control }
    Assert-ControlMutation $taskManifest 'POST' $Entity $Key $Body
    $taskObject.state='unknown'; Save-Control # Durable intention BEFORE send, never auto retry.
    $taskReply=Invoke-ControlRequest 'POST' ('/entity/'+$Entity) $Body
    $taskManifest.operations+=@(@{utc=[DateTime]::UtcNow.ToString('o');key=$Key;method='POST';status=$taskReply.status})
    if (-not $taskReply.ok -or -not $taskReply.data.id -or $taskReply.data.externalCode -cne $taskCode) { Save-Control; throw 'Create unconfirmed; reconcile owned intention before any repeat.' }
    $taskObject.id=$taskReply.data.id; $taskObject.state='confirmed'; Save-Control
    return $taskReply.data
}
function Update-Control([string]$Key,$Body) {
    $taskObject=$taskManifest.objects[$Key]
    $taskCurrent=Read-Control ('/entity/'+$taskObject.entity+'/'+$taskObject.id)
    Assert-ControlOwned $taskManifest $Key $taskCurrent
    if ($taskObject.entity -ceq 'variant') { Assert-ControlOwned $taskManifest 'P' (Read-Control ('/entity/product/'+$taskManifest.objects.P.id)) }
    Assert-ControlMutation $taskManifest 'PUT' $taskObject.entity $Key $Body
    $taskObject.pending=@{method='PUT';body=$Body}; Save-Control
    $taskReply=Invoke-ControlRequest 'PUT' ('/entity/'+$taskObject.entity+'/'+$taskObject.id) $Body
    $taskManifest.operations+=@(@{utc=[DateTime]::UtcNow.ToString('o');key=$Key;method='PUT';status=$taskReply.status})
    if (-not $taskReply.ok) { Save-Control; throw 'Update unconfirmed; no automatic repeat.' }
    $taskObject.Remove('pending'); Save-Control
}
function Read-ControlPair([string]$Key) {
    $taskObject=$taskManifest.objects[$Key]
    $taskRow=Read-Control ('/entity/'+$taskObject.entity+'/'+$taskObject.id)
    Assert-ControlOwned $taskManifest $Key $taskRow
    $taskPair=@{}
    foreach ($taskKind in @(@('retail','MOYSKLAD_RETAIL_PRICE_TYPE_ID'),@('wholesale','MOYSKLAD_WHOLESALE_PRICE_TYPE_ID'))) {
        $taskPrices=@($taskRow.salePrices | Where-Object { $_.priceType.id -ceq $taskConfig[$taskKind[1]] })
        if ($taskPrices.Count -ne 1 -or $taskPrices[0].currency.meta.href -cne ($taskBase+'/entity/currency/'+$taskRub.id)) { throw 'Missing/ambiguous selected RUB price.' }
        $taskPair[$taskKind[0]]=$taskPrices[0].value
    }
    return $taskPair
}
try {
    New-Item -ItemType Directory -Force -Path $taskCache | Out-Null
    $taskOrg=Read-Control ('/entity/organization/'+$taskConfig.MOYSKLAD_ORGANIZATION_ID)
    $taskStore=Read-Control ('/entity/store/'+$taskConfig.MOYSKLAD_WAREHOUSE_ID)
    if ($taskOrg.name -cne 'Склад Грозный' -or $taskStore.name -cne 'Основной склад' -or $taskOrg.archived -or $taskStore.archived) { throw 'Selected active organization/store mismatch.' }
    $taskScope=$taskOrg.id+'/'+$taskStore.id+'/'+$taskConfig.MOYSKLAD_RETAIL_PRICE_TYPE_ID+'/'+$taskConfig.MOYSKLAD_WHOLESALE_PRICE_TYPE_ID
    if (Test-Path -LiteralPath $taskFile) {
        $taskManifest=[IO.File]::ReadAllText($taskFile) | ConvertFrom-Json -AsHashtable -Depth 100
        if ($taskManifest.scope -cne $taskScope -or $taskManifest.version -ne 1 -or $taskManifest.package -cne 'MS-PROBE-20261008-A') { throw 'Manifest scope mismatch.' }
    } else {
        if ($Phase -ceq 'Cleanup') { throw 'No manifest to clean.' }
        $taskManifest=@{version=1;package='MS-PROBE-20261008-A';scope=$taskScope;objects=@{};operations=@();evidence=@{}}
        Save-Control
    }
    if ($Phase -ceq 'Cleanup') {
        if ($taskManifest.objects.P.state -ceq 'confirmed') {
            $taskParentRead=Invoke-ControlRequest 'GET' ('/entity/product/'+$taskManifest.objects.P.id)
            if ($taskParentRead.status -eq 404 -and $taskManifest.objects.P.pending.method -ceq 'DELETE') {
                $taskManifest.objects.P.state='deleted'; $taskManifest.objects.P.Remove('pending'); Save-Control
            } else {
                if (-not $taskParentRead.ok) { throw 'Parent cleanup read unknown.' }
                Assert-ControlOwned $taskManifest 'P' $taskParentRead.data
                $taskChildren=Read-Control (Get-ControlVariantPath $taskManifest.objects.P.id)
                if ($null -eq $taskChildren.meta.size -or $taskChildren.meta.size -ne @($taskChildren.rows).Count) { throw 'Child-link collection incomplete; stop cleanup.' }
                Assert-ControlCatalogLinks $taskManifest $taskChildren.rows
            }
        }
        foreach ($taskKey in @('ZERO','OWN','INHERIT','P')) {
            $taskObject=$taskManifest.objects[$taskKey]
            if (-not $taskObject -or $taskObject.state -ceq 'deleted') { continue }
            $taskCurrent=Invoke-ControlRequest 'GET' ('/entity/'+$taskObject.entity+'/'+$taskObject.id)
            if ($taskCurrent.status -eq 404 -and $taskObject.pending.method -ceq 'DELETE') { $taskObject.state='deleted'; $taskObject.Remove('pending'); Save-Control; continue }
            if (-not $taskCurrent.ok -or $taskCurrent.data.externalCode -cne $taskObject.code) { throw 'Cleanup ownership read failed; stop.' }
            Assert-ControlOwned $taskManifest $taskKey $taskCurrent.data
            if ($taskKey -ceq 'P') {
                $taskChildren=Read-Control (Get-ControlVariantPath $taskObject.id)
                if ($null -eq $taskChildren.meta.size -or $taskChildren.meta.size -ne 0 -or @($taskChildren.rows).Count -ne 0) { throw 'Parent still has a child link; stop cleanup.' }
            } else { Assert-ControlOwned $taskManifest 'P' (Read-Control ('/entity/product/'+$taskManifest.objects.P.id)) }
            Assert-ControlMutation $taskManifest 'DELETE' $taskObject.entity $taskKey $null
            $taskObject.pending=@{method='DELETE'}; Save-Control
            $taskReply=Invoke-ControlRequest 'DELETE' ('/entity/'+$taskObject.entity+'/'+$taskObject.id)
            $taskManifest.operations+=@(@{utc=[DateTime]::UtcNow.ToString('o');key=$taskKey;method='DELETE';status=$taskReply.status})
            if (-not $taskReply.ok) { Save-Control; throw 'Delete unconfirmed; stop cleanup for read reconciliation.' }
            $taskCheck=Invoke-ControlRequest 'GET' ('/entity/'+$taskObject.entity+'/'+$taskObject.id)
            if ($taskCheck.status -ne 404) { Save-Control; throw 'Deletion not confirmed by GET.' }
            $taskObject.state='deleted'; $taskObject.Remove('pending'); Save-Control
        }
        $taskManifest.evidence.cleanup_utc=[DateTime]::UtcNow.ToString('o'); Save-Control
        @{result='catalog_cleanup_confirmed';deleted=@($taskManifest.objects.Values | Where-Object { $_.state -ceq 'deleted' }).Count;requests=$taskRequests} | ConvertTo-Json -Compress
        return
    }
    if ($Phase -ceq 'RemoveOwnPrice') {
        if (-not $taskManifest.evidence.prices -or $taskManifest.evidence.after_zero_remove) { throw 'Removal phase requires existing evidence and cannot repeat.' }
        $taskCurrency=Read-Control '/entity/currency?limit=1000'
        $taskRubRows=@($taskCurrency.rows | Where-Object { $_.isoCode -ceq 'RUB' -or $_.code -ceq '643' })
        if ($taskRubRows.Count -ne 1) { throw 'RUB selection ambiguous.' }; $taskRub=$taskRubRows[0]
        $taskPair=Read-ControlPair 'OWN'
        if ($taskPair.retail -ne 1400000 -or $taskPair.wholesale -ne 1250000) { throw 'Own price changed outside control sequence; stop.' }
        Update-Control 'OWN' @{salePrices=New-ControlPrices 0 0}
        $taskManifest.evidence.after_zero_remove=Read-ControlPair 'OWN'
        $taskManifest.evidence.after_zero_remove_utc=[DateTime]::UtcNow.ToString('o'); Save-Control
        @{result='zero_price_removal_observed';prices=$taskManifest.evidence.after_zero_remove;requests=$taskRequests} | ConvertTo-Json -Compress
        return
    }
    if ($taskManifest.evidence.prices) { throw 'Price evidence already recorded; do not repeat.' }
    if ($taskManifest.evidence.before) { throw 'Partial price sequence exists; preserve evidence and reconcile rather than restarting.' }
    $taskCurrency=Read-Control '/entity/currency?limit=1000'
    $taskRubRows=@($taskCurrency.rows | Where-Object { $_.isoCode -ceq 'RUB' -or $_.code -ceq '643' })
    if ($taskRubRows.Count -ne 1) { throw 'RUB selection ambiguous.' }; $taskRub=$taskRubRows[0]
    $taskMetadata=Read-Control '/entity/variant/metadata'
    $taskCharacteristic=@($taskMetadata.characteristics | Where-Object { $_.name -ceq 'цвет' })
    if ($taskCharacteristic.Count -ne 1) { throw 'Existing characteristic not found uniquely.' }
    # Preflight all four locators BEFORE creating any object.
    foreach ($taskItem in @(@('P','product'),@('INHERIT','variant'),@('OWN','variant'),@('ZERO','variant'))) {
        $taskRows=@(Find-Control $taskItem[1] ($taskManifest.package+'-'+$taskItem[0]))
        Get-ControlCreateDecision $taskManifest.objects[$taskItem[0]] $taskRows | Out-Null
    }
    $taskParent=Create-Control 'product' 'P' @{name=$taskManifest.package+'-P';externalCode=$taskManifest.package+'-P';trackingType='NOT_TRACKED';salePrices=New-ControlPrices 1300000 1200000}
    foreach ($taskKey in @('INHERIT','OWN','ZERO')) {
        $taskBody=@{externalCode=$taskManifest.package+'-'+$taskKey;product=New-ControlRef 'product' $taskParent.id;characteristics=@(@{id=$taskCharacteristic[0].id;value=$taskKey})}
        if ($taskKey -ceq 'OWN') { $taskBody.salePrices=New-ControlPrices 1400000 1250000 }
        if ($taskKey -ceq 'ZERO') { $taskBody.salePrices=New-ControlPrices 0 1250000 }
        Create-Control 'variant' $taskKey $taskBody | Out-Null
    }
    $taskBefore=@{}; foreach ($taskKey in @('P','INHERIT','OWN','ZERO')) { $taskBefore[$taskKey]=Read-ControlPair $taskKey }
    $taskManifest.evidence.before=$taskBefore; Save-Control
    Update-Control 'P' @{salePrices=New-ControlPrices 1500000 1350000}
    $taskAfter=@{}; foreach ($taskKey in @('P','INHERIT','OWN','ZERO')) { $taskAfter[$taskKey]=Read-ControlPair $taskKey }
    $taskManifest.evidence.after_parent=$taskAfter; Save-Control
    Update-Control 'OWN' @{salePrices=@()}
    $taskRemoved=Read-ControlPair 'OWN'
    $taskManifest.evidence.after_remove=$taskRemoved
    $taskManifest.evidence.prices=@{checked_utc=[DateTime]::UtcNow.ToString('o');before=$taskBefore;after_parent=$taskAfter;after_remove=$taskRemoved;api='remap/1.2';rub=$true}
    Save-Control
    @{result='price_observations_recorded';requests=$taskRequests;prices=$taskManifest.evidence.prices;cleanup='required_next'} | ConvertTo-Json -Depth 8 -Compress
} catch { throw ('Bounded price control stopped; line='+$_.InvocationInfo.ScriptLineNumber+'; status='+$taskLastStatus+'; details/credentials withheld. Inspect ignored manifest before next mutation.') }
finally { $taskClient.Dispose(); $taskHandler.Dispose(); $taskConfig.Clear() }
