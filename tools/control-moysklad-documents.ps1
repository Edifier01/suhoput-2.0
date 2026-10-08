param([ValidateSet('RepairChannel','Inspect','Preflight','Prepare','RecoverAgent','Exercise','Cleanup')][string]$Phase='Prepare')
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'moysklad-document-control-lib.ps1')
. (Join-Path $PSScriptRoot 'moysklad-control-lib.ps1')
. (Join-Path $PSScriptRoot 'moysklad-probe-lib.ps1')
$taskRoot=Split-Path -Parent $PSScriptRoot
$taskCache=Join-Path $taskRoot '.cache/moysklad'; $taskFile=Join-Path $taskCache 'control-manifest.local.json'
$taskConfig=@{}
foreach ($taskLine in [IO.File]::ReadAllLines((Join-Path $taskRoot 'infra/.env.integrations.local'))) {
    if ($taskLine -match '^([A-Z][A-Z0-9_]*)=(.*)$') { $taskConfig[$Matches[1]]=$Matches[2].Trim().Trim('"',"'") }
}
$taskBase='https://api.moysklad.ru/api/remap/1.2'
if (-not $taskConfig.MOYSKLAD_TOKEN -or ($taskConfig.MOYSKLAD_API_BASE_URL -and $taskConfig.MOYSKLAD_API_BASE_URL -cne $taskBase)) { throw 'Invalid config; withheld.' }
$taskHandler=[Net.Http.HttpClientHandler]::new(); $taskHandler.AllowAutoRedirect=$false; $taskHandler.AutomaticDecompression=[Net.DecompressionMethods]::GZip
$taskClient=[Net.Http.HttpClient]::new($taskHandler); $taskClient.Timeout=[TimeSpan]::FromSeconds(30)
$taskClient.DefaultRequestHeaders.Authorization=[Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer',$taskConfig.MOYSKLAD_TOKEN)
$taskClient.DefaultRequestHeaders.Add('Accept-Encoding','gzip')
$taskRequests=0; $taskLastStatus='not_requested'
function Save-DocControl {
    Save-ControlAtomic $taskFile $taskManifest
}
function Request-Doc([string]$Method,[string]$Path,$Body=$null) {
    if ($Path -notmatch '^(/entity/(organization|store|currency|product|variant|counterparty|saleschannel|service|enter|customerorder|demand|supply|loss|move|inventory|invoiceout|invoicein|salesreturn|purchasereturn|retaildemand|retailsalesreturn|internalorder|processingorder|paymentin|paymentout|cashin|cashout|prepayment|prepaymentreturn)(/[0-9a-f-]{36}(/positions)?)?|/report/stock/bystore)(\?|$)' -or $Path.Contains('..')) { throw 'Path outside document probe scope.' }
    if ($Method -cne 'GET' -and $Path -notmatch '^/entity/(product|counterparty|saleschannel|service|enter|customerorder|demand)(/[0-9a-f-]{36})?$') { throw 'Mutation path outside scope.' }
    Start-Sleep -Milliseconds 500; $script:taskRequests++; $taskRequest=$null; $taskResponse=$null
    try {
        $taskRequest=[Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::new($Method),$taskBase+$Path)
        if ($null -ne $Body) { $taskRequest.Content=[Net.Http.StringContent]::new(($Body | ConvertTo-Json -Depth 40 -Compress),[Text.Encoding]::UTF8,'application/json') }
        $taskResponse=$taskClient.SendAsync($taskRequest).GetAwaiter().GetResult(); $script:taskLastStatus=[int]$taskResponse.StatusCode
        if (-not $taskResponse.IsSuccessStatusCode) {
            $taskError=$taskResponse.Content.ReadAsStringAsync().GetAwaiter().GetResult() | ConvertFrom-Json -AsHashtable -Depth 50
            $script:taskLastErrors=@(Convert-ControlErrors $taskError.errors $taskConfig.Values)
            $script:taskLastEndpoint=($Path -split '\?')[0]
            return @{ok=$false;status=[int]$taskResponse.StatusCode;error_codes=@($taskError.errors | ForEach-Object { $_.code });errors=$script:taskLastErrors}
        }
        $taskText=$taskResponse.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        return @{ok=$true;status=[int]$taskResponse.StatusCode;data=if ($taskText) { $taskText | ConvertFrom-Json -AsHashtable -Depth 100 } else { $null }}
    } catch { $script:taskLastStatus='transport_or_json_error'; return @{ok=$false;status='transport_or_json_error'} }
    finally { if ($taskResponse) { $taskResponse.Dispose() }; if ($taskRequest) { $taskRequest.Dispose() } }
}
function Read-Doc([string]$Path) { $taskReply=Request-Doc 'GET' $Path; if (-not $taskReply.ok) { $taskManifest.evidence.last_read_error=@{endpoint=($Path -split '\?')[0];status=$taskReply.status;errors=$taskReply.errors}; Save-DocControl; throw 'Required read unavailable.' }; return $taskReply.data }
function Ref-Doc([string]$Entity,[string]$Id) { return @{meta=@{href=$taskBase+'/entity/'+$Entity+'/'+$Id;type=$Entity;mediaType='application/json'}} }
function Find-Doc([string]$Entity,[string]$Code) {
    $taskPage=Read-Doc ('/entity/'+$Entity+'?limit=100&filter='+[Uri]::EscapeDataString('externalCode='+$Code))
    if ($null -eq $taskPage.meta.size -or $taskPage.meta.size -ne @($taskPage.rows).Count) { throw 'Locator collection incomplete.' }
    foreach ($taskRow in $taskPage.rows) { if ($taskRow.externalCode -cne $Code) { throw 'Locator mismatch.' } }
    return @($taskPage.rows)
}
function Read-Positions($Object) {
    $taskPage=Read-Doc ('/entity/'+$Object.entity+'/'+$Object.id+'/positions?limit=1000')
    if ($null -eq $taskPage.meta.size -or $taskPage.meta.size -ne @($taskPage.rows).Count) { throw 'Full positions required.' }
    # Only approved synthetic position fields are retained. No raw code or personal fields.
    return @($taskPage.rows | ForEach-Object {
        # Services have no physical reserve; the API omits this property for delivery.
        # Missing goods reserve and explicit null still remain unknown for strict reconciliation.
        $taskReserve=if ($_.assortment.meta.type -ceq 'service' -and -not $_.ContainsKey('reserve')) { 0 } else { $_.reserve }
        @{id=$_.id;assortment=$_.assortment;quantity=$_.quantity;price=$_.price;reserve=$taskReserve}
    })
}
function Assert-DocRead($Object,$Row) {
    if ($Row.id -cne $Object.id -or $Row.externalCode -cne $Object.code) { throw 'Owned document identity changed.' }
    $taskBody=$Object.intention
    if ($Object.entity -cin @('customerorder','enter','demand')) {
        foreach ($taskField in @('organization','store')) { if (-not $Row[$taskField].meta.href -or $Row[$taskField].meta.href -cne $taskBody[$taskField].meta.href) { throw 'Owned document scope changed.' } }
        if ($Row.syncId -cne $taskBody.syncId) { throw 'Stable document sync ID changed.' }
        if ($Object.entity -cne 'enter' -and ($Row.agent.meta.href -cne $taskBody.agent.meta.href -or $Row.salesChannel.meta.href -cne $taskBody.salesChannel.meta.href)) { throw 'Owned agent/channel links changed.' }
        if ($Object.entity -ceq 'demand' -and $Row.customerOrder.meta.href -cne $taskBody.customerOrder.meta.href) { throw 'Shipment order link changed.' }
        $taskActual=@(Read-Positions $Object | Sort-Object { $_.assortment.meta.href })
        $taskExpected=@($Object.current_positions | Sort-Object { $_.assortment.meta.href })
        if ($taskActual.Count -ne $taskExpected.Count) { throw 'Full composition differs.' }
        for ($taskIndex=0; $taskIndex -lt $taskExpected.Count; $taskIndex++) {
            if ($taskActual[$taskIndex].assortment.meta.href -cne $taskExpected[$taskIndex].assortment.meta.href) { throw 'Assortment differs.' }
            foreach ($taskField in @('quantity','price')) { if ($null -eq $taskActual[$taskIndex][$taskField] -or $taskActual[$taskIndex][$taskField] -ne $taskExpected[$taskIndex][$taskField]) { throw 'Position value differs.' } }
            if ($Object.entity -ceq 'customerorder' -and $taskActual[$taskIndex].reserve -ne $taskExpected[$taskIndex].reserve) { throw 'Reserve differs.' }
        }
    } elseif ($Object.entity -ceq 'product' -and $Row.trackingType -cne 'NOT_TRACKED') { throw 'Test product became marked.' }
    elseif ($Object.entity -ceq 'counterparty' -and ($Row.name -cne $taskBody.name -or $Row.email -or $Row.phone -or $Row.actualAddress -or $Row.legalAddress)) { throw 'Synthetic counterparty changed.' }
}
function Confirm-Doc([string]$Key,$Row) {
    $taskObject=$taskManifest.objects[$Key]
    if (-not $Row.id) { throw 'Read lacks stable ID.' }
    $taskObject.id=$Row.id; Assert-DocRead $taskObject $Row
    $taskObject.state='confirmed'; $taskObject.href=$taskBase+'/entity/'+$taskObject.entity+'/'+$taskObject.id; Save-DocControl
}
function Create-Doc([string]$Entity,[string]$Key,[string]$Suffix,$Body,[switch]$DiscardReply) {
    if ($Entity -cin @('enter','customerorder','demand')) { Assert-LiveSkus }
    $taskRows=@(Find-Doc $Entity ($taskManifest.package+'-'+$Suffix))
    $taskSaved=$taskManifest.objects[$Key]
    if ($taskSaved) {
        $taskDecision=Get-ControlCreateDecision $taskSaved $taskRows
        if ($taskDecision -ceq 'reuse') { Assert-DocRead $taskSaved $taskRows[0]; return }
        $taskObject=$taskSaved; $Body=$taskSaved.intention
    } else {
        if ($taskRows.Count -ne 0) { throw 'Preexisting package object without ownership.' }
        $taskObject=@{entity=$Entity;code=$taskManifest.package+'-'+$Suffix;id=$null;state='prepared';intention=$Body;current_positions=$Body.positions}
        $taskManifest.objects[$Key]=$taskObject; Save-DocControl
    }
    Assert-DocumentControl $taskManifest 'POST' $Key $Body
    $taskObject.state='unknown'; Save-DocControl
    $taskReply=Request-Doc 'POST' ('/entity/'+$Entity) $Body
    $taskManifest.operations+=@(@{utc=[DateTime]::UtcNow.ToString('o');key=$Key;method='POST';status=$taskReply.status;error_codes=$taskReply.error_codes;discarded=[bool]$DiscardReply}); Save-DocControl
    if (-not $taskReply.ok) { throw 'Create unconfirmed; no automatic retry.' }
    if ($DiscardReply) { return } # Intentionally do not retain response ID. Next process must GET.
    Confirm-Doc $Key $taskReply.data
}
function Recover-Doc([string]$Key) {
    $taskObject=$taskManifest.objects[$Key]
    if (-not $taskObject -or $taskObject.state -cne 'unknown') { throw 'No unknown create to reconcile.' }
    $taskRows=@(Find-Doc $taskObject.entity $taskObject.code)
    if ($taskRows.Count -ne 1) { throw 'Missing/ambiguous read does not permit another POST.' }
    Confirm-Doc $Key $taskRows[0]
    $taskManifest.evidence['recovered_'+$Key]=@{utc=[DateTime]::UtcNow.ToString('o');matches=1;post_repeated=$false}; Save-DocControl
}
function Update-Doc([string]$Key,$Body) {
    Assert-LiveSkus
    $taskObject=$taskManifest.objects[$Key]
    Assert-DocRead $taskObject (Read-Doc ('/entity/'+$taskObject.entity+'/'+$taskObject.id))
    Assert-DocumentControl $taskManifest 'PUT' $Key $Body
    $taskObject.pending=@{method='PUT';body=$Body}; Save-DocControl
    $taskReply=Request-Doc 'PUT' ('/entity/'+$taskObject.entity+'/'+$taskObject.id) $Body
    $taskManifest.operations+=@(@{utc=[DateTime]::UtcNow.ToString('o');key=$Key;method='PUT';status=$taskReply.status}); Save-DocControl
    if (-not $taskReply.ok) { throw 'Update unconfirmed; no automatic repeat.' }
    if ($Body.ContainsKey('positions')) { $taskObject.current_positions=$Body.positions }
    $taskObject.Remove('pending'); Save-DocControl
    Assert-DocRead $taskObject (Read-Doc ('/entity/'+$taskObject.entity+'/'+$taskObject.id))
}
function Set-DocReserve([string]$Key,[bool]$Enabled) {
    $taskPositions=@(Read-Positions $taskManifest.objects[$Key])
    foreach ($taskPosition in $taskPositions) { $taskPosition.reserve=if ($Enabled -and $taskPosition.assortment.meta.type -cne 'service') { $taskPosition.quantity } else { 0 } }
    Update-Doc $Key @{positions=$taskPositions}
}
function New-DocPositions([bool]$Reserve,[bool]$Wholesale=$false) {
    $taskRows=@()
    foreach ($taskItem in @(@('INHERIT',1),@('OWN',2),@('DELIVERY',1))) {
        $taskObject=$taskManifest.objects[$taskItem[0]]
        $taskPrice=if ($taskItem[0] -ceq 'DELIVERY') { 50000 } elseif ($Wholesale) { 1350000 } else { 1500000 }
        $taskRows+=@{assortment=Ref-Doc $taskObject.entity $taskObject.id;quantity=$taskItem[1];price=$taskPrice;reserve=if ($Reserve -and $taskItem[0] -cne 'DELIVERY') { $taskItem[1] } else { 0 }}
    }
    return $taskRows
}
function New-DocBody([string]$Suffix,[string]$Agent,$Positions) {
    return @{name=$taskManifest.package+'-'+$Suffix;externalCode=$taskManifest.package+'-'+$Suffix;syncId=[Guid]::NewGuid().ToString();organization=Ref-Doc 'organization' $taskConfig.MOYSKLAD_ORGANIZATION_ID;store=Ref-Doc 'store' $taskConfig.MOYSKLAD_WAREHOUSE_ID;agent=@{meta=@{href=$Agent;type='counterparty';mediaType='application/json'}};salesChannel=Ref-Doc 'saleschannel' $taskManifest.objects.CHANNEL.id;positions=$Positions;applicable=$true}
}
function Read-TestStock([string]$Label) {
    $taskResult=@{}
    foreach ($taskKey in @('INHERIT','OWN','SIMPLE')) {
        $taskObject=$taskManifest.objects[$taskKey]
        $taskSavedZero=$null
        if ($taskManifest.evidence.cleanup_stock -and $taskManifest.evidence.cleanup_stock.stock) { $taskSavedZero=$taskManifest.evidence.cleanup_stock.stock[$taskKey] }
        if ((Get-ControlStockReadMode $taskObject $taskSavedZero) -ceq 'skip_deleted') { $taskResult[$taskKey]=$taskSavedZero; continue }
        $taskFilter='store='+$taskManifest.store_href+';stockMode=all;'+$taskObject.entity+'='+$taskObject.href
        $taskPage=Read-Doc ('/report/stock/bystore?limit=1000&filter='+[Uri]::EscapeDataString($taskFilter))
        if ($null -eq $taskPage.meta.size -or $taskPage.meta.size -ne 1 -or @($taskPage.rows).Count -ne 1 -or (($taskPage.rows[0].meta.href -split '\?')[0]) -cne $taskObject.href) { throw 'Exact test SKU stock row unavailable.' }
        $taskStores=@($taskPage.rows[0].stockByStore)
        if ($taskStores.Count -ne 1 -or $taskStores[0].meta.href -cne $taskManifest.store_href -or $null -eq $taskStores[0].stock -or $null -eq $taskStores[0].reserve -or $null -eq $taskStores[0].inTransit) { throw 'Selected-store stock fields incomplete.' }
        $taskResult[$taskKey]=@{stock=$taskStores[0].stock;reserve=$taskStores[0].reserve;inTransit=$taskStores[0].inTransit;available=$taskStores[0].stock-$taskStores[0].reserve}
    }
    $taskManifest.evidence[$Label]=@{utc=[DateTime]::UtcNow.ToString('o');stock=$taskResult}; Save-DocControl
    return $taskResult
}
function Delete-Doc([string]$Key) {
    $taskObject=$taskManifest.objects[$Key]
    if (-not $taskObject -or $taskObject.state -ceq 'deleted') { return }
    if ($taskObject.state -ceq 'rejected') {
        if (@(Find-Doc $taskObject.entity $taskObject.code).Count -ne 0) { throw 'Rejected locator now exists; stop.' }
        return # No confirmed target exists; no DELETE and no POST.
    }
    $taskReply=Request-Doc 'GET' ('/entity/'+$taskObject.entity+'/'+$taskObject.id)
    if ($taskReply.status -eq 404 -and $taskObject.pending.method -ceq 'DELETE') { $taskObject.state='deleted'; $taskObject.Remove('pending'); Save-DocControl; return }
    if (-not $taskReply.ok) { throw 'Cleanup read unknown.' }
    Assert-DocRead $taskObject $taskReply.data; Assert-DocumentControl $taskManifest 'DELETE' $Key $null
    $taskObject.pending=@{method='DELETE'}; Save-DocControl
    $taskReply=Request-Doc 'DELETE' ('/entity/'+$taskObject.entity+'/'+$taskObject.id)
    $taskManifest.operations+=@(@{utc=[DateTime]::UtcNow.ToString('o');key=$Key;method='DELETE';status=$taskReply.status}); Save-DocControl
    if (-not $taskReply.ok) { throw 'Delete unconfirmed; stop.' }
    $taskRead=Request-Doc 'GET' ('/entity/'+$taskObject.entity+'/'+$taskObject.id)
    if ($taskRead.status -ne 404) { throw 'Deletion not confirmed.' }
    $taskObject.state='deleted'; $taskObject.Remove('pending'); Save-DocControl
}
function Assert-LiveSkus {
    foreach ($taskKey in @('P','INHERIT','OWN','ZERO','SIMPLE')) {
        $taskObject=$taskManifest.objects[$taskKey]
        if (-not $taskObject -or $taskObject.state -ceq 'deleted') { continue }
        if ($taskObject.state -cne 'confirmed') { throw 'Test SKU is not confirmed.' }
        $taskRow=Read-Doc ('/entity/'+$taskObject.entity+'/'+$taskObject.id)
        if ($taskKey -ceq 'SIMPLE') {
            if ($taskRow.id -cne $taskObject.id -or $taskRow.externalCode -cne $taskObject.code -or $taskRow.trackingType -cne 'NOT_TRACKED') { throw 'Simple test SKU identity/marking changed.' }
        } else { Assert-ControlOwned $taskManifest $taskKey $taskRow }
    }
}
function Read-CompleteLinks([string]$Entity,[string]$Filter) {
    $taskPage=Read-Doc ('/entity/'+$Entity+'?limit=1000&filter='+[Uri]::EscapeDataString($Filter))
    if ($null -eq $taskPage.meta.size -or $taskPage.meta.size -ne @($taskPage.rows).Count) { throw 'Linked graph incomplete; stop cleanup.' }
    Assert-ControlLinkedRows $taskManifest $taskPage.rows
}
function Read-ChannelLinks([string]$Entity) {
    # Some document families expose salesChannel but do not support that filter.
    # Enumerate the complete collection with strict pagination, then select exact href locally.
    $taskPageState=New-ProbePageState
    do {
        $taskPage=Read-Doc ('/entity/'+$Entity+'?limit=1000&offset='+$taskPageState.offset)
        Add-ProbePage $taskPageState $taskPage
        $taskLinked=@($taskPage.rows | Where-Object { $_.salesChannel.meta.href -ceq $taskManifest.objects.CHANNEL.href })
        Assert-ControlLinkedRows $taskManifest $taskLinked
    } while ($taskPageState.offset -lt $taskPageState.size)
}
function Assert-CleanupGraph {
    Assert-LiveSkus
    if ($taskManifest.objects.SIMPLE.state -ceq 'confirmed') {
        $taskChildren=Read-Doc (Get-ControlVariantPath $taskManifest.objects.SIMPLE.id)
        if ($null -eq $taskChildren.meta.size -or $taskChildren.meta.size -ne 0 -or @($taskChildren.rows).Count -ne 0) { throw 'Foreign child of SIMPLE; stop cleanup.' }
    }
    # Search every supported stock/order document family for references to new synthetic SKUs.
    # Any unsupported/denied/incomplete GET stops cleanup before the first mutation.
    foreach ($taskSku in @('P','INHERIT','OWN','ZERO','SIMPLE','DELIVERY')) {
        $taskObject=$taskManifest.objects[$taskSku]
        if (-not $taskObject -or $taskObject.state -ceq 'deleted') { continue }
        foreach ($taskEntity in @('customerorder','demand','enter','supply','loss','move','inventory','invoiceout','invoicein','salesreturn','purchasereturn','retaildemand','retailsalesreturn','internalorder','processingorder')) {
            Read-CompleteLinks $taskEntity ('assortment='+$taskObject.href)
        }
    }
    if ($taskManifest.objects.RETAIL_AGENT.state -ceq 'confirmed') {
        foreach ($taskEntity in @('customerorder','demand','supply','invoiceout','invoicein','salesreturn','purchasereturn','paymentin','paymentout','cashin','cashout','prepayment','prepaymentreturn')) { Read-CompleteLinks $taskEntity ('agent='+$taskManifest.objects.RETAIL_AGENT.href) }
    }
    if ($taskManifest.objects.CHANNEL.state -ceq 'confirmed' -and -not $taskManifest.objects.CHANNEL.existing_reference) {
        foreach ($taskEntity in @('customerorder','demand')) { Read-CompleteLinks $taskEntity ('salesChannel='+$taskManifest.objects.CHANNEL.href) }
        foreach ($taskEntity in @('retaildemand','retailsalesreturn','salesreturn')) { Read-ChannelLinks $taskEntity }
    }
    foreach ($taskKey in @('STOCK','RETAIL','WHOLESALE','RACE_A','RACE_B','SHIP')) {
        $taskObject=$taskManifest.objects[$taskKey]
        if (-not $taskObject -or $taskObject.state -ceq 'deleted') { continue }
        $taskRow=Read-Doc ('/entity/'+$taskObject.entity+'/'+$taskObject.id)
        foreach ($taskField in @('demands','payments','purchaseOrders','productionTasks','invoicesOut','moves','prepayments','salesReturns','supplies','invoicesIn')) {
            foreach ($taskLink in @($taskRow[$taskField] | Where-Object { $null -ne $_ })) {
                Assert-ControlLinkedRows $taskManifest @(@{id=($taskLink.meta.href -split '/')[-1]})
            }
        }
    }
}
try {
    $taskManifest=[IO.File]::ReadAllText($taskFile) | ConvertFrom-Json -AsHashtable -Depth 100
    $taskScope=$taskConfig.MOYSKLAD_ORGANIZATION_ID+'/'+$taskConfig.MOYSKLAD_WAREHOUSE_ID+'/'+$taskConfig.MOYSKLAD_RETAIL_PRICE_TYPE_ID+'/'+$taskConfig.MOYSKLAD_WHOLESALE_PRICE_TYPE_ID
    if ($taskManifest.scope -cne $taskScope -or $taskManifest.package -cne 'MS-PROBE-20261008-A' -or $taskManifest.version -ne 1) { throw 'Manifest scope mismatch.' }
    $taskOrg=Read-Doc ('/entity/organization/'+$taskConfig.MOYSKLAD_ORGANIZATION_ID); $taskStore=Read-Doc ('/entity/store/'+$taskConfig.MOYSKLAD_WAREHOUSE_ID)
    if ($taskOrg.name -cne 'Склад Грозный' -or $taskStore.name -cne 'Основной склад' -or $taskOrg.archived -or $taskStore.archived) { throw 'Selected org/store changed.' }
    $taskManifest.organization_href=$taskBase+'/entity/organization/'+$taskOrg.id; $taskManifest.store_href=$taskBase+'/entity/store/'+$taskStore.id
    $taskChoices=[IO.File]::ReadAllText((Join-Path $taskCache 'control-choices.local.json')) | ConvertFrom-Json -AsHashtable
    if ($taskChoices.wholesale_counterparty_id -notmatch '^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$' -or -not $taskChoices.automations_confirmed) { throw 'Owner reference and automation confirmation required.' }
    $taskWholesale=Read-Doc ('/entity/counterparty/'+$taskChoices.wholesale_counterparty_id)
    if ($taskWholesale.id -cne $taskChoices.wholesale_counterparty_id -or $taskWholesale.archived) { throw 'Selected active wholesale reference unavailable.' }
    $taskManifest.wholesale_href=$taskBase+'/entity/counterparty/'+$taskWholesale.id; Save-DocControl
    if ($Phase -ceq 'RepairChannel') {
        $taskPrevious=$taskManifest.objects.CHANNEL
        if ($taskPrevious.state -cne 'rejected' -or $taskPrevious.id) { throw 'Only read-confirmed rejected channel attempt can be retried by explicit owner instruction.' }
        if (@(Find-Doc 'saleschannel' $taskPrevious.code).Count -ne 0) { throw 'Duplicate channel exists; do not POST.' }
        $taskManifest.channel_attempts=@($taskManifest.channel_attempts | Where-Object { $null -ne $_ })+@($taskPrevious)
        $taskBody=@{name=$taskManifest.package+'-CHANNEL';externalCode=$taskManifest.package+'-CHANNEL';type='OTHER'}
        $taskManifest.objects.Remove('CHANNEL'); Save-DocControl
        Create-Doc 'saleschannel' 'CHANNEL' 'CHANNEL' $taskBody
        @{result='corrected_test_channel_created';requests=$taskRequests;type='OTHER'} | ConvertTo-Json -Compress; return
    }
    if ($Phase -ceq 'Preflight') {
        Assert-CleanupGraph
        $taskManifest.evidence.cleanup_preflight=@{utc=[DateTime]::UtcNow.ToString('o');requests=$taskRequests;foreign_links=0}; Save-DocControl
        @{result='cleanup_graph_preflight_confirmed';requests=$taskRequests;mutations=0;foreign_links=0} | ConvertTo-Json -Compress; return
    }
    if ($Phase -ceq 'Inspect') {
        $taskFindings=@()
        foreach ($taskEntry in $taskManifest.objects.GetEnumerator()) {
            if ($taskEntry.Value.state -ceq 'unknown') {
                $taskRows=@(Find-Doc $taskEntry.Value.entity $taskEntry.Value.code)
                $taskFindings+=@{key=$taskEntry.Key;matches=$taskRows.Count}
                if ($taskEntry.Value.entity -ceq 'customerorder' -and $taskRows.Count -eq 1) {
                    $taskRawPositions=Read-Doc ('/entity/customerorder/'+$taskRows[0].id+'/positions?limit=1000')
                    $taskFindings[-1].position_shapes=@($taskRawPositions.rows | ForEach-Object { @{assortment_type=$_.assortment.meta.type;quantity=$_.quantity;price=$_.price;reserve_present=$_.ContainsKey('reserve');reserve=$_.reserve} })
                }
                $taskLastPost=@($taskManifest.operations | Where-Object { $_.key -ceq $taskEntry.Key -and $_.method -ceq 'POST' } | Select-Object -Last 1)
                if ($taskLastPost.Count -eq 1 -and (Test-ControlRejectedChannel $taskEntry.Value $taskLastPost[0].status $taskRows)) { $taskEntry.Value.state='rejected' }
            }
        }
        $taskChannels=Read-Doc '/entity/saleschannel?limit=1000'
        if ($null -eq $taskChannels.meta.size -or $taskChannels.meta.size -ne @($taskChannels.rows).Count) { throw 'Channel collection incomplete.' }
        $taskManifest.evidence.inspection=@{utc=[DateTime]::UtcNow.ToString('o');unknown=$taskFindings;channels=@($taskChannels.rows | ForEach-Object { @{id=$_.id;archived=$_.archived} })}; Save-DocControl
        @{result='read_only_inspection';unknown=$taskFindings;active_channels=@($taskChannels.rows | Where-Object { -not $_.archived }).Count;mutations=0;requests=$taskRequests} | ConvertTo-Json -Depth 6 -Compress; return
    }
    if ($Phase -ceq 'Prepare') {
        if ($taskManifest.objects.RETAIL_AGENT -and $taskManifest.objects.RETAIL_AGENT.state -cne 'prepared') { throw 'Prepare already sent; do not repeat.' }
        foreach ($taskKey in @('P','INHERIT','OWN','ZERO')) {
            $taskObject=$taskManifest.objects[$taskKey]; $taskRow=Read-Doc ('/entity/'+$taskObject.entity+'/'+$taskObject.id); Assert-ControlOwned $taskManifest $taskKey $taskRow
            $taskObject.href=$taskBase+'/entity/'+$taskObject.entity+'/'+$taskObject.id
        }
        $taskCurrency=Read-Doc '/entity/currency?limit=1000'; $taskRub=@($taskCurrency.rows | Where-Object { $_.isoCode -ceq 'RUB' -or $_.code -ceq '643' })
        if ($taskRub.Count -ne 1) { throw 'RUB ambiguous.' }
        $taskPrice=@(@{value=1300000;currency=Ref-Doc 'currency' $taskRub[0].id;priceType=Ref-Doc 'pricetype' $taskConfig.MOYSKLAD_RETAIL_PRICE_TYPE_ID},@{value=1200000;currency=Ref-Doc 'currency' $taskRub[0].id;priceType=Ref-Doc 'pricetype' $taskConfig.MOYSKLAD_WHOLESALE_PRICE_TYPE_ID})
        Create-Doc 'product' 'SIMPLE' 'SIMPLE' @{name=$taskManifest.package+'-SIMPLE';externalCode=$taskManifest.package+'-SIMPLE';trackingType='NOT_TRACKED';salePrices=$taskPrice}
        Create-Doc 'saleschannel' 'CHANNEL' 'CHANNEL' @{name=$taskManifest.package+'-CHANNEL';externalCode=$taskManifest.package+'-CHANNEL';type='OTHER'}
        Create-Doc 'service' 'DELIVERY' 'DELIVERY' @{name=$taskManifest.package+'-DELIVERY';externalCode=$taskManifest.package+'-DELIVERY';salePrices=@(@{value=50000;currency=Ref-Doc 'currency' $taskRub[0].id;priceType=Ref-Doc 'pricetype' $taskConfig.MOYSKLAD_RETAIL_PRICE_TYPE_ID})}
        Create-Doc 'counterparty' 'RETAIL_AGENT' 'RETAIL' @{name=$taskManifest.package+'-RETAIL';externalCode=$taskManifest.package+'-RETAIL'} -DiscardReply
        @{result='agent_response_intentionally_discarded';next='RecoverAgent in new process';requests=$taskRequests} | ConvertTo-Json -Compress; return
    }
    if ($Phase -ceq 'RecoverAgent') {
        if ($taskManifest.objects.RETAIL) { throw 'Retail create already prepared/sent; reconcile in Exercise, never repeat this phase.' }
        if ($taskManifest.objects.STOCK -and $taskManifest.objects.STOCK.state -cnotin @('prepared','confirmed')) { throw 'Stock create unresolved; no repeat.' }
        if ($taskManifest.objects.RETAIL_AGENT.state -ceq 'unknown') { Recover-Doc 'RETAIL_AGENT' }
        elseif ($taskManifest.objects.RETAIL_AGENT.state -ceq 'confirmed') { Assert-DocRead $taskManifest.objects.RETAIL_AGENT (Read-Doc ('/entity/counterparty/'+$taskManifest.objects.RETAIL_AGENT.id)) }
        else { throw 'Retail agent not confirmed.' }
        $taskManifest.retail_href=$taskManifest.objects.RETAIL_AGENT.href; Save-DocControl
        $taskStockPositions=@(); foreach ($taskItem in @(@('INHERIT',1),@('OWN',2),@('SIMPLE',1))) { $taskObject=$taskManifest.objects[$taskItem[0]]; $taskStockPositions+=@{assortment=Ref-Doc $taskObject.entity $taskObject.id;quantity=$taskItem[1];price=100} }
        Create-Doc 'enter' 'STOCK' 'STOCK' @{name=$taskManifest.package+'-STOCK';externalCode=$taskManifest.package+'-STOCK';syncId=[Guid]::NewGuid().ToString();organization=Ref-Doc 'organization' $taskOrg.id;store=Ref-Doc 'store' $taskStore.id;positions=$taskStockPositions;applicable=$true}
        if (-not $taskManifest.evidence.after_enter) { Read-TestStock 'after_enter' | Out-Null }
        if ($taskManifest.objects.WHOLESALE.state -ceq 'unknown') { Recover-Doc 'WHOLESALE' }
        else { Create-Doc 'customerorder' 'WHOLESALE' 'WHOLESALE' (New-DocBody 'WHOLESALE' $taskManifest.wholesale_href (New-DocPositions $false $true)) }
        Create-Doc 'customerorder' 'RETAIL' 'RETAIL' (New-DocBody 'RETAIL' $taskManifest.retail_href (New-DocPositions $true)) -DiscardReply
        @{result='order_response_intentionally_discarded';next='Exercise in new process';requests=$taskRequests} | ConvertTo-Json -Compress; return
    }
    if ($Phase -ceq 'Exercise') {
        if ($taskManifest.evidence.after_ship -or $taskManifest.objects.SHIP) { throw 'Exercise already executed; do not repeat.' }
        Recover-Doc 'RETAIL'
        $taskRetail=$taskManifest.objects.RETAIL
        # Approved protocol experiment: only AFTER full read confirmation, same immutable syncId/payload.
        Assert-LiveSkus
        $taskReplay=Request-Doc 'POST' '/entity/customerorder' $taskRetail.intention
        $taskManifest.operations+=@(@{utc=[DateTime]::UtcNow.ToString('o');key='RETAIL';method='POST';status=$taskReplay.status;confirmed_replay=$true}); Save-DocControl
        if (-not $taskReplay.ok -or $taskReplay.data.id -cne $taskRetail.id) { throw 'Replay did not confirm same document; stop.' }
        Assert-DocRead $taskRetail $taskReplay.data
        $taskRows=@(Find-Doc 'customerorder' $taskRetail.code); if ($taskRows.Count -ne 1) { throw 'Replay duplicated document.' }
        $taskManifest.evidence.syncid_replay=@{same_id=$true;matches=1;utc=[DateTime]::UtcNow.ToString('o')}; Save-DocControl
        Read-TestStock 'full_retail_reserve' | Out-Null
        Set-DocReserve 'RETAIL' $false; Read-TestStock 'retail_released' | Out-Null
        Set-DocReserve 'WHOLESALE' $true; Read-TestStock 'full_wholesale_reserve' | Out-Null
        Set-DocReserve 'WHOLESALE' $false; Set-DocReserve 'RETAIL' $true; Read-TestStock 'retail_reacquired' | Out-Null
        $taskShip=New-DocBody 'SHIP' $taskManifest.retail_href (New-DocPositions $true)
        $taskShip.customerOrder=Ref-Doc 'customerorder' $taskRetail.id
        Create-Doc 'demand' 'SHIP' 'SHIP' $taskShip
        Read-TestStock 'after_ship' | Out-Null
        # Reservation of the last unit: prepare durable intentions before dispatching both requests.
        $taskStock=Read-TestStock 'before_race'; if ($taskStock.SIMPLE.stock -ne 1 -or $taskStock.SIMPLE.reserve -ne 0) { throw 'Race requires exactly one free synthetic unit.' }
        $taskRaceRequests=@(); $taskRacePending=@()
        foreach ($taskItem in @(@('RACE_A','RACE-A'),@('RACE_B','RACE-B'))) {
            $taskKey=$taskItem[0]; $taskRows=@(Find-Doc 'customerorder' ($taskManifest.package+'-'+$taskItem[1])); if ($taskRows.Count -ne 0 -or $taskManifest.objects[$taskKey]) { throw 'Race locator already exists.' }
            $taskBody=New-DocBody $taskItem[1] $taskManifest.retail_href @(@{assortment=Ref-Doc 'product' $taskManifest.objects.SIMPLE.id;quantity=1;price=1300000;reserve=1})
            $taskManifest.objects[$taskKey]=@{entity='customerorder';code=$taskBody.externalCode;state='prepared';id=$null;intention=$taskBody;current_positions=$taskBody.positions}
            Assert-LiveSkus; Assert-DocumentControl $taskManifest 'POST' $taskKey $taskBody
            $taskManifest.objects[$taskKey].state='unknown'; Save-DocControl
            $taskRequest=[Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Post,$taskBase+'/entity/customerorder')
            $taskRequest.Content=[Net.Http.StringContent]::new(($taskBody | ConvertTo-Json -Depth 30 -Compress),[Text.Encoding]::UTF8,'application/json')
            $taskRaceRequests+=@(@{key=$taskKey;request=$taskRequest})
        }
        foreach ($taskItem in $taskRaceRequests) { $taskRacePending+=@(@{key=$taskItem.key;future=$taskClient.SendAsync($taskItem.request)}); $taskRequests++ }
        foreach ($taskItem in $taskRacePending) {
            $taskResponse=$null
            try {
                $taskResponse=$taskItem.future.GetAwaiter().GetResult()
                $taskManifest.operations+=@(@{utc=[DateTime]::UtcNow.ToString('o');key=$taskItem.key;method='POST';status=[int]$taskResponse.StatusCode;concurrent=$true}); Save-DocControl
                if (-not $taskResponse.IsSuccessStatusCode) { throw 'Race create not confirmed; reconcile before cleanup.' }
                $taskRow=$taskResponse.Content.ReadAsStringAsync().GetAwaiter().GetResult() | ConvertFrom-Json -AsHashtable -Depth 100
                Confirm-Doc $taskItem.key $taskRow
            } finally { if ($taskResponse) { $taskResponse.Dispose() } }
        }
        foreach ($taskItem in $taskRaceRequests) { $taskItem.request.Dispose() }
        Read-TestStock 'after_race' | Out-Null
        Set-DocReserve 'RACE_A' $false; Set-DocReserve 'RACE_B' $false; Read-TestStock 'race_released' | Out-Null
        @{result='document_observations_recorded';requests=$taskRequests;stock=@{retail=$taskManifest.evidence.full_retail_reserve.stock;released=$taskManifest.evidence.retail_released.stock;wholesale=$taskManifest.evidence.full_wholesale_reserve.stock;shipped=$taskManifest.evidence.after_ship.stock;race=$taskManifest.evidence.after_race.stock};syncid_replay=$taskManifest.evidence.syncid_replay;cleanup='required_next'} | ConvertTo-Json -Depth 8 -Compress; return
    }
    # Cleanup only registered synthetic documents, then verify zero before deleting references.
    # Reconcile a lost DELETE before any PUT/preflight that would require that object to exist.
    foreach ($taskKey in @('SHIP','RACE_A','RACE_B','RETAIL','WHOLESALE','STOCK','DELIVERY','CHANNEL','RETAIL_AGENT','SIMPLE')) {
        if ($taskManifest.objects[$taskKey].pending.method -ceq 'DELETE') { Delete-Doc $taskKey }
    }
    Assert-CleanupGraph
    if ($taskManifest.objects.SHIP.state -ceq 'confirmed') { Update-Doc 'SHIP' @{applicable=$false}; Delete-Doc 'SHIP' }
    foreach ($taskKey in @('RACE_A','RACE_B','RETAIL','WHOLESALE')) {
        if ($taskManifest.objects[$taskKey].state -ceq 'confirmed') { Set-DocReserve $taskKey $false }
        Delete-Doc $taskKey
    }
    if ($taskManifest.objects.STOCK.state -ceq 'confirmed') { Update-Doc 'STOCK' @{applicable=$false}; Delete-Doc 'STOCK' }
    $taskStock=Read-TestStock 'cleanup_stock'
    foreach ($taskSku in $taskStock.Values) { if ($taskSku.stock -ne 0 -or $taskSku.reserve -ne 0 -or $taskSku.inTransit -ne 0) { throw 'Nonzero test stock/reserve/transit; stop reference cleanup.' } }
    foreach ($taskKey in @('DELIVERY','CHANNEL','RETAIL_AGENT','SIMPLE')) { Delete-Doc $taskKey }
    $taskManifest.evidence.document_cleanup_utc=[DateTime]::UtcNow.ToString('o'); Save-DocControl
    @{result='document_cleanup_confirmed';requests=$taskRequests;stock_zero=$true;deleted=@($taskManifest.objects.Values | Where-Object { $_.state -ceq 'deleted' }).Count} | ConvertTo-Json -Compress
} catch {
    $taskSafeFailure=@(Convert-ControlErrors @(@{error=$_.Exception.Message}) $taskConfig.Values)[0].description
    throw ('Bounded document control stopped; source='+[IO.Path]::GetFileName($_.InvocationInfo.ScriptName)+'; line='+$_.InvocationInfo.ScriptLineNumber+'; exception_type='+$_.Exception.GetType().Name+'; status='+$taskLastStatus+'; reason='+$taskSafeFailure+'; response/PII/credentials withheld. Reconcile ignored manifest before next mutation.')
}
finally { $taskClient.Dispose(); $taskHandler.Dispose(); $taskConfig.Clear() }
