function Assert-DocumentControl($Manifest,[string]$Method,[string]$Key,$Body) {
    $taskDefinitions=@{SIMPLE=@('product','SIMPLE');CHANNEL=@('saleschannel','CHANNEL');DELIVERY=@('service','DELIVERY');RETAIL_AGENT=@('counterparty','RETAIL');STOCK=@('enter','STOCK');RETAIL=@('customerorder','RETAIL');WHOLESALE=@('customerorder','WHOLESALE');RACE_A=@('customerorder','RACE-A');RACE_B=@('customerorder','RACE-B');SHIP=@('demand','SHIP')}
    $taskDef=$taskDefinitions[$Key]; $taskObject=$Manifest.objects[$Key]
    if ($Manifest.package -cne 'MS-PROBE-20261008-A' -or -not $taskDef -or $taskObject.entity -cne $taskDef[0] -or $taskObject.code -cne ($Manifest.package+'-'+$taskDef[1])) { throw 'Document control object outside approved package.' }
    $taskDocument=$taskDef[0] -cin @('enter','customerorder','demand')
    if ($Method -ceq 'POST') {
        if ($taskObject.state -cne 'prepared' -or $taskObject.id -or $Body.name -cne $taskObject.code -or $Body.externalCode -cne $taskObject.code) { throw 'Only initial prepared create is allowed.' }
        $taskFields=@('name','externalCode')
        if ($Key -ceq 'SIMPLE') { $taskFields+=@('trackingType','salePrices'); if ($Body.trackingType -cne 'NOT_TRACKED') { throw 'Only unmarked product.' } }
        if ($Key -ceq 'DELIVERY') { $taskFields+=@('salePrices') }
        if ($Key -ceq 'CHANNEL') { $taskFields+=@('type'); if ($Body.type -cne 'OTHER') { throw 'Explicit synthetic channel type OTHER required.' } }
        if ($taskDocument) { $taskFields+=@('syncId','organization','store','positions','applicable','agent','salesChannel','customerOrder') }
        if ($taskDocument -and $Body.syncId -notmatch '^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$') { throw 'Stable UUID required before send.' }
    } elseif ($Method -cin @('PUT','DELETE')) {
        if ($taskObject.state -cne 'confirmed' -or $taskObject.pending -or $taskObject.id -notmatch '^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$') { throw 'Mutation requires confirmed owned object without pending operation.' }
        $taskFields=if ($Method -ceq 'DELETE') { @() } elseif ($taskDef[0] -ceq 'customerorder') { @('positions') } elseif ($taskDef[0] -cin @('demand','enter')) { @('applicable') } else { @() }
    } else { throw 'Unsupported method.' }
    if ($null -eq $Body) { if ($Method -cne 'DELETE') { throw 'Mutation body required.' }; return }
    foreach ($taskField in $Body.Keys) { if ($taskField -cnotin $taskFields) { throw 'Unapproved control field.' } }
    if ($taskDocument -and $Method -ceq 'POST') {
        if (-not $Manifest.organization_href -or -not $Manifest.store_href -or -not $Body.organization.meta.href -or -not $Body.store.meta.href -or -not $Body.ContainsKey('positions') -or @($Body.positions).Count -eq 0) { throw 'Nonempty selected scope and complete composition required.' }
        if ($Body.organization.meta.href -cne $Manifest.organization_href -or $Body.store.meta.href -cne $Manifest.store_href) { throw 'Only selected organization/warehouse.' }
        if ($taskDef[0] -cne 'enter') {
            $taskAgent=if ($Key -ceq 'WHOLESALE') { $Manifest.wholesale_href } else { $Manifest.retail_href }
            if (-not $taskAgent -or -not $Manifest.objects.CHANNEL.href -or $Body.agent.meta.href -cne $taskAgent -or $Body.salesChannel.meta.href -cne $Manifest.objects.CHANNEL.href) { throw 'Only approved agent and synthetic channel links.' }
        }
        if ($Key -ceq 'SHIP' -and $Body.customerOrder.meta.href -cne $Manifest.objects.RETAIL.href) { throw 'Only linked synthetic retail shipment.' }
    }
    if ($taskDocument -and $Body.ContainsKey('positions')) {
        $taskLimits=if ($Key -ceq 'STOCK') { @{INHERIT=1;OWN=2;SIMPLE=1} } elseif ($Key -cin @('RACE_A','RACE_B')) { @{SIMPLE=1} } else { @{INHERIT=1;OWN=2;DELIVERY=1} }
        $taskUsed=@{}
        foreach ($taskPosition in $Body.positions) {
            foreach ($taskField in $taskPosition.Keys) { if ($taskField -cnotin @('id','assortment','quantity','price','reserve')) { throw 'Unapproved position field.' } }
            $taskSku=@($taskLimits.Keys | Where-Object { $Manifest.objects[$_].state -ceq 'confirmed' -and $Manifest.objects[$_].href -ceq $taskPosition.assortment.meta.href })
            if ($taskSku.Count -ne 1 -or $taskUsed.ContainsKey($taskSku[0])) { throw 'Foreign/duplicate control assortment.' }
            $taskSku=$taskSku[0]; $taskUsed[$taskSku]=$true
            if ($taskPosition.quantity -ne $taskLimits[$taskSku] -or $null -eq $taskPosition.price -or $taskPosition.price -lt 0 -or $taskPosition.price -gt 1500000) { throw 'Quantity/price outside approved bounds.' }
            if ($Key -ceq 'STOCK' -and $taskPosition.price -ne 100) { throw 'Only approved synthetic cost.' }
            if ($taskSku -ceq 'DELIVERY' -and ($taskPosition.reserve -gt 0 -or $taskPosition.price -ne 50000)) { throw 'Delivery cannot reserve physical stock.' }
            if ($taskDef[0] -ceq 'customerorder' -and (-not $taskPosition.ContainsKey('reserve') -or $null -eq $taskPosition.reserve)) { throw 'Explicit order reserve required.' }
            if ($taskPosition.ContainsKey('reserve') -and ($null -eq $taskPosition.reserve -or $taskPosition.reserve -lt 0 -or $taskPosition.reserve -gt $taskPosition.quantity)) { throw 'Reserve outside approved quantity.' }
        }
        if ($taskUsed.Count -ne $taskLimits.Count) { throw 'Only complete approved composition.' }
    }
}
function Assert-ControlLinkedRows($Manifest,$Rows) {
    $taskIds=@($Manifest.objects.Values | Where-Object { $_.state -ceq 'confirmed' -and $_.id } | ForEach-Object { $_.id })
    foreach ($taskRow in $Rows) { if (-not $taskRow.id -or $taskRow.id -cnotin $taskIds) { throw 'Foreign linked object; stop before cleanup mutations.' } }
}
function Test-ControlRejectedChannel($Saved,$Status,$Rows) {
    return $Saved.entity -ceq 'saleschannel' -and $Saved.state -ceq 'unknown' -and -not $Saved.id -and $Status -eq 412 -and @($Rows).Count -eq 0
}
function Convert-ControlErrors($Errors,$Secrets=@()) {
    foreach ($taskError in $Errors) {
        $taskDescription=[string]$taskError.error
        foreach ($taskSecret in $Secrets) { if ([string]$taskSecret -and ([string]$taskSecret).Length -gt 8) { $taskDescription=$taskDescription.Replace([string]$taskSecret,'[redacted]') } }
        $taskDescription=$taskDescription -replace '(?i)Bearer\s+\S+','Bearer [redacted]' -replace '[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}','[email]' -replace '(?i)[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}','[id]' -replace '(?<!\w)\+?\d[\d ()-]{8,}\d(?!\w)','[number]'
        if ($taskDescription.Length -gt 500) { $taskDescription=$taskDescription.Substring(0,500) }
        $taskResult=@{code=$taskError.code;description=$taskDescription}
        if ($taskError.parameter -cin @('type','name','externalCode','assortment','salesChannel')) { $taskResult.parameter=$taskError.parameter }
        elseif ($taskDescription -match "(?i)['\""«](type|name|externalCode|assortment|salesChannel)['\""»]") { $taskResult.parameter=$Matches[1] }
        $taskResult
    }
}
function Get-ControlStockReadMode($Object,$SavedStock) {
    if ($Object.state -ceq 'confirmed') { return 'live' }
    if ($Object.state -ceq 'deleted') {
        foreach ($taskField in @('stock','reserve','inTransit')) { if ($null -eq $SavedStock[$taskField] -or $SavedStock[$taskField] -ne 0) { throw 'Deleted SKU lacks saved zero-stock evidence.' } }
        return 'skip_deleted'
    }
    throw 'Stock read requires confirmed object.'
}
