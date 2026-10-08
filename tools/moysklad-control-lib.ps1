# Guards shared by the bounded, owner-approved unmarked control run.
function Assert-ControlMutation($Manifest,[string]$Method,[string]$Entity,[string]$Key,$Body) {
    $taskEntities=@{P='product';INHERIT='variant';OWN='variant';ZERO='variant'}
    if ($Manifest.package -cne 'MS-PROBE-20261008-A' -or $taskEntities[$Key] -cne $Entity) { throw 'Mutation outside approved catalog package.' }
    $taskObject=$Manifest.objects[$Key]
    if (-not $taskObject -or $taskObject.entity -cne $Entity -or $taskObject.code -cne ($Manifest.package+'-'+$Key)) { throw 'Object ownership mismatch.' }
    if ($Method -ceq 'POST') {
        if ($taskObject.state -cne 'prepared' -or $taskObject.id -or $Body.externalCode -cne $taskObject.code) { throw 'Create is not a new prepared intention.' }
        $taskAllowed=@('externalCode','salePrices','characteristics','product')
        if ($Entity -ceq 'product') {
            $taskAllowed=@('name','externalCode','trackingType','salePrices')
            if ($Body.name -cne $taskObject.code -or $Body.trackingType -cne 'NOT_TRACKED') { throw 'Only approved unmarked product can be created.' }
        }
    } elseif ($Method -cin @('PUT','DELETE')) {
        if ($taskObject.pending) { throw 'Pending mutation requires read reconciliation, not another mutation.' }
        if ($taskObject.state -cne 'confirmed' -or $taskObject.id -notmatch '^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$') { throw 'Mutation requires a confirmed owned UUID.' }
        $taskAllowed=if ($Method -ceq 'PUT') { @('salePrices') } else { @() }
    } else { throw 'Unsupported mutation method.' }
    if ($null -ne $Body) {
        foreach ($taskField in $Body.Keys) { if ($taskField -cnotin $taskAllowed) { throw 'Unapproved mutation field.' } }
    }
}
function Get-ControlCreateDecision($Saved,$Rows) {
    $taskRows=@($Rows)
    if ($null -eq $Saved) {
        if ($taskRows.Count -eq 0) { return 'create' }
        throw 'Existing locator without owned intention; cannot adopt.'
    }
    if ($Saved.state -ceq 'prepared' -and -not $Saved.id -and -not $Saved.pending -and $Saved.intention -and $taskRows.Count -eq 0) { return 'continue_prepared' }
    if (-not $Saved.pending -and $Saved.state -ceq 'confirmed' -and $Saved.id -and $taskRows.Count -eq 1 -and $taskRows[0].id -ceq $Saved.id) { return 'reuse' }
    throw 'Saved intention requires reconciliation; no second create.'
}
function Assert-ControlOwned($Manifest,[string]$Key,$Row) {
    $taskObject=$Manifest.objects[$Key]
    if (-not $taskObject -or $Row.id -cne $taskObject.id -or $Row.externalCode -cne $taskObject.code) { throw 'Owned object identity changed.' }
    if ($Key -ceq 'P' -and $Row.trackingType -cne 'NOT_TRACKED') { throw 'Owned product no longer unmarked; stop.' }
    if ($taskObject.entity -ceq 'variant' -and $Row.product.meta.href -cne ('https://api.moysklad.ru/api/remap/1.2/entity/product/'+$Manifest.objects.P.id)) { throw 'Variant parent link changed; stop.' }
}
function Assert-ControlCatalogLinks($Manifest,$Rows) {
    $taskOwned=@($Manifest.objects.Values | Where-Object { $_.entity -ceq 'variant' -and $_.state -ceq 'confirmed' } | ForEach-Object { $_.id })
    foreach ($taskRow in $Rows) { if (-not $taskRow.id -or $taskRow.id -cnotin $taskOwned) { throw 'Foreign child link; stop cleanup.' } }
}
function Get-ControlVariantPath([string]$ParentId) {
    if ($ParentId -notmatch '^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$') { throw 'Parent ID must be UUID.' }
    return '/entity/variant?limit=1000&filter='+[Uri]::EscapeDataString('productid='+$ParentId)
}
function Save-ControlAtomic([string]$Path,$Value,[scriptblock]$Commit={param($Source,$Target) [IO.File]::Move($Source,$Target,$true)},[int]$MaxAttempts=10) {
    $taskJson=$Value | ConvertTo-Json -Depth 50
    for ($taskAttempt=1; $taskAttempt -le $MaxAttempts; $taskAttempt++) {
        try {
            [IO.File]::WriteAllText($Path+'.tmp',$taskJson,[Text.UTF8Encoding]::new($false))
            & $Commit ($Path+'.tmp') $Path
            return
        } catch {
            if ($taskAttempt -ge $MaxAttempts -or (-not ($_.Exception -is [IO.IOException]) -and -not ($_.Exception.InnerException -is [IO.IOException]))) { throw }
            Start-Sleep -Milliseconds 100
        }
    }
    throw 'Manifest commit did not complete.'
}
