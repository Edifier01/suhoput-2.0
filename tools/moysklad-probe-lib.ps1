# Pure analyzers for early probes; these do not authorize or execute API writes.
function New-ProbePageState { return @{offset=0;size=$null;ids=@();pages=0} }
function Add-ProbePage($State, $Page) {
    if ($null -eq $Page.meta.size -or $Page.meta.size -lt 0 -or [decimal]$Page.meta.size -ne [decimal]::Truncate([decimal]$Page.meta.size)) { throw 'Missing or invalid collection size.' }
    $taskSize = [int]$Page.meta.size
    if ($null -ne $Page.meta.offset -and $Page.meta.offset -ne $State.offset) { throw 'Response offset differs from requested checkpoint.' }
    if ($null -ne $State.size -and $State.size -ne $taskSize) { throw 'Collection size changed; restart read.' }
    $taskRows = @($Page.rows)
    if ($taskRows.Count -eq 0 -and $State.offset -lt $taskSize) { throw 'Empty intermediate page.' }
    $taskIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($taskId in $State.ids) { [void]$taskIds.Add($taskId) }
    foreach ($taskRow in $taskRows) {
        if (-not $taskRow.id -or -not $taskIds.Add([string]$taskRow.id)) { throw 'Missing or duplicate ID.' }
    }
    if ($State.offset + $taskRows.Count -gt $taskSize) { throw 'Collection count exceeded size.' }
    $State.size=$taskSize; $State.offset += $taskRows.Count; $State.ids=@($taskIds); $State.pages++
}
function Get-ProbeCodeEvidence($Positions) {
    $taskResult = @{
        positions=0; unit_codes=0; packages=0; unexpanded_packages=0; duplicate_codes=0
        gs_codes=0; crypto_candidates=0; tag1162_codes=0; unknown_code_types=0
        quantity_matches=0; quantity_mismatches=0; missing_variant_or_position=0
        positions_without_codes=0; full_code_proven=$false; lengths=@{}
    }
    $taskSeen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($taskPosition in $Positions) {
        $taskResult.positions++
        if (-not $taskPosition.id -or -not $taskPosition.assortment.meta.href) { $taskResult.missing_variant_or_position++ }
        $taskUnits=0
        $taskQueue=[Collections.Generic.Queue[object]]::new()
        foreach ($taskNode in @($taskPosition.trackingCodes)) { if ($null -ne $taskNode) { $taskQueue.Enqueue($taskNode) } }
        while ($taskQueue.Count) {
            $taskNode=$taskQueue.Dequeue()
            if ($taskNode.type -ceq 'trackingcode') {
                $taskResult.unit_codes++; $taskUnits++
                $taskCis=[string]$taskNode.cis
                if (-not $taskCis -or -not $taskSeen.Add($taskCis)) { $taskResult.duplicate_codes++ }
                $taskLength=[string]$taskCis.Length
                if (-not $taskResult.lengths.ContainsKey($taskLength)) { $taskResult.lengths[$taskLength]=0 }
                $taskResult.lengths[$taskLength]++
                if ($taskCis.Contains([char]29)) { $taskResult.gs_codes++ }
                if ($taskCis -cmatch '^01[0-9]{14}21.+\x1d91[^\x1d]{4}\x1d92.+$') { $taskResult.crypto_candidates++ }
            } elseif ($taskNode.type -cin @('consumerpack','transportpack')) {
                $taskResult.packages++
                if (@($taskNode.trackingCodes | Where-Object { $null -ne $_ }).Count -eq 0) { $taskResult.unexpanded_packages++ }
                foreach ($taskChild in @($taskNode.trackingCodes)) { if ($null -ne $taskChild) { $taskQueue.Enqueue($taskChild) } }
            } else { $taskResult.unknown_code_types++ }
        }
        if ($taskUnits -eq 0) { $taskResult.positions_without_codes++ }
        elseif ($null -ne $taskPosition.quantity -and $taskPosition.quantity -eq $taskUnits) { $taskResult.quantity_matches++ }
        else { $taskResult.quantity_mismatches++ }
        $taskQueue.Clear()
        foreach ($taskNode in @($taskPosition.trackingCodes_1162)) { if ($null -ne $taskNode) { $taskQueue.Enqueue($taskNode) } }
        while ($taskQueue.Count) {
            $taskNode=$taskQueue.Dequeue()
            if ($taskNode.type -ceq 'trackingcode' -and $taskNode.cis_1162) { $taskResult.tag1162_codes++ }
            foreach ($taskChild in @($taskNode.trackingCodes_1162)) { if ($null -ne $taskChild) { $taskQueue.Enqueue($taskChild) } }
        }
    }
    return $taskResult
}
function Resolve-ProbeDocument($Documents, $Intention) {
    # An empty read never proves a timed-out POST had no effect.
    if ([string]::IsNullOrWhiteSpace($Intention.externalCode) -or -not $Intention.organization -or -not $Intention.store -or @($Intention.positions).Count -eq 0) { return 'unknown' }
    $taskMatches=@($Documents | Where-Object { $_.externalCode -ceq $Intention.externalCode })
    if ($taskMatches.Count -eq 0) { return 'unknown' }
    if ($taskMatches.Count -ne 1) { return 'conflict' }
    $taskDocument=$taskMatches[0]
    if (-not $taskDocument.id) { return 'unknown' }
    if ($taskDocument.organization -cne $Intention.organization -or $taskDocument.store -cne $Intention.store) { return 'conflict' }
    $taskActual=@($taskDocument.positions | Sort-Object variant)
    $taskExpected=@($Intention.positions | Sort-Object variant)
    if ($taskActual.Count -ne $taskExpected.Count) { return 'conflict' }
    for ($taskIndex=0; $taskIndex -lt $taskExpected.Count; $taskIndex++) {
        foreach ($taskField in @('variant','quantity','price','reserve')) {
            if ($null -eq $taskActual[$taskIndex][$taskField] -or $taskActual[$taskIndex][$taskField] -cne $taskExpected[$taskIndex][$taskField]) { return 'conflict' }
        }
    }
    return 'confirmed'
}
function Get-ProbeMetadataEvidence($Reply) {
    $taskResult=@{status=$Reply.status;states=$null;attributes=$null}
    if (-not $Reply.ok) { return $taskResult }
    foreach ($taskField in @('states','attributes')) {
        $taskCollection=$Reply.data[$taskField]
        if ($taskCollection -is [array]) { $taskResult[$taskField]=$taskCollection.Count }
        elseif ($null -ne $taskCollection.meta.size -and $taskCollection.meta.size -ge 0) { $taskResult[$taskField]=$taskCollection.meta.size }
    }
    return $taskResult
}
