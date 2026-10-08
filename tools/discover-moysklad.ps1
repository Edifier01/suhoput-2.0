param([Parameter(Mandatory)][string]$WarehouseName, [string]$OrganizationName, [switch]$ProbeCatalog, [switch]$FullCatalog)
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
$taskFile = Join-Path $taskRoot 'infra/.env.integrations.local'
$taskText = [IO.File]::ReadAllText($taskFile)
$taskConfig = @{}
foreach ($taskLine in ($taskText -split "`r?`n")) {
    if ($taskLine -match '^([A-Z][A-Z0-9_]*)=(.*)$') {
        $taskValue = $Matches[2].Trim()
        if ($taskValue.Length -ge 2 -and (($taskValue.StartsWith('"') -and $taskValue.EndsWith('"')) -or ($taskValue.StartsWith("'") -and $taskValue.EndsWith("'")))) { $taskValue = $taskValue.Substring(1, $taskValue.Length-2) }
        $taskConfig[$Matches[1]] = $taskValue
    }
}
if (-not $taskConfig['MOYSKLAD_TOKEN']) { throw 'MOYSKLAD_TOKEN is missing; fill the local file. Values are never printed.' }
$taskBase = 'https://api.moysklad.ru/api/remap/1.2'
if ($taskConfig['MOYSKLAD_API_BASE_URL'] -and $taskConfig['MOYSKLAD_API_BASE_URL'] -ne $taskBase) { throw 'Unexpected API host; request blocked.' }
$taskHandler = [Net.Http.HttpClientHandler]::new()
$taskHandler.AllowAutoRedirect = $false
$taskHandler.AutomaticDecompression = [Net.DecompressionMethods]::GZip -bor [Net.DecompressionMethods]::Deflate
$taskClient = [Net.Http.HttpClient]::new($taskHandler)
$taskClient.Timeout = [TimeSpan]::FromSeconds(20)
$taskClient.DefaultRequestHeaders.Authorization = [Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer',$taskConfig['MOYSKLAD_TOKEN'])
$taskClient.DefaultRequestHeaders.Add('Accept-Encoding','gzip')
function Get-TaskMs([string]$Path) {
    Start-Sleep -Milliseconds 500
    try {
        $taskResponse = $taskClient.GetAsync($taskBase + $Path).GetAwaiter().GetResult()
        if (-not $taskResponse.IsSuccessStatusCode) { return @{ ok=$false; status=[int]$taskResponse.StatusCode } }
        $taskBody = $taskResponse.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        return @{ok=$true; status=[int]$taskResponse.StatusCode; data=($taskBody | ConvertFrom-Json -Depth 100)}
    } catch { return @{ok=$false; status='transport_error'} }
}
function Set-TaskSetting([string]$Key, [string]$Value) {
    if ($Value -match "[`r`n]") { throw 'Invalid configuration value.' }
    $taskPattern = '(?m)^' + [regex]::Escape($Key) + '=.*$'
    if ($script:taskText -match $taskPattern) {
        $script:taskText = [regex]::Replace($script:taskText, $taskPattern, [Text.RegularExpressions.MatchEvaluator]{ param($match) $Key + '=' + $Value })
    } else { $script:taskText += "`n" + $Key + '=' + $Value + "`n" }
}
try {
    $taskStores = Get-TaskMs '/entity/store?limit=1000'
    if (-not $taskStores.ok) { throw ('Warehouse read failed, status=' + $taskStores.status + '; token was not printed.') }
    $taskChosen = @($taskStores.data.rows | Where-Object { $_.name -ceq $WarehouseName -and -not $_.archived })
    if ($taskChosen.Count -ne 1) {
        $taskCandidates = @($taskStores.data.rows | Where-Object { $_.name -like '*Грозн*' } | ForEach-Object { @{ name=$_.name; id=$_.id; archived=$_.archived } })
        Write-Output (@{result='warehouse_confirmation_required'; requested=$WarehouseName; candidates=$taskCandidates} | ConvertTo-Json -Compress -Depth 5)
        return
    }
    $taskWarehouse = $taskChosen[0]
    Set-TaskSetting 'MOYSKLAD_WAREHOUSE_NAME' $taskWarehouse.name
    Set-TaskSetting 'MOYSKLAD_WAREHOUSE_ID' $taskWarehouse.id
    Set-TaskSetting 'MOYSKLAD_ACCOUNT_ID' $taskWarehouse.accountId
    $taskPrices = Get-TaskMs '/context/companysettings/pricetype'
    $taskPriceRows = @()
    if ($taskPrices.ok) {
        $taskPriceRows = @($taskPrices.data)
        if ($taskPrices.data -isnot [array]) {
            if ($taskPrices.data.PSObject.Properties['rows']) { $taskPriceRows = @($taskPrices.data.rows) }
            elseif ($taskPrices.data.PSObject.Properties['priceTypes']) { $taskPriceRows = @($taskPrices.data.priceTypes) }
        }
        foreach ($taskPair in @(@('Розница','MOYSKLAD_RETAIL_PRICE_TYPE_ID'), @('Цена продажи','MOYSKLAD_WHOLESALE_PRICE_TYPE_ID'))) {
            $taskMatched = @($taskPriceRows | Where-Object { $_.name -ceq $taskPair[0] })
            if ($taskMatched.Count -eq 1) { Set-TaskSetting $taskPair[1] $taskMatched[0].id }
        }
    }
    $taskOrgs = Get-TaskMs '/entity/organization?limit=1000'
    if ($OrganizationName -and -not $taskOrgs.ok) { throw ('Organization read failed, status=' + $taskOrgs.status + '; configuration not saved.') }
    $taskActiveOrgs = @()
    if ($taskOrgs.ok) {
        $taskActiveOrgs = @($taskOrgs.data.rows | Where-Object { -not $_.archived })
        if ($OrganizationName) {
            $taskMatchingOrg = @($taskActiveOrgs | Where-Object { $_.name -ceq $OrganizationName })
            if ($taskMatchingOrg.Count -ne 1) { throw 'Organization name is not unique or was not found; confirm locally. Values were not printed.' }
            Set-TaskSetting 'MOYSKLAD_ORGANIZATION_ID' $taskMatchingOrg[0].id
            Set-TaskSetting 'MOYSKLAD_ORGANIZATION_NAME' $taskMatchingOrg[0].name
        } elseif ($taskActiveOrgs.Count -eq 1) { Set-TaskSetting 'MOYSKLAD_ORGANIZATION_ID' $taskActiveOrgs[0].id }
    }
    $taskShops = Get-TaskMs '/entity/retailstore?limit=1000'
    $taskLinkedShops = @()
    if ($taskShops.ok) {
        Set-TaskSetting 'MOYSKLAD_RETAIL_STORE_ID' ''
        $taskLinkedShops = @($taskShops.data.rows | Where-Object { -not $_.archived -and $_.store.meta.href -eq ($taskBase + '/entity/store/' + $taskWarehouse.id) })
        if ($taskLinkedShops.Count -eq 1) {
            Set-TaskSetting 'MOYSKLAD_SHOP_NAME' $taskLinkedShops[0].name
            Set-TaskSetting 'MOYSKLAD_RETAIL_STORE_ID' $taskLinkedShops[0].id
        }
    }
    [IO.File]::WriteAllText($taskFile, $taskText, [Text.UTF8Encoding]::new($false))
    $taskPrivate = Join-Path $taskRoot '.cache/moysklad/discovery.local.json'
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $taskPrivate) | Out-Null
    $taskOptions = @{ organizations=@($taskActiveOrgs | ForEach-Object { @{id=$_.id;name=$_.name} }); shops=@($taskShops.data.rows | ForEach-Object { @{id=$_.id;name=$_.name;warehouse_reference=$_.store.meta.href} }) }
    [IO.File]::WriteAllText($taskPrivate, ($taskOptions | ConvertTo-Json -Depth 6), [Text.UTF8Encoding]::new($false))
    Write-Output (@{ result='read_only_discovery'; warehouse=@{name=$taskWarehouse.name;id=$taskWarehouse.id}; price_types=@($taskPriceRows | ForEach-Object{@{name=$_.name;id=$_.id}}); active_organizations=$taskActiveOrgs.Count; warehouse_linked_shops=$taskLinkedShops.Count; shop_count=@($taskShops.data.rows).Count; statuses=@{prices=$taskPrices.status;organizations=$taskOrgs.status;shops=$taskShops.status}; mutations=0 } | ConvertTo-Json -Compress -Depth 6)
    if ($ProbeCatalog) {
        $taskProducts = Get-TaskMs '/entity/product?limit=50'
        $taskVariants = Get-TaskMs '/entity/variant?limit=50'
        $taskCurrencies = Get-TaskMs '/entity/currency?limit=1000'
        $taskFilter = [Uri]::EscapeDataString('store=' + $taskBase + '/entity/store/' + $taskWarehouse.id + ';stockMode=all')
        $taskStock = Get-TaskMs ('/report/stock/bystore?limit=50&filter=' + $taskFilter)
        $taskSample = @()
        if ($taskProducts.ok) { $taskSample += @($taskProducts.data.rows) }
        if ($taskVariants.ok) { $taskSample += @($taskVariants.data.rows) }
        $taskSummary = @{
            checked_utc=[DateTime]::UtcNow.ToString('o'); api='remap/1.2'; method='GET'; mutations=0
            statuses=@{products=$taskProducts.status;variants=$taskVariants.status;currencies=$taskCurrencies.status;selected_stock=$taskStock.status}
            total_products=$taskProducts.data.meta.size; total_variants=$taskVariants.data.meta.size
            product_sample=@($taskProducts.data.rows).Count; variant_sample=@($taskVariants.data.rows).Count
            product_fields=@($taskProducts.data.rows[0].PSObject.Properties.Name)
            variant_fields=@($taskVariants.data.rows[0].PSObject.Properties.Name)
            characteristic_names=@($taskVariants.data.rows | ForEach-Object { $_.characteristics } | ForEach-Object { $_.name } | Sort-Object -Unique)
            sample_with_images=@($taskSample | Where-Object { $_.images.meta.size -gt 0 }).Count
            currencies=@($taskCurrencies.data.rows | ForEach-Object { @{iso=$_.isoCode;code=$_.code} })
            price_13000_samples=@($taskSample | ForEach-Object { $_.salePrices } | Where-Object { $_.priceType.id -eq $taskConfig['MOYSKLAD_RETAIL_PRICE_TYPE_ID'] -and $_.value -eq 1300000 }).Count
            selected_stock_rows=@($taskStock.data.rows).Count
            selected_stock_fields=@($taskStock.data.rows[0].stockByStore[0].PSObject.Properties.Name)
            all_stock_rows_single_selected_store=@($taskStock.data.rows | Where-Object { @($_.stockByStore).Count -ne 1 -or $_.stockByStore[0].meta.href -ne ($taskBase+'/entity/store/'+$taskWarehouse.id) }).Count -eq 0
            fractional_stock_rows=@($taskStock.data.rows | ForEach-Object { $_.stockByStore } | Where-Object { [decimal]$_.stock -ne [decimal]::Truncate([decimal]$_.stock) -or [decimal]$_.reserve -ne [decimal]::Truncate([decimal]$_.reserve) }).Count
        }
        [IO.File]::WriteAllText((Join-Path $taskRoot '.cache/moysklad/probe.local.json'), ($taskSummary | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
        Write-Output ($taskSummary | ConvertTo-Json -Compress -Depth 8)
    }
    if ($FullCatalog) {
        $taskTotals = @{}
        foreach ($taskEntity in @('product','variant')) {
            $taskOffset=0; $taskIds=[Collections.Generic.HashSet[string]]::new(); $taskPages=0; $taskStableSize=$null; $taskImages=0; $taskMissingRetail=0; $taskControl13000=0
            do {
                $taskPage = Get-TaskMs ('/entity/'+$taskEntity+'?limit=1000&offset='+$taskOffset)
                if (-not $taskPage.ok) { throw ('Catalog page read failed, entity='+$taskEntity+', offset='+$taskOffset+', status='+$taskPage.status) }
                $taskSize=[int]$taskPage.data.meta.size
                if ($null -eq $taskStableSize) { $taskStableSize=$taskSize }
                if ($taskSize -ne $taskStableSize) { throw 'Catalog changed during pagination; no complete snapshot claimed.' }
                foreach ($taskItem in $taskPage.data.rows) {
                    if (-not $taskIds.Add($taskItem.id)) { throw 'Duplicate item during pagination; no complete snapshot claimed.' }
                    if ($taskItem.images.meta.size -gt 0) { ++$taskImages }
                    $taskRetail=@($taskItem.salePrices | Where-Object { $_.priceType.id -eq $taskConfig['MOYSKLAD_RETAIL_PRICE_TYPE_ID'] })
                    if ($taskRetail.Count -ne 1 -or $taskRetail[0].value -le 0) { ++$taskMissingRetail }
                    if ($taskRetail.Count -eq 1 -and $taskRetail[0].value -eq 1300000) { ++$taskControl13000 }
                }
                ++$taskPages
                $taskOffset+=@($taskPage.data.rows).Count
                if ($taskOffset -lt $taskSize -and @($taskPage.data.rows).Count -eq 0) { throw 'Empty intermediate page; no complete snapshot claimed.' }
            } while ($taskOffset -lt $taskSize)
            $taskTotals[$taskEntity]=@{expected=$taskSize; unique=$taskIds.Count; pages=$taskPages; with_images=$taskImages; nonpositive_or_missing_retail_price=$taskMissingRetail; price_13000_examples=$taskControl13000}
        }
        $taskPagination=@{checked_utc=[DateTime]::UtcNow.ToString('o');method='GET';mutations=0;result='stable_metadata_pagination';totals=$taskTotals;resume_after_process_stop='not_tested';variant_price_inheritance='not_proven'}
        [IO.File]::WriteAllText((Join-Path $taskRoot '.cache/moysklad/pagination.local.json'), ($taskPagination | ConvertTo-Json -Depth 6), [Text.UTF8Encoding]::new($false))
        Write-Output ($taskPagination | ConvertTo-Json -Compress -Depth 6)
    }
} finally { $taskClient.Dispose(); $taskHandler.Dispose(); $taskConfig.Clear(); $taskText=$null }
