# VPNGuard - сетевой kill switch через брандмауэр Windows (общие функции).
# Идея: выбранной программе (например, Claude) запрещён выход в интернет через
# физические адаптеры (Ethernet, Wi-Fi). Через VPN-адаптер (TUN) и через локальный
# прокси VPN-клиента (127.0.0.1) трафик идёт как обычно. Пропал VPN - трафик программы
# просто некуда отправить: без опроса и без задержки.
# Файл только объявляет функции. Правила меняет Firewall.ps1 (нужны права администратора).

$VGFwGroup = 'VPNGuard Kill Switch'
$VGFwTunPattern = 'wintun|tun|tap|hiddify|happ|sing-box|xray|wireguard|v2ray|clash|amnezia|vpn|virtual|hyper-v|loopback|bluetooth'

# Где искать исполняемые файлы для известных программ (пути относительно профиля пользователя
# или абсолютные). Шаблоны раскрываются через Get-ChildItem; отсутствующие пропускаются.
$VGFwKnownPaths = @{
    claude = @(
        'AppData\Local\AnthropicClaude\claude.exe',
        'AppData\Local\AnthropicClaude\app-*\claude.exe',
        'AppData\Local\Programs\claude\claude.exe',
        'AppData\Local\Programs\Claude\Claude.exe',
        '.local\bin\claude.exe',
        '.local\share\claude\versions\*.exe',
        '.local\share\claude\versions\*\claude.exe',
        '%ProgramFiles%\WindowsApps\Claude_*\app\claude.exe',
        '%ProgramFiles%\WindowsApps\AnthropicPBC.Claude_*\app\claude.exe',
        '%ProgramFiles%\Claude\claude.exe'
    )
    chatgpt = @(
        'AppData\Local\Programs\ChatGPT\ChatGPT.exe',
        '%ProgramFiles%\WindowsApps\OpenAI.ChatGPT-Desktop_*\app\ChatGPT.exe'
    )
}

function Expand-VGFwPattern([string]$Pattern, [string]$UserProfile) {
    $p = [Environment]::ExpandEnvironmentVariables($Pattern)
    if (-not [IO.Path]::IsPathRooted($p)) {
        if (-not $UserProfile) { return @() }
        $p = Join-Path $UserProfile $p
    }
    $p = $p -replace '/', '\'
    try {
        return @(Get-ChildItem -Path $p -File -Force -ErrorAction Ignore | % { $_.FullName })
    } catch { return @() }
}

# Все найденные пути к программе: известные места + пути уже запущенных процессов с этим именем.
function Get-VGFwAppPaths([string]$App, [string]$UserProfile, [string[]]$ExtraPaths = @(), [switch]$NoRunning) {
    $found = New-Object 'System.Collections.Generic.List[string]'
    $add = { param($x) if ($x -and -not ($found | ? { $_ -ieq $x })) { $found.Add($x) } }
    $name = $App.ToLower()
    if ($VGFwKnownPaths.ContainsKey($name)) {
        foreach ($pat in $VGFwKnownPaths[$name]) { foreach ($f in (Expand-VGFwPattern $pat $UserProfile)) { & $add $f } }
    }
    foreach ($pat in $ExtraPaths) { foreach ($f in (Expand-VGFwPattern $pat $UserProfile)) { & $add $f } }
    if (-not $NoRunning) {
        foreach ($proc in @(Get-Process -Name $name -ErrorAction Ignore)) {
            try { if ($proc.Path) { & $add $proc.Path } } catch { }
        }
    }
    return @($found)
}

# Имена физических сетевых адаптеров (Ethernet, Wi-Fi). Виртуальные и VPN-адаптеры не входят.
function Get-VGFwPhysicalAliases {
    # Только адаптеры, которые реально есть в системе и подключены к стеку IP: на скрытую или
    # отключённую карту Windows не даст создать правило («The specified interface was not found»).
    $list = @()
    try {
        $live = @(Get-NetIPInterface -ErrorAction Stop | % { $_.InterfaceAlias } | Sort-Object -Unique)
        $list = @(Get-NetAdapter -Physical -ErrorAction Stop |
            ? { $_.InterfaceDescription -notmatch $VGFwTunPattern -and $_.Name -notmatch $VGFwTunPattern } |
            % { $_.Name })
        # Внешний виртуальный коммутатор Hyper-V забирает трафик физической карты на себя.
        $list += @(Get-NetAdapter -ErrorAction Stop |
            ? { $_.Name -like 'vEthernet*' -and $_.InterfaceDescription -match 'Hyper-V Virtual Ethernet' -and $_.Name -notmatch 'Default Switch|WSL' } |
            % { $_.Name })
        $list = @($list | ? { $live -contains $_ })
    } catch { }
    return @($list | Sort-Object -Unique)
}

# Ошибку пишем в тот же файл состояния: окно сразу её покажет, а не будет ждать 90 секунд.
function Write-VGFwError([string]$Path, [string]$Message) {
    $prev = Read-VGFwStatus $Path
    $status = [ordered]@{
        time             = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        rules            = @(if ($prev) { @($prev.rules) })
        aliases          = @(if ($prev) { @($prev.aliases) })
        firewall_enabled = @(if ($prev) { @($prev.firewall_enabled) })
        note             = ''
        installed        = [bool]($prev -and $prev.installed -ne $false -and @($prev.rules).Count)
        error            = $Message
    }
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $status | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Get-VGFwRuleName([string]$App, [string]$Program) {
    # Символ «|» в именах правил брандмауэр Windows запрещает.
    return ("VPNGuard KS - $App - $Program" -replace '\|', '/')
}

# План: одно блокирующее правило на каждый найденный исполняемый файл.
function Get-VGFwPlan([string[]]$Apps, [string]$UserProfile, [string[]]$Aliases, [hashtable]$ExtraPaths = @{}, [switch]$NoRunning) {
    $plan = @()
    foreach ($app in $Apps) {
        $a = $app.ToLower()
        $extra = @(); if ($ExtraPaths.ContainsKey($a)) { $extra = @($ExtraPaths[$a]) }
        foreach ($prog in (Get-VGFwAppPaths -App $a -UserProfile $UserProfile -ExtraPaths $extra -NoRunning:$NoRunning)) {
            $plan += [pscustomobject]@{ App = $a; Program = $prog; Name = (Get-VGFwRuleName $a $prog); Aliases = @($Aliases) }
        }
    }
    return @($plan)
}

# Программы под выключателем = все отмеченные галочкой (apps) минус исключения (firewall_exclude).
function Get-VGFwApps($Apps, $Exclude) {
    $ex = @($Exclude | ? { $_ } | % { ([string]$_).ToLower() })
    return @($Apps | ? { $_ } | % { ([string]$_).ToLower() } | ? { $ex -notcontains $_ } | Sort-Object -Unique)
}
function Read-VGFwConfig([string]$ConfigPath) {
    $res = @{ Apps = @(); Extra = @{} }
    if (-not (Test-Path -LiteralPath $ConfigPath)) { return $res }
    $c = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $res.Apps = @(Get-VGFwApps @($c.apps | ? { $_ -is [string] }) @($c.firewall_exclude | ? { $_ -is [string] }))
    if ($c.firewall_paths) {
        foreach ($prop in $c.firewall_paths.PSObject.Properties) { $res.Extra[$prop.Name.ToLower()] = @($prop.Value | ? { $_ -is [string] }) }
    }
    return $res
}

# Приводит правила группы к плану: добавляет недостающие, обновляет адаптеры, удаляет лишние.
# Новые правила создаются до удаления старых, чтобы не было окна без защиты.
function Sync-VGFwRules($Plan, [switch]$DryRun) {
    $log = New-Object 'System.Collections.Generic.List[string]'
    $existing = @{}
    foreach ($r in @(Get-NetFirewallRule -Group $VGFwGroup -ErrorAction Ignore)) { $existing[$r.DisplayName] = $r }
    $wanted = @{}
    foreach ($item in $Plan) {
        $wanted[$item.Name] = $true
        if (-not $item.Aliases -or $item.Aliases.Count -eq 0) { $log.Add("ПРОПУСК $($item.Program): не найдено физических адаптеров"); continue }
        if ($existing.ContainsKey($item.Name)) {
            $cur = @()
            try { $cur = @(($existing[$item.Name] | Get-NetFirewallInterfaceFilter).InterfaceAlias) } catch { }
            $same = ((@($cur | Sort-Object) -join '|') -eq (@($item.Aliases | Sort-Object) -join '|'))
            if (-not $same) {
                if (-not $DryRun) { Set-NetFirewallRule -Name $existing[$item.Name].Name -InterfaceAlias $item.Aliases -ErrorAction Stop }
                $log.Add("ОБНОВЛЕНО $($item.Program): адаптеры $($item.Aliases -join ', ')")
            }
            if (-not $DryRun -and $existing[$item.Name].Enabled -ne 'True') { Enable-NetFirewallRule -Name $existing[$item.Name].Name }
            continue
        }
        if (-not $DryRun) {
            try {
                New-NetFirewallRule -DisplayName $item.Name -Group $VGFwGroup -Direction Outbound -Action Block `
                    -Program $item.Program -InterfaceAlias $item.Aliases -Profile Any -Enabled True `
                    -Description 'AiGuard: программа выходит в интернет только через защищённое соединение.' -ErrorAction Stop | Out-Null
            } catch {
                $log.Add("ОШИБКА $($item.Program): $($_.Exception.Message)")
                continue
            }
        }
        $log.Add("ДОБАВЛЕНО $($item.Program): блок на $($item.Aliases -join ', ')")
    }
    foreach ($name in @($existing.Keys)) {
        if (-not $wanted.ContainsKey($name)) {
            if (-not $DryRun) { Remove-NetFirewallRule -Name $existing[$name].Name -ErrorAction Ignore }
            $log.Add("УДАЛЕНО $name")
        }
    }
    return @($log)
}

function Remove-VGFwRules {
    @(Get-NetFirewallRule -Group $VGFwGroup -ErrorAction Ignore) | Remove-NetFirewallRule -ErrorAction Ignore
}

# Файл состояния пишет синхронизация (от администратора); окно VPNGuard его только читает.
function Write-VGFwStatus([string]$Path, $Plan, [string[]]$Aliases, [string]$Note = '', [bool]$Installed = $true) {
    $enabledProfiles = @()
    try { $enabledProfiles = @(Get-NetFirewallProfile -ErrorAction Stop | ? { $_.Enabled -eq 'True' } | % { $_.Name }) } catch { }
    $status = [ordered]@{
        time             = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        rules            = @($Plan | ? { $_.Aliases.Count -gt 0 } | % { [ordered]@{ app = $_.App; program = $_.Program } })
        aliases          = @($Aliases)
        firewall_enabled = @($enabledProfiles)
        note             = $Note
        installed        = $Installed
    }
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $status | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Read-VGFwStatus([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    try { return (Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json) } catch { return $null }
}

# Короткая строка для окна: что закрыто брандмауэром.
function Format-VGFwSummary($Status) {
    if (-not $Status -or $Status.installed -eq $false) { return 'Аварийный выключатель (брандмауэр): выключен. Включается на вкладке «Брандмауэр».' }
    $rules = @($Status.rules)
    if ($rules.Count -eq 0) { return "Брандмауэр: правил нет ($($Status.time))." }
    $known = @{ claude = 'Claude'; chatgpt = 'ChatGPT'; codex = 'Codex'; cursor = 'Cursor'; windsurf = 'Windsurf'; perplexity = 'Perplexity'; telegram = 'Telegram'; discord = 'Discord' }
    $apps = @($rules | % { $a = [string]$_.app; if ($known.ContainsKey($a)) { $known[$a] } elseif ($a) { $a.Substring(0,1).ToUpper() + $a.Substring(1) } } | Sort-Object -Unique) -join ', '
    $fw = if (@($Status.firewall_enabled).Count -eq 0) { ' ВНИМАНИЕ: брандмауэр Windows выключен.' } else { '' }
    return "Аварийный выключатель: $apps только через защищённое соединение (правил: $($rules.Count), проверено $($Status.time)).$fw"
}

# Запущенные копии программы, которых нет в правилах (например, после обновления).
function Get-VGFwUncovered($Status, [string[]]$Apps) {
    $covered = @(); if ($Status) { $covered = @($Status.rules | % { $_.program }) }
    $out = @()
    foreach ($app in $Apps) {
        foreach ($proc in @(Get-Process -Name $app -ErrorAction Ignore)) {
            try { $p = $proc.Path } catch { $p = $null }
            if ($p -and -not ($covered | ? { $_ -ieq $p }) -and -not ($out -contains $p)) { $out += $p }
        }
    }
    return @($out)
}
