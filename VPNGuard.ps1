# AiGuard — контроль выбранных программ по состоянию защищённого соединения.
# Пропал VPN - Claude, ChatGPT и другие выбранные программы закрываются (или ставятся на паузу).
# Настройки - в окне: двойной щелчок по значку в трее или ярлык VPNGuard на рабочем столе.
param(
    [switch]$DryRun,         # только писать в лог, ничего не трогать
    [string]$Targets = "",   # для проверки: другие имена процессов через запятую
    [switch]$ForceBad,       # для проверки: считать, что VPN отвалился
    [string]$TestProxy = "", # для проверки: подставной прокси (127.0.0.1:порт)
    [switch]$SelfTest,
    [switch]$Preview,
    [switch]$Background      # запуск при старте Windows: окно не открывать
)

$ErrorActionPreference = 'Continue'
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$ConfigPath = Join-Path $Here 'config.json'
$LogPath = Join-Path $Here 'vpnguard.log'
if ($SelfTest -or $Preview) {
    $DryRun = $true
    $Targets = 'vpnguard_test_nonexistent'
    $LogPath = Join-Path $Here 'verification/test.log'
}

$RunKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
# Ярлык запуска: в новых сборках «Запуск AiGuard.vbs», в старых — «Запуск VPNGuard.vbs»
$Launcher = @('Запуск AiGuard.vbs','Запуск VPNGuard.vbs') | ? { Test-Path -LiteralPath (Join-Path $Here $_) } | Select-Object -First 1
if (-not $Launcher) { $Launcher = 'Запуск AiGuard.vbs' }
$RunValue = 'wscript.exe "' + (Join-Path $Here $Launcher) + '" /background'

# --- один экземпляр; повторный запуск просто открывает окно у уже работающего
$instanceSuffix = if ($SelfTest -or $Preview) { '_test_' + $PID } else { '' }
$showEvent = New-Object System.Threading.EventWaitHandle($false, 'AutoReset', ('Local\VPNGuard_show' + $instanceSuffix))
$mutex = New-Object System.Threading.Mutex($false, ('Local\VPNGuard_single' + $instanceSuffix))
# Штатное завершение по сигналу (restart.ps1), работает и без окна
$quitEvent = New-Object System.Threading.EventWaitHandle($false, 'ManualReset', ('Local\VPNGuard_quit' + $instanceSuffix))
# код 3 = уже запущен; сторож не считает это ни сбоем, ни штатным выходом
if (-not $mutex.WaitOne(0)) { if (-not $Background) { [void]$showEvent.Set() }; exit 3 }

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Net.Http
Add-Type -Path (Join-Path $Here 'NetworkMonitor.cs')
Add-Type -Path (Join-Path $Here 'ProcessTree.cs')
Add-Type -Path (Join-Path $Here 'ProbeEngine.cs')
# Сетевой kill switch (брандмауэр): только чтение состояния, правила меняет Firewall.ps1
. (Join-Path $Here 'FirewallCore.ps1')
$FwStatusPath = Join-Path $Here 'state\firewall-status.json'
$fwStatus = $null; $fwNext = Get-Date; $fwAskAt = $null
Add-Type @"
using System; using System.Runtime.InteropServices;
public static class VGNt {
  [DllImport("ntdll.dll")] public static extern int NtSuspendProcess(IntPtr h);
  [DllImport("ntdll.dll")] public static extern int NtResumeProcess(IntPtr h);
}
"@
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Windows.Forms.Application]::EnableVisualStyles()

function Log($msg) {
    $line = "{0} {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $msg
    try { Add-Content -Path $LogPath -Value $line -Encoding UTF8 } catch {}
}

# ================= настройки =================
$Presets = [ordered]@{
    'claude'     = 'Claude (и Claude Code)'
    'chatgpt'    = 'ChatGPT'
    'codex'      = 'Codex'
    'cursor'     = 'Cursor'
    'windsurf'   = 'Windsurf'
    'perplexity' = 'Perplexity'
    'telegram'   = 'Telegram'
    'discord'    = 'Discord'
}
$CountryNames = [ordered]@{
    AM='Армения'; GE='Грузия'; KZ='Казахстан'; TR='Турция'; AE='ОАЭ'; NL='Нидерланды'; DE='Германия'
    FI='Финляндия'; SE='Швеция'; PL='Польша'; LV='Латвия'; LT='Литва'; EE='Эстония'; FR='Франция'
    GB='Великобритания'; US='США'; CA='Канада'; JP='Япония'; SG='Сингапур'; HK='Гонконг'; RS='Сербия'
    CH='Швейцария'; AT='Австрия'; ES='Испания'; IT='Италия'; CZ='Чехия'; MD='Молдова'; UZ='Узбекистан'; RU='Россия'
}
function Country-Label($cc) { if ($CountryNames.Contains($cc)) { "$cc - $($CountryNames[$cc])" } else { $cc } }

$Cfg = $null
function Load-Config {
    $c = Get-Content $ConfigPath -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if (-not $c -or $c -is [Array] -or $c -isnot [pscustomobject]) { throw 'Конфигурация должна быть JSON-объектом.' }
    foreach ($required in @('apps','allow_ips','allow_countries')) {
        if ($null -eq $c.PSObject.Properties[$required] -or $c.$required -isnot [Array]) { throw "Поле $required должно быть массивом." }
        foreach ($value in $c.$required) { if ($value -isnot [string]) { throw "Поле $required содержит значение другого типа." } }
    }
    if ($null -ne $c.PSObject.Properties['probe_route']) {
        if ($c.probe_route -isnot [string] -or $c.probe_route -notmatch '^(system|direct|(http|socks5)://[^/\s:]+:\d{1,5})$') { throw 'Поле probe_route: system, direct, http://хост:порт или socks5://хост:порт.' }
    }
    foreach ($list in @('ip_services','ipv6_services')) {
        if ($null -ne $c.PSObject.Properties[$list]) {
            if ($c.$list -isnot [Array]) { throw "Поле $list должно быть массивом." }
            foreach ($value in $c.$list) { if ($value -isnot [string] -or $value -notmatch '^https?://') { throw "Поле ${list}: адреса должны начинаться с http:// или https://." } }
        }
    }
    if ($null -ne $c.PSObject.Properties['firewall_exclude']) {
        if ($c.firewall_exclude -isnot [Array]) { throw 'Поле firewall_exclude должно быть массивом.' }
        foreach ($value in $c.firewall_exclude) { if ($value -isnot [string]) { throw 'Поле firewall_exclude содержит значение другого типа.' } }
    }
    if ($null -ne $c.PSObject.Properties['firewall_asked'] -and $c.firewall_asked -isnot [bool]) { throw 'Поле firewall_asked должно быть true или false.' }
    if ($null -ne $c.PSObject.Properties['dns_check'] -and $c.dns_check -notin @('warn','block','off')) { throw 'Поле dns_check: warn, block или off.' }
    foreach ($flag in @('kill_after_grace','watch_proxy','notifications','check_ipv6','route_check')) {
        if ($null -ne $c.PSObject.Properties[$flag] -and $c.$flag -isnot [bool]) { throw "Поле $flag должно быть true или false." }
    }
    foreach ($field in @('interval_sec','grace_sec')) {
        if ($null -ne $c.PSObject.Properties[$field]) {
            $number = 0
            if (-not [int]::TryParse([string]$c.$field,[ref]$number) -or $number -lt 0 -or $number -gt 600) { throw "Некорректное значение $field." }
        }
    }
    $script:Cfg = [ordered]@{
        app_actions      = @{}
        apps             = @($c.apps | ? { $_ } | % { $_.ToLower() })
        allow_ips        = @($c.allow_ips | ? { $_ })
        allow_countries  = @($c.allow_countries | ? { $_ } | % { $_.ToUpper() })
        interval_sec     = $(if ($c.interval_sec) { [Math]::Max(3, [int]$c.interval_sec) } else { 3 })
        grace_sec        = [int]$c.grace_sec
        kill_after_grace = ($c.kill_after_grace -ne $false)
        watch_proxy      = ($c.watch_proxy -ne $false)
        notifications    = ($c.notifications -ne $false)
        ip_services      = @($c.ip_services | ? { $_ })
        ipv6_services    = @($c.ipv6_services | ? { $_ })
        check_ipv6       = ($c.check_ipv6 -ne $false)
        probe_route      = $(if ($c.probe_route) { [string]$c.probe_route } else { 'system' })
        route_check      = ($c.route_check -ne $false)
        dns_check        = $(if ($c.dns_check) { [string]$c.dns_check } else { 'warn' })
        firewall_exclude = @($c.firewall_exclude | ? { $_ } | % { $_.ToLower() })
        firewall_asked   = ($c.firewall_asked -eq $true)
    }
    if ($null -ne $c.PSObject.Properties['firewall_paths']) { $Cfg.firewall_paths = $c.firewall_paths }
    if (-not $Cfg.ipv6_services) { $Cfg.ipv6_services = @('https://api6.ipify.org','https://ipv6.icanhazip.com','https://v6.ident.me') }
    if ($c.app_actions) { foreach ($prop in $c.app_actions.PSObject.Properties) { if ($prop.Value -in @('default','freeze','grace','kill')) { $Cfg.app_actions[$prop.Name] = $prop.Value } } }
    if (-not $Cfg.ip_services) { $Cfg.ip_services = @('https://api.ipify.org','https://ipv4.icanhazip.com','https://v4.ident.me','https://checkip.amazonaws.com') }
    $script:Apps = $(if ($Targets) { $Targets.Split(',') | % { $_.Trim().ToLower() } } else { $Cfg.apps })
    $script:cfgStamp = (Get-Item $ConfigPath).LastWriteTime
}
function Save-Config {
    if ($SelfTest -or $Preview) { return }
    $tempPath = $ConfigPath + '.tmp'
    $Cfg | ConvertTo-Json -Depth 5 | Set-Content -Path $tempPath -Encoding UTF8
    Move-Item -LiteralPath $tempPath -Destination $ConfigPath -Force
    $script:cfgStamp = (Get-Item $ConfigPath).LastWriteTime
}
Load-Config

function Get-Autostart { [bool](Get-ItemProperty $RunKey -ErrorAction SilentlyContinue).VPNGuard }
function Set-Autostart($on) {
    if ($SelfTest -or $Preview) { return }
    if ($on) { Set-ItemProperty $RunKey -Name VPNGuard -Value $RunValue }
    else { Remove-ItemProperty $RunKey -Name VPNGuard -ErrorAction SilentlyContinue }
}

# ================= проверки =================
$http = New-Object System.Net.Http.HttpClient
$http.Timeout = [TimeSpan]::FromSeconds(5)
$countryCache = @{}

# Country resolution is polled by the UI timer, never waited on its thread.
function Start-CountryCheck($ip) {
    $jobs = @()
    foreach ($url in @("https://ipinfo.io/$ip/country", "https://api.country.is/$ip")) {
        try { $jobs += $http.GetStringAsync($url) } catch {}
    }
    $script:countryPending = @{ ip=$ip; tasks=$jobs; t0=Get-Date }
}
function Poll-CountryCheck {
    if (-not $script:countryPending) { return }
    $job = $script:countryPending
    $cc = $null
    foreach ($task in $job.tasks) {
        if ($task.Status -eq 'RanToCompletion') {
            $r = $task.Result.Trim()
            if ($r -match '"country"\s*:\s*"([A-Z]{2})"') { $r = $Matches[1] }
            if ($r -match '^[A-Za-z]{2}$') { $cc = $r.ToUpper(); break }
        }
    }
    if (-not $cc -and @($job.tasks | Where-Object { -not $_.IsCompleted }).Count -gt 0 -and ((Get-Date)-$job.t0).TotalSeconds -lt 5) { return }
    $script:countryPending = $null
    if ($script:state -eq 'paused') { return }
    if ($cc) { $countryCache[$job.ip] = $cc; $script:lastCountry = $cc }
    Resolve-Address $job.ip $cc
}
function Test-IpRule([string]$Address, [string]$Rule) {
    $ip = $null; $net = $null
    $parts = $Rule.Split('/')
    if ($parts.Count -gt 2 -or -not [Net.IPAddress]::TryParse($Address, [ref]$ip) -or -not [Net.IPAddress]::TryParse($parts[0], [ref]$net)) { return $false }
    if ($ip.AddressFamily -ne $net.AddressFamily) { return $false }
    $a = $ip.GetAddressBytes(); $b = $net.GetAddressBytes()
    $bits = $a.Length * 8
    if ($parts.Count -eq 2) {
        $n = 0
        if (-not [int]::TryParse($parts[1], [ref]$n) -or $n -lt 0 -or $n -gt $bits) { return $false }
        $bits = $n
    }
    for ($i=0; $i -lt $a.Length; $i++) {
        $take = [Math]::Min(8, [Math]::Max(0, $bits - $i*8))
        $mask = if ($take -eq 0) { 0 } else { (255 -shl (8-$take)) -band 255 }
        if (($a[$i] -band $mask) -ne ($b[$i] -band $mask)) { return $false }
    }
    return $true
}
function Resolve-Address($ip, $cc) {
    foreach ($rule in $Cfg.allow_ips) { if (Test-IpRule $ip $rule) { Set-Good $ip $cc; return } }
    if ($cc -and $Cfg.allow_countries -contains $cc) { Set-Good $ip $cc; return }
    if ($cc) { Set-Bad "Адрес не разрешён: $ip ($cc)" } else { Set-Bad "Страна $ip не определена" }
}

$InetKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
function Get-Proxy {
    if ($TestProxy) { return $TestProxy }
    $p = Get-ItemProperty $InetKey -ErrorAction SilentlyContinue
    if ($p.ProxyEnable -ne 1 -or -not $p.ProxyServer) { return $null }
    return [string]$p.ProxyServer
}
function Test-ProxyAlive($proxy) {
    if ($proxy -notmatch '(127\.0\.0\.1|localhost):(\d+)') { return $true }
    $port = [int]$Matches[2]
    $l = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners()
    return [bool]($l | ? { $_.Port -eq $port })
}
$TunPattern = 'wintun|tun|tap|hiddify|happ|sing-box|xray|wireguard|v2ray|clash'
function Get-TunAdapters {
    [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() |
        ? { $_.OperationalStatus -eq 'Up' -and ($_.Description -match $TunPattern -or $_.Name -match $TunPattern) } |
        % { $_.Id }
}

# ================= состояние =================
$startedAt = Get-Date
$incidentCount = 0; $checkCount = 0; $lastChecked = $null; $pauseUntil = $null
$serviceResults = @(); $countryPending = $null
$lastIpv6 = ''; $ipv6Status = 'off'   # ok | unavailable | unknown | off

# ================= P04: маршрут до сервисов, DNS, утечка IPv6 =================
# Адрес, который видит сам сервис: Cloudflare /cdn-cgi/trace у этих доменов отдаёт ip= клиента.
$RouteTargets = [ordered]@{
    claude     = @('https://claude.ai/cdn-cgi/trace', 'https://api.anthropic.com/cdn-cgi/trace')
    chatgpt    = @('https://chatgpt.com/cdn-cgi/trace', 'https://api.openai.com/cdn-cgi/trace')
    perplexity = @('https://www.perplexity.ai/cdn-cgi/trace')
}
# Резолвер, который реально ходит к авторитетным серверам (не список DNS из настроек Windows).
$DnsSources = @(
    @{ Name = 'whoami.akamai.net'; Type = 1; Label = 'Akamai whoami (A)' },
    @{ Name = 'o-o.myaddr.l.google.com'; Type = 16; Label = 'Google myaddr (TXT)' }
)
$DnsTestAnswers = $null      # только для тестов: @{ 'whoami.akamai.net' = @('x.x.x.x'); ... }
$extraPending = $null; $extraNext = Get-Date; $extraProblem = $null
$routeResults = @(); $dnsResult = $null; $ipv6Verdict = 'off'; $dnsWarned = ''
$geoJobs = @{}

function Get-Geo($ip) {
    # код страны; '' - определить не удалось; $null - ещё ждём ответа
    if ($countryCache.ContainsKey($ip)) { return $countryCache[$ip] }
    $j = $geoJobs[$ip]
    if (-not $j) {
        $tasks = @()
        foreach ($url in @("https://ipinfo.io/$ip/country", "https://api.country.is/$ip")) { try { $tasks += $http.GetStringAsync($url) } catch {} }
        $geoJobs[$ip] = @{ tasks = $tasks; t0 = Get-Date }
        return $null
    }
    foreach ($t in $j.tasks) {
        if ($t.Status -eq 'RanToCompletion') {
            $r = $t.Result.Trim()
            if ($r -match '"country"\s*:\s*"([A-Z]{2})"') { $r = $Matches[1] }
            if ($r -match '^[A-Za-z]{2}$') { $cc = $r.ToUpper(); $countryCache[$ip] = $cc; $geoJobs.Remove($ip); return $cc }
        }
    }
    if (@($j.tasks | ? { -not $_.IsCompleted }).Count -eq 0 -or ((Get-Date) - $j.t0).TotalSeconds -gt 6) { $geoJobs.Remove($ip); return '' }
    return $null
}
function Test-AddressAllowed($ip) {
    # yes | no | unknown ; $null - ждём страну
    foreach ($rule in $Cfg.allow_ips) { if (Test-IpRule $ip $rule) { return 'yes' } }
    $cc = Get-Geo $ip
    if ($null -eq $cc) { return $null }
    if ($cc -eq '') { return 'unknown' }
    if ($Cfg.allow_countries -contains $cc) { return 'yes' }
    return 'no'
}
function Start-ExtraChecks {
    $jobs = @()
    if ($Cfg.route_check) {
        foreach ($app in $Apps) {
            if (-not $RouteTargets.Contains($app)) { continue }
            foreach ($u in $RouteTargets[$app]) { $jobs += [pscustomobject]@{ Kind = 'route'; App = $app; Url = $u; Task = [VGProbe]::Start($u, $Cfg.probe_route, 'any', 6000) } }
        }
    }
    if ($Cfg.dns_check -ne 'off') {
        foreach ($s in $DnsSources) {
            $task = if ($DnsTestAnswers) { [System.Threading.Tasks.Task]::FromResult([string[]]@($DnsTestAnswers[$s.Name])) } else { [VGProbe]::DnsAsync($s.Name, $s.Type) }
            $jobs += [pscustomobject]@{ Kind = 'dns'; App = ''; Url = $s.Label; Task = $task }
        }
    }
    $script:extraPending = @{ jobs = $jobs; t0 = Get-Date }
}
function Poll-ExtraChecks {
    if (-not $script:extraPending) { return }
    $p = $script:extraPending
    $elapsed = ((Get-Date) - $p.t0).TotalSeconds
    if (@($p.jobs | ? { -not $_.Task.IsCompleted }).Count -gt 0 -and $elapsed -lt 8) { return }
    $now = Get-Date
    $routes = @(); $resolvers = @(); $dnsErrors = @(); $waiting = $false
    foreach ($j in $p.jobs) {
        $done = $j.Task.Status -eq 'RanToCompletion'
        if ($j.Kind -eq 'route') {
            $seen = ''; $verdict = 'unknown'; $note = ''
            if ($done -and $j.Task.Result.Status -eq 'ok') {
                $seen = $j.Task.Result.Value
                $verdict = Test-AddressAllowed $seen
                if ($null -eq $verdict) { $waiting = $true; $verdict = 'unknown' }
            } elseif ($done) { $note = Format-ProbeResult $j.Task.Result } else { $note = 'нет ответа' }
            $routes += [pscustomobject]@{ App = $j.App; Url = $j.Url; Seen = $seen; Verdict = $verdict; Note = $note; Time = $now }
        } else {
            if ($done) {
                foreach ($a in $j.Task.Result) { $ipObj = $null; if ($a -and [Net.IPAddress]::TryParse($a.Trim(), [ref]$ipObj) -and $a -match '[.:]') { $resolvers += $ipObj.ToString() } }
            } else { $dnsErrors += "$($j.Url): $(if ($j.Task.Exception) { $j.Task.Exception.GetBaseException().Message } else { 'нет ответа' })" }
        }
    }
    $resolvers = @($resolvers | Select-Object -Unique)
    $dnsVerdicts = @{}
    foreach ($ip in $resolvers) { $v = Test-AddressAllowed $ip; if ($null -eq $v) { $waiting = $true; $v = 'unknown' }; $dnsVerdicts[$ip] = $v }
    $v6 = 'off'
    if ($Cfg.check_ipv6) {
        switch ($script:ipv6Status) {
            'ok' { $v6 = Test-AddressAllowed $script:lastIpv6; if ($null -eq $v6) { $waiting = $true; $v6 = 'unknown' } }
            'unavailable' { $v6 = 'unavailable' }
            'unknown' { $v6 = 'unknown' }
        }
    }
    if ($waiting -and $elapsed -lt 12) { return }   # ждём страну для найденных адресов
    $script:extraPending = $null
    $script:routeResults = $routes
    $dnsState = if ($Cfg.dns_check -eq 'off') { 'off' } elseif (-not $resolvers.Count) { 'unknown' } elseif (@($dnsVerdicts.Values | ? { $_ -eq 'no' }).Count) { 'leak' } elseif (@($dnsVerdicts.Values | ? { $_ -ne 'yes' }).Count) { 'unknown' } else { 'ok' }
    $script:dnsResult = [pscustomobject]@{
        State = $dnsState; Time = $now; Errors = $dnsErrors
        Resolvers = @($resolvers | % { [pscustomobject]@{ Ip = $_; Country = $(if ($countryCache.ContainsKey($_)) { $countryCache[$_] } else { '' }); Verdict = $dnsVerdicts[$_] } })
    }
    $script:ipv6Verdict = $v6
    $problem = $null
    $leak = @($routes | ? { $_.Verdict -eq 'no' } | Select-Object -First 1)
    if ($leak.Count) { $problem = "Маршрут до $($leak[0].App) мимо защищённого соединения: сервис видит $($leak[0].Seen)" }
    elseif ($v6 -eq 'no') { $problem = "IPv6 мимо защищённого соединения: $script:lastIpv6" }
    elseif ($dnsState -eq 'leak' -and $Cfg.dns_check -eq 'block') { $problem = "DNS мимо защищённого соединения: $(($resolvers | ? { $dnsVerdicts[$_] -eq 'no' }) -join ', ')" }
    if ($dnsState -eq 'leak') {
        # резолверы одного провайдера меняют адреса: предупреждаем один раз на набор стран
        $key = (@($script:dnsResult.Resolvers | ? { $_.Verdict -eq 'no' } | % { $_.Country } | Sort-Object -Unique) -join ',')
        if ($key -ne $script:dnsWarned) {
            $script:dnsWarned = $key
            $list = ($script:dnsResult.Resolvers | ? { $_.Verdict -eq 'no' } | % { "$($_.Ip) $($_.Country)" }) -join ', '
            Log "DNS идёт мимо защищённого соединения: $list"
            if ($Cfg.dns_check -eq 'warn') { Notify "DNS-запросы идут мимо защищённого соединения ($list). Программы не блокируются: так настроено." 'Warning' }
        }
    } else { $script:dnsWarned = '' }
    $before = $script:extraProblem
    $script:extraProblem = $problem
    if ($problem) {
        if ($problem -ne $before) { Log "Доп. проверка: $problem" }
        if ($script:state -ne 'paused') { Set-Bad $problem }
    } elseif ($before) {
        Log 'Доп. проверки снова в порядке'
        Check-Now
    }
    $script:extraNext = $now.AddSeconds($(if ($problem) { 5 } else { 30 }))
}

$state = 'checking'      # checking | ok | bad | paused
$statusText = 'Проверка...'
$badSince = $null
$frozen = @{}
$lastIp = ''; $lastCountry = ''
$ProxyWhenGood = $null; $TunWhenGood = @()
$pending = $null
$nextCheck = Get-Date
$lastTickAt = $null

# ================= журнал заморозок (P02) =================
# Кого заморозил этот движок: PID + время создания. Если движок упадёт, следующий экземпляр
# примет эти процессы под контроль без повторной заморозки и разморозит их, когда VPN в порядке.
$StateDir = if ($SelfTest -or $Preview) { Join-Path $Here 'verification/state' } else { Join-Path $Here 'state' }
New-Item -ItemType Directory -Force $StateDir | Out-Null
$JournalPath = Join-Path $StateDir 'frozen.json'
$HeartbeatPath = Join-Path $StateDir 'engine-heartbeat.txt'
function Save-Journal {
    $entries = @(foreach ($id in @($frozen.Keys)) {
        $e = $frozen[$id]
        if ($e -is [hashtable]) { [ordered]@{ pid = [int]$id; name = [string]$e.Name; start = [int64]$e.Start } }
    })
    $tmp = "$JournalPath.tmp"
    try {
        ConvertTo-Json -InputObject @($entries) -Depth 3 | Set-Content -Path $tmp -Encoding UTF8
        Move-Item -Path $tmp -Destination $JournalPath -Force
    } catch { Log "Журнал заморозок не записан: $($_.Exception.Message)" }
}
function Restore-Journal {
    if (-not (Test-Path $JournalPath)) { return 0 }
    $adopted = 0
    # PS 5.1 отдаёт JSON-массив одним объектом: разворачиваем явно
    try { $items = @((Get-Content $JournalPath -Raw -Encoding UTF8 | ConvertFrom-Json) | % { $_ }) }
    catch { Log "Журнал заморозок повреждён, пропускаю: $($_.Exception.Message)"; $items = @() }
    foreach ($it in $items) {
        if (-not $it -or -not $it.pid) { continue }
        try { $p = [Diagnostics.Process]::GetProcessById([int]$it.pid); $st = $p.StartTime.Ticks } catch { continue }
        if ($st -ne [int64]$it.start) { Log "Журнал: PID $($it.pid) теперь другой процесс, не трогаю"; continue }
        $frozen[[int]$it.pid] = @{ Name = [string]$it.name; Start = $st }
        $adopted++
        Log "После сбоя принят под контроль замороженный $($it.name) ($($it.pid))"
    }
    Save-Journal
    return $adopted
}
function Write-EngineHeartbeat {
    try { [IO.File]::WriteAllText($HeartbeatPath, "$PID $([DateTime]::UtcNow.Ticks)") } catch {}
}

function Get-TargetProcs {
    $names = @($Apps)
    $processes = @{}
    $selected = @{}
    $script:processOwners = @{}
    foreach ($process in [Diagnostics.Process]::GetProcesses()) {
        $processes[$process.Id] = $process
        if ($process.Id -ne $PID -and $names -contains $process.ProcessName.ToLower()) {
            $selected[$process.Id] = $process
            $script:processOwners[$process.Id] = $process.ProcessName.ToLower()
        }
    }
    $parents = [VPNGuardProcessTree]::Parents()
    do {
        $added = $false
        foreach ($childId in $parents.Keys) {
            $parentId = $parents[$childId]
            if ($childId -eq $PID -or $selected.ContainsKey($childId) -or -not $selected.ContainsKey($parentId) -or -not $processes.ContainsKey($childId)) { continue }
            try {
                if ($processes[$childId].StartTime -lt $selected[$parentId].StartTime) { continue }
                $selected[$childId] = $processes[$childId]
                $script:processOwners[$childId] = $script:processOwners[$parentId]
                $added = $true
            } catch { }
        }
    } while ($added)
    return $selected.Values
}
function Freeze-All($Processes = @(Get-TargetProcs)) {
    foreach ($p in $Processes) {
        if ($frozen.ContainsKey($p.Id)) { continue }
        if ($DryRun) { Log "[тест] заморозил бы $($p.ProcessName) ($($p.Id))"; $frozen[$p.Id] = $p.ProcessName; continue }
        try { $rc = [VGNt]::NtSuspendProcess($p.Handle); if ($rc -ne 0) { throw "NtSuspendProcess: $rc" }; $frozen[$p.Id] = @{ Name=$p.ProcessName; Start=$p.StartTime.Ticks }; Log "Заморожено: $($p.ProcessName) ($($p.Id))" }
        catch { Log "Не удалось заморозить $($p.ProcessName): $($_.Exception.Message)" }
    }
    Save-Journal
}
function Kill-All($Processes = @(Get-TargetProcs)) {
    foreach ($p in $Processes) {
        if ($DryRun) { Log "[тест] закрыл бы $($p.ProcessName) ($($p.Id))"; continue }
        try { $p.Kill(); Log "Закрыто: $($p.ProcessName) ($($p.Id))" } catch {}
        $frozen.Remove($p.Id)
    }
    Save-Journal
}
function Resume-All {
    $live = @{}
    if (-not $DryRun -and $frozen.Count -gt 0) { foreach ($proc in [Diagnostics.Process]::GetProcesses()) { $live[$proc.Id] = $proc } }
    foreach ($id in @($frozen.Keys)) {
        if (-not $DryRun) {
            $p = $live[$id]
            if ($p) {
                try { if ($p.StartTime.Ticks -eq $frozen[$id].Start) { $rc = [VGNt]::NtResumeProcess($p.Handle); if ($rc -ne 0) { throw "NtResumeProcess: $rc" } } }
                catch { Log "Ошибка возобновления PID ${id}: $($_.Exception.Message)"; continue }
            }
        }
        $processLabel = if ($DryRun) { $frozen[$id] } else { $frozen[$id].Name }
        Log "Разморожено: $processLabel ($id)"
        $frozen.Remove($id)
    }
    Save-Journal
}
function Enforce {
    if ($script:state -eq 'checking') { Freeze-All; return }
    if ($script:state -ne 'bad') { return }
    $elapsed = ((Get-Date) - $script:badSince).TotalSeconds
    foreach ($p in @(Get-TargetProcs)) {
        $owner = $script:processOwners[$p.Id]
        if (-not $owner) { $owner = $p.ProcessName.ToLower() }
        $action = Get-AppAction $owner $elapsed
        if ($action -eq 'kill') { Kill-All @($p) } else { Freeze-All @($p) }
    }
}

function Get-AppAction($name, $elapsed) {
    $mode = $Cfg.app_actions[$name]
    if ($mode -eq 'freeze') { return 'freeze' }
    if ($mode -eq 'kill') { return 'kill' }
    if ($mode -eq 'grace') { $delay = if ($Cfg.grace_sec -gt 0) { $Cfg.grace_sec } else { 20 }; if ($elapsed -ge $delay) { return 'kill' }; return 'freeze' }
    if ($Cfg.kill_after_grace -and $elapsed -ge $Cfg.grace_sec) { return 'kill' }
    return 'freeze'
}
function Action-Word {
    if (-not $Cfg.kill_after_grace) { 'на паузе' } elseif ($Cfg.grace_sec -le 0) { 'закрыты' } else { "на паузе, через $($Cfg.grace_sec) с закроются" }
}
function Set-Bad($why) {
    if ($script:state -ne 'bad') {
        $script:incidentCount++
        Log "Соединение пропало: $why"
        Notify "Защищённое соединение пропало ($why). Применены правила защиты приложений." 'Warning'
        $script:badSince = Get-Date
    }
    $script:state = 'bad'
    $script:statusText = "Блок: $why"
    Enforce
    $script:nextCheck = (Get-Date).AddSeconds(2)
    Update-Ui
}
function Set-Good($ip, $cc) {
    # P04: подтверждённая утечка маршрута/IPv6/DNS не снимается, пока доп. проверка не пройдёт
    if ($script:extraProblem) { Set-Bad $script:extraProblem; return }
    if ($script:state -eq 'bad') { Log "Соединение вернулось: $ip $cc"; Notify 'Соединение снова защищено, программы разблокированы' }
    $script:badSince = $null
    $script:state = 'ok'
    $script:statusText = "Защита включена"
    $px = Get-Proxy
    $script:ProxyWhenGood = $(if ($px -and (Test-ProxyAlive $px)) { $px } else { $null })
    $script:TunWhenGood = @(Get-TunAdapters)
    Resume-All
    Update-Ui
}

function Quick-Check {
    if ($script:state -eq 'paused') { return }
    if ([VPNGuardNetworkMonitor]::ConsumeChange()) {
        $script:pending = $null
        $script:countryPending = $null
        $script:extraPending = $null; $script:extraNext = Get-Date
        $script:state = 'checking'
        $script:statusText = 'Сеть изменилась: проверяем выходной адрес'
        $script:nextCheck = Get-Date
        Freeze-All
        Update-Ui
        return
    }
    if ($script:state -ne 'ok') { return }
    $why = $null
    if (-not [System.Net.NetworkInformation.NetworkInterface]::GetIsNetworkAvailable()) { $why = 'сеть пропала' }
    elseif ($Cfg.watch_proxy -and $script:TunWhenGood.Count -gt 0) {
        $now = @(Get-TunAdapters)
        if (@($script:TunWhenGood | ? { $now -notcontains $_ }).Count -gt 0) { $why = 'Адаптер туннеля (TUN) отключился' }
    }
    if (-not $why -and $Cfg.watch_proxy -and $script:ProxyWhenGood) {
        $cur = Get-Proxy
        if (-not $cur) { $why = 'Прокси туннеля выключен' }
        elseif ($cur -ne $script:ProxyWhenGood) { $why = "прокси сменился на $cur" }
        elseif (-not (Test-ProxyAlive $cur)) { $why = 'Туннель не отвечает (порт прокси закрыт)' }
    }
    if ($why) { $script:pending = $null; $script:countryPending = $null; Set-Bad $why }
}

# проверка внешнего IP без подвисания окна: запросы идут в фоне, результат забираем таймером
function Start-IpCheck {
    # P03: каждая проба знает источник, маршрут (system/direct/http/socks5), семейство и время.
    $route = $Cfg.probe_route
    $jobs = @()
    foreach ($u in $Cfg.ip_services) { $jobs += [pscustomobject]@{ Url = $u; Family = 'v4'; Task = [VGProbe]::Start($u, $route, 'v4', 5000) } }
    if ($Cfg.check_ipv6) { foreach ($u in $Cfg.ipv6_services) { $jobs += [pscustomobject]@{ Url = $u; Family = 'v6'; Task = [VGProbe]::Start($u, $route, 'v6', 5000) } } }
    $script:pending = @{ tasks = $jobs; t0 = Get-Date }
}
function Format-ProbeResult($r) {
    switch ($r.Status) {
        'ok'          { return $r.Value }
        'invalid'     { return 'Некорректный ответ' }
        'timeout'     { return 'Таймаут' }
        'unavailable' { return 'IPv6 недоступен' }
        default       { return "Ошибка: $($r.Error)" }
    }
}
function Poll-IpCheck {
    if (-not $script:pending) { return }
    $jobs = @($script:pending.tasks)
    $done = @($jobs | ? { $_.Task.IsCompleted }).Count
    if ($done -lt $jobs.Count -and ((Get-Date) - $script:pending.t0).TotalSeconds -lt 6) { return }
    $script:pending = $null
    $script:lastChecked = Get-Date; $script:checkCount++
    $rows = @(); $ips = @(); $v6 = @()
    foreach ($j in $jobs) {
        if ($j.Task.Status -eq 'RanToCompletion') { $r = $j.Task.Result }
        else {
            $r = New-Object VGProbeResult
            $r.Source = $j.Url; $r.Route = $Cfg.probe_route; $r.Family = $j.Family; $r.Status = 'timeout'; $r.Error = 'нет ответа за 6 с'
        }
        if ($r.Status -eq 'ok') { if ($r.Family -eq 'v6') { $v6 += $r.Value } else { $ips += $r.Value } }
        $rows += [pscustomobject]@{
            Service = $r.Source; Family = $r.Family; Status = $r.Status; Result = (Format-ProbeResult $r)
            Route = $(if ($r.RouteUsed) { $r.RouteUsed } else { $r.Route })
            Time = $(if ($r.FinishedUtc -gt [datetime]::MinValue) { $r.FinishedUtc.ToLocalTime() } else { Get-Date })
            Ms = $r.ElapsedMs
        }
    }
    $script:serviceResults = $rows
    $g6 = @($v6 | Group-Object | Sort-Object Count -Descending)
    $script:lastIpv6 = $(if ($g6.Count) { $g6[0].Name } else { '' })
    $v6rows = @($rows | ? { $_.Family -eq 'v6' })
    $script:ipv6Status = $(if ($v6.Count) { 'ok' } elseif (@($v6rows | ? { $_.Status -eq 'unavailable' }).Count) { 'unavailable' } elseif ($v6rows.Count) { 'unknown' } else { 'off' })
    Finish-Check $ips
    $script:nextCheck = (Get-Date).AddSeconds($(if ($script:state -eq 'bad') { 2 } else { $Cfg.interval_sec }))
}
function Finish-Check($ips) {
    if ($script:state -eq 'paused') { return }
    if ($ForceBad) { Set-Bad 'тест: соединение считается незащищённым'; return }
    $groups = @($ips | Group-Object | Sort-Object Count -Descending)
    if ($groups.Count -eq 0) { Set-Bad 'нет интернета / IP не узнать'; return }
    $ip = $groups[0].Name
    if ($ip -ne $script:lastIp) { Log "IP: $ip"; $script:lastIp = $ip; $script:lastCountry = '' }
    if ($groups.Count -gt 1) { Set-Bad 'сервисы видят разные IP: требуется проверка маршрутов'; return }
    if ($groups[0].Count -lt 2) { Set-Bad 'ответил только один сервис проверки'; return }
    if ($countryCache.ContainsKey($ip)) { $script:lastCountry = $countryCache[$ip]; Resolve-Address $ip $script:lastCountry; return }
    # An explicitly allowed address does not depend on geolocation availability.
    foreach ($rule in $Cfg.allow_ips) { if (Test-IpRule $ip $rule) { Set-Good $ip ''; Start-CountryCheck $ip; return } }
    if ($script:state -eq 'ok') { Set-Bad 'Новый адрес: проверяется страна' }
    Start-CountryCheck $ip
}

function Check-Now {
    if ($script:state -eq 'paused') { return }
    if (-not $script:pending -and -not $script:countryPending) { Start-IpCheck }
}

# ================= трей =================
function Make-Icon($color) {
    $bmp = New-Object System.Drawing.Bitmap 16, 16
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'
    $g.FillEllipse((New-Object System.Drawing.SolidBrush $color), 1, 1, 14, 14)
    $g.DrawEllipse((New-Object System.Drawing.Pen ([System.Drawing.Color]::Black)), 1, 1, 14, 14)
    $g.Dispose()
    [System.Drawing.Icon]::FromHandle($bmp.GetHicon())
}
$Colors = @{
    ok       = [System.Drawing.Color]::FromArgb(34, 160, 70)
    bad      = [System.Drawing.Color]::FromArgb(210, 40, 40)
    checking = [System.Drawing.Color]::FromArgb(220, 170, 0)
    paused   = [System.Drawing.Color]::Gray
}
$icons = @{}; foreach ($k in $Colors.Keys) { $icons[$k] = Make-Icon $Colors[$k] }

$tray = New-Object System.Windows.Forms.NotifyIcon
$tray.Icon = $icons.checking
$tray.Visible = $true
$menu = New-Object System.Windows.Forms.ContextMenuStrip
$miStatus = $menu.Items.Add('Проверка...'); $miStatus.Enabled = $false
[void]$menu.Items.Add('-')
$miOpen = $menu.Items.Add('Открыть AiGuard'); $miOpen.Font = New-Object System.Drawing.Font($miOpen.Font, [System.Drawing.FontStyle]::Bold)
$miPause = $menu.Items.Add('Пауза защиты')
[void]$menu.Items.Add('-')
$miExit = $menu.Items.Add('Выход')
$tray.ContextMenuStrip = $menu

function Notify($text, $tip = 'Info') {
    if ($SelfTest -or $Preview) { return }
    if (-not $Cfg.notifications) { return }
    $tray.BalloonTipTitle = 'AiGuard'; $tray.BalloonTipText = $text; $tray.BalloonTipIcon = $tip
    $tray.ShowBalloonTip(4000)
}

# ================= окно =================
$F = New-Object System.Drawing.Font('Segoe UI', 10)
$FB = New-Object System.Drawing.Font('Segoe UI', 13, [System.Drawing.FontStyle]::Bold)
$FS = New-Object System.Drawing.Font('Segoe UI', 9)
function New-Ctl($type, $x, $y, $w, $h, $text = $null) {
    $c = New-Object "System.Windows.Forms.$type"
    $c.Location = New-Object System.Drawing.Point($x, $y)
    $c.Size = New-Object System.Drawing.Size($w, $h)
    if ($null -ne $text) { $c.Text = $text }
    $c
}
function New-Hint($parent, $x, $y, $w, $h, $text) {
    $l = New-Ctl Label $x $y $w $h $text; $l.Font = $FS; $l.ForeColor = [System.Drawing.Color]::DimGray; $parent.Controls.Add($l); $l
}

$form = New-Object System.Windows.Forms.Form
$form.Text = 'AiGuard - защита при обрыве соединения'
$form.Font = $F
$form.ClientSize = New-Object System.Drawing.Size(600, 560)
$form.FormBorderStyle = 'FixedSingle'; $form.MaximizeBox = $false
$form.StartPosition = 'CenterScreen'
$form.Icon = $icons.ok

# --- статус сверху
$pnl = New-Ctl Panel 0 0 600 92; $pnl.BackColor = [System.Drawing.Color]::FromArgb(245, 246, 248); $form.Controls.Add($pnl)
$dot = New-Ctl Panel 16 18 22 22; $pnl.Controls.Add($dot)
$lblState = New-Ctl Label 46 14 360 28 'Проверка...'; $lblState.Font = $FB; $pnl.Controls.Add($lblState)
$lblIp = New-Ctl Label 46 46 380 40 ''; $lblIp.Font = $FS; $pnl.Controls.Add($lblIp)
$btnPause = New-Ctl Button 420 14 164 32 'Пауза защиты'; $pnl.Controls.Add($btnPause)
$btnCheck = New-Ctl Button 420 50 164 30 'Проверить сейчас'; $btnCheck.Font = $FS; $pnl.Controls.Add($btnCheck)

$tabs = New-Ctl TabControl 10 100 580 404; $form.Controls.Add($tabs)
$tApps = New-Object System.Windows.Forms.TabPage 'Программы'
$tAllow = New-Object System.Windows.Forms.TabPage 'Где можно работать'
$tBeh = New-Object System.Windows.Forms.TabPage 'Поведение'
$tLog = New-Object System.Windows.Forms.TabPage 'Журнал'
$tabs.TabPages.AddRange(@($tApps, $tAllow, $tBeh, $tLog))

# --- вкладка Программы
New-Hint $tApps 12 10 550 36 'Отмеченные программы закрываются, когда защищённое соединение пропадает, и не запускаются, пока оно не вернётся.' | Out-Null
$clbApps = New-Ctl CheckedListBox 12 50 548 220; $clbApps.CheckOnClick = $true; $tApps.Controls.Add($clbApps)
$lblAdd = New-Ctl Label 12 282 300 22 'Добавить свою программу (имя процесса):'; $lblAdd.Font = $FS; $tApps.Controls.Add($lblAdd)
$cbProc = New-Ctl ComboBox 12 306 330 28; $cbProc.DropDownStyle = 'DropDown'; $tApps.Controls.Add($cbProc)
$btnAddApp = New-Ctl Button 350 304 100 30 'Добавить'; $tApps.Controls.Add($btnAddApp)
$btnDelApp = New-Ctl Button 458 304 102 30 'Убрать'; $tApps.Controls.Add($btnDelApp)
New-Hint $tApps 12 340 550 30 'В списке - запущенные сейчас программы. Можно выбрать или вписать имя без .exe.' | Out-Null

# --- вкладка Где можно работать
New-Hint $tAllow 12 8 550 36 'Программы работают, только если внешний IP есть в списке ИЛИ его страна разрешена. Остальное считается обрывом соединения.' | Out-Null
$g1 = New-Ctl GroupBox 12 46 268 318 'Разрешённые IP'; $tAllow.Controls.Add($g1)
$lbIps = New-Ctl ListBox 10 24 248 180; $g1.Controls.Add($lbIps)
$tbIp = New-Ctl TextBox 10 210 160 28; $g1.Controls.Add($tbIp)
$btnAddIp = New-Ctl Button 176 208 82 30 'Добавить'; $g1.Controls.Add($btnAddIp)
$btnCurIp = New-Ctl Button 10 244 248 30 'Добавить текущий IP'; $g1.Controls.Add($btnCurIp)
$btnDelIp = New-Ctl Button 10 278 248 30 'Убрать выбранный'; $g1.Controls.Add($btnDelIp)
$g2 = New-Ctl GroupBox 290 46 268 318 'Разрешённые страны'; $tAllow.Controls.Add($g2)
$lbCc = New-Ctl ListBox 10 24 248 180; $g2.Controls.Add($lbCc)
$cbCc = New-Ctl ComboBox 10 210 160 28; $cbCc.DropDownStyle = 'DropDownList'
foreach ($k in $CountryNames.Keys) { [void]$cbCc.Items.Add((Country-Label $k)) }; $g2.Controls.Add($cbCc)
$btnAddCc = New-Ctl Button 176 208 82 30 'Добавить'; $g2.Controls.Add($btnAddCc)
$btnCurCc = New-Ctl Button 10 244 248 30 'Добавить текущую страну'; $g2.Controls.Add($btnCurCc)
$btnDelCc = New-Ctl Button 10 278 248 30 'Убрать выбранную'; $g2.Controls.Add($btnDelCc)

# --- вкладка Поведение
$g3 = New-Ctl GroupBox 12 10 548 150 'Что делать, когда соединение пропало'; $tBeh.Controls.Add($g3)
$rbKill = New-Ctl RadioButton 14 26 520 26 'Закрывать программы сразу'; $g3.Controls.Add($rbKill)
$rbGrace = New-Ctl RadioButton 14 58 250 26 'Сначала пауза, закрыть через'; $g3.Controls.Add($rbGrace)
$nudGrace = New-Ctl NumericUpDown 268 58 64 26; $nudGrace.Minimum = 1; $nudGrace.Maximum = 600; $nudGrace.Value = 20; $g3.Controls.Add($nudGrace)
$lblSec = New-Ctl Label 338 60 60 24 'секунд'; $g3.Controls.Add($lblSec)
$rbFreeze = New-Ctl RadioButton 14 90 520 26 'Только пауза, не закрывать (оживут, когда соединение вернётся)'; $g3.Controls.Add($rbFreeze)
New-Hint $g3 32 118 500 24 'Пауза: окно программы замирает, но данные не теряются.' | Out-Null

$chkProxy = New-Ctl CheckBox 14 172 548 26 'Мгновенно ловить обрыв (следить за прокси Happ / Hiddify и TUN-адаптером)'; $tBeh.Controls.Add($chkProxy)
$lblInt = New-Ctl Label 14 206 196 24 'Сверять внешний IP каждые'; $tBeh.Controls.Add($lblInt)
$nudInt = New-Ctl NumericUpDown 214 204 60 26; $nudInt.Minimum = 3; $nudInt.Maximum = 60; $tBeh.Controls.Add($nudInt)
$lblInt2 = New-Ctl Label 280 206 80 24 'секунд'; $tBeh.Controls.Add($lblInt2)
$chkAuto = New-Ctl CheckBox 14 244 548 26 'Запускать вместе с Windows'; $tBeh.Controls.Add($chkAuto)
$chkNotify = New-Ctl CheckBox 14 276 548 26 'Показывать уведомления'; $tBeh.Controls.Add($chkNotify)
New-Hint $tBeh 14 312 548 50 'Если AiGuard упадёт, он перезапустится сам. Совсем выключить - пункт «Выход» в меню значка у часов.' | Out-Null

# --- вкладка Журнал
$tbLog = New-Ctl TextBox 8 8 556 320; $tbLog.Multiline = $true; $tbLog.ReadOnly = $true; $tbLog.ScrollBars = 'Vertical'
$tbLog.Font = New-Object System.Drawing.Font('Consolas', 9); $tbLog.BackColor = [System.Drawing.Color]::White; $tLog.Controls.Add($tbLog)
$btnLogRef = New-Ctl Button 8 334 140 30 'Обновить'; $tLog.Controls.Add($btnLogRef)
$btnLogOpen = New-Ctl Button 156 334 160 30 'Открыть файлом'; $tLog.Controls.Add($btnLogOpen)

# --- низ
$lblSaved = New-Ctl Label 12 518 300 26 ''; $lblSaved.ForeColor = $Colors.ok; $form.Controls.Add($lblSaved)
$btnSave = New-Ctl Button 362 512 112 36 'Сохранить'; $form.Controls.Add($btnSave)
$btnClose = New-Ctl Button 480 512 108 36 'Закрыть'; $form.Controls.Add($btnClose)
$form.AcceptButton = $btnSave
. (Join-Path $Here 'Interface.ps1')

function Refresh-Log {
    if (-not (Test-Path -LiteralPath $LogPath)) { $tbLog.Text = ''; return }
    try { $tbLog.Lines = @(Get-Content $LogPath -Encoding UTF8 -Tail 300); $tbLog.SelectionStart = $tbLog.TextLength; $tbLog.ScrollToCaret() } catch { $tbLog.Text = '' }
}
function Fill-Form {
    $script:editActions = @{}
    foreach ($key in $Cfg.app_actions.Keys) { $script:editActions[$key] = $Cfg.app_actions[$key] }
    $clbApps.Items.Clear()
    foreach ($k in $Presets.Keys) { $i = $clbApps.Items.Add("$($Presets[$k])  [$k]"); $clbApps.SetItemChecked($i, ($Cfg.apps -contains $k)) }
    foreach ($a in $Cfg.apps) { if (-not $Presets.Contains($a)) { $i = $clbApps.Items.Add("$a  [$a]"); $clbApps.SetItemChecked($i, $true) } }
    $cbProc.Items.Clear()
    Get-Process | % { $_.ProcessName.ToLower() } | Sort-Object -Unique | % { [void]$cbProc.Items.Add($_) }
    $lbIps.Items.Clear(); foreach ($x in $Cfg.allow_ips) { [void]$lbIps.Items.Add($x) }
    $lbCc.Items.Clear(); foreach ($x in $Cfg.allow_countries) { [void]$lbCc.Items.Add((Country-Label $x)) }
    if (-not $Cfg.kill_after_grace) { $rbFreeze.Checked = $true }
    elseif ($Cfg.grace_sec -le 0) { $rbKill.Checked = $true }
    else { $rbGrace.Checked = $true; $nudGrace.Value = [Math]::Min(600, $Cfg.grace_sec) }
    $chkProxy.Checked = $Cfg.watch_proxy
    $nudInt.Value = [Math]::Min(60, [Math]::Max(3, $Cfg.interval_sec))
    $chkAuto.Checked = Get-Autostart
    $chkNotify.Checked = $Cfg.notifications
    $lblSaved.Text = ''
    Refresh-Log
}
function Read-Form {
    $apps = @()
    for ($i = 0; $i -lt $clbApps.Items.Count; $i++) {
        if ($clbApps.GetItemChecked($i) -and $clbApps.Items[$i] -match '\[([^\]]+)\]$') { $apps += $Matches[1] }
    }
    $Cfg.app_actions = @{}
    foreach ($key in $script:editActions.Keys) { $Cfg.app_actions[$key] = $script:editActions[$key] }
    $Cfg.apps = $apps
    $Cfg.allow_ips = @($lbIps.Items | % { [string]$_ })
    $Cfg.allow_countries = @($lbCc.Items | % { ([string]$_).Substring(0, 2) })
    if ($rbKill.Checked) { $Cfg.kill_after_grace = $true; $Cfg.grace_sec = 0 }
    elseif ($rbGrace.Checked) { $Cfg.kill_after_grace = $true; $Cfg.grace_sec = [int]$nudGrace.Value }
    else { $Cfg.kill_after_grace = $false; $Cfg.grace_sec = 0 }
    $Cfg.watch_proxy = $chkProxy.Checked
    $Cfg.interval_sec = [int]$nudInt.Value
    $Cfg.notifications = $chkNotify.Checked
    if (-not $Targets) { $script:Apps = $Cfg.apps }
}
function Show-Settings {
    if (-not $form.Visible) { Fill-Form }; Update-Ui
    $form.Show(); $form.WindowState = 'Normal'; $form.Activate(); $form.BringToFront()
}

$btnAddApp.Add_Click({
    $n = $cbProc.Text.Trim().ToLower() -replace '\.exe$', ''
    if (-not $n) { return }
    for ($i = 0; $i -lt $clbApps.Items.Count; $i++) { if (([string]$clbApps.Items[$i]).EndsWith("[$n]")) { $clbApps.SetItemChecked($i, $true); return } }
    $i = $clbApps.Items.Add("$n  [$n]"); $clbApps.SetItemChecked($i, $true); $cbProc.Text = ''
})
$btnDelApp.Add_Click({
    $i = $clbApps.SelectedIndex
    if ($i -lt 0) { return }
    if ($clbApps.Items[$i] -match '\[([^\]]+)\]$' -and $Presets.Contains($Matches[1])) { $clbApps.SetItemChecked($i, $false) } else { $clbApps.Items.RemoveAt($i) }
})
$addIp = { param($v) $v = $v.Trim(); if ((Test-IpRule ($v.Split('/')[0]) $v) -and -not $lbIps.Items.Contains($v)) { [void]$lbIps.Items.Add($v) } elseif ($v) { [System.Windows.Forms.MessageBox]::Show('Введите корректный IP или подсеть CIDR; дубликаты уже есть в списке.', 'AiGuard') | Out-Null } }
$btnAddIp.Add_Click({ & $addIp $tbIp.Text; $tbIp.Text = '' })
$btnCurIp.Add_Click({ if ($script:lastIp) { & $addIp $script:lastIp } })
$btnDelIp.Add_Click({ if ($lbIps.SelectedIndex -ge 0) { $lbIps.Items.RemoveAt($lbIps.SelectedIndex) } })
$addCc = { param($cc) if (-not $cc) { return }; $lbl = Country-Label $cc; if (-not $lbCc.Items.Contains($lbl)) { [void]$lbCc.Items.Add($lbl) } }
$btnAddCc.Add_Click({ if ($cbCc.SelectedItem) { & $addCc ([string]$cbCc.SelectedItem).Substring(0, 2) } })
$btnCurCc.Add_Click({ if ($script:lastCountry) { & $addCc $script:lastCountry } })
$btnDelCc.Add_Click({ if ($lbCc.SelectedIndex -ge 0) { $lbCc.Items.RemoveAt($lbCc.SelectedIndex) } })
$btnLogRef.Add_Click({ Refresh-Log })
$btnLogOpen.Add_Click({ Start-Process notepad.exe $LogPath })
$tabs.Add_SelectedIndexChanged({ if ($tabs.SelectedTab -eq $tLog) { Refresh-Log } })

$btnSave.Add_Click({
    if ($lbIps.Items.Count -eq 0 -and $lbCc.Items.Count -eq 0) {
        $r = [System.Windows.Forms.MessageBox]::Show('Не разрешено ни одного IP и ни одной страны - защищённые программы будут закрыты всегда. Сохранить?', 'AiGuard', 'YesNo', 'Warning')
        if ($r -ne 'Yes') { return }
    }
    Read-Form
    try { Save-Config; Set-Autostart $chkAuto.Checked; Log 'Настройки сохранены'; $lblSaved.Text = 'Сохранено ' + (Get-Date -Format 'HH:mm:ss') }
    catch { [System.Windows.Forms.MessageBox]::Show("Не удалось сохранить: $($_.Exception.Message)", 'AiGuard') | Out-Null; return }
    # Новые галочки в «Приложениях» сразу попадают под аварийный выключатель (без нового запроса прав).
    if ((Test-FwOn) -and -not $script:fwPending) { [void](Invoke-FwChange 'Sync') }
    elseif (-not $Cfg.firewall_asked -and @($Apps).Count -gt 0) { Ask-FirstRunFirewall }
    if ($script:state -ne 'paused') { Check-Now }
})
$btnClose.Add_Click({ $form.Hide() })
$form.Add_FormClosing({ param($s, $e) if ($e.CloseReason -eq 'UserClosing') { $e.Cancel = $true; $form.Hide() } })

function Toggle-Pause {
    if ($script:state -eq 'paused') {
        $script:pauseUntil = $null
        $script:state = 'checking'; $script:statusText = 'Проверка...'; Log 'Защита снова включена'
        $script:nextCheck = Get-Date; Update-Ui
    } else {
        $script:pending = $null; $script:countryPending = $null
        $minutes = @(5,15,30,0)[$cbPause.SelectedIndex]
        $script:pauseUntil = if ($minutes -gt 0) { (Get-Date).AddMinutes($minutes) } else { $null }
        Resume-All; $script:badSince = $null
        $script:state = 'paused'; $script:statusText = 'Защита на паузе'; Log 'Защита на паузе'
        Update-Ui
    }
}
function Update-PauseDeadline {
    if ($script:state -eq 'paused' -and $script:pauseUntil -and (Get-Date) -ge $script:pauseUntil) { Toggle-Pause }
}
$btnPause.Add_Click({ Toggle-Pause })
$btnCheck.Add_Click({ if ($script:state -eq 'paused') { return }; $lblIp.Text = 'Проверяю...'; Check-Now })

function Update-Ui {
    $tray.Icon = $icons[$script:state]
    $t = "AiGuard: $script:statusText"; if ($t.Length -gt 63) { $t = $t.Substring(0, 63) }
    $tray.Text = $t
    $miStatus.Text = $script:statusText
    $miPause.Text = $(if ($script:state -eq 'paused') { 'Включить защиту' } else { 'Пауза защиты' })
    $btnPause.Text = $miPause.Text
    $dot.BackColor = $Colors[$script:state]
    $lblState.Text = $script:statusText
    $lblState.ForeColor = $(if ($script:state -eq 'bad') { $Colors.bad } else { [System.Drawing.Color]::FromArgb(232,238,247) })
    $ipLine = $(if ($script:lastIp) { "IP: $script:lastIp" + $(if ($script:lastCountry) { ", $(Country-Label $script:lastCountry)" } else { '' }) } else { 'IP: ещё не известен' })
    $prot = $(if ($Apps.Count) { ($Apps | % { if ($Presets.Contains($_)) { ($Presets[$_] -split ' ')[0] } else { $_ } }) -join ', ' } else { 'ничего не выбрано' })
    $lblIp.Text = $ipLine
    Update-Dashboard
}

$miOpen.Add_Click({ Show-Settings })
$tray.Add_DoubleClick({ Show-Settings })
$miPause.Add_Click({ Toggle-Pause })
$miExit.Add_Click({
    Resume-All; Log 'AiGuard выключен'
    $tray.Visible = $false
    [System.Windows.Forms.Application]::Exit()
})

# ================= главный таймер (0,25 с) =================
$tick = 0
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 250
$timer.Add_Tick({
    try {
        $script:tick++
        $tickNow = Get-Date
        if ($script:lastTickAt -and ($tickNow - $script:lastTickAt).TotalSeconds -gt 5 -and $script:state -ne 'paused') {
            Log ("Таймер стоял {0:N0} с (сон или зависание): перепроверяю соединение" -f ($tickNow - $script:lastTickAt).TotalSeconds)
            [VPNGuardNetworkMonitor]::Signal()
        }
        $script:lastTickAt = $tickNow
        if ($script:tick % 8 -eq 0) { Write-EngineHeartbeat }
        if ($quitEvent.WaitOne(0)) {
            $timer.Stop(); Resume-All; Log 'Штатное завершение по сигналу перезапуска'
            $tray.Visible = $false; [System.Windows.Forms.Application]::Exit(); return
        }
        if ($showEvent.WaitOne(0)) { Show-Settings }
        Update-PauseDeadline
        if ((Get-Date) -ge $script:fwNext) { $script:fwStatus = Read-VGFwStatus $FwStatusPath; $script:fwNext = (Get-Date).AddSeconds(30) }
        Poll-FwChange
        if ($script:fwAskAt -and (Get-Date) -ge $script:fwAskAt) { $script:fwAskAt = $null; Ask-FirstRunFirewall }
        if ($script:tick % 4 -eq 0) { Update-Dashboard }
        if ($script:state -eq 'paused') { return }
        # Invalidate pre-change responses before any request can release processes.
        Quick-Check
        Poll-CountryCheck
        Poll-IpCheck
        Poll-ExtraChecks
        if (-not $script:extraPending -and $script:state -in @('ok','bad') -and (Get-Date) -ge $script:extraNext) { Start-ExtraChecks }
        if (-not $script:pending -and -not $script:countryPending -and (Get-Date) -ge $script:nextCheck) { Start-IpCheck }
        if ($script:tick % 2 -eq 0) {
            Enforce
            $it = Get-Item $ConfigPath -ErrorAction SilentlyContinue
            if ($it -and $it.LastWriteTime -ne $script:cfgStamp) { try { Load-Config; Log 'config.json перечитан' } catch {} }
        }
    } catch { Log "Ошибка: $($_.Exception.Message)" }
})

if ($SelfTest -or $Preview) { . (Join-Path $Here 'Verify.ps1'); exit 0 }

Log ("AiGuard запущен. Защищаю: {0}. Разрешено: IP {1}; страны {2}{3}" -f ($Apps -join ', '), ($Cfg.allow_ips -join ', '), ($Cfg.allow_countries -join ', '), $(if ($DryRun) { ' [ТЕСТ]' } else { '' }))
$adoptedAfterCrash = Restore-Journal
if ($adoptedAfterCrash -gt 0) { Notify "AiGuard перезапущен после сбоя. Программ на паузе: $adoptedAfterCrash, разморожу после проверки соединения." 'Warning' }
Write-EngineHeartbeat
Update-Ui
Start-IpCheck
[VPNGuardNetworkMonitor]::Start()
$fwStatus = Read-VGFwStatus $FwStatusPath
if (-not $Cfg.firewall_asked -and -not ($fwStatus -and $fwStatus.installed -ne $false -and @($fwStatus.rules).Count)) { $fwAskAt = (Get-Date).AddSeconds(4) }
$timer.Start()
if (-not $Background) { Show-Settings }
try { [System.Windows.Forms.Application]::Run() }
finally { $timer.Stop(); [VPNGuardNetworkMonitor]::Stop(); $http.Dispose(); Resume-All; $tray.Visible = $false; try { $mutex.ReleaseMutex() } catch {} }
exit 0
