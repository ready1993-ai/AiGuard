# VPNGuard - сторож движка (P02).
# Запускает VPNGuard.ps1 и следит за ним:
#  - движок упал (код не 0 и не 3) - перезапуск через пару секунд; новый движок сам примет
#    замороженные программы из журнала state\frozen.json и разморозит их после проверки VPN;
#  - движок завис (heartbeat не обновлялся HangSec секунд) - снять и перезапустить;
#  - 5 сбоев подряд за 2 минуты - закрыть программы из журнала (защита не должна оставлять их
#    замороженными навсегда и не должна выпускать их без проверки VPN), потом пробовать снова;
#  - код 0 (пункт «Выход») - сторож тоже завершается.
param(
    [switch]$Background,
    [string]$Engine = (Join-Path $PSScriptRoot 'VPNGuard.ps1'),
    [string]$EngineArgs = '',
    [string]$StateDir = (Join-Path $PSScriptRoot 'state'),
    [string]$LogPath = (Join-Path $PSScriptRoot 'vpnguard.log'),
    [string]$MutexName = 'Local\VPNGuard_watchdog',
    [int]$HangSec = 20,
    [int]$StartGraceSec = 30,
    [double]$RestartDelaySec = 2,
    [int]$CrashLimit = 5,
    [int]$CooldownSec = 30,
    [int]$MaxRuns = 0          # 0 - без ограничения (для тестов)
)
$ErrorActionPreference = 'Continue'

function WLog($msg) {
    $line = "{0} [сторож] {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $msg
    try { Add-Content -Path $LogPath -Value $line -Encoding UTF8 } catch {}
}

function Start-Engine([bool]$bg) {
    $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden', '-File', "`"$Engine`"")
    if ($bg) { $a += '-Background' }
    if ($EngineArgs) { $a += $EngineArgs }
    $p = Start-Process -FilePath 'powershell.exe' -ArgumentList $a -WindowStyle Hidden -PassThru
    $null = $p.Handle   # без этого ExitCode после завершения бывает пустым
    return $p
}

function Get-HeartbeatAge([int]$enginePid) {
    $path = Join-Path $StateDir 'engine-heartbeat.txt'
    try {
        $parts = ([IO.File]::ReadAllText($path)).Trim().Split(' ')
        if ([int]$parts[0] -ne $enginePid) { return [double]::MaxValue }
        return ([DateTime]::UtcNow - [DateTime]::new([int64]$parts[1], 'Utc')).TotalSeconds
    } catch { return [double]::MaxValue }
}

function Close-Journaled {
    $path = Join-Path $StateDir 'frozen.json'
    if (-not (Test-Path $path)) { return }
    try { $items = @((Get-Content $path -Raw -Encoding UTF8 | ConvertFrom-Json) | % { $_ }) } catch { WLog "журнал повреждён: $($_.Exception.Message)"; return }
    foreach ($it in $items) {
        if (-not $it -or -not $it.pid) { continue }
        try { $p = [Diagnostics.Process]::GetProcessById([int]$it.pid) } catch { continue }
        try { $st = $p.StartTime.Ticks } catch { continue }
        if ($st -ne [int64]$it.start) { WLog "PID $($it.pid) уже другой процесс, не трогаю"; continue }
        try { $p.Kill(); WLog "закрыт замороженный $($it.name) ($($it.pid))" } catch { WLog "не удалось закрыть $($it.pid): $($_.Exception.Message)" }
    }
    try { Set-Content -Path $path -Value '[]' -Encoding UTF8 } catch {}
}

$mutex = New-Object System.Threading.Mutex($false, $MutexName)
if (-not $mutex.WaitOne(0)) {
    # Сторож уже работает: просто попросим движок показать окно.
    if (-not $Background) { $null = Start-Engine $false }
    exit 0
}

New-Item -ItemType Directory -Force $StateDir | Out-Null
$crashes = New-Object System.Collections.Generic.List[datetime]
$bg = [bool]$Background
$runs = 0
WLog "запущен (движок: $Engine)"
try {
    while ($true) {
        $p = Start-Engine $bg
        $runs++
        $t0 = Get-Date
        $hung = $false
        while (-not $p.WaitForExit(1000)) {
            if (((Get-Date) - $t0).TotalSeconds -lt $StartGraceSec) { continue }
            $age = Get-HeartbeatAge $p.Id
            if ($age -gt $HangSec) {
                WLog ("движок PID {0} не отвечает {1} с - снимаю и перезапускаю" -f $p.Id, $(if ($age -eq [double]::MaxValue) { 'давно' } else { [int]$age }))
                try { $p.Kill() } catch {}
                [void]$p.WaitForExit(5000)
                $hung = $true
                break
            }
        }
        $code = if ($hung) { -1 } else { $p.ExitCode }
        if ($code -eq 0) { WLog 'движок завершён штатно, сторож выключается'; break }
        if ($code -eq 3) {
            # Уже работает другой движок (например, запущенный вручную) - ждём и пробуем снова.
            Start-Sleep -Seconds 10
        } else {
            if (-not $hung) { WLog "движок упал (код $code), перезапуск" }
            $now = Get-Date
            $crashes.Add($now)
            while ($crashes.Count -gt 0 -and ($now - $crashes[0]).TotalSeconds -gt 120) { $crashes.RemoveAt(0) }
            if ($crashes.Count -ge $CrashLimit) {
                WLog "$($crashes.Count) сбоев за 2 минуты: закрываю замороженные программы, пауза $CooldownSec с"
                Close-Journaled
                $crashes.Clear()
                Start-Sleep -Seconds $CooldownSec
            } else {
                Start-Sleep -Milliseconds ([int]($RestartDelaySec * 1000))
            }
        }
        $bg = $true
        if ($MaxRuns -gt 0 -and $runs -ge $MaxRuns) { WLog "достигнут MaxRuns=$MaxRuns"; break }
    }
} finally {
    try { $mutex.ReleaseMutex() } catch {}
}
exit 0
