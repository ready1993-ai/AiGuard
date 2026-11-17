# AiGuard - управление сетевым kill switch (брандмауэр Windows).
#   -Install    включить: правила + задача планировщика, которая обновляет их сама (нужны права администратора)
#   -Uninstall  выключить: удалить правила и задачу (нужны права администратора)
#   -Sync       обновить правила (так запускает задача планировщика)
#   -Status     показать текущие правила
#   -DryRun     только показать, что было бы сделано
param(
    [switch]$Install,
    [switch]$Uninstall,
    [switch]$Sync,
    [switch]$Status,
    [switch]$DryRun,
    [string]$UserProfile = $env:USERPROFILE,
    [string]$ConfigFile = ''
)

$ErrorActionPreference = 'Stop'
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $ConfigFile) { $ConfigFile = Join-Path $Here 'config.json' }
$StatusFile = Join-Path $Here 'state\firewall-status.json'
$FwLog = Join-Path $Here 'firewall.log'
$TaskName = 'VPNGuard Kill Switch'
. (Join-Path $Here 'FirewallCore.ps1')

function FwLog($msg) {
    $line = '{0} {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $msg
    Write-Host $line
    try { Add-Content -LiteralPath $FwLog -Value $line -Encoding UTF8 } catch { }
}
function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-Sync {
    $cfg = Read-VGFwConfig $ConfigFile
    if ($cfg.Apps.Count -eq 0) {
        FwLog 'Нет отмеченных программ (или все в исключениях): правила AiGuard удаляются.'
        if (-not $DryRun) { Remove-VGFwRules; Write-VGFwStatus $StatusFile @() @() 'нет программ' }
        return
    }
    $aliases = @(Get-VGFwPhysicalAliases)
    $plan = @(Get-VGFwPlan -Apps $cfg.Apps -UserProfile $UserProfile -Aliases $aliases -ExtraPaths $cfg.Extra)
    if ($aliases.Count -eq 0) { throw 'Не найдено подключённых сетевых адаптеров (Ethernet / Wi-Fi). Подключите сеть и повторите.' }
    if ($plan.Count -eq 0) { FwLog "Не найдено ни одного файла программ: $($cfg.Apps -join ', ')." }
    $syncLog = @(Sync-VGFwRules -Plan $plan -DryRun:$DryRun)
    foreach ($line in $syncLog) { FwLog $line }
    $failed = @($syncLog | ? { $_ -like 'ОШИБКА*' })
    if ($failed.Count) {
        # Удачные правила оставляем, в состояние пишем только реально созданные.
        $plan = @($plan | ? { $p = $_.Program; -not ($failed | ? { $_ -like "ОШИБКА $p*" }) })
        if (-not $DryRun) { Write-VGFwStatus $StatusFile $plan $aliases }
        throw ($failed[0] -replace '^ОШИБКА ', '')
    }
    if (-not $DryRun) { Write-VGFwStatus $StatusFile $plan $aliases }
    FwLog ("Синхронизация: программ {0}, правил {1}, адаптеры: {2}" -f $cfg.Apps.Count, $plan.Count, ($aliases -join ', '))
}

function Register-SyncTask {
    $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $taskArgs = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}" -Sync -UserProfile "{1}" -ConfigFile "{2}"' -f (Join-Path $Here 'Firewall.ps1'), $UserProfile, $ConfigFile
    $action = New-ScheduledTaskAction -Execute $ps -Argument $taskArgs
    $triggers = @(
        (New-ScheduledTaskTrigger -AtStartup),
        (New-ScheduledTaskTrigger -AtLogOn),
        (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 15))
    )
    # Подключение к новой сети (Wi-Fi, кабель): событие 10000 журнала NetworkProfile.
    try {
        $cls = Get-CimClass -ClassName MSFT_TaskEventTrigger -Namespace 'Root/Microsoft/Windows/TaskScheduler'
        $evt = New-CimInstance -CimClass $cls -ClientOnly
        $evt.Enabled = $true
        $evt.Subscription = '<QueryList><Query Id="0" Path="Microsoft-Windows-NetworkProfile/Operational"><Select Path="Microsoft-Windows-NetworkProfile/Operational">*[System[EventID=10000]]</Select></Query></QueryList>'
        $triggers += $evt
    } catch { FwLog "Триггер на смену сети не добавлен: $($_.Exception.Message)" }
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $triggers -Principal $principal -Settings $settings `
        -Description 'AiGuard: обновляет правила брандмауэра, чтобы выбранные программы ходили в интернет только через защищённое соединение.' -Force | Out-Null
    # Окно VPNGuard (без прав администратора) может только запустить эту задачу, чтобы сразу применить
    # новый список программ. Изменить задачу или правила напрямую оно по-прежнему не может.
    try {
        $svc = New-Object -ComObject Schedule.Service; $svc.Connect()
        $t = $svc.GetFolder('\').GetTask($TaskName)
        $sd = $t.GetSecurityDescriptor(4)
        if ($sd -notmatch '\(A;;GRGX;;;AU\)') { $t.SetSecurityDescriptor($sd + '(A;;GRGX;;;AU)', 0) }
    } catch { FwLog "Права на запуск задачи не выданы: $($_.Exception.Message)" }
}

try {
    if ($Status) {
        $s = Read-VGFwStatus $StatusFile
        Write-Host (Format-VGFwSummary $s)
        foreach ($r in @(Get-NetFirewallRule -Group $VGFwGroup -ErrorAction Ignore)) {
            $prog = ($r | Get-NetFirewallApplicationFilter).Program
            $al = ($r | Get-NetFirewallInterfaceFilter).InterfaceAlias -join ', '
            Write-Host ("  [{0}] {1}  ->  блок на: {2}" -f $(if ($r.Enabled -eq 'True') { 'вкл' } else { 'выкл' }), $prog, $al)
        }
        $cfg = Read-VGFwConfig $ConfigFile
        foreach ($p in (Get-VGFwUncovered $s $cfg.Apps)) { Write-Host "  НЕ ЗАЩИЩЕНО (запущено, правила нет): $p" }
        exit 0
    }
    if (($Install -or $Uninstall -or $Sync) -and -not $DryRun -and -not (Test-Admin)) {
        Write-Host 'Нужны права администратора: запустите через «Включить kill switch.cmd».'
        exit 5
    }
    if ($Uninstall) {
        if (-not $DryRun) {
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Ignore
            Remove-VGFwRules
            Write-VGFwStatus $StatusFile @() @() 'выключено пользователем' $false
        }
        FwLog 'Kill switch выключен: правила и задача удалены.'
        exit 0
    }
    if ($Install) {
        $profiles = @(Get-NetFirewallProfile | ? { $_.Enabled -ne 'True' } | % { $_.Name })
        if ($profiles.Count) { FwLog "ВНИМАНИЕ: брандмауэр Windows выключен для профилей: $($profiles -join ', '). Правила работать не будут." }
        Invoke-Sync
        if (-not $DryRun) { Register-SyncTask; FwLog "Задача «$TaskName» создана: обновление при входе, при смене сети и каждые 15 минут." }
        exit 0
    }
    if ($Sync) { Invoke-Sync; exit 0 }
    Write-Host 'Параметры: -Install | -Uninstall | -Sync | -Status [-DryRun]'
} catch {
    FwLog "ОШИБКА: $($_.Exception.Message)"
    if (-not $DryRun -and -not $Status) { try { Write-VGFwError $StatusFile $_.Exception.Message } catch { } }
    exit 1
}
