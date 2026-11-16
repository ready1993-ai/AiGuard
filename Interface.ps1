# Native interface; no embedded browser, server or external UI dependency.
$script:editActions = @{}
$bg = [Drawing.ColorTranslator]::FromHtml('#0D1422')
$surface = [Drawing.ColorTranslator]::FromHtml('#151F30')
$field = [Drawing.ColorTranslator]::FromHtml('#1D2A3D')
$ink = [Drawing.ColorTranslator]::FromHtml('#E8EEF7')
$muted = [Drawing.ColorTranslator]::FromHtml('#9DAEC5')
$accent = [Drawing.ColorTranslator]::FromHtml('#73E2C1')
$form.Text = 'VPNGuard  •  Контроль соединения'
$form.ClientSize = New-Object Drawing.Size(1080,760)
$form.BackColor = $bg; $form.ForeColor = $ink
$form.AutoScaleMode = 'Dpi'
$form.Font = New-Object Drawing.Font('Segoe UI',10)
$form.MaximizeBox = $false

function Style-Tree($root) {
    foreach ($c in $root.Controls) {
        $c.ForeColor = $ink; $c.BackColor = $surface
        if ($c -is [Windows.Forms.Button]) {
            $c.FlatStyle = 'Flat'; $c.FlatAppearance.BorderSize = 0; $c.BackColor = $field
            $c.Cursor = [Windows.Forms.Cursors]::Hand
        }
        if ($c -is [Windows.Forms.TextBox] -or $c -is [Windows.Forms.ListBox] -or $c -is [Windows.Forms.ComboBox] -or $c -is [Windows.Forms.NumericUpDown]) {
            $c.BackColor = $field
            if ($c -is [Windows.Forms.TextBox] -or $c -is [Windows.Forms.ListBox]) { $c.BorderStyle = 'FixedSingle' }
        }
        if ($c -is [Windows.Forms.ComboBox]) {
            $c.FlatStyle = 'Flat'
            if ($c.DropDownStyle -eq 'DropDownList') {
                $c.DrawMode = 'OwnerDrawFixed'; $c.ItemHeight = 23
                $c.Add_DrawItem({
                    param($sender,$e)
                    $brush = New-Object Drawing.SolidBrush($field)
                    $e.Graphics.FillRectangle($brush,$e.Bounds); $brush.Dispose()
                    if ($e.Index -ge 0) {
                        [Windows.Forms.TextRenderer]::DrawText($e.Graphics,[string]$sender.Items[$e.Index],$sender.Font,$e.Bounds,$ink,([Windows.Forms.TextFormatFlags]::Left -bor [Windows.Forms.TextFormatFlags]::VerticalCenter))
                    }
                })
            }
        }
        if ($c -is [Windows.Forms.Label] -and $c.Font.Size -le 9) { $c.ForeColor = $muted }
        if ($c.HasChildren) { Style-Tree $c }
    }
}
function Label-At($parent,$x,$y,$w,$h,$text,$size=10,$color=$ink) {
    $c = New-Ctl Label $x $y $w $h $text
    $c.Font = New-Object Drawing.Font('Segoe UI',$size)
    $c.ForeColor = $color; $parent.Controls.Add($c); return $c
}
$side = New-Ctl Panel 0 0 218 760; $side.BackColor = $surface; $form.Controls.Add($side)
Label-At $side 25 30 180 35 'VPNGuard' 22 $accent | Out-Null
Label-At $side 27 72 175 24 'ВАШЕ СОЕДИНЕНИЕ' 8 $muted | Out-Null
Label-At $side 26 625 170 44 "Локальная защита`nБез аккаунта и облака" 9 $muted | Out-Null
Label-At $side 26 704 170 24 'DESKTOP  /  2.0' 9 $muted | Out-Null

$pnl.SetBounds(242,24,814,160); $pnl.BackColor = $surface
$dot.SetBounds(22,29,10,10)
$lblState.SetBounds(45,18,520,40); $lblState.Font = New-Object Drawing.Font('Segoe UI',22,[Drawing.FontStyle]::Bold)
$lblIp.SetBounds(24,70,530,28); $lblIp.Font = New-Object Drawing.Font('Segoe UI',12)
$btnPause.SetBounds(592,20,198,36)
$btnCheck.SetBounds(592,106,198,32)
$cbPause = New-Ctl ComboBox 592 64 198 30; $cbPause.DropDownStyle = 'DropDownList'
[void]$cbPause.Items.AddRange(@('Пауза на 5 минут','Пауза на 15 минут','Пауза на 30 минут','Пауза без таймера'))
$cbPause.SelectedIndex = 0; $pnl.Controls.Add($cbPause)
$lblSubtitle = Label-At $pnl 24 112 550 24 'Проверяем соединение и разрешённые адреса' 9 $muted

$hostPanel = New-Ctl Panel 242 204 814 472; $hostPanel.BackColor = $surface; $form.Controls.Add($hostPanel)
$tabs.Visible = $false
$script:pages = @{}; $script:navButtons = @{}
$overview = New-Ctl Panel 0 0 814 472; $hostPanel.Controls.Add($overview); $script:pages['Обзор'] = $overview
foreach ($pair in @(@('Приложения',$tApps),@('Доступ',$tAllow),@('Поведение',$tBeh),@('Журнал',$tLog))) {
    $page = New-Ctl Panel 16 18 782 440
    foreach ($c in @($pair[1].Controls)) {
        $c.Left = [int]($c.Left * 1.34); $c.Width = [int]($c.Width * 1.34)
        $page.Controls.Add($c)
    }
    $hostPanel.Controls.Add($page); $script:pages[$pair[0]] = $page; $page.Visible = $false
}
function Show-Page($name) {
    foreach ($key in $script:pages.Keys) {
        $script:pages[$key].Visible = ($key -eq $name)
        $script:navButtons[$key].BackColor = if ($key -eq $name) { $field } else { $surface }
        $script:navButtons[$key].ForeColor = if ($key -eq $name) { $accent } else { $muted }
    }
    if ($name -eq 'Журнал') { Refresh-Log }
    if ($name -eq 'Диагностика') { Refresh-Diagnostics }
}
$diag = New-Ctl Panel 20 16 774 440; $hostPanel.Controls.Add($diag); $script:pages['Диагностика'] = $diag
$navY = 135
foreach ($name in @('Обзор','Приложения','Доступ','Поведение','Диагностика','Журнал')) {
    $b = New-Ctl Button 16 $navY 186 46 ('   ' + $name)
    $b.Tag = $name; $b.TextAlign = 'MiddleLeft'; $side.Controls.Add($b); $script:navButtons[$name] = $b
    $b.Add_Click({ param($sender,$e) Show-Page $sender.Tag }); $navY += 54
}

Label-At $overview 24 20 750 32 'Спокойно работайте. Соединение под наблюдением.' 16 | Out-Null
Label-At $overview 24 57 750 24 'Состояние защиты и события текущего сеанса' 10 $muted | Out-Null
function Make-Card($x,$title,$value,$hint) {
    $panel = New-Ctl Panel $x 103 242 112; $panel.BackColor = $field; $overview.Controls.Add($panel)
    Label-At $panel 16 12 210 22 $title 9 $muted | Out-Null
    $v = Label-At $panel 16 35 210 40 $value 25 $accent
    Label-At $panel 16 83 210 22 $hint 8 $muted | Out-Null
    return $v
}
$cardApps = Make-Card 24 'ПРИЛОЖЕНИЙ ПОД ЗАЩИТОЙ' '—' 'Выбранных в настройках'
$cardChecks = Make-Card 286 'ПРОВЕРОК СОЕДИНЕНИЯ' '0' 'За текущий сеанс'
$cardIncidents = Make-Card 548 'СРАБАТЫВАНИЙ' '0' 'Переходов в блокировку'
$lblDetail = Label-At $overview 24 242 760 50 'Ожидание проверки соединения…' 12
$lblActivity = Label-At $overview 24 307 760 46 '' 10 $muted
$lblPolicy = Label-At $overview 24 369 760 72 '' 9 $muted

# Per-application action overrides are edited with the rest of the settings.
$appsPage = $script:pages['Приложения']
$clbApps.Height = 184
$lblAdd.Top = 242; $cbProc.Top = 268; $btnAddApp.Top = 266; $btnDelApp.Top = 266
foreach ($c in $appsPage.Controls) { if ($c -is [Windows.Forms.Label] -and $c.Top -eq 340) { $c.Visible = $false } }
$btnExe = New-Ctl Button 16 306 216 32 'Выбрать .exe…'; $appsPage.Controls.Add($btnExe)
Label-At $appsPage 16 350 720 36 'Действие для выбранного приложения (задержка из «Поведения», иначе 20 с):' 10 $muted | Out-Null
$cbAction = New-Ctl ComboBox 16 386 442 30; $cbAction.DropDownStyle = 'DropDownList'
[void]$cbAction.Items.AddRange(@('Общее правило','Только заморозить','Заморозить, затем закрыть','Закрыть сразу')); $cbAction.SelectedIndex = 0
$appsPage.Controls.Add($cbAction)
$btnRule = New-Ctl Button 474 384 276 32 'Применить к приложению'; $appsPage.Controls.Add($btnRule)
Label-At $appsPage 250 312 500 24 'Изменения вступят в силу после сохранения' 9 $muted | Out-Null
$clbApps.Add_SelectedIndexChanged({
    if ($clbApps.SelectedItem -match '\[([^\]]+)\]$') {
        $mode = $script:editActions[$Matches[1]]
        $cbAction.SelectedIndex = [Math]::Max(0,[Array]::IndexOf(@('default','freeze','grace','kill'),$mode))
    }
})
$btnRule.Add_Click({
    if ($clbApps.SelectedItem -match '\[([^\]]+)\]$') {
        $script:editActions[$Matches[1]] = @('default','freeze','grace','kill')[$cbAction.SelectedIndex]
        $lblSaved.Text = 'Правило изменено. Нажмите «Сохранить».'
    }
})
$btnExe.Add_Click({
    $dialog = New-Object Windows.Forms.OpenFileDialog
    $dialog.Filter = 'Программы (*.exe)|*.exe'; $dialog.Title = 'Выберите защищаемую программу'
    if ($dialog.ShowDialog() -eq 'OK') { $cbProc.Text = [IO.Path]::GetFileNameWithoutExtension($dialog.FileName); $btnAddApp.PerformClick() }
    $dialog.Dispose()
})
# Clarify guarantees: sampling and suspension are not a network firewall.
foreach ($c in $appsPage.Controls) { if ($c -is [Windows.Forms.Label] -and $c.Top -eq 10) { $c.Text = 'Выберите процессы для контроля. При обрыве VPN применяются общие или индивидуальные правила.' } }
$g1.Text = 'Разрешённые IP / подсети CIDR'
foreach ($box in @($g1,$g2)) {
    foreach ($c in $box.Controls) { $c.Left = [int]($c.Left * 1.34); $c.Width = [int]($c.Width * 1.34) }
}
$rbFreeze.Text = 'Только заморозить до восстановления VPN'
$chkProxy.Text = 'Следить за отключением VPN-прокси и TUN-адаптера'
foreach ($c in $g3.Controls) { if ($c -is [Windows.Forms.Label] -and $c.Top -eq 118) { $c.Text = 'Заморозка сохраняет процесс, но не заменяет сетевой kill switch.' } }
Label-At $script:pages['Поведение'] 18 374 730 44 'Во время первой проверки приложения временно заморожены. Пауза защиты снимает ограничения.' 9 $muted | Out-Null

Label-At $diag 0 0 760 32 'Диагностика соединения' 18 | Out-Null
Label-At $diag 0 40 760 40 'Ответы независимых сервисов, состояние прокси и активные VPN-адаптеры.' 10 $muted | Out-Null
$tbDiag = New-Ctl TextBox 0 90 770 260; $tbDiag.Multiline = $true; $tbDiag.ReadOnly = $true; $tbDiag.ScrollBars = 'Vertical'
$tbDiag.Font = New-Object Drawing.Font('Consolas',10); $diag.Controls.Add($tbDiag)
$btnDiag = New-Ctl Button 0 364 180 34 'Обновить'; $diag.Controls.Add($btnDiag)
$btnExport = New-Ctl Button 194 364 230 34 'Экспорт диагностики…'; $diag.Controls.Add($btnExport)
Label-At $diag 0 410 770 28 'Отчёт содержит ваши IP и имена приложений. Перед передачей проверьте его.' 9 $muted | Out-Null
function Format-Verdict($v) {
    switch ($v) { 'yes' { 'через VPN' } 'ok' { 'через VPN' } 'no' { 'УТЕЧКА' } 'leak' { 'УТЕЧКА' } 'unavailable' { 'IPv6 нет' } 'off' { 'выключено' } default { 'не определено' } }
}
function Format-ExtraDiagnostics {
    $out = @('МАРШРУТ ДО СЕРВИСОВ (адрес, который видит сам сервис)')
    if ($script:routeResults.Count) {
        foreach ($r in $script:routeResults) { $out += ("  {0,-10} {1,-44} {2,-16} {3}{4}" -f $r.App, $r.Url, $r.Seen, (Format-Verdict $r.Verdict), $(if ($r.Note) { " ($($r.Note))" } else { '' })) }
    } else { $out += '  ещё не проверялся или для выбранных программ нет точки проверки' }
    $out += ''
    $d = $script:dnsResult
    if (-not $d) { $out += 'DNS: ещё не проверялся' }
    else {
        $out += ("DNS: {0}  ({1:HH:mm:ss}, источники: Akamai whoami, Google myaddr)" -f (Format-Verdict $d.State), $d.Time)
        foreach ($r in $d.Resolvers) { $out += ("  резолвер {0} {1} - {2}" -f $r.Ip, $r.Country, (Format-Verdict $r.Verdict)) }
        foreach ($e in $d.Errors) { $out += "  ошибка: $e" }
        if ($d.State -eq 'leak') { $out += $(if ($Cfg.dns_check -eq 'block') { '  Режим block: программы блокируются.' } else { '  Режим warn: только предупреждение. Исправляется в VPN: DNS через туннель или режим TUN.' }) }
    }
    $out += "IPv6: $(Format-Verdict $script:ipv6Verdict)$(if ($script:lastIpv6) { " ($script:lastIpv6)" })"
    return ($out -join "`r`n")
}
function Refresh-Diagnostics {
    $lines = @("VPNGuard 2.0  |  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')", '', "Состояние: $script:statusText",
        "Последний IP: $script:lastIp", "Страна: $script:lastCountry", '', 'ОТВЕТЫ СЕРВИСОВ')
    $lines[-1] = "ОТВЕТЫ СЕРВИСОВ (маршрут проб: $($Cfg.probe_route))"
    foreach ($r in $script:serviceResults) {
        if ($r.Family) { $lines += ("[{0}] {1}  через {2}  →  {3}  ({4} мс, {5:HH:mm:ss})" -f $r.Family, $r.Service, $r.Route, $r.Result, $r.Ms, $r.Time) }
        else { $lines += "$($r.Service)  →  $($r.Result)" }
    }
    if (-not $script:serviceResults.Count) { $lines += 'Результатов пока нет' }
    $px = Get-Proxy
    $lines += @('', "Прокси: $(if ($px) { $px } else { 'не задан' })", "Активных TUN-адаптеров: $(@(Get-TunAdapters).Count)",
        "Приложения: $($Apps -join ', ')", '', "IPv6: $(switch ($script:ipv6Status) { 'ok' { "виден адрес $script:lastIpv6" } 'unavailable' { 'на компьютере нет IPv6' } 'unknown' { 'пробы не ответили' } default { 'проверка выключена' } })",
        '', (Format-ExtraDiagnostics),
        'Расхождение IP-сервисов — причина блокировки, но само по себе не доказывает утечку.')
    $tbDiag.Lines = $lines
}
$btnDiag.Add_Click({ Refresh-Diagnostics; Check-Now })
$btnExport.Add_Click({
    Refresh-Diagnostics
    $d = New-Object Windows.Forms.SaveFileDialog; $d.Filter = 'Текстовый отчёт|*.txt'; $d.FileName = 'VPNGuard-diagnostics.txt'
    if ($d.ShowDialog() -eq 'OK') { try { [IO.File]::WriteAllText($d.FileName,$tbDiag.Text,[Text.Encoding]::UTF8); $lblSaved.Text = 'Отчёт сохранён' } catch { [Windows.Forms.MessageBox]::Show($_.Exception.Message,'VPNGuard') | Out-Null } }
    $d.Dispose()
})

$lblSaved.SetBounds(244,703,480,34)
$btnSave.SetBounds(738,696,170,42); $btnSave.Text = 'Сохранить'
$btnClose.SetBounds(920,696,136,42); $btnClose.Text = 'Свернуть'
Style-Tree $form
$form.BackColor = $bg; $hostPanel.BackColor = $surface
$btnSave.BackColor = $accent; $btnSave.ForeColor = $bg
foreach ($v in @($cardApps,$cardChecks,$cardIncidents)) { $v.ForeColor = $accent; $v.Parent.BackColor = $field; foreach ($c in $v.Parent.Controls) { $c.BackColor = $field } }
$lblSaved.BackColor = $bg; $lblSaved.ForeColor = $accent
Show-Page 'Обзор'

function Update-Dashboard {
    $cardApps.Text = [string]@($Apps).Count
    $cardChecks.Text = [string]$script:checkCount
    $cardIncidents.Text = [string]$script:incidentCount
    $lblState.Text = switch ($script:state) { 'ok' { 'Соединение разрешено' }; 'bad' { 'Сработала защита' }; 'paused' { 'Защита на паузе' }; default { 'Проверяем соединение' } }
    $lblDetail.Text = $script:statusText
    $last = if ($script:lastChecked) { $script:lastChecked.ToString('HH:mm:ss') } else { 'ещё не завершена' }
    $lblSubtitle.Text = 'Последняя проверка: ' + $last
    $uptime = (Get-Date) - $script:startedAt
    $lblActivity.Text = "Сеанс: $([int]$uptime.TotalHours) ч $($uptime.Minutes) мин   •   Заморожено процессов: $($frozen.Count)`nКонтроль IP: каждые $($Cfg.interval_sec) с   •   IP / подсетей: $($Cfg.allow_ips.Count)   •   Стран: $($Cfg.allow_countries.Count)"
    $policy = if (-not $Cfg.kill_after_grace) { 'Заморозка до восстановления' } elseif ($Cfg.grace_sec -gt 0) { "Заморозка → закрытие через $($Cfg.grace_sec) с" } else { 'Немедленное закрытие' }
    $lblPolicy.Text = "Общее правило: $policy. Индивидуальных правил: $($Cfg.app_actions.Count).`nКонтроль процессов не заменяет сетевой kill switch VPN-клиента."
    if ($script:state -eq 'paused') {
        $lblDetail.Text = if ($script:pauseUntil) { 'Автовключение защиты через ' + [Math]::Max(0,[int]($script:pauseUntil-(Get-Date)).TotalSeconds) + ' с' } else { 'Включите защиту вручную, когда закончите.' }
    }
    if ($script:state -eq 'bad' -and $script:badSince -and $Cfg.kill_after_grace -and $Cfg.grace_sec -gt 0) {
        $remaining = [Math]::Max(0,[int]($Cfg.grace_sec - ((Get-Date)-$script:badSince).TotalSeconds))
        $lblSubtitle.Text = "По общему правилу: до закрытия $remaining с"
    }
}
