@echo off
rem VPNGuard: turn off firewall kill switch (asks for administrator rights)
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell.exe -Verb RunAs -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-NoExit','-File','%~dp0Firewall.ps1','-Uninstall')"
