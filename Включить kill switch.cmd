@echo off
rem VPNGuard: turn on firewall kill switch (asks for administrator rights)
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell.exe -Verb RunAs -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-NoExit','-File','%~dp0Firewall.ps1','-Install','-UserProfile','%USERPROFILE%')"
