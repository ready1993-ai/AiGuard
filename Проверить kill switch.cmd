@echo off
rem VPNGuard: show firewall kill switch status (no admin rights needed)
powershell -NoProfile -ExecutionPolicy Bypass -NoExit -File "%~dp0Firewall.ps1" -Status
