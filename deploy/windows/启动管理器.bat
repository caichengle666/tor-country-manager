@echo off
chcp 65001 >nul
cd /d "%~dp0"

if not exist "TorCountryManager.exe" (
  echo 找不到 TorCountryManager.exe
  pause
  exit /b 1
)

if not exist "runtime\tor\tor.exe" (
  echo 找不到 Windows Tor 核心：runtime\tor\tor.exe
  pause
  exit /b 1
)

start "" powershell.exe -NoProfile -WindowStyle Hidden -Command "Start-Sleep -Seconds 2; Start-Process 'http://127.0.0.1:8080'"
echo 管理页面：http://127.0.0.1:8080
echo SOCKS5 代理：127.0.0.1:1080
echo 关闭本窗口会停止管理器和由它启动的 Tor 实例。
echo.
"TorCountryManager.exe" -config "config.json"
echo.
echo 管理器已经停止。
pause

