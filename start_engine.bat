@echo off
:: Aragorn Engine Launcher — must be run as administrator.
:: Right-click this file and select "Run as administrator".
::
:: Starts the Aragorn MCP server on http://127.0.0.1:14401/mcp
:: for kernel debugging via MCP.

title Aragorn Kernel Debugger Engine

cd /d "%~dp0"

echo ============================================
echo  Aragorn - Direct Kernel Debugger Engine
echo ============================================
echo.

:: Check for admin
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: This script must be run as administrator.
    echo Right-click and select "Run as administrator".
    pause
    exit /b 1
)

echo [OK] Running as administrator
echo [..] Starting MCP server on http://127.0.0.1:14401/mcp
echo.

python server.py --http

pause
