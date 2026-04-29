@echo off
chcp 65001 >nul 2>&1
title netcheck v2.3
cd /d "%~dp0"

echo ========================================
echo   netcheck v2.3 一键启动
echo ========================================

where python >nul 2>&1
if %errorlevel% neq 0 (
    where python3 >nul 2>&1
    if %errorlevel% neq 0 (
        echo [错误] 未找到 Python，请先安装 Python 3.8+
        echo 下载地址: https://www.python.org/downloads/
        echo 安装时请勾选 "Add Python to PATH"
        pause
        exit /b 1
    )
    set PYTHON=python3
) else (
    set PYTHON=python
)

%PYTHON% -c "import PyQt5" >nul 2>&1
if %errorlevel% neq 0 (
    echo [提示] 正在安装 PyQt5，请稍候...
    %PYTHON% -m pip install PyQt5 -i https://pypi.tuna.tsinghua.edu.cn/simple
    if %errorlevel% neq 0 (
        echo [错误] PyQt5 安装失败，请手动运行: pip install PyQt5
        pause
        exit /b 1
    )
    echo [完成] PyQt5 安装成功
)

echo [启动] netcheck v2.3...
%PYTHON% "%~dp0netcheck_v2.3.py"
if %errorlevel% neq 0 (
    echo.
    echo [错误] 程序异常退出
    pause
)
