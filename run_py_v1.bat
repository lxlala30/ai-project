@echo off
REM 进入指定目录
cd /d "D:\lx\2026\ai-project"

REM 检查是否成功进入目录
if %errorlevel% neq 0 (
    echo 无法进入指定目录: D:\lx\2026\ai-project
    pause
    exit /b 1
)

:loop
REM 调用 Python 脚本 main.py
echo 正在调用 Python 脚本 py-ai1.0.py...
python .\py-xiaozhi\py-ai1.0.py

REM 等待指令执行完成
echo Python 脚本 py-ai1.0.py 执行完成。

@REM REM 提示用户是否重新执行脚本
@REM echo.
@REM echo 按回车键重新执行脚本，或按任意其他键退出...
@REM set /p "="
@REM if errorlevel 255 goto :eof
@REM goto :loop

@REM :eof
@REM echo 脚本已退出。
@REM pause