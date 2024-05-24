@echo off

uglifyjs "%~n1.js" --enclose --mangle --compress --webkit --v8 --ie --no-annotations --output "%~n1-1.js"

if not %errorlevel% == 0 (
echo.
echo program exited with code %errorlevel%.
echo press any key to exit.
pause>nul
)