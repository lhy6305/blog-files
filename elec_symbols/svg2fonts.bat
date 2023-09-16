@echo off

fontforge.bat.lnk -script svgs2ttf.py test.json

echo.
echo.
echo program exited with code %errorlevel%.
echo press any key to exit.
pause>nul
exit
