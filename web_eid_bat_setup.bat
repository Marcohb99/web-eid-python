@echo off

cd app 
set nativeappname=\webeidPython.py
set nativepath=%cd%%nativeappname%
set batname=webeidPython.bat

echo @echo off> %batname%
echo call python %nativepath%>> %batname%

cd ..