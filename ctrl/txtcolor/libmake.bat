@echo off
del 	txtcolor.lib
echo        Assembling library modules.
echo.
\masm32\bin\ml /c /coff *.asm
\masm32\bin\lib *.obj /out:txtcolor.lib

dir makefont.*

@echo off
