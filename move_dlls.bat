rem First, compile the 32 and 64 bit version of TinyTracer (in a Release mode). Then, you can use this script to copy them into the directory with the run_me.bat (default: install32_64).
set INSTALL_DIR=install32_64
move Release\PinNSieve.dll %INSTALL_DIR%\PinNSieve32.dll
move x64\Release\PinNSieve.dll %INSTALL_DIR%\PinNSieve64.dll
pause