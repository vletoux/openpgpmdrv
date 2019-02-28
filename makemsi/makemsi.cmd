::@echo off
set VERSION=1.0.0.0

set WIX_PATH="C:\Program Files (x86)\Windows Installer XML v3\bin"
:: Inf2cat and signtool are installed by Windows Driver Kit:
set INF2CAT_PATH=C:\WinDDK\7600.16385.0\bin\selfsign
set SIGNTOOL_PATH=C:\WinDDK\7600.16385.0\bin\x86

:: Certificate name and store
::set CERTIFICATENAME=Fedict eID(test)
::set CERTIFICATESTORE=PrivateCertStore
:: To create a test certificate: 
::   %SIGNTOOL_PATH%\MakeCert.exe -r -pe -ss  %CERTIFICATESTORE% -n "CN=%CERTIFICATENAME%" fedicteidtest.cer

:: Path to images
set IMG_PATH=..\img

set BUILDPATH=%~dp0

cd %BUILDPATH%

md %BUILDPATH%\Release
md %BUILDPATH%\Build

:: copy inf files
copy %BUILDPATH%\..\OpenPGPminidriver\openpgpmdrv.inf %BUILDPATH%\Release

:: copy dll files
copy %BUILDPATH%\..\Release\openpgpmdrv32.dll %BUILDPATH%\Release
copy %BUILDPATH%\..\Release\openpgpmdrv64.dll %BUILDPATH%\Release

:: copy icon
::copy %IMG_PATH%\beid.ico %BUILDPATH%\Release\

:: Create catalog
%INF2CAT_PATH%\inf2cat.exe /driver:%BUILDPATH%\Release\ /os:Vista_X86,Vista_X64,7_X86,7_X64,Server2008R2_X64,Server2008_X64,Server2008_X86,Server2003_X64,Server2003_X86,XP_X64,XP_X86

:: Sign the catalog
::%SIGNTOOL_PATH%\SignTool.exe sign /v /s %CERTIFICATESTORE% /n "%CERTIFICATENAME%"  /t http://timestamp.verisign.com/scripts/timestamp.dll %BUILDPATH%\Debug\openpgpmdrv.cat
::%SIGNTOOL_PATH%\SignTool.exe sign /v /s %CERTIFICATESTORE% /n "%CERTIFICATENAME%"  /t http://timestamp.verisign.com/scripts/timestamp.dll %BUILDPATH%\Release\openpgpmdrv.cat

:: Create MSI 64 bit Release
%WIX_PATH%\candle -dVersion=%VERSION% -ext %WIX_PATH%\WixDifxAppExtension.dll openpgpmdrv64release.wxs 
%WIX_PATH%\light -ext %WIX_PATH%\WixDifxAppExtension.dll -ext WixUIExtension openpgpmdrv64release.wixobj %WIX_PATH%\difxapp_x64.wixlib -o Build\OpenPGPmdrv-%VERSION%-x64.msi

:: Create MSI 32 bit Release
%WIX_PATH%\candle -dVersion=%VERSION% -ext %WIX_PATH%\WixDifxAppExtension.dll openpgpmdrv32release.wxs 
%WIX_PATH%\light -ext %WIX_PATH%\WixDifxAppExtension.dll -ext WixUIExtension openpgpmdrv32release.wixobj %WIX_PATH%\difxapp_x86.wixlib -o Build\OpenPGPmdrv-%VERSION%-x86.msi

:: Cleanup
del openpgpmdrv32release.wixobj
del Build\OpenPGPmdrv-%VERSION%-x86.wixpdb

del openpgpmdrv64release.wixobj
del Build\OpenPGPmdrv-%VERSION%-x64.wixpdb

pause  