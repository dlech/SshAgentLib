# Activate Visual Studio 2022 x64 developer tool shell
$vsDevPath = "${env:ProgramFiles}\Microsoft Visual Studio\2022\Community"
Import-Module "${vsDevPath}\Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
Enter-VsDevShell -VsInstallPath "${vsDevPath}" -DevCmdArguments '-arch=x64'
