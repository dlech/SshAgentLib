# run tests with code coverage
#
# Requires:
#   dotnet tool install --global coverlet.console

$dll = "SshAgentLibTests\bin\Debug\SshAgentLibTests.dll"
coverlet "$dll" --target "vstest.console.exe" --targetargs "$dll" --output "coverage/" --format "opencover"
if ($LastExitCode) {
    exit $LastExitCode
}
