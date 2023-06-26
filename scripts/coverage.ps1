# run tests with code coverage
#
# Requires:
#   dotnet tool restore

$dll = "SshAgentLibTests\bin\Debug\SshAgentLibTests.dll"

dotnet coverlet "$dll" --target "vstest.console.exe" --targetargs "$dll" --output "coverage/" --format "opencover"
if ($LastExitCode) {
    exit $LastExitCode
}
