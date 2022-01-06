# run tests with code coverage
#
# Requires:
#   dotnet tool install --global coverlet.console

$dll = "SshAgentLibTests\bin\Debug\SshAgentLibTests.dll"
coverlet "$dll" --target "vstest.console.exe" --targetargs "$dll /TestAdapterPath:packages\NUnit3TestAdapter.4.2.0\build\net35" --output "coverage/" --format "opencover"
if ($LastExitCode) {
    exit $LastExitCode
}
