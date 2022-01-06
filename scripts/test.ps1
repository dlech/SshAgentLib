# build and run unit tests
msbuild "SshAgentLibTests"
if ($LastExitCode) {
    exit $LastExitCode
}
vstest.console "SshAgentLibTests\bin\Debug\SshAgentLibTests.dll"
if ($LastExitCode) {
    exit $LastExitCode
}
