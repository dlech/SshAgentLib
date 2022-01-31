# build and run unit tests
msbuild "SshAgentLibTests"
if ($LastExitCode) {
    exit $LastExitCode
}
vstest.console "SshAgentLibTests\bin\Debug\net462\SshAgentLibTests.dll" $args
if ($LastExitCode) {
    exit $LastExitCode
}
