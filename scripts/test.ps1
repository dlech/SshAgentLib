# build and run unit tests
msbuild "SshAgentLibTests"
vstest.console "SshAgentLibTests\bin\Debug\SshAgentLibTests.dll" /TestAdapterPath:"packages\NUnit3TestAdapter.4.2.0\build\net35"
