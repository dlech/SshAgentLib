# build and run unit tests
msbuild "SshAgentLibTests"
vstest.console "SshAgentLibTests\bin\Debug\SshAgentLibTests.dll" /TestAdapterPath:"packages\NUnit3TestAdapter.3.7.0\tools"
