#!/bin/sh
# build and run tests on mono

set -e

msbuild -restore SshAgentLibTests/SshAgentLibTests.csproj
mono ./packages/NUnit.ConsoleRunner/tools/nunit3-console.exe SshAgentLibTests/bin/Debug/SshAgentLibTests.dll --framework=mono-4.0 --noresult "$@"
