# generate report for code coverage
#
# Requires:
#   dotnet tool install -g dotnet-reportgenerator-globaltool

reportgenerator -reports:coverage/coverage.opencover.xml -targetdir:coverage/html -reporttypes:Html
if ($LastExitCode) {
    exit $LastExitCode
}
