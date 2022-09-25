#!/bin/sh
# intall NUnit 3.x for Mono.

nuget install NUnit.Console -Version 3.15.0 -source https://www.nuget.org/api/v2/ -Output packages -ExcludeVersion
