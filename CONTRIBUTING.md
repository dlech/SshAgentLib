
# Development environment

This section describes the required development environment.

## Prerequisites

- Visual Studio 2022
- [GTK#](https://www.mono-project.com/download/stable/#download-win) (optional - only needed to build full solution)

## Command line

If not using the Visual Studio IDE, there are some [scripts](./scripts) to help
with development.

    - `shell.ps1` activates the Visual Studio tools in the current Powershell terminal.
    - `test.ps1` runs the unit tests

## Setup

If you don't use the Visual Studio IDE, run these command to fetch the code and
install dependencies.

    git clone https://github.com/dlech/SshAgentLib
    cd SshAgentLib
    ./scripts/shell.ps1
    nuget restore
