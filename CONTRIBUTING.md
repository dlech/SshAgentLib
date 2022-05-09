
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

## Linux

The info above applies to Windows only. For Linux, only the most recent Ubuntu
LTS is officially supported.

### Dependencies

Nuget is only needed to install NUnit to for building and running the unit tests.
You will need a more recent `nuget` than what is available in the Ubuntu archives.

Then run the following commands:

    sudo add-apt-repository ppa:dlech/keepass2-plugins-beta
    sudo apt update
    sudo apt install mono-devel libbccrypto-cil libgtk2.0-cil-dev libglade2.0-cil-dev libargon2-dev
    ./scripts/install-nunit.sh

To build the entire project:

    xbuild

To build and run unit tests:

    ./scripts/run-tests-mono.sh

Note: additional arguments for `run-tests-mono.sh` will be passed to `nunit-console.exe`.
This can be used with `--explore` to list test names and with `--test=NAMES`
or `--where=EXPRESSION` to run individual tests.
