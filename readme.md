SshAgentLib
===========

SshAgentLib is a .NET library that can be used to create an SSH agent for 
PuTTY and OpenSSH clients and an SSH client for Pageant and OpenSSH agents.

__WARNING__: This is not a stable API.

It is currently only being used for [KeeAgent][1] (a plugin for KeePass 2.x).

Graphical User Interface Libraries
==================================

Each library contains controls/widgets for creating user interfaces that 
use the base SshAgentLib.

WinForms
--------
Provides controls based on the [System.Windows.Forms][2] library

Gtk
---
Provides widgets based on the [GtkSharp][3] library


[1]: http://lechnology.com/KeeAgent
[2]: http://msdn.microsoft.com/en-us/library/system.windows.forms.aspx
[3]: http://www.mono-project.com/GtkSharp
[4]: http://techbase.kde.org/Development/Languages/Qyoto