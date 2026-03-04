## ZeroTrace

Native Windows uninstaller utility written in C# / WPF that replaces the previous PowerShell-based ZeroTrace engine.  
Author: **akahobby**

---

## Overview

ZeroTrace is a lightweight, portable uninstall helper for Windows 10 and Windows 11.  
It lists installed applications (including Steam games), launches their official uninstallers, waits for completion, and then scans for common leftover files, folders, shortcuts, and registry keys that you can optionally remove.

The application is implemented as a .NET 8 WPF desktop app and can be published as a single self-contained executable that does not require a separate .NET runtime installation.

---

## Features

- **Installed application browser**: Minimal Geek Uninstaller–style UI with a searchable list of installed programs.
- **Registry-based detection**: Enumerates applications from:
  - `HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall`
  - `HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`
  - `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall`
- **Steam game support**:
  - Detects Steam installation via `HKCU\Software\Valve\Steam` and `HKLM\Software\WOW6432Node\Valve\Steam`.
  - Parses `steamapps/libraryfolders.vdf` and `steamapps/appmanifest_<appid>.acf` to list installed games.
- **Uninstall orchestration**:
  - For non‑Steam apps, runs the official uninstall command (preferring `QuietUninstallString` when available).
  - Detects MSI uninstallers and converts `/I` to `/X` so they run in uninstall mode.
  - Waits for process exit **and** for the registry uninstall entry to be removed.
  - For Steam games, launches `steam://uninstall/<appid>` and monitors the file system until the app manifest and game folder are removed, with cancel support.
- **Leftover scan**:
  - Runs automatically after uninstall completes.
  - Scans:
    - Former `InstallLocation`
    - `%AppData%\AppName`
    - `%LocalAppData%\AppName`
    - `%ProgramData%\AppName` (and common `Publisher\AppName` variants)
    - Start Menu shortcuts in `%AppData%\Microsoft\Windows\Start Menu\Programs` and `%ProgramData%\Microsoft\Windows\Start Menu\Programs`
    - Registry keys under:
      - `HKCU\Software\Publisher\AppName`
      - `HKLM\Software\Publisher\AppName`
    - For Steam games, also:
      - `Documents\My Games\AppName`
      - `LocalLow\AppName`
      - Any leftover directories in Steam libraries whose names match the game name.
- **Leftover review dialog**:
  - Shows each leftover with:
    - Checkbox
    - Path
    - Type (`Folder`, `File`, `RegistryKey`, `Shortcut`)
    - Optional size
  - Lets you choose which items to delete via **Remove Selected**.
- **Safety-focused deletion**:
  - Never deletes:
    - `Windows` or `Windows\System32`
    - `Program Files` / `Program Files (x86)` roots
    - `Users` root
    - Steam root directories
  - Rejects overly generic locations that do not clearly reference the application name or publisher.
  - Logs every deletion attempt (including skipped, unsafe targets).
- **Logging**:
  - Each run creates a timestamped log file under `%ProgramData%\ZeroTrace\Logs`.
  - All log messages are also streamed into the collapsible log panel in the UI.
- **Elevation support**:
  - Runs normally without administrative rights.
  - Provides a **Restart as Administrator** option that relaunches ZeroTrace elevated via UAC.

---

## Steam uninstall detection

- ZeroTrace locates Steam using the registry keys:
  - `HKCU\Software\Valve\Steam`
  - `HKLM\Software\WOW6432Node\Valve\Steam`
- Steam libraries are read from `steamapps/libraryfolders.vdf`.
- Each installed game is discovered via `steamapps/appmanifest_<appid>.acf`, from which the app ID, game name, and install directory are parsed.
- When uninstalling a Steam game:
  - ZeroTrace launches `steam://uninstall/<appid>` via `Process.Start` (no process waiting).
  - It then polls once per second until:
    - The corresponding `appmanifest_<appid>.acf` no longer exists **and**
    - The game install folder no longer exists or is empty.
  - Cancellation is supported while monitoring.
  - Once complete, the standard leftover scan is executed.

---

## Leftover scanning behavior

Leftover scanning runs **only after** an uninstall attempt finishes (Steam or non‑Steam).

ZeroTrace inspects:

- The former `InstallLocation`, if it still exists.
- Per‑user and machine‑wide data folders derived from the application name and publisher:
  - `%AppData%\AppName`
  - `%LocalAppData%\AppName`
  - `%ProgramData%\AppName`
  - `%ProgramData%\Publisher\AppName` (when publisher is available)
- Start Menu entries whose shortcut names match the application name:
  - `%AppData%\Microsoft\Windows\Start Menu\Programs\*.lnk`
  - `%ProgramData%\Microsoft\Windows\Start Menu\Programs\*.lnk`
- Registry keys that conventionally store application settings:
  - `HKCU\Software\Publisher\AppName`
  - `HKLM\Software\Publisher\AppName`
- Steam‑specific leftovers for games:
  - `Documents\My Games\AppName`
  - `%USERPROFILE%\AppData\LocalLow\AppName`
  - Directories under each Steam library’s `steamapps\common` folder whose names contain the game name.

All candidates are presented to the user in a dedicated leftover dialog before any removal occurs.

---

## Build from source

- **Requirements**
  - Windows 10 or Windows 11
  - .NET SDK 8.0 or later

- **Projects**
  - `ZeroTrace.Core` – logic engine (enumeration, Steam detection, uninstall coordination, leftover scanning, deletion, logging)
  - `ZeroTrace.App` – WPF UI (application list, details, uninstall flow, log panel, leftover dialog)

- **Build the solution**

```bash
dotnet build ZeroTrace.sln -c Release
```

You can also open `ZeroTrace.sln` in Visual Studio 2022 or later and build from the IDE.

---

## Portable EXE publish command

To create a **self-contained, single-file** portable executable (no separate .NET runtime required), publish the WPF app project:

```bash
dotnet publish ZeroTrace.App/ZeroTrace.App.csproj -c Release -r win-x64 ^
  /p:PublishSingleFile=true ^
  /p:SelfContained=true ^
  /p:IncludeNativeLibrariesForSelfExtract=true
```

The resulting EXE will be placed under:

- `ZeroTrace.App\bin\Release\net8.0-windows\win-x64\publish\ZeroTrace.App.exe`

You can zip this single executable and run it on any compatible Windows 10 / Windows 11 machine without installation.

---

## Log file location

At runtime, ZeroTrace writes logs to:

- `%ProgramData%\ZeroTrace\Logs\ZeroTrace_YYYYMMDD_HHMMSS.log`

These log files mirror the messages shown in the in‑app log panel and are useful for auditing operations or troubleshooting.

---

## License

MIT License
