# ZeroTrace

PowerShell-based engine used by ZeroTrace to audit and clean residual application traces on Windows systems.

---

## Overview

ZeroTrace Engine performs structured detection and optional cleanup of leftover files, registry keys, services, scheduled tasks, and firewall rules associated with installed applications.

It provides an interactive audit system before any removal occurs and supports safe preview execution.

---

## Architecture

ZeroTrace is separated into two components:

- **Launcher (BAT)** – lightweight bootstrapper that downloads and runs the engine
- **Engine (PS1)** – full cleanup logic

The launcher dynamically pulls the latest engine version from this repository at runtime to ensure users always run the latest stable engine build.

---

## Features

- Interactive target review before cleanup
- Scan-Only mode (safe preview)
- Live cleanup mode
- Optional restore point creation
- Structured summary reporting
- Detailed logging output
- Administrator elevation required

Logs are written to:

C:\ProgramData\ZeroTrace\Logs

---

## Modes

| Mode           | Description |
|----------------|------------|
| SCAN-ONLY      | Displays what would be removed (no changes made) |
| LIVE CLEAN     | Removes detected targets after confirmation |
| RESTORE POINT  | Creates a system restore point before cleanup |
| SKIP UNINSTALL | Performs residual-only cleanup |

---

## How It Works

1. Enumerates installed applications from registry sources.
2. Generates potential residual targets based on install paths and vendor/app naming.
3. Displays a structured audit view.
4. Allows exclusion of individual targets.
5. Executes cleanup (or preview in scan mode).
6. Outputs a detailed summary.

---

## Requirements

- Windows 10 or Windows 11
- Windows PowerShell 5.1
- Administrator privileges

---

## Safety Notice

This tool performs file system and registry operations.

Always review detected targets carefully before confirming cleanup.

Use at your own discretion.

---

## License

MIT License
