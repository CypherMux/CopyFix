# CopyFix

A dual verification File Integrity Monitor designed to detect and defend against the "Copy Fail" kernel vulnerability. (CVE-2026-31431)

## Why I Made This Tool

A recent kernel vulnerability called *Copy Fail* allowed attackers to modify the page cache *(RAM)* of root owned binaries without modifying the actual file on the disk. This meant traditional FIM *(File Integrity Monitoring)* tools such as AIDE or Tripwire were completely blind to such an attack.

I built `CopyFix` to fix the blind spot in these tools. Instead of just checking the disk, `CopyFix` hashes **both** the on-disk binary and the in-memory executable *(`/proc/<PID>/exe`)*. If they don't match up, the tool will alert you.

## How It Operates

`CopyFix` doesn't just trust the disk, instead it performs a dual verification check on critical system binaries.

*  **1. The Baseline:** The tool calculates the SHA-256 hash of the file **on disk** *(using `O_DIRECT` to bypass the cache)*.

*  **2. The Runtime:** It finds the active Process ID (PID) and calculates the SHA-256 hash of the executable **in memory** by reading `/proc/<PID>/exe`.

*  **The Comparison:** If the disk hash and the memory hash do not match, `CopyFix` alerts you that the binary has been tampered with in the RAM.

## Some Of The Features

*  **Fileless Malware Detection:** It catches exploits that live only in the page cache of the system.

*  **Dual-Verification:** It compares on-disk integrity against in-memory execution.

*  **Critical Binary Targeting:** The tool focuses mainly on high value targets such as `/usr/bin/su`, `/usr/bin/sudo`, and `/usr/bin/ssh`.

*  **Lightweight Structurally:** Pure Python3 codebase with no heavy dependencies to not put such a toll on your system.

## Usage

# Scan a specific binary


```sudo ./copyfix.py --check /usr/bin/su```

# Scan all critical binaries at once

```sudo ./copyfix.py --scan-all```

## Requirements

Because `CopyFix` needs to read the memory of root-owned processes *(`/proc/<PID>/exe`)* it **must** run as root *(sudo)*.

## Disclaimer

*This tool is intended for educational purposes, CTFs, and authorized defensive monitoring of systems. Always ensure you have explicit permission to monitor systems that you do not own.*
