```
   ____        ____        _____      __      __     _________       _____      __     __  
  / ___)      / __ \      (  __ \     ) \    / (    (_   _____)     (_   _)    (_ \   / _) 
 / /         / /  \ \      ) )_) )     \ \  / /       ) (___          | |        \ \_/ /   
( (         ( ()  () )    (  ___/       \ \/ /       (   ___)         | |         \   /    
( (         ( ()  () )     ) )           \  /         ) (             | |         / _ \    
 \ \___      \ \__/ /     ( (             )(         (   )           _| |__     _/ / \ \_  
  \____)      \____/      /__\           /__\         \_/           /_____(    (__/   \__) 
                                                                                           
```

***A dual verification File Integrity Monitor designed to detect and defend against the "Copy Fail" kernel vulnerability. (CVE-2026-31431)***

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

## Installation & Usage

`CopyFix` is a standalone Python script with zero external dependencies so all you need is Python3 which is preinstalled on almost all Linux distributions. If you do **not** have Python3 installed on your system please follow step *0.8-0.9* of the installation process, if you do you can skip the first few steps.

### 0.8: Check If You Have Python3 Installed On Your System Using The Following Command

```python3 --version```

*If you get a "command not found" error, you can install Python3 using your system's package manager in the next step.*

### 0.9: Install Python3 To Your System

**Arch Linux**

```sudo pacman -S python```

**Debian/Ubuntu**

```sudo apt update && sudo apt install python3```

**Fedora**

```sudo dnf install python3```

### 1. Clone The Repo & Redirect To Newly Installed Directory

```git clone https://github.com/CypherMux/CopyFix.git && cd CopyFix```

### 2. Make The Script Executable

```chmod +x copyfix.py```

## Usage

## Scan a specific binary


```sudo ./copyfix.py --check /usr/bin/su```

## Scan all critical binaries at once

```sudo ./copyfix.py --scan-all```

## Requirements

Because `CopyFix` needs to read the memory of root-owned processes *(`/proc/<PID>/exe`)* it **must** run as root *(sudo)*.

## Disclaimer

*This tool is intended for educational purposes, CTFs, and authorized defensive monitoring of systems. Always ensure you have explicit permission to monitor systems that you do not own.*
