#!/usr/bin/env python3
import os
import sys
import hashlib
import subprocess

def get_disk_hash(filepath):
    """Hashes the first 4KB of a file directly from the disk."""
    sha256 = hashlib.sha256()
    try:
        fd = os.open(filepath, os.O_RDONLY | os.O_DIRECT)
        try:

        # Read exactly 100 bytes or one memory page
            chunk = os.read(fd,100)
            sha256.update(chunk)
        finally:
            os.close(fd)
        return sha256.hexdigest()
    except Exception as e:
        print(f"[-] Error reading disk file {filepath}: {e}")
        return None

def get_memory_hash(pid):
    """Hashes the first 4KB of the in-memory executable."""
    exe_path = f"/proc/{pid}/exe"
    sha256 = hashlib.sha256()
    try:
        with open(exe_path, 'rb') as f:
            # Read exactly 100 bytes or one memory page
            chunk = f.read(100)
            sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        print(f"[-] Error reading memory from PID {pid}: {e}")
        return None

def check_binary(binary_path):
    print(f"[*] Analyzing target: {binary_path}")

    # 1. Get the initial disk hash
    disk_hash = get_disk_hash(binary_path)
    if not disk_hash:
        return

    # 2. Find the PID
    binary_name = os.path.basename(binary_path)

    try:
        # Get all PIDs for the binary
        all_pids = subprocess.check_output(["pgrep", binary_name]).decode().strip().split('\n')

        # Get our own parent's PID to avoid scanning ourselves in the process
        my_ppid = str(os.getppid())

        # Filter out the parent PID we just discovered
        valid_pids = [p for p in all_pids if p and p != my_ppid]

        if not valid_pids:
            print(f"[-] Process '{binary_name}' is not currently running (excluding parent). Unable to check memory.")
            return

        pid = valid_pids[0]

    except subprocess.CalledProcessError:
        print(f"[-] Process '{binary_name}' is not currently running. Unable to check memory.")
        return

    if not pid_output:
        print(f"[-] Process '{binary_name}' is not currently running, unable to check memory.")
        return

    # Grab the first PID in the list and strip any of the trailing whitespace
    pid = pid_output.split('\n')[0].strip()

    # SAFETY CHECK: This ensures pid actually has a value
    if not pid:
        print(f"[-] Could not parse a valid PID for '{binary_name}'. Skipping.")
        return

    print(f"[*] Found active PID: {pid}")
    
    # 3. Get the memory hash
    memory_hash = get_memory_hash(pid)
    if not memory_hash:
        return

    # 4. Compare the two hashes
    print(f"    Disk Hash: {disk_hash[:16]}...")
    print(f"    Memory Hash: {memory_hash[:16]}...")

    if disk_hash == memory_hash:
        print(f"[+] SUCCESS: {binary_name} matches the disk. No tampering has been detected.\n")
    else:
        print(f"[!] CRITICAL ALERT: COPY FAIL HAS BEEN DETECTED ON {binary_name}!")
        print(f"[!] The file on disk is clean, but the memory has been tampered with.\n")
        

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[-] Please run as root (sudo python3 copyfix.py)")
        sys.exit(1)

    # The Signature
    print("==============================================================================")
    print("CopyFix - a tool by Stlwtrs")
    print("Dual-Verification File Integrity Monitoring Tool")
    print("==============================================================================\n")

    # If the user passes a specific file, check it instead.
    # Otherwise, check a default list of critical binaries.
    if len(sys.argv) > 2 and sys.argv[1] == "--check":
            targets = [sys.argv[2]]
    elif len(sys.argv) > 1: 
            targets = [sys.argv[1]]
        # If they pass a file path without --check
    else:
            targets = ["/usr/bin/su", "/usr/bin/sudo", "/usr/bin/ssh"]
            print("[*] No target specified. Scanning the default critical binaries...\n")

    for target in targets:
            if not os.path.exists(target):
                print(f"[-] Target {target} does not exist. Skipping.\n")
                continue
            check_binary(target)
