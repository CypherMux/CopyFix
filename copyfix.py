#!/usr/bin/env python3
import os
import sys
import hashlib
import subprocess

def get_disk_hash(filepath):
    """Hashes the first 100 bytes of a file directly from the disk."""
    sha256 = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            chunk = f.read(100)
            sha256.update(chunk)
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
    pid = None

    try:
        # Use pgrep -x to match the exact binary name, not partial strings
        output = subprocess.check_output(["pgrep", "-x", binary_name]).decode('utf-8')

        # Split by newline and filter out the empty strings
        all_pids = [p.strip() for p in output.split('\n') if p.strip()]

        my_pid = str(os.getpid())

        # Filter out your own PID just in case of future errors
        valid_pids = [p for p in all_pids if p != my_pid]

        if not valid_pids:
            print(f"[-] Process '{binary_name}' is not currently running (excluding self). Unable to check memory.\n")
            return

        # Grab the first valid PID
        pid = valid_pids[0]

    except subprocess.CalledProcessError:

    # pgrep returns exit code 1 if no processes are found on system
        print(f"[-] Process '{binary_name}' is not currently running. Unable to check memory.\n")
        return
    except Exception as e:
            print(f"[-] Error searching for PID: {e}\n")
            return
    
    print(f"[*] Found active PID: {pid}")
    
    # 3. Get the memory hash
    memory_hash = get_memory_hash(pid)
    if not memory_hash:
        return

# 4. Compare the two hashes
print(f"    Disk Hash: {get_disk_hash[:16]}...")
print(f"    Memory Hash: {get_memory_hash[:16]}...")

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

    targets = []

    if len(sys.argv) == 1:
        # No arguments provided check/comment
        targets = ["/usr/bin/su", "/usr/bin/sudo", "/usr/bin/ssh"]
        print("[*] No target specified. Scanning the default critical binaries...\n")

    elif len(sys.argv) == 3 and sys.argv[1] == "--check":

        # Specific target provided check/comment
        targets = [sys.argv[2]]
    else:
        print("Usage: sudo ./copyfix.py [--check /path/to/binary]")
        print("       sudo ./copyfix.py (scans defaults)")
        sys.exit(1)

    for target in targets:
        if not os.path.exists(target):
            print(f"[-] Target {target} does not exist. Skipping.\n")
            continue
        check_binary(target)

    
