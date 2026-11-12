#!/usr/bin/env python3
import os
import sys
import hashlib
import subprocess

def get_disk_hash(filepath):
    """Hashes a file directly from the disk, bypassing the page cache."""
    sha256 = hashlib.sha256()
    try:
      # O_DIRECT forces the kernel to read from the disk, not the RAM cache.
      # NOTE: O_DIRECT requires the buffer size and file offset to be fully aligned.
      # We use a block size of 4096 bytes for this exact reason.

        fd = os.open(filepath, os.O_RDONLY | os.O_DIRECT)
        try:
            while True:
                chunk = os.read(fd, 4096)
                if not chunk:
                    break
                sha256.update(chunk)
        finally:
            os.close(fd)
        return sha256.hexdigest()
    except Exception as e:
        print(f"[-] Error reading disk file {filepath}: {e}")
        return None

def get_memory_hash(pid)
    """Hashes the in-memory executable of a running process."""
    exe_path = f"/proc/{pid}/exe"
    sha256 = hashlib.sha256()
    try:
        with open(exe_path, 'rb') as f:
            while True:
                chunk = f.read(4096)
                if not chunk:
                    break
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        print(f"[-] Error reading memory from PID {pid}: {e}")
        return None

def check_binary(binary_path):
    print(f"[*] Analyzing target: {binary_path}")

    # 1. Get the initial disk hash (O_DIRECT)
    disk_hash =
get_disk_hash(binary_path)
    if not disk_hash:
        return

    # 2. Finds the PID of the running process
    # Uses pgrep to find if the binary is currently running
    binary_name =
os.path.basename(binary_path)
    try:
        pid_output =
subprocess.check.output(["pgrep", "-n", binary_name]).decode().strip()
        if not pid_output:
            print(f"[-] Process '{binary_name}' is not currently running. Unable to check memory.")
            return
        pid = pid_output.split('\n')[0]
    except
subprocess.CalledProcessError:
        print(f"[-] Process '{binary_name' is not currently running. Unable to check memory.")
        return
    print("f[*] Found active PID: {pid}")

    # 3. Get the memory hash
    memory_hash = get_memory_hash(pid)
    if not memory_hash:
        return

    # 4. Compare the hashes
    print(f"    Disk Hash: {disk_hash[:16]}...")
    print(f"    Memory Hash: {memory_hash[:16]}...")

    if disk_hash == memory_hash:
        print(f"[+] SUCCESS: {binary_name} matches the disk. No tampering detected.\n")
    else:
        print(f"[!] CRITICAL ALERT: COPY FAIL DETECTED ON {binary_name}!")
        print(f"[!] The file on disk is clean, but the memory has been tampered with.\n")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[-] Please run as root (sudo python3 copyfix.py)")
        sys.exit(1)

    # The Signature
print("==============================================================================")
    print("    CopyFix - a tool by Stlwtrs")
    print("    Dual-Verification File Integrity Monitoring Tool")
print("==============================================================================\n")

    # If the user passes a specific file, check it instead.
    # Otherwise, check a default list of critical binaries.
    if len(sys.argv) > 1:
        targets = [sys.argv[1]]
    else:
        targets = ["/usr/bin/su", "/usr/bin/sudo", "/usr/bin/ssh"]
        print("[*] No target specified. Scanning the default critical binaries...\n")

    for target in targets:
        if not os.path.exists(target):
            print(f"[-] Target {target} does not exist. Skipping.\n")
            continue
        check_binary(target)
