# Security Policy

## Supported Versions

Currently, only the latest version of `CopyFix` on the `main` branch is supported with security updates.

| Version | Supported          |
| ------- | ------------------ |
| Main    | :white_check_mark: |
| < 1.0   | :x:                |


## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a vulnerability in `CopyFix` *(e.g. a way to bypass the hash comparison, a privilege escalation vector, or a denial of service vulnerability)*, please report it responsibly.

Please send an email to **stlwtrs@proton.me** or reach out to me via my TryHackMe or LinkedIn profiles listed on my GitHub profile.

You should receive a response within 48 hours. If for some reason you do not, please follow up via LinkedIn to ensure I received your original message.

Please include the following details in your report:

* Type of issue *(e.g. bypass, crash, memory leak, etc..)*

* Full paths of source file(s) related to the manifestation of the issue.

* The location of the affected source code *(tag/branch/commit or direct URL)*

* Any special configuration required to reproduce the issue.

* PoC or exploit code (if applicable)

* Impact of the issue, including how an attacker might exploit the issue.

## Scope

`CopyFix` is designed to detect *existing* memory tampering by comparing hashes. It is **not** designed to prevent an attacker with `root` prvileges from killing the `CopyFix` process or manipulating the output. The scope of this policy covers vulnerabilities **within the Python script itself**.
