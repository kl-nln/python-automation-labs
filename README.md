# python-automation-labs

Practical Python automation labs built to develop real-world scripting skills for IT, cloud, and security workflows. Each lab focuses on a small tool that solves a real problem, with clean structure, logging, and safe error handling.

---

## What’s in this repo

This repo currently contains scripts that:
- Print basic system information (OS, username, working directory)
- Scan a folder and generate a report grouping files by type (extension)
- Add logging + error handling so scripts fail safely and are easy to troubleshoot

---

## Scripts

### 1) `system_info.py` — System Info Printer

#### What the script does
Prints:
- Operating system (name + version)
- Current username
- Current working directory

#### Why it matters
This is a common first step in automation: verifying environment details before running tasks (diagnostics, auditing, deployment scripts, etc.).

#### How to run
```bash
python system_info.py


# Example Output 

=== SYSTEM INFORMATION ===
OS: Windows
OS Version: 11
Username: Kiante
Current Directory: C:\Users\Kiante\python-automation-labs
==========================


=== Folder Scan Report ===
Folder: C:\Users\Kiante\python-automation-labs
Total files found: 5

[.py] (2 files)
  - day3_scan_folder.py
  - system_info.py

[.md] (1 files)
  - README.md

[<no_extension>] (2 files)
  - .gitignore
  - requirements.txt
