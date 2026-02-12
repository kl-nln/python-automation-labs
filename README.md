# Python Automation Labs

A portfolio of practical Python automation scripts for system administration, cybersecurity, networking, and cloud operations.

## 📁 Repository Structure

```
python-automation-labs/
│
├── system_admin/          # System administration scripts
├── cybersecurity/         # Security automation tools
├── networking/            # Network scanning and monitoring
├── cloud_automation/      # AWS/cloud automation (coming soon)
├── productivity/          # Personal productivity tools (coming soon)
├── utils/                 # Shared utilities and helpers
│
├── requirements.txt
└── README.md
```

## 🛠️ Current Scripts

### System Administration (`system_admin/`)

#### 1. `system_info.py` - System Information Display
**What it does:**
- Displays OS name and version
- Shows current username
- Prints current working directory

**How to run:**
```bash
python system_admin/system_info.py
```

**Example output:**
```
=== SYSTEM INFORMATION ===
OS: Windows
OS Version: 11
Username: Kiante
Current Directory: C:\Users\Kiante\python-automation-labs
==========================
```

---

#### 2. `day3_scan_folder.py` - Basic Folder Scanner
**What it does:**
- Scans a target directory
- Groups files by extension type
- Outputs results to `scan_report.txt`

**How to run:**
```bash
python system_admin/day3_scan_folder.py
```

---

#### 3. `day3_scan_folder_logged.py` - Advanced Folder Scanner
**What it does:**
- Everything from the basic scanner, plus:
- Logs all operations to `scan_folder.log`
- Handles missing/invalid folders gracefully
- Catches permission errors without crashing
- Optional report copying to another directory

**How to run:**
```bash
python system_admin/day3_scan_folder_logged.py
```

**Example scan_report.txt:**
```
=== Folder Scan Report ===
Timestamp: 2026-02-09 10:15:30
Folder: C:\Users\Kiante\python-automation-labs
Recursive: False
Total files found: 8

[.py] (3 files)
  - day3_scan_folder.py
  - day3_scan_folder_logged.py
  - system_info.py

[.md] (1 files)
  - README.md
```

---

#### 4. `disk_monitor.py` - Disk Usage Monitor (Week 2)
**What it does:**
- Scans all available disk drives
- Calculates total, used, and free space
- Alerts if any drive exceeds 80% usage
- Logs all operations with timestamps

**Why it matters:**
- Prevents disk space issues before they cause problems
- Essential for system administration
- Foundation for automated monitoring systems

**How to run:**
```bash
python system_admin/disk_monitor.py --summary
```

**Example output:**
```
======================================================================
DISK USAGE REPORT
Timestamp: 2026-02-12 08:43:37
Alert Threshold: 80%
======================================================================

[OK] Drive: C:\
   Total:     953.04 GB
   Used:      320.01 GB
   Free:      633.04 GB
   Usage:     33.58%
   Status:    OK

======================================================================
```

---

#### 5. `file_integrity.py` - File Integrity Checker (Week 2)
**What it does:**
- Creates SHA-256 hash baselines of files
- Detects modifications, additions, and deletions
- Monitors unauthorized file changes
- Essential for security auditing and compliance

**Security+ relevance:**
- File integrity monitoring (FIM)
- Tamper detection
- Baseline configuration management

**How to run:**
```bash
# Create baseline
python system_admin/file_integrity.py --baseline <folder>

# Check for changes
python system_admin/file_integrity.py --check <folder>
```

**Example output:**
```
======================================================================
FILE INTEGRITY CHECK REPORT
Timestamp: 2026-02-10 13:48:25
======================================================================

⚠️  1 CHANGE(S) DETECTED

MODIFIED FILES (1):
  - file1.txt
    Baseline: a1b2c3d4e5f6...
    Current:  9z8y7x6w5v4u...

UNCHANGED: 1 files
======================================================================
```

---

#### 6. `process_monitor.py` - Process Monitor (Week 2)
**What it does:**
- Lists all running processes
- Shows top CPU and memory consumers
- Searches for specific processes
- Detects suspicious processes based on:
  - Process names (mimikatz, psexec, etc.)
  - Execution paths (temp folders, downloads)
  - High resource usage (CPU > 80%, Memory > 1GB)

**Security+ relevance:**
- Process monitoring for threat detection
- Anomaly detection
- Incident response

**How to run:**
```bash
# Show system summary
python system_admin/process_monitor.py --summary

# Top 10 CPU consumers
python system_admin/process_monitor.py --top 10

# Top 10 memory consumers
python system_admin/process_monitor.py --memory 10

# Search for a process
python system_admin/process_monitor.py --search chrome

# Detect suspicious processes
python system_admin/process_monitor.py --suspicious
```

**Example output:**
```
====================================================================================================
TOP 10 PROCESSES (BY CPU)
====================================================================================================
PID      Name                      CPU %    Memory MB    Threads    Status
----------------------------------------------------------------------------------------------------
31240    chrome.exe                124.3    1090.8       40         running
25972    chrome.exe                30.8     603.3        26         running
13724    TradingView.exe           15.6     665.5        23         running
====================================================================================================
```

---

## 🔧 Configuration

All scripts use centralized configuration in `utils/config.py`.

### Modifying Settings

Edit `utils/config.py` to change script behavior:

```python
# Disk Monitor
DISK_ALERT_THRESHOLD = 80  # Change to 70 for earlier warnings

# Process Monitor  
PROCESS_CPU_THRESHOLD = 80.0
PROCESS_MEMORY_THRESHOLD = 1024

# Add suspicious process names
SUSPICIOUS_PROCESS_NAMES = [
    "mimikatz",
    "psexec",
    "your_malware.exe",  # Add custom entries
]
```

### Benefits of Centralized Config

- ✅ Change settings without editing code
- ✅ Consistent values across all scripts
- ✅ Easy to version control
- ✅ Clear documentation of all settings

---

## 🚀 Setup Instructions

### Prerequisites
- Python 3.10 or higher
- Git

### Installation

1. **Clone the repository:**
```bash
git clone https://github.com/CodeBroKinty/python-automation-labs.git
cd python-automation-labs
```

2. **Create virtual environment:**
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

3. **Install dependencies:**
```bash
pip install -r requirements.txt
```

---

## 📦 Dependencies

Install required packages:
```bash
pip install -r requirements.txt
```

Current dependencies:
- `psutil` - System and process utilities

---

## 📝 Skills Demonstrated

- ✅ Python fundamentals (variables, functions, loops, conditionals)
- ✅ File system operations (`os`, `pathlib`, `shutil`)
- ✅ Error handling (`try/except`)
- ✅ Logging configuration and best practices
- ✅ Code organization and modularity
- ✅ Git version control
- ✅ Professional documentation
- ✅ Cryptographic hashing (SHA-256)
- ✅ Process and system monitoring
- ✅ Configuration management

---

## 🎯 Project Goals

This repository is being built as part of a structured learning path covering:
- **Week 1:** Python fundamentals + file operations ✅
- **Week 2:** System administration automation ✅
- **Week 3:** Cybersecurity tools (log parsing, threat detection)
- **Week 4:** Network automation (scanning, monitoring)
- **Week 5:** AWS cloud automation
- **Week 6:** Productivity tools + portfolio polish

---

## 📚 Learning Resources

- [Automate the Boring Stuff with Python](https://automatetheboringstuff.com/)
- [Python Official Documentation](https://docs.python.org/3/)
- CompTIA Security+ study materials

---

## 📄 License

This project is for educational and portfolio purposes.

---

**Note:** Generated files (`*.log`, `scan_report.txt`, `integrity_baseline.json`) are excluded from version control via `.gitignore`.
