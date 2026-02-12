"""
config.py
Centralized configuration for all automation scripts.

Modify these values instead of changing script code.
"""

# ============================================================
# DISK MONITOR CONFIGURATION
# ============================================================
DISK_ALERT_THRESHOLD = 80  # Alert if disk usage exceeds this percentage
DISK_LOG_FILE = "disk_monitor.log"


# ============================================================
# FILE INTEGRITY CONFIGURATION
# ============================================================
INTEGRITY_BASELINE_FILE = "integrity_baseline.json"
INTEGRITY_LOG_FILE = "file_integrity.log"


# ============================================================
# PROCESS MONITOR CONFIGURATION
# ============================================================
PROCESS_LOG_FILE = "process_monitor.log"
PROCESS_CPU_THRESHOLD = 80.0  # Alert if process uses > X% CPU
PROCESS_MEMORY_THRESHOLD = 1024  # Alert if process uses > X MB RAM

# Suspicious process indicators
SUSPICIOUS_PROCESS_NAMES = [
    "mimikatz",
    "psexec",
    "ncat",
    "netcat",
    "nc.exe",
    "powercat",
    "procdump",
    "pwdump",
]

SUSPICIOUS_PROCESS_PATHS = [
    "\\temp\\",
    "\\tmp\\",
    "\\appdata\\local\\temp\\",
    "\\downloads\\",
    "\\public\\",
]


# ============================================================
# LOGGING CONFIGURATION
# ============================================================
LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
LOG_LEVEL_CONSOLE = "INFO"  # DEBUG, INFO, WARNING, ERROR
LOG_LEVEL_FILE = "DEBUG"


# ============================================================
# GENERAL SETTINGS
# ============================================================
DEFAULT_SCAN_RECURSIVE = True  # Default for file/folder scans
ENABLE_COLORED_OUTPUT = False  # Colored terminal output (requires colorama)
