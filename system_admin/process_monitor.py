"""
process_monitor.py
Monitors running processes, CPU usage, and memory consumption.

Usage:
    python system_admin/process_monitor.py --top 10           # Show top 10 processes
    python system_admin/process_monitor.py --search chrome    # Find specific process
    python system_admin/process_monitor.py --suspicious       # Detect suspicious processes
"""

import psutil
import sys
from pathlib import Path
from datetime import datetime
import argparse

# Add repo root to Python path
repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from utils.logger import setup_logger


# Configuration
LOG_FILE = "process_monitor.log"
CPU_THRESHOLD = 80.0  # Alert if process uses > 80% CPU
MEMORY_THRESHOLD = 1024  # Alert if process uses > 1GB RAM (in MB)

# Suspicious process indicators
SUSPICIOUS_NAMES = [
    "mimikatz",
    "psexec",
    "ncat",
    "netcat",
    "nc.exe",
    "powercat",
]

SUSPICIOUS_PATHS = [
    "\\temp\\",
    "\\tmp\\",
    "\\appdata\\local\\temp\\",
    "\\downloads\\",
]


def get_process_info(proc):
    """
    Get detailed information about a process.
    
    Args:
        proc: psutil.Process object
    
    Returns:
        dict: Process information or None if access denied
    """
    try:
        # Get process details
        with proc.oneshot():
            info = {
                "pid": proc.pid,
                "name": proc.name(),
                "status": proc.status(),
                "cpu_percent": proc.cpu_percent(interval=0.1),
                "memory_mb": proc.memory_info().rss / (1024 * 1024),
                "num_threads": proc.num_threads(),
                "username": proc.username() if hasattr(proc, 'username') else "N/A",
                "created": datetime.fromtimestamp(proc.create_time()).strftime('%Y-%m-%d %H:%M:%S'),
            }
            
            # Try to get executable path (may fail for some processes)
            try:
                info["exe"] = proc.exe()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                info["exe"] = "N/A"
            
            return info
            
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None


def get_all_processes(logger):
    """
    Get information about all running processes.
    
    Args:
        logger: Logger instance
    
    Returns:
        list: List of process info dictionaries
    """
    processes = []
    
    for proc in psutil.process_iter(['pid', 'name']):
        info = get_process_info(proc)
        if info:
            processes.append(info)
    
    logger.info(f"Found {len(processes)} running processes")
    return processes


def get_top_processes(processes, count=10, sort_by="cpu"):
    """
    Get top N processes by CPU or memory usage.
    
    Args:
        processes: List of process info dicts
        count: Number of top processes to return
        sort_by: 'cpu' or 'memory'
    
    Returns:
        list: Top N processes
    """
    if sort_by == "cpu":
        sorted_procs = sorted(processes, key=lambda p: p["cpu_percent"], reverse=True)
    elif sort_by == "memory":
        sorted_procs = sorted(processes, key=lambda p: p["memory_mb"], reverse=True)
    else:
        sorted_procs = processes
    
    return sorted_procs[:count]


def search_processes(processes, search_term, logger):
    """
    Search for processes by name.
    
    Args:
        processes: List of process info dicts
        search_term: Process name to search for
        logger: Logger instance
    
    Returns:
        list: Matching processes
    """
    search_term = search_term.lower()
    matches = [p for p in processes if search_term in p["name"].lower()]
    
    logger.info(f"Found {len(matches)} processes matching '{search_term}'")
    return matches


def detect_suspicious_processes(processes, logger):
    """
    Detect potentially suspicious processes.
    
    Args:
        processes: List of process info dicts
        logger: Logger instance
    
    Returns:
        list: Suspicious processes with reasons
    """
    suspicious = []
    
    for proc in processes:
        reasons = []
        
        # Check suspicious names
        proc_name_lower = proc["name"].lower()
        for sus_name in SUSPICIOUS_NAMES:
            if sus_name in proc_name_lower:
                reasons.append(f"Suspicious name: {sus_name}")
        
        # Check suspicious paths
        if proc["exe"] != "N/A":
            proc_exe_lower = proc["exe"].lower()
            for sus_path in SUSPICIOUS_PATHS:
                if sus_path in proc_exe_lower:
                    reasons.append(f"Suspicious location: {sus_path}")
        
        # Check high resource usage
        if proc["cpu_percent"] > CPU_THRESHOLD:
            reasons.append(f"High CPU: {proc['cpu_percent']:.1f}%")
        
        if proc["memory_mb"] > MEMORY_THRESHOLD:
            reasons.append(f"High memory: {proc['memory_mb']:.1f} MB")
        
        if reasons:
            suspicious.append({
                "process": proc,
                "reasons": reasons
            })
            logger.warning(f"Suspicious: {proc['name']} (PID {proc['pid']}) - {', '.join(reasons)}")
    
    return suspicious


def print_process_table(processes, title="PROCESSES"):
    """
    Print processes in a formatted table.
    
    Args:
        processes: List of process info dicts
        title: Table title
    """
    print("\n" + "=" * 100)
    print(f"{title}")
    print("=" * 100)
    
    # Header
    print(f"{'PID':<8} {'Name':<25} {'CPU %':<8} {'Memory MB':<12} {'Threads':<10} {'Status':<10}")
    print("-" * 100)
    
    # Rows
    for proc in processes:
        print(
            f"{proc['pid']:<8} "
            f"{proc['name'][:24]:<25} "
            f"{proc['cpu_percent']:<8.1f} "
            f"{proc['memory_mb']:<12.1f} "
            f"{proc['num_threads']:<10} "
            f"{proc['status']:<10}"
        )
    
    print("=" * 100 + "\n")


def print_suspicious_report(suspicious):
    """
    Print suspicious processes report.
    
    Args:
        suspicious: List of suspicious process dicts
    """
    print("\n" + "=" * 100)
    print("SUSPICIOUS PROCESS REPORT")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 100)
    
    if not suspicious:
        print("\n✓ No suspicious processes detected\n")
    else:
        print(f"\n⚠️  {len(suspicious)} SUSPICIOUS PROCESS(ES) DETECTED\n")
        
        for item in suspicious:
            proc = item["process"]
            reasons = item["reasons"]
            
            print(f"Process: {proc['name']} (PID {proc['pid']})")
            print(f"  Path: {proc['exe']}")
            print(f"  CPU: {proc['cpu_percent']:.1f}% | Memory: {proc['memory_mb']:.1f} MB")
            print(f"  User: {proc['username']}")
            print(f"  Reasons:")
            for reason in reasons:
                print(f"    - {reason}")
            print()
    
    print("=" * 100 + "\n")


def print_system_summary(logger):
    """
    Print overall system resource summary.
    
    Args:
        logger: Logger instance
    """
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    
    print("\n" + "=" * 100)
    print("SYSTEM RESOURCE SUMMARY")
    print("=" * 100)
    print(f"CPU Usage:    {cpu_percent}%")
    print(f"Memory Total: {memory.total / (1024**3):.2f} GB")
    print(f"Memory Used:  {memory.used / (1024**3):.2f} GB ({memory.percent}%)")
    print(f"Memory Free:  {memory.available / (1024**3):.2f} GB")
    print("=" * 100 + "\n")
    
    logger.info(f"System CPU: {cpu_percent}% | Memory: {memory.percent}%")


def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(
        description="Process Monitor - Track CPU, memory, and detect suspicious activity"
    )
    parser.add_argument(
        "--top",
        type=int,
        metavar="N",
        help="Show top N processes by CPU usage"
    )
    parser.add_argument(
        "--memory",
        type=int,
        metavar="N",
        help="Show top N processes by memory usage"
    )
    parser.add_argument(
        "--search",
        metavar="NAME",
        help="Search for processes by name"
    )
    parser.add_argument(
        "--suspicious",
        action="store_true",
        help="Detect suspicious processes"
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Show system resource summary"
    )
    
    args = parser.parse_args()
    
    # Setup logger
    logger = setup_logger(__name__, LOG_FILE)
    
    logger.info("=" * 50)
    logger.info("Process Monitor Started")
    logger.info("=" * 50)
    
    try:
        # Get all processes
        processes = get_all_processes(logger)
        
        if args.summary:
            print_system_summary(logger)
        
        if args.top:
            top_procs = get_top_processes(processes, count=args.top, sort_by="cpu")
            print_process_table(top_procs, f"TOP {args.top} PROCESSES (BY CPU)")
        
        if args.memory:
            top_procs = get_top_processes(processes, count=args.memory, sort_by="memory")
            print_process_table(top_procs, f"TOP {args.memory} PROCESSES (BY MEMORY)")
        
        if args.search:
            matches = search_processes(processes, args.search, logger)
            if matches:
                print_process_table(matches, f"SEARCH RESULTS: '{args.search}'")
            else:
                print(f"\nNo processes found matching '{args.search}'\n")
        
        if args.suspicious:
            suspicious = detect_suspicious_processes(processes, logger)
            print_suspicious_report(suspicious)
        
        # If no arguments, show help
        if not any([args.top, args.memory, args.search, args.suspicious, args.summary]):
            parser.print_help()
            print("\nExample usage:")
            print("  Show top 10 CPU:      python system_admin/process_monitor.py --top 10")
            print("  Show top 10 memory:   python system_admin/process_monitor.py --memory 10")
            print("  Search for Chrome:    python system_admin/process_monitor.py --search chrome")
            print("  Detect suspicious:    python system_admin/process_monitor.py --suspicious")
            print("  System summary:       python system_admin/process_monitor.py --summary")
        
        logger.info("Process Monitor Completed Successfully")
        
    except KeyboardInterrupt:
        logger.warning("Monitoring cancelled by user")
        print("\nCancelled.")
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
        print(f"\n❌ Error: {e}")
        print("Check process_monitor.log for details.")


if __name__ == "__main__":
    main()
