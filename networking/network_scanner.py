"""
network_scanner.py
Unified network reconnaissance tool combining ping sweep, port scanning, and service detection.

Usage:
    python networking/network_scanner.py --target 192.168.1.0/24
    python networking/network_scanner.py --target 192.168.1.1 --deep
    python networking/network_scanner.py --target scanme.nmap.org --quick
"""

import subprocess
import socket
import sys
import ipaddress
from pathlib import Path
from datetime import datetime
import concurrent.futures
import argparse
import json

# Add repo root to Python path
repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from utils.logger import setup_logger

# Configuration
LOG_FILE = "network_scanner.log"
REPORTS_DIR = Path("network_reports")

# Common ports for different scan modes
QUICK_PORTS = [21, 22, 23, 80, 443, 3389]
STANDARD_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3306, 3389, 5432, 8080]
DEEP_PORTS = list(range(1, 1025))  # First 1024 ports


def ping_host(ip_address):
    """Quick ping check."""
    import platform
    system = platform.system().lower()
    
    if system == "windows":
        command = ["ping", "-n", "1", "-w", "1000", str(ip_address)]
    else:
        command = ["ping", "-c", "1", "-W", "1", str(ip_address)]
    
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=2)
        return result.returncode == 0
    except:
        return False


def scan_port(ip, port, timeout=1):
    """Quick port scan."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False


def grab_banner(ip, port, timeout=2):
    """Grab service banner."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        
        # Try to receive banner
        banner = sock.recv(1024)
        sock.close()
        
        return banner.decode('utf-8', errors='ignore').strip()
    except:
        return None


def scan_host(ip, ports, logger=None):
    """
    Complete scan of a single host.
    
    Args:
        ip: IP address to scan
        ports: List of ports to scan
        logger: Logger instance
    
    Returns:
        dict: Scan results for host
    """
    host_info = {
        "ip": str(ip),
        "alive": False,
        "open_ports": [],
        "services": {}
    }
    
    # Ping check
    if ping_host(ip):
        host_info["alive"] = True
        
        if logger:
            logger.info(f"Host {ip} is alive")
        
        # Port scan
        for port in ports:
            if scan_port(ip, port):
                host_info["open_ports"].append(port)
                
                # Try to grab banner
                banner = grab_banner(ip, port)
                if banner:
                    host_info["services"][port] = banner[:100]
                
                if logger:
                    logger.info(f"{ip}:{port} open - {banner[:50] if banner else 'no banner'}")
    
    return host_info


def parse_target(target):
    """Parse target specification."""
    try:
        if "/" in target:
            network = ipaddress.ip_network(target, strict=False)
            return [str(ip) for ip in network.hosts()]
        elif "-" in target:
            start_ip, end_ip = target.split("-")
            start = ipaddress.ip_address(start_ip.strip())
            end = ipaddress.ip_address(end_ip.strip())
            
            current = start
            ips = []
            while current <= end:
                ips.append(str(current))
                current = ipaddress.ip_address(int(current) + 1)
            return ips
        else:
            ipaddress.ip_address(target)
            return [target]
    except ValueError as e:
        raise ValueError(f"Invalid target: {target}. Error: {e}")


def network_scan(targets, ports, max_workers=20, logger=None):
    """
    Scan multiple targets.
    
    Args:
        targets: List of IP addresses
        ports: List of ports to scan
        max_workers: Concurrent threads
        logger: Logger instance
    
    Returns:
        list: Scan results for all hosts
    """
    results = []
    total = len(targets)
    completed = 0
    
    print(f"\n🔍 Scanning {total} host(s) with {len(ports)} ports each...")
    print(f"⚙️  Using {max_workers} concurrent threads\n")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {executor.submit(scan_host, ip, ports, logger): ip for ip in targets}
        
        for future in concurrent.futures.as_completed(future_to_ip):
            completed += 1
            result = future.result()
            
            if result["alive"]:
                results.append(result)
            
            if completed % 10 == 0 or completed == total:
                print(f"Progress: {completed}/{total} ({(completed/total)*100:.1f}%)", end="\r")
    
    print()
    return results


def print_summary(results, scan_mode):
    """Print scan summary."""
    print("\n" + "=" * 80)
    print("NETWORK SCAN SUMMARY")
    print(f"Scan Mode: {scan_mode.upper()}")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 80)
    
    total_hosts = len(results)
    total_ports = sum(len(r["open_ports"]) for r in results)
    
    print(f"\n📊 OVERVIEW")
    print(f"   Live hosts discovered: {total_hosts}")
    print(f"   Total open ports: {total_ports}")
    
    if results:
        print(f"\n✅ DISCOVERED HOSTS")
        
        for host in sorted(results, key=lambda x: ipaddress.ip_address(x["ip"])):
            print(f"\n   📍 {host['ip']}")
            print(f"      Open ports: {len(host['open_ports'])}")
            
            if host["open_ports"]:
                ports_str = ", ".join(map(str, sorted(host["open_ports"])))
                print(f"      Ports: {ports_str}")
                
                # Show services with banners
                if host["services"]:
                    print(f"      Services detected:")
                    for port, banner in sorted(host["services"].items()):
                        preview = banner.split('\n')[0][:60]
                        print(f"         {port}: {preview}")
    
    print("\n" + "=" * 80 + "\n")


def export_report(results, scan_mode, output_dir):
    """Export comprehensive report."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Text report
    txt_file = output_dir / f"network_scan_{timestamp}.txt"
    with open(txt_file, 'w') as f:
        f.write("NETWORK SCAN REPORT\n")
        f.write(f"Scan Mode: {scan_mode.upper()}\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 80 + "\n\n")
        
        for host in sorted(results, key=lambda x: ipaddress.ip_address(x["ip"])):
            f.write(f"Host: {host['ip']}\n")
            f.write(f"Open Ports: {', '.join(map(str, sorted(host['open_ports'])))}\n")
            
            if host["services"]:
                f.write("Services:\n")
                for port, banner in sorted(host["services"].items()):
                    f.write(f"  Port {port}: {banner[:80]}\n")
            f.write("\n")
    
    # JSON export
    json_file = output_dir / f"network_scan_{timestamp}.json"
    with open(json_file, 'w') as f:
        json.dump({
            "scan_mode": scan_mode,
            "timestamp": datetime.now().isoformat(),
            "results": results
        }, f, indent=2)
    
    print(f"📁 Reports saved:")
    print(f"   Text: {txt_file.name}")
    print(f"   JSON: {json_file.name}")
    
    return txt_file, json_file


def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(
        description="Network Scanner - Unified reconnaissance tool"
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Target: IP, CIDR (192.168.1.0/24), or range (192.168.1.1-192.168.1.50)"
    )
    
    scan_mode = parser.add_mutually_exclusive_group()
    scan_mode.add_argument(
        "--quick",
        action="store_true",
        help="Quick scan (6 common ports)"
    )
    scan_mode.add_argument(
        "--deep",
        action="store_true",
        help="Deep scan (first 1024 ports)"
    )
    
    parser.add_argument(
        "--workers",
        type=int,
        default=20,
        help="Concurrent threads (default: 20)"
    )
    parser.add_argument(
        "--export",
        action="store_true",
        help="Export results to file"
    )
    
    args = parser.parse_args()
    
    # Setup
    logger = setup_logger(__name__, LOG_FILE)
    
    logger.info("=" * 50)
    logger.info("Network Scanner Started")
    logger.info("=" * 50)
    
    try:
        # Determine scan mode
        if args.quick:
            ports = QUICK_PORTS
            mode = "quick"
        elif args.deep:
            ports = DEEP_PORTS
            mode = "deep"
        else:
            ports = STANDARD_PORTS
            mode = "standard"
        
        print(f"\n🎯 Target: {args.target}")
        print(f"📋 Scan Mode: {mode.upper()} ({len(ports)} ports)")
        
        # Parse targets
        targets = parse_target(args.target)
        
        if not targets:
            print("\n❌ No valid targets")
            return
        
        # Run scan
        start_time = datetime.now()
        
        results = network_scan(targets, ports, args.workers, logger)
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        # Print results
        print_summary(results, mode)
        
        print(f"⏱️  Scan completed in {duration:.2f} seconds")
        
        # Export if requested
        if args.export:
            REPORTS_DIR.mkdir(exist_ok=True)
            export_report(results, mode, REPORTS_DIR)
        
        logger.info(f"Scan completed in {duration:.2f}s - {len(results)} hosts found")
        
    except KeyboardInterrupt:
        logger.warning("Scan cancelled")
        print("\n\nCancelled.")
    except Exception as e:
        logger.exception(f"Error: {e}")
        print(f"\n❌ Error: {e}")


if __name__ == "__main__":
    main()
