"""
port_scanner.py
TCP port scanner with service detection.

Usage:
    python networking/port_scanner.py --target 192.168.1.1 --ports 80,443,22
    python networking/port_scanner.py --target 192.168.1.1 --common
    python networking/port_scanner.py --target 192.168.1.1 --range 1-1024
    python networking/port_scanner.py --target scanme.nmap.org --common
"""

import socket
import sys
from pathlib import Path
from datetime import datetime
import concurrent.futures
import argparse

# Add repo root to Python path
repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from utils.logger import setup_logger

# Configuration
LOG_FILE = "port_scanner.log"
MAX_WORKERS = 100  # Concurrent scan threads
SOCKET_TIMEOUT = 1  # Seconds to wait for connection

# Common ports and their services
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1723: "PPTP",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
}

# Well-known ports (extended list)
WELL_KNOWN_SERVICES = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP-Server",
    68: "DHCP-Client",
    69: "TFTP",
    80: "HTTP",
    88: "Kerberos",
    110: "POP3",
    119: "NNTP",
    123: "NTP",
    135: "RPC",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    139: "NetBIOS-SSN",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP-Trap",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    587: "SMTP-Submission",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1434: "MSSQL-Monitor",
    1521: "Oracle",
    1723: "PPTP",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    5901: "VNC-1",
    5902: "VNC-2",
    6379: "Redis",
    8000: "HTTP-Alt",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt",
    9000: "SonarQube",
    9090: "WebSM",
    27017: "MongoDB",
}


def scan_port(target, port, timeout=SOCKET_TIMEOUT):
    """
    Scan a single port on target host.
    
    Args:
        target: Target IP or hostname
        port: Port number to scan
        timeout: Connection timeout in seconds
    
    Returns:
        dict: Scan result with port, status, and service info
    """
    try:
        # Create socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        # Attempt connection
        result = sock.connect_ex((target, port))
        
        sock.close()
        
        # Get service name
        service = WELL_KNOWN_SERVICES.get(port, "unknown")
        
        if result == 0:
            # Port is open
            return {
                "port": port,
                "status": "open",
                "service": service
            }
        else:
            # Port is closed or filtered
            return {
                "port": port,
                "status": "closed",
                "service": service
            }
            
    except socket.timeout:
        return {
            "port": port,
            "status": "filtered",
            "service": WELL_KNOWN_SERVICES.get(port, "unknown")
        }
    except socket.gaierror:
        return {
            "port": port,
            "status": "error",
            "service": "unknown",
            "error": "Hostname resolution failed"
        }
    except socket.error as e:
        return {
            "port": port,
            "status": "error",
            "service": "unknown",
            "error": str(e)
        }
    except Exception as e:
        return {
            "port": port,
            "status": "error",
            "service": "unknown",
            "error": str(e)
        }


def parse_ports(port_spec):
    """
    Parse port specification into list of ports.
    
    Supports:
    - Comma-separated: 80,443,22
    - Range: 1-1024
    - Mixed: 80,443,8000-8100
    
    Args:
        port_spec: Port specification string
    
    Returns:
        list: List of port numbers
    """
    ports = set()
    
    # Split by comma
    parts = port_spec.split(',')
    
    for part in parts:
        part = part.strip()
        
        # Check if range (e.g., 1-1024)
        if '-' in part:
            try:
                start, end = part.split('-')
                start = int(start.strip())
                end = int(end.strip())
                
                if start < 1 or end > 65535:
                    raise ValueError(f"Port range must be 1-65535")
                if start > end:
                    raise ValueError(f"Invalid range: {start}-{end}")
                
                ports.update(range(start, end + 1))
            except ValueError as e:
                raise ValueError(f"Invalid port range '{part}': {e}")
        else:
            # Single port
            try:
                port = int(part)
                if port < 1 or port > 65535:
                    raise ValueError(f"Port must be 1-65535")
                ports.add(port)
            except ValueError:
                raise ValueError(f"Invalid port number: {part}")
    
    return sorted(list(ports))


def port_scan(target, ports, max_workers=MAX_WORKERS, logger=None):
    """
    Scan multiple ports on target host concurrently.
    
    Args:
        target: Target IP or hostname
        ports: List of port numbers to scan
        max_workers: Maximum concurrent threads
        logger: Logger instance
    
    Returns:
        dict: Scan results categorized by status
    """
    results = {
        "open": [],
        "closed": [],
        "filtered": [],
        "errors": []
    }
    
    total = len(ports)
    completed = 0
    
    if logger:
        logger.info(f"Scanning {total} ports on {target} with {max_workers} workers")
    
    print(f"\n🔍 Scanning {total} port(s) on {target}...")
    print(f"⚙️  Using {max_workers} concurrent threads\n")
    
    # Use ThreadPoolExecutor for concurrent scanning
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all scan tasks
        future_to_port = {executor.submit(scan_port, target, port): port for port in ports}
        
        # Process results as they complete
        for future in concurrent.futures.as_completed(future_to_port):
            completed += 1
            result = future.result()
            
            # Progress indicator
            if completed % 50 == 0 or completed == total:
                print(f"Progress: {completed}/{total} ({(completed/total)*100:.1f}%)", end="\r")
            
            # Categorize result
            status = result["status"]
            
            if status == "open":
                results["open"].append(result)
                if logger:
                    logger.info(f"OPEN: {result['port']} ({result['service']})")
            elif status == "closed":
                results["closed"].append(result)
                if logger:
                    logger.debug(f"CLOSED: {result['port']}")
            elif status == "filtered":
                results["filtered"].append(result)
                if logger:
                    logger.debug(f"FILTERED: {result['port']}")
            else:
                results["errors"].append(result)
                if logger:
                    logger.warning(f"ERROR: {result['port']} - {result.get('error', 'unknown')}")
    
    print()  # New line after progress
    
    if logger:
        logger.info(f"Scan complete: {len(results['open'])} open, {len(results['closed'])} closed")
    
    return results


def print_results(target, results, ports_scanned):
    """Print formatted port scan results."""
    open_ports = results["open"]
    closed = results["closed"]
    filtered = results["filtered"]
    errors = results["errors"]
    
    print("\n" + "=" * 70)
    print("PORT SCAN RESULTS")
    print(f"Target: {target}")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    
    # Summary
    print(f"\n📊 SUMMARY")
    print(f"   Ports scanned: {ports_scanned}")
    print(f"   Open: {len(open_ports)}")
    print(f"   Closed: {len(closed)}")
    print(f"   Filtered: {len(filtered)}")
    print(f"   Errors: {len(errors)}")
    
    # Open ports (most important)
    if open_ports:
        print(f"\n✅ OPEN PORTS ({len(open_ports)})")
        print(f"   {'Port':<8} {'Service':<20} {'Status'}")
        print(f"   {'-'*8} {'-'*20} {'-'*10}")
        
        # Sort by port number
        open_sorted = sorted(open_ports, key=lambda x: x["port"])
        
        for result in open_sorted:
            print(f"   {result['port']:<8} {result['service']:<20} {result['status']}")
    else:
        print(f"\n❌ NO OPEN PORTS FOUND")
    
    # Filtered ports (suspicious - firewall may be blocking)
    if filtered:
        print(f"\n🔒 FILTERED PORTS ({len(filtered)})")
        filtered_ports = [str(r["port"]) for r in sorted(filtered, key=lambda x: x["port"])]
        print(f"   {', '.join(filtered_ports[:20])}")
        if len(filtered) > 20:
            print(f"   ... and {len(filtered) - 20} more")
    
    # Errors (if any)
    if errors:
        print(f"\n⚠️  ERRORS ({len(errors)})")
        for result in errors[:5]:
            error_msg = result.get('error', 'Unknown error')
            print(f"   Port {result['port']}: {error_msg}")
        if len(errors) > 5:
            print(f"   ... and {len(errors) - 5} more errors")
    
    print("\n" + "=" * 70 + "\n")


def export_results(target, results, output_file):
    """Export scan results to file."""
    with open(output_file, 'w') as f:
        f.write("PORT SCAN RESULTS\n")
        f.write(f"Target: {target}\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 70 + "\n\n")
        
        open_ports = sorted(results["open"], key=lambda x: x["port"])
        
        f.write("OPEN PORTS:\n")
        for result in open_ports:
            f.write(f"{result['port']:<8} {result['service']}\n")
        
        f.write(f"\nTotal: {len(open_ports)} open ports\n")
    
    print(f"📁 Results exported to: {output_file}")


def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(
        description="Port Scanner - TCP port scanning tool"
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Target IP address or hostname"
    )
    
    # Port selection (mutually exclusive)
    port_group = parser.add_mutually_exclusive_group(required=True)
    port_group.add_argument(
        "--ports",
        help="Ports to scan: comma-separated (80,443) or range (1-1024)"
    )
    port_group.add_argument(
        "--common",
        action="store_true",
        help="Scan common ports (FTP, SSH, HTTP, HTTPS, etc.)"
    )
    port_group.add_argument(
        "--range",
        help="Port range to scan (e.g., 1-1024)"
    )
    
    parser.add_argument(
        "--workers",
        type=int,
        default=MAX_WORKERS,
        help=f"Number of concurrent threads (default: {MAX_WORKERS})"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=SOCKET_TIMEOUT,
        help=f"Connection timeout in seconds (default: {SOCKET_TIMEOUT})"
    )
    parser.add_argument(
        "--output",
        help="Export results to file"
    )
    
    args = parser.parse_args()
    
    # Setup logger
    logger = setup_logger(__name__, LOG_FILE)
    
    logger.info("=" * 50)
    logger.info("Port Scanner Started")
    logger.info("=" * 50)
    
    try:
        target = args.target
        
        # Determine which ports to scan
        if args.common:
            ports = sorted(COMMON_PORTS.keys())
            print(f"📋 Scanning {len(ports)} common ports")
        elif args.ports:
            ports = parse_ports(args.ports)
        elif args.range:
            ports = parse_ports(args.range)
        else:
            print("❌ No ports specified")
            return
        
        if not ports:
            print("\n❌ No valid ports to scan")
            return
        
        print(f"🎯 Target: {target}")
        
        # Perform port scan
        start_time = datetime.now()
        
        results = port_scan(target, ports, args.workers, logger)
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        # Print results
        print_results(target, results, len(ports))
        
        print(f"⏱️  Scan completed in {duration:.2f} seconds")
        
        # Export if requested
        if args.output:
            export_results(target, results, args.output)
        
        logger.info(f"Port Scanner Completed in {duration:.2f}s")
        
    except KeyboardInterrupt:
        logger.warning("Scan cancelled by user")
        print("\n\nScan cancelled.")
    except ValueError as e:
        logger.error(f"Invalid input: {e}")
        print(f"\n❌ Error: {e}")
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
        print(f"\n❌ Error: {e}")
        print("Check port_scanner.log for details.")


if __name__ == "__main__":
    main()
