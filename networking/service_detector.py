"""
service_detector.py
Service detection and banner grabbing tool.

Usage:
    python networking/service_detector.py --target 192.168.1.1 --port 80
    python networking/service_detector.py --target scanme.nmap.org --port 22,80,443
    python networking/service_detector.py --target 127.0.0.1 --scan-first
"""

import socket
import sys
from pathlib import Path
from datetime import datetime
import re
import argparse

# Add repo root to Python path
repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from utils.logger import setup_logger

# Configuration
LOG_FILE = "service_detector.log"
BANNER_TIMEOUT = 3  # Seconds to wait for banner
RECV_BUFFER = 4096  # Bytes to receive

# HTTP probe request
HTTP_PROBE = b"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n"

# Common service probes
SERVICE_PROBES = {
    21: b"",  # FTP sends banner immediately
    22: b"",  # SSH sends banner immediately
    23: b"",  # Telnet sends banner immediately
    25: b"EHLO probe\r\n",  # SMTP
    80: HTTP_PROBE,  # HTTP
    110: b"",  # POP3 sends banner immediately
    143: b"",  # IMAP sends banner immediately
    443: b"",  # HTTPS (would need SSL, skipping for now)
    3306: b"",  # MySQL sends banner immediately
    5432: b"",  # PostgreSQL sends banner immediately
}

# Service signatures for identification
SERVICE_SIGNATURES = {
    "SSH": [
        (r"SSH-(\d+\.\d+)-OpenSSH[_-]([\d\.]+)", "OpenSSH {1}"),
        (r"SSH-(\d+\.\d+)-Cisco", "Cisco SSH"),
        (r"SSH-(\d+\.\d+)", "SSH Protocol {0}"),
    ],
    "HTTP": [
        (r"Server:\s*Apache/([\d\.]+)", "Apache {0}"),
        (r"Server:\s*nginx/([\d\.]+)", "nginx {0}"),
        (r"Server:\s*Microsoft-IIS/([\d\.]+)", "IIS {0}"),
        (r"Server:\s*(\S+)", "HTTP Server: {0}"),
    ],
    "FTP": [
        (r"220.*ProFTPD ([\d\.]+)", "ProFTPD {0}"),
        (r"220.*vsftpd ([\d\.]+)", "vsftpd {0}"),
        (r"220.*FileZilla Server ([\d\.]+)", "FileZilla {0}"),
        (r"220.*Microsoft FTP", "Microsoft FTP"),
        (r"220\s+(\S+)", "FTP: {0}"),
    ],
    "SMTP": [
        (r"220.*Postfix", "Postfix SMTP"),
        (r"220.*Exim ([\d\.]+)", "Exim {0}"),
        (r"220.*Microsoft ESMTP", "Microsoft Exchange"),
        (r"220\s+(\S+)", "SMTP: {0}"),
    ],
    "MySQL": [
        (r"[\x00-\xff]*5\.([0-9\.]+)", "MySQL 5.{0}"),
        (r"[\x00-\xff]*8\.([0-9\.]+)", "MySQL 8.{0}"),
    ],
    "PostgreSQL": [
        (r"PostgreSQL", "PostgreSQL"),
    ],
}

# OS Detection patterns
OS_PATTERNS = {
    "Windows": [
        r"Microsoft",
        r"Windows",
        r"IIS",
        r"MSSQL",
    ],
    "Linux": [
        r"Ubuntu",
        r"Debian",
        r"CentOS",
        r"Red Hat",
        r"Apache/2",
    ],
    "Unix": [
        r"FreeBSD",
        r"OpenBSD",
        r"Solaris",
    ],
}


def grab_banner(target, port, timeout=BANNER_TIMEOUT):
    """
    Connect to port and grab service banner.
    
    Args:
        target: Target IP or hostname
        port: Port number
        timeout: Socket timeout in seconds
    
    Returns:
        dict: Banner information
    """
    banner = None
    service_info = {
        "port": port,
        "banner": None,
        "service": "unknown",
        "version": None,
        "os_hint": None
    }
    
    try:
        # Create socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        # Connect
        sock.connect((target, port))
        
        # Send probe if available
        probe = SERVICE_PROBES.get(port)
        if probe:
            if probe == HTTP_PROBE:
                probe = probe.replace(b"{host}", target.encode())
            sock.sendall(probe)
        
        # Receive banner
        banner = sock.recv(RECV_BUFFER)
        
        sock.close()
        
        # Decode banner
        if banner:
            try:
                banner_str = banner.decode('utf-8', errors='ignore').strip()
                service_info["banner"] = banner_str
            except:
                # Binary data, store as hex
                service_info["banner"] = banner.hex()[:100]
        
    except socket.timeout:
        service_info["banner"] = "timeout"
    except ConnectionRefusedError:
        service_info["banner"] = "connection_refused"
    except Exception as e:
        service_info["banner"] = f"error: {str(e)}"
    
    return service_info


def analyze_banner(service_info):
    """
    Analyze banner to identify service and version.
    
    Args:
        service_info: Service info dict with banner
    
    Returns:
        dict: Updated service info with detection results
    """
    banner = service_info.get("banner", "")
    
    if not banner or banner in ["timeout", "connection_refused"] or banner.startswith("error"):
        return service_info
    
    # Try to match against known signatures
    for service_type, patterns in SERVICE_SIGNATURES.items():
        for pattern, name_template in patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                # Extract version if captured
                if match.groups():
                    version_info = name_template.format(*match.groups())
                    service_info["service"] = service_type
                    service_info["version"] = version_info
                else:
                    service_info["service"] = service_type
                    service_info["version"] = name_template
                break
        
        if service_info["service"] != "unknown":
            break
    
    # Try OS detection
    for os_name, os_patterns in OS_PATTERNS.items():
        for pattern in os_patterns:
            if re.search(pattern, banner, re.IGNORECASE):
                service_info["os_hint"] = os_name
                break
        
        if service_info["os_hint"]:
            break
    
    return service_info


def detect_service(target, port, logger=None):
    """
    Detect service running on target:port.
    
    Args:
        target: Target IP or hostname
        port: Port number
        logger: Logger instance
    
    Returns:
        dict: Service detection results
    """
    if logger:
        logger.info(f"Probing {target}:{port}")
    
    # Grab banner
    service_info = grab_banner(target, port)
    
    # Analyze banner
    service_info = analyze_banner(service_info)
    
    if logger:
        if service_info["version"]:
            logger.info(f"Detected: {target}:{port} = {service_info['version']}")
        elif service_info["service"] != "unknown":
            logger.info(f"Detected: {target}:{port} = {service_info['service']}")
    
    return service_info


def scan_and_detect(target, ports, logger=None):
    """
    Scan ports and detect services.
    
    Args:
        target: Target IP or hostname
        ports: List of port numbers
        logger: Logger instance
    
    Returns:
        list: List of service detection results
    """
    results = []
    
    print(f"\n🔍 Detecting services on {target}...")
    
    for i, port in enumerate(ports, 1):
        print(f"Progress: {i}/{len(ports)} - Port {port}", end="\r")
        
        result = detect_service(target, port, logger)
        results.append(result)
    
    print()  # New line after progress
    
    return results


def quick_port_check(target, port, timeout=1):
    """
    Quick check if port is open.
    
    Args:
        target: Target IP or hostname
        port: Port number
        timeout: Timeout in seconds
    
    Returns:
        bool: True if port is open
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        sock.close()
        return result == 0
    except:
        return False


def find_open_ports(target, logger=None):
    """
    Quick scan of common ports to find open ones.
    
    Args:
        target: Target IP or hostname
        logger: Logger instance
    
    Returns:
        list: List of open port numbers
    """
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080]
    
    print(f"\n🔍 Scanning common ports on {target}...")
    
    open_ports = []
    
    for port in common_ports:
        if quick_port_check(target, port):
            open_ports.append(port)
            print(f"   Found open port: {port}")
            if logger:
                logger.info(f"Open port found: {port}")
    
    return open_ports


def print_results(target, results):
    """Print formatted service detection results."""
    print("\n" + "=" * 80)
    print("SERVICE DETECTION RESULTS")
    print(f"Target: {target}")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 80)
    
    # Filter out failed connections
    successful = [r for r in results if r["banner"] and 
                  r["banner"] not in ["timeout", "connection_refused"] and 
                  not r["banner"].startswith("error")]
    
    print(f"\n📊 SUMMARY")
    print(f"   Ports probed: {len(results)}")
    print(f"   Services detected: {len(successful)}")
    
    if successful:
        print(f"\n✅ DETECTED SERVICES")
        print(f"   {'Port':<8} {'Service':<20} {'Version/Details':<40}")
        print(f"   {'-'*8} {'-'*20} {'-'*40}")
        
        for result in successful:
            service = result.get("service", "unknown")
            version = result.get("version", "")
            
            # Show version or first 40 chars of banner
            if version:
                details = version
            else:
                details = result["banner"][:40] if result["banner"] else "No banner"
            
            print(f"   {result['port']:<8} {service:<20} {details:<40}")
            
            # Show OS hint if detected
            if result.get("os_hint"):
                print(f"            OS Hint: {result['os_hint']}")
    
    # Show banners
    if successful:
        print(f"\n📋 RAW BANNERS")
        for result in successful:
            if result["banner"] and len(result["banner"]) > 0:
                print(f"\n   Port {result['port']}:")
                # Show first 200 chars of banner
                banner_preview = result["banner"][:200]
                for line in banner_preview.split('\n')[:5]:
                    if line.strip():
                        print(f"      {line.strip()}")
    
    print("\n" + "=" * 80 + "\n")


def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(
        description="Service Detector - Banner grabbing and service identification"
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Target IP address or hostname"
    )
    parser.add_argument(
        "--port",
        help="Port(s) to probe (comma-separated)"
    )
    parser.add_argument(
        "--scan-first",
        action="store_true",
        help="Scan common ports first, then detect services"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=BANNER_TIMEOUT,
        help=f"Banner timeout in seconds (default: {BANNER_TIMEOUT})"
    )
    
    args = parser.parse_args()
    
    # Setup logger
    logger = setup_logger(__name__, LOG_FILE)
    
    logger.info("=" * 50)
    logger.info("Service Detector Started")
    logger.info("=" * 50)
    
    try:
        target = args.target
        
        # Determine ports to probe
        if args.scan_first:
            ports = find_open_ports(target, logger)
            if not ports:
                print("\n❌ No open ports found")
                return
        elif args.port:
            ports = [int(p.strip()) for p in args.port.split(',')]
        else:
            print("❌ Specify --port or use --scan-first")
            parser.print_help()
            return
        
        print(f"\n🎯 Target: {target}")
        print(f"📋 Probing {len(ports)} port(s): {', '.join(map(str, ports))}")
        
        # Detect services
        start_time = datetime.now()
        
        results = scan_and_detect(target, ports, logger)
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        # Print results
        print_results(target, results)
        
        print(f"⏱️  Detection completed in {duration:.2f} seconds")
        
        logger.info(f"Service Detector Completed in {duration:.2f}s")
        
    except KeyboardInterrupt:
        logger.warning("Detection cancelled by user")
        print("\n\nCancelled.")
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
        print(f"\n❌ Error: {e}")
        print("Check service_detector.log for details.")


if __name__ == "__main__":
    main()
