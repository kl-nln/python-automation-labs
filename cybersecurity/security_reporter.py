"""
security_reporter.py
Generate professional reports from security tool outputs (CSV, Markdown, JSON).

Usage:
    python cybersecurity/security_reporter.py --log-analysis sample_auth.log
    python cybersecurity/security_reporter.py --brute-force sample_brute_force.log
    python cybersecurity/security_reporter.py --integrity tamper_baseline.json
"""

import sys
import csv
import json
import re
from pathlib import Path
from datetime import datetime
from collections import defaultdict
import argparse

# Add repo root to Python path
repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from utils.logger import setup_logger

# Configuration
LOG_FILE = "security_reporter.log"
REPORTS_DIR = Path("security_reports")


def ensure_reports_dir():
    """Create reports directory if it doesn't exist."""
    REPORTS_DIR.mkdir(exist_ok=True)
    return REPORTS_DIR


def parse_auth_log_line(line):
    """Parse authentication log line (reused from log_parser)."""
    pattern = r'(\w+\s+\d+\s+\d+:\d+:\d+).*?(Failed|Accepted) password for (invalid user )?(\S+) from (\S+)'
    
    match = re.search(pattern, line)
    if match:
        timestamp_str = match.group(1)
        status = match.group(2)
        invalid_prefix = match.group(3)
        username = match.group(4)
        ip_address = match.group(5)
        
        current_year = datetime.now().year
        try:
            timestamp = datetime.strptime(f"{current_year} {timestamp_str}", "%Y %b %d %H:%M:%S")
        except ValueError:
            timestamp = None
        
        return {
            "timestamp": timestamp,
            "status": status,
            "username": username,
            "ip_address": ip_address,
            "is_invalid_user": bool(invalid_prefix)
        }
    
    return None


def parse_auth_log(log_file, logger):
    """Parse authentication log file."""
    log_path = Path(log_file)
    
    if not log_path.exists():
        logger.error(f"Log file not found: {log_file}")
        return []
    
    entries = []
    
    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            entry = parse_auth_log_line(line)
            if entry:
                entries.append(entry)
    
    logger.info(f"Parsed {len(entries)} log entries from {log_file}")
    return entries


def export_failed_logins_csv(entries, output_file, logger):
    """Export failed login attempts to CSV."""
    failed_entries = [e for e in entries if e["status"] == "Failed"]
    
    if not failed_entries:
        logger.warning("No failed logins to export")
        return False
    
    csv_path = REPORTS_DIR / output_file
    
    try:
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=[
                'timestamp', 'username', 'ip_address', 'is_invalid_user'
            ])
            
            writer.writeheader()
            
            for entry in failed_entries:
                writer.writerow({
                    'timestamp': entry['timestamp'].strftime('%Y-%m-%d %H:%M:%S') if entry['timestamp'] else 'N/A',
                    'username': entry['username'],
                    'ip_address': entry['ip_address'],
                    'is_invalid_user': 'Yes' if entry['is_invalid_user'] else 'No'
                })
        
        logger.info(f"CSV exported: {csv_path} ({len(failed_entries)} records)")
        return csv_path
        
    except Exception as e:
        logger.exception(f"Failed to export CSV: {e}")
        return False


def export_attack_summary_csv(entries, output_file, logger):
    """Export attack summary statistics to CSV."""
    failed_entries = [e for e in entries if e["status"] == "Failed"]
    
    # Aggregate by IP
    by_ip = defaultdict(lambda: {"count": 0, "users": set()})
    
    for entry in failed_entries:
        by_ip[entry["ip_address"]]["count"] += 1
        by_ip[entry["ip_address"]]["users"].add(entry["username"])
    
    csv_path = REPORTS_DIR / output_file
    
    try:
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=[
                'ip_address', 'failed_attempts', 'unique_users', 'risk_level'
            ])
            
            writer.writeheader()
            
            # Sort by count descending
            sorted_ips = sorted(by_ip.items(), key=lambda x: x[1]["count"], reverse=True)
            
            for ip, data in sorted_ips:
                # Calculate risk level
                if data["count"] >= 10:
                    risk = "CRITICAL"
                elif data["count"] >= 5:
                    risk = "HIGH"
                elif data["count"] >= 3:
                    risk = "MEDIUM"
                else:
                    risk = "LOW"
                
                writer.writerow({
                    'ip_address': ip,
                    'failed_attempts': data["count"],
                    'unique_users': len(data["users"]),
                    'risk_level': risk
                })
        
        logger.info(f"Attack summary CSV exported: {csv_path}")
        return csv_path
        
    except Exception as e:
        logger.exception(f"Failed to export summary CSV: {e}")
        return False


def generate_markdown_report(entries, output_file, logger):
    """Generate comprehensive Markdown report."""
    total_entries = len(entries)
    failed_entries = [e for e in entries if e["status"] == "Failed"]
    success_entries = [e for e in entries if e["status"] == "Accepted"]
    
    # Aggregate data
    by_ip = defaultdict(int)
    by_user = defaultdict(int)
    invalid_users = set()
    
    for entry in failed_entries:
        by_ip[entry["ip_address"]] += 1
        by_user[entry["username"]] += 1
        if entry["is_invalid_user"]:
            invalid_users.add(entry["username"])
    
    md_path = REPORTS_DIR / output_file
    
    try:
        with open(md_path, 'w', encoding='utf-8') as f:
            # Header
            f.write("# Security Analysis Report\n\n")
            f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write("---\n\n")
            
            # Executive Summary
            f.write("## Executive Summary\n\n")
            f.write(f"- **Total Authentication Events:** {total_entries}\n")
            f.write(f"- **Successful Logins:** {len(success_entries)}\n")
            f.write(f"- **Failed Login Attempts:** {len(failed_entries)}\n")
            
            if total_entries > 0:
                failure_rate = (len(failed_entries) / total_entries) * 100
                f.write(f"- **Failure Rate:** {failure_rate:.1f}%\n")
            
            f.write(f"- **Unique Attack IPs:** {len(by_ip)}\n")
            f.write(f"- **Targeted Accounts:** {len(by_user)}\n")
            f.write(f"- **Invalid Usernames Attempted:** {len(invalid_users)}\n\n")
            
            # Risk Assessment
            critical_ips = [ip for ip, count in by_ip.items() if count >= 10]
            high_risk_ips = [ip for ip, count in by_ip.items() if count >= 5 and count < 10]
            
            f.write("## Risk Assessment\n\n")
            if critical_ips:
                f.write(f"🔴 **CRITICAL:** {len(critical_ips)} IP(s) with 10+ failed attempts\n\n")
            if high_risk_ips:
                f.write(f"🟠 **HIGH:** {len(high_risk_ips)} IP(s) with 5-9 failed attempts\n\n")
            if not critical_ips and not high_risk_ips:
                f.write("✅ **LOW RISK:** No IPs exceeded 5 failed attempts\n\n")
            
            # Top Attack Sources
            f.write("## Top Attack Sources\n\n")
            f.write("| Rank | IP Address | Failed Attempts | Targeted Accounts |\n")
            f.write("|------|------------|-----------------|-------------------|\n")
            
            top_ips = sorted(by_ip.items(), key=lambda x: x[1], reverse=True)[:10]
            for i, (ip, count) in enumerate(top_ips, 1):
                # Count unique users per IP
                users_for_ip = set(e["username"] for e in failed_entries if e["ip_address"] == ip)
                f.write(f"| {i} | `{ip}` | {count} | {len(users_for_ip)} |\n")
            
            f.write("\n")
            
            # Targeted Accounts
            f.write("## Most Targeted Accounts\n\n")
            f.write("| Rank | Username | Failed Attempts | Unique IPs |\n")
            f.write("|------|----------|-----------------|------------|\n")
            
            top_users = sorted(by_user.items(), key=lambda x: x[1], reverse=True)[:10]
            for i, (user, count) in enumerate(top_users, 1):
                # Count unique IPs per user
                ips_for_user = set(e["ip_address"] for e in failed_entries if e["username"] == user)
                f.write(f"| {i} | `{user}` | {count} | {len(ips_for_user)} |\n")
            
            f.write("\n")
            
            # Invalid Usernames
            if invalid_users:
                f.write("## Account Enumeration Attempts\n\n")
                f.write(f"**{len(invalid_users)} invalid username(s) attempted:**\n\n")
                for user in sorted(invalid_users)[:20]:
                    f.write(f"- `{user}`\n")
                if len(invalid_users) > 20:
                    f.write(f"\n*...and {len(invalid_users) - 20} more*\n")
                f.write("\n")
            
            # Recommendations
            f.write("## Recommendations\n\n")
            
            if critical_ips:
                f.write("### Immediate Actions\n\n")
                f.write("1. **Block the following IPs immediately:**\n\n")
                for ip in critical_ips[:5]:
                    f.write(f"   - `{ip}` ({by_ip[ip]} attempts)\n")
                f.write("\n")
            
            f.write("### General Security Measures\n\n")
            f.write("- Implement rate limiting on authentication endpoints\n")
            f.write("- Enable account lockout after 5 failed attempts\n")
            f.write("- Use fail2ban or similar intrusion prevention\n")
            f.write("- Enable multi-factor authentication (MFA)\n")
            f.write("- Review and strengthen password policies\n")
            f.write("- Monitor for successful logins from previously failed IPs\n\n")
            
            # Footer
            f.write("---\n\n")
            f.write("*Report generated by Security Reporter*\n")
        
        logger.info(f"Markdown report generated: {md_path}")
        return md_path
        
    except Exception as e:
        logger.exception(f"Failed to generate Markdown report: {e}")
        return False


def export_json_summary(entries, output_file, logger):
    """Export structured JSON summary for programmatic use."""
    failed_entries = [e for e in entries if e["status"] == "Failed"]
    
    # Aggregate data
    by_ip = defaultdict(lambda: {"count": 0, "users": set()})
    by_user = defaultdict(lambda: {"count": 0, "ips": set()})
    
    for entry in failed_entries:
        by_ip[entry["ip_address"]]["count"] += 1
        by_ip[entry["ip_address"]]["users"].add(entry["username"])
        by_user[entry["username"]]["count"] += 1
        by_user[entry["username"]]["ips"].add(entry["ip_address"])
    
    # Convert sets to lists for JSON serialization
    ip_summary = {
        ip: {
            "failed_attempts": data["count"],
            "unique_users": len(data["users"]),
            "usernames": list(data["users"])
        }
        for ip, data in by_ip.items()
    }
    
    user_summary = {
        user: {
            "failed_attempts": data["count"],
            "unique_ips": len(data["ips"]),
            "source_ips": list(data["ips"])
        }
        for user, data in by_user.items()
    }
    
    summary = {
        "generated": datetime.now().isoformat(),
        "total_events": len(entries),
        "failed_logins": len(failed_entries),
        "successful_logins": len(entries) - len(failed_entries),
        "by_ip": ip_summary,
        "by_user": user_summary
    }
    
    json_path = REPORTS_DIR / output_file
    
    try:
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2)
        
        logger.info(f"JSON summary exported: {json_path}")
        return json_path
        
    except Exception as e:
        logger.exception(f"Failed to export JSON: {e}")
        return False


def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(
        description="Security Reporter - Generate professional reports from security logs"
    )
    parser.add_argument(
        "--log-analysis",
        metavar="LOG_FILE",
        help="Generate reports from authentication log"
    )
    parser.add_argument(
        "--format",
        choices=['csv', 'markdown', 'json', 'all'],
        default='all',
        help="Report format (default: all)"
    )
    
    args = parser.parse_args()
    
    # Setup logger
    logger = setup_logger(__name__, LOG_FILE)
    
    logger.info("=" * 50)
    logger.info("Security Reporter Started")
    logger.info("=" * 50)
    
    try:
        # Ensure reports directory exists
        ensure_reports_dir()
        
        if args.log_analysis:
            log_file = args.log_analysis
            
            # Parse log file
            entries = parse_auth_log(log_file, logger)
            
            if not entries:
                print("\n❌ No data to analyze")
                return
            
            print(f"\n📊 Analyzing {len(entries)} authentication events...")
            print(f"📁 Reports will be saved to: {REPORTS_DIR.absolute()}\n")
            
            generated_files = []
            
            # Generate requested formats
            if args.format in ['csv', 'all']:
                print("Generating CSV reports...")
                
                csv1 = export_failed_logins_csv(entries, "failed_logins.csv", logger)
                if csv1:
                    generated_files.append(csv1)
                    print(f"  ✓ Failed logins: {csv1.name}")
                
                csv2 = export_attack_summary_csv(entries, "attack_summary.csv", logger)
                if csv2:
                    generated_files.append(csv2)
                    print(f"  ✓ Attack summary: {csv2.name}")
            
            if args.format in ['markdown', 'all']:
                print("\nGenerating Markdown report...")
                
                md = generate_markdown_report(entries, "security_report.md", logger)
                if md:
                    generated_files.append(md)
                    print(f"  ✓ Comprehensive report: {md.name}")
            
            if args.format in ['json', 'all']:
                print("\nGenerating JSON summary...")
                
                js = export_json_summary(entries, "security_summary.json", logger)
                if js:
                    generated_files.append(js)
                    print(f"  ✓ JSON summary: {js.name}")
            
            # Summary
            print(f"\n✅ Generated {len(generated_files)} report(s)")
            print(f"📂 Location: {REPORTS_DIR.absolute()}\n")
            
            logger.info(f"Generated {len(generated_files)} reports")
        
        else:
            parser.print_help()
            print("\nExample usage:")
            print("  Generate all reports:     python cybersecurity/security_reporter.py --log-analysis sample_auth.log")
            print("  CSV only:                 python cybersecurity/security_reporter.py --log-analysis sample_auth.log --format csv")
            print("  Markdown only:            python cybersecurity/security_reporter.py --log-analysis sample_auth.log --format markdown")
        
        logger.info("Security Reporter Completed")
        
    except KeyboardInterrupt:
        logger.warning("Operation cancelled by user")
        print("\nCancelled.")
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
        print(f"\n❌ Error: {e}")
        print("Check security_reporter.log for details.")


if __name__ == "__main__":
    main()
