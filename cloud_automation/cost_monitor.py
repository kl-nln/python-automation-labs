"""
cost_monitor.py
AWS cost monitoring and analysis tool.

Usage:
    python cloud_automation/cost_monitor.py --current
    python cloud_automation/cost_monitor.py --by-service
    python cloud_automation/cost_monitor.py --forecast
    python cloud_automation/cost_monitor.py --export
"""

import sys
from pathlib import Path
from datetime import datetime, timedelta
import csv
import argparse

# Add repo root to Python path
repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from utils.logger import setup_logger

# Import boto3
try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
except ImportError:
    print("❌ boto3 not installed. Run: pip install boto3")
    sys.exit(1)

# Configuration
LOG_FILE = "cost_monitor.log"
REPORTS_DIR = Path("cloud_automation_reports")


def get_ce_client():
    """Create Cost Explorer client."""
    try:
        return boto3.client('ce', region_name='us-east-1')
    except NoCredentialsError:
        print("❌ AWS credentials not found!")
        sys.exit(1)


def get_current_month_cost(ce_client, logger=None):
    """Get current month-to-date cost."""
    try:
        # Get first day of current month
        today = datetime.now()
        start = today.replace(day=1).strftime('%Y-%m-%d')
        end = today.strftime('%Y-%m-%d')
        
        response = ce_client.get_cost_and_usage(
            TimePeriod={
                'Start': start,
                'End': end
            },
            Granularity='MONTHLY',
            Metrics=['UnblendedCost']
        )
        
        if response['ResultsByTime']:
            amount = float(response['ResultsByTime'][0]['Total']['UnblendedCost']['Amount'])
            
            if logger:
                logger.info(f"Current month cost: ${amount:.2f}")
            
            return {
                'amount': amount,
                'start_date': start,
                'end_date': end,
                'currency': response['ResultsByTime'][0]['Total']['UnblendedCost']['Unit']
            }
        else:
            return None
            
    except ClientError as e:
        if logger:
            logger.error(f"Error getting cost data: {e}")
        print(f"❌ Error: {e}")
        return None


def get_cost_by_service(ce_client, logger=None):
    """Get cost breakdown by AWS service."""
    try:
        today = datetime.now()
        start = today.replace(day=1).strftime('%Y-%m-%d')
        end = today.strftime('%Y-%m-%d')
        
        response = ce_client.get_cost_and_usage(
            TimePeriod={
                'Start': start,
                'End': end
            },
            Granularity='MONTHLY',
            Metrics=['UnblendedCost'],
            GroupBy=[
                {
                    'Type': 'DIMENSION',
                    'Key': 'SERVICE'
                }
            ]
        )
        
        services = []
        
        if response['ResultsByTime']:
            for group in response['ResultsByTime'][0]['Groups']:
                service_name = group['Keys'][0]
                amount = float(group['Metrics']['UnblendedCost']['Amount'])
                
                if amount > 0:  # Only include services with actual cost
                    services.append({
                        'service': service_name,
                        'cost': amount
                    })
        
        # Sort by cost (highest first)
        services.sort(key=lambda x: x['cost'], reverse=True)
        
        if logger:
            logger.info(f"Cost breakdown: {len(services)} services with charges")
        
        return services
        
    except ClientError as e:
        if logger:
            logger.error(f"Error getting service costs: {e}")
        print(f"❌ Error: {e}")
        return []


def get_monthly_comparison(ce_client, months=3, logger=None):
    """Get cost comparison for last N months."""
    try:
        # Calculate date range
        today = datetime.now()
        end = today.strftime('%Y-%m-%d')
        
        # Go back N months
        start_date = today.replace(day=1) - timedelta(days=(months * 31))
        start = start_date.strftime('%Y-%m-%d')
        
        response = ce_client.get_cost_and_usage(
            TimePeriod={
                'Start': start,
                'End': end
            },
            Granularity='MONTHLY',
            Metrics=['UnblendedCost']
        )
        
        monthly_costs = []
        
        for period in response['ResultsByTime']:
            amount = float(period['Total']['UnblendedCost']['Amount'])
            monthly_costs.append({
                'start': period['TimePeriod']['Start'],
                'end': period['TimePeriod']['End'],
                'cost': amount
            })
        
        if logger:
            logger.info(f"Retrieved {len(monthly_costs)} months of cost data")
        
        return monthly_costs
        
    except ClientError as e:
        if logger:
            logger.error(f"Error getting monthly comparison: {e}")
        print(f"❌ Error: {e}")
        return []


def get_forecast(ce_client, logger=None):
    """Get cost forecast for current month."""
    try:
        today = datetime.now()
        start = today.strftime('%Y-%m-%d')
        
        # End of month
        if today.month == 12:
            next_month = today.replace(year=today.year + 1, month=1, day=1)
        else:
            next_month = today.replace(month=today.month + 1, day=1)
        
        end = next_month.strftime('%Y-%m-%d')
        
        response = ce_client.get_cost_forecast(
            TimePeriod={
                'Start': start,
                'End': end
            },
            Metric='UNBLENDED_COST',
            Granularity='MONTHLY'
        )
        
        if response['Total']:
            amount = float(response['Total']['Amount'])
            
            if logger:
                logger.info(f"Forecasted cost: ${amount:.2f}")
            
            return {
                'amount': amount,
                'currency': response['Total']['Unit']
            }
        else:
            return None
            
    except ClientError as e:
        if logger:
            logger.warning(f"Could not get forecast: {e}")
        # Forecast not available for new accounts
        return None


def print_current_cost(cost_data):
    """Print current month cost."""
    print("\n" + "=" * 80)
    print("AWS COST MONITOR - CURRENT MONTH")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 80)
    
    if not cost_data:
        print("\n✓ No cost data available yet")
        print("\nℹ️  Cost data can take 24 hours to appear in new accounts.")
        print("=" * 80 + "\n")
        return
    
    print(f"\n💰 CURRENT SPENDING")
    print(f"   Period: {cost_data['start_date']} to {cost_data['end_date']}")
    print(f"   Total: ${cost_data['amount']:.2f} {cost_data['currency']}")
    
    # Calculate daily average
    start = datetime.strptime(cost_data['start_date'], '%Y-%m-%d')
    end = datetime.strptime(cost_data['end_date'], '%Y-%m-%d')
    days = (end - start).days + 1
    
    if days > 0:
        daily_avg = cost_data['amount'] / days
        print(f"   Daily average: ${daily_avg:.2f}")
    
    print("\n" + "=" * 80 + "\n")


def print_service_breakdown(services):
    """Print cost by service."""
    print("\n" + "=" * 80)
    print("AWS COST BY SERVICE")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 80)
    
    if not services:
        print("\n✓ No service costs recorded yet")
        print("\nℹ️  Cost data can take 24 hours to appear.")
        print("=" * 80 + "\n")
        return
    
    total = sum(s['cost'] for s in services)
    
    print(f"\n📊 SERVICE BREAKDOWN")
    print(f"   Total services with charges: {len(services)}")
    print(f"   Total cost: ${total:.2f}")
    
    print(f"\n💵 TOP SERVICES")
    print(f"   {'Service':<40} {'Cost':<12} {'%':<8}")
    print(f"   {'-'*40} {'-'*12} {'-'*8}")
    
    for service in services[:10]:  # Top 10
        percentage = (service['cost'] / total * 100) if total > 0 else 0
        print(f"   {service['service']:<40} ${service['cost']:<11.2f} {percentage:>6.1f}%")
    
    if len(services) > 10:
        print(f"\n   ... and {len(services) - 10} more services")
    
    print("\n" + "=" * 80 + "\n")


def print_monthly_comparison(monthly_costs):
    """Print monthly cost comparison."""
    print("\n" + "=" * 80)
    print("MONTHLY COST COMPARISON")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 80)
    
    if not monthly_costs:
        print("\n✓ No historical data available")
        print("=" * 80 + "\n")
        return
    
    print(f"\n📈 COST TREND")
    print(f"   {'Month':<12} {'Cost':<12} {'Change':<12}")
    print(f"   {'-'*12} {'-'*12} {'-'*12}")
    
    prev_cost = None
    
    for period in monthly_costs:
        month = datetime.strptime(period['start'], '%Y-%m-%d').strftime('%Y-%m')
        cost = period['cost']
        
        if prev_cost is not None and prev_cost > 0:
            change = ((cost - prev_cost) / prev_cost) * 100
            change_str = f"{change:+.1f}%"
        else:
            change_str = "N/A"
        
        print(f"   {month:<12} ${cost:<11.2f} {change_str:<12}")
        prev_cost = cost
    
    print("\n" + "=" * 80 + "\n")


def print_forecast(forecast_data, current_cost):
    """Print cost forecast."""
    print("\n" + "=" * 80)
    print("COST FORECAST")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 80)
    
    if not forecast_data:
        print("\n⚠️  Forecast not available")
        print("\nℹ️  Forecasts require at least a few days of billing data.")
        print("=" * 80 + "\n")
        return
    
    print(f"\n🔮 MONTH-END PROJECTION")
    print(f"   Current spending: ${current_cost:.2f}")
    print(f"   Forecasted total: ${forecast_data['amount']:.2f}")
    print(f"   Remaining budget: ${forecast_data['amount'] - current_cost:.2f}")
    
    print("\n" + "=" * 80 + "\n")


def export_cost_report(current_cost, services, monthly_costs, output_file):
    """Export cost report to CSV."""
    REPORTS_DIR.mkdir(exist_ok=True)
    csv_path = REPORTS_DIR / output_file
    
    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        
        # Current cost
        writer.writerow(['CURRENT MONTH COST'])
        writer.writerow(['Amount', 'Currency', 'Start Date', 'End Date'])
        if current_cost:
            writer.writerow([
                f"${current_cost['amount']:.2f}",
                current_cost['currency'],
                current_cost['start_date'],
                current_cost['end_date']
            ])
        writer.writerow([])
        
        # Service breakdown
        writer.writerow(['COST BY SERVICE'])
        writer.writerow(['Service', 'Cost'])
        for service in services:
            writer.writerow([service['service'], f"${service['cost']:.2f}"])
        writer.writerow([])
        
        # Monthly comparison
        writer.writerow(['MONTHLY COMPARISON'])
        writer.writerow(['Month', 'Cost'])
        for period in monthly_costs:
            month = datetime.strptime(period['start'], '%Y-%m-%d').strftime('%Y-%m')
            writer.writerow([month, f"${period['cost']:.2f}"])
    
    print(f"📁 Exported to: {csv_path}")


def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(
        description="AWS Cost Monitor - Track and analyze AWS spending"
    )
    parser.add_argument(
        "--current",
        action="store_true",
        help="Show current month cost"
    )
    parser.add_argument(
        "--by-service",
        action="store_true",
        help="Show cost breakdown by service"
    )
    parser.add_argument(
        "--comparison",
        action="store_true",
        help="Show monthly cost comparison"
    )
    parser.add_argument(
        "--forecast",
        action="store_true",
        help="Show cost forecast"
    )
    parser.add_argument(
        "--export",
        action="store_true",
        help="Export cost report to CSV"
    )
    
    args = parser.parse_args()
    
    # Setup logger
    logger = setup_logger(__name__, LOG_FILE)
    
    logger.info("=" * 50)
    logger.info("Cost Monitor Started")
    logger.info("=" * 50)
    
    try:
        print("\n💰 Connecting to AWS Cost Explorer...")
        
        # Create Cost Explorer client
        ce = get_ce_client()
        
        # Get current cost
        current_cost = get_current_month_cost(ce, logger)
        
        # If no flags, show current cost by default
        if not any([args.current, args.by_service, args.comparison, args.forecast, args.export]):
            args.current = True
        
        # Execute requested actions
        if args.current:
            print_current_cost(current_cost)
        
        if args.by_service:
            services = get_cost_by_service(ce, logger)
            print_service_breakdown(services)
        
        if args.comparison:
            monthly_costs = get_monthly_comparison(ce, logger=logger)
            print_monthly_comparison(monthly_costs)
        
        if args.forecast:
            forecast = get_forecast(ce, logger)
            if current_cost:
                print_forecast(forecast, current_cost['amount'])
            else:
                print("\n⚠️  Cannot forecast without current cost data")
        
        if args.export:
            services = get_cost_by_service(ce, logger)
            monthly_costs = get_monthly_comparison(ce, logger=logger)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            export_cost_report(current_cost, services, monthly_costs, f"cost_report_{timestamp}.csv")
        
        logger.info("Cost Monitor Completed")
        
    except KeyboardInterrupt:
        logger.warning("Operation cancelled")
        print("\n\nCancelled.")
    except Exception as e:
        logger.exception(f"Error: {e}")
        print(f"\n❌ Error: {e}")


if __name__ == "__main__":
    main()
