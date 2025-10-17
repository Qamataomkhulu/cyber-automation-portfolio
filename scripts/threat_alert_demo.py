#!/usr/bin/env python3
"""
Threat Alert Demo with AbuseIPDB Integration
Generates sample security alerts with real IP reputation checks
"""

import json
import random
import requests
from datetime import datetime
import os

# AbuseIPDB API Configuration
ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY', '')
ABUSEIPDB_URL = 'https://api.abuseipdb.com/api/v2/check'

def check_ip_reputation(ip_address):
    """
    Check IP reputation using AbuseIPDB API
    Returns dict with reputation data
    """
    if not ABUSEIPDB_API_KEY:
        return {
            'ip': ip_address,
            'abuse_score': 0,
            'country': 'Unknown',
            'usage_type': 'Unknown',
            'is_public': True,
            'is_whitelisted': False,
            'error': 'API key not configured'
        }
    
    headers = {
        'Key': ABUSEIPDB_API_KEY,
        'Accept': 'application/json'
    }
    
    params = {
        'ipAddress': ip_address,
        'maxAgeInDays': '90',
        'verbose': ''
    }
    
    try:
        response = requests.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=10)
        
        if response.status_code == 200:
            data = response.json()['data']
            return {
                'ip': data['ipAddress'],
                'abuse_score': data['abuseConfidenceScore'],
                'country': data.get('countryCode', 'Unknown'),
                'usage_type': data.get('usageType', 'Unknown'),
                'is_public': data.get('isPublic', True),
                'is_whitelisted': data.get('isWhitelisted', False),
                'total_reports': data.get('totalReports', 0),
                'last_reported': data.get('lastReportedAt', None)
            }
        else:
            print(f"AbuseIPDB API error: {response.status_code}")
            return {
                'ip': ip_address,
                'abuse_score': 0,
                'error': f'API returned {response.status_code}'
            }
    
    except requests.exceptions.RequestException as e:
        print(f"Error checking IP {ip_address}: {e}")
        return {
            'ip': ip_address,
            'abuse_score': 0,
            'error': str(e)
        }


def generate_sample_alerts():
    """
    Generate sample security alerts with IP reputation checks
    """
    
    # Sample suspicious IPs (some known malicious for demo)
    suspicious_ips = [
        '45.142.212.61',   # Known malicious
        '185.220.101.39',  # Tor exit node
        '192.168.1.100',   # Internal (won't be in AbuseIPDB)
        '8.8.8.8',         # Google DNS (clean)
        '103.109.247.10',  # Random
    ]
    
    alert_templates = [
        {
            'title': 'Multiple Failed SSH Login Attempts',
            'description': 'Detected {count} failed SSH authentication attempts from {ip}',
            'severity': 'High',
            'mitre': 'T1110.001 - Brute Force: Password Guessing'
        },
        {
            'title': 'Suspicious PowerShell Execution',
            'description': 'Encoded PowerShell command executed with network connection to {ip}',
            'severity': 'Critical',
            'mitre': 'T1059.001 - PowerShell'
        },
        {
            'title': 'Unusual Outbound Connection',
            'description': 'Workstation initiated connection to suspicious IP {ip} on port 443',
            'severity': 'Medium',
            'mitre': 'T1071.001 - Application Layer Protocol: Web Protocols'
        },
        {
            'title': 'Potential Data Exfiltration',
            'description': 'Large data transfer ({size}MB) to external IP {ip}',
            'severity': 'High',
            'mitre': 'T1041 - Exfiltration Over C2 Channel'
        }
    ]
    
    alerts = []
    
    for i in range(random.randint(3, 6)):
        template = random.choice(alert_templates)
        ip = random.choice(suspicious_ips)
        
        # Check IP reputation
        print(f"Checking reputation for {ip}...")
        reputation = check_ip_reputation(ip)
        
        # Determine threat level based on abuse score
        if reputation['abuse_score'] > 75:
            threat_level = 'Critical'
        elif reputation['abuse_score'] > 50:
            threat_level = 'High'
        elif reputation['abuse_score'] > 25:
            threat_level = 'Medium'
        else:
            threat_level = 'Low'
        
        # Create alert with reputation data
        alert = {
            'id': f'ALERT-{datetime.now().strftime("%Y%m%d")}-{i+1:03d}',
            'timestamp': datetime.now().isoformat(),
            'title': template['title'],
            'description': template['description'].format(
                ip=ip,
                count=random.randint(15, 150),
                size=random.randint(100, 5000)
            ),
            'severity': template['severity'],
            'mitre_technique': template['mitre'],
            'source_ip': ip,
            'ip_reputation': {
                'abuse_score': reputation['abuse_score'],
                'country': reputation.get('country', 'Unknown'),
                'threat_level': threat_level,
                'is_whitelisted': reputation.get('is_whitelisted', False),
                'total_reports': reputation.get('total_reports', 0)
            },
            'recommended_action': get_recommended_action(reputation['abuse_score'])
        }
        
        alerts.append(alert)
    
    return alerts


def get_recommended_action(abuse_score):
    """
    Return recommended action based on abuse score
    """
    if abuse_score > 75:
        return 'IMMEDIATE: Block IP at firewall and isolate affected host'
    elif abuse_score > 50:
        return 'HIGH PRIORITY: Investigate and consider blocking'
    elif abuse_score > 25:
        return 'Monitor closely and correlate with other indicators'
    else:
        return 'Low risk - continue monitoring'


def main():
    """
    Main function to generate alerts and save to JSON
    """
    print("=" * 60)
    print("Threat Alert Demo - Generating Alerts with IP Reputation")
    print("=" * 60)
    
    # Check if API key is configured
    if not ABUSEIPDB_API_KEY:
        print("⚠️  WARNING: ABUSEIPDB_API_KEY not set in environment")
        print("    IP reputation checks will return mock data")
        print("    Set the key in GitHub Secrets for real checks")
    
    # Generate alerts
    alerts = generate_sample_alerts()
    
    # Prepare output
    output = {
        'generated_at': datetime.now().isoformat(),
        'total_alerts': len(alerts),
        'alerts': alerts
    }
    
    # Save to alerts.json
    output_file = 'docs/alerts.json'
    os.makedirs('docs', exist_ok=True)
    
    with open(output_file, 'w') as f:
        json.dump(output, f, indent=2)
    
    print(f"\n✅ Generated {len(alerts)} alerts")
    print(f"📝 Saved to {output_file}")
    print(f"🕐 Timestamp: {output['generated_at']}")
    
    # Print summary
    print("\nAlert Summary:")
    print("-" * 60)
    for alert in alerts:
        rep = alert['ip_reputation']
        print(f"  {alert['title']}")
        print(f"    IP: {alert['source_ip']} | Abuse Score: {rep['abuse_score']}")
        print(f"    Threat Level: {rep['threat_level']}")
        print()


if __name__ == '__main__':
    main()
