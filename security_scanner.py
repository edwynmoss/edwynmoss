#!/usr/bin/env python3
"""
Advanced Security Scanner
Author: Edwyn Moss
Description: Comprehensive security assessment tool for network analysis
"""

import socket
import threading
import subprocess
import sys
from datetime import datetime
import json

class SecurityScanner:
    def __init__(self):
        self.target = None
        self.open_ports = []
        self.scan_results = {}
        
    def port_scan(self, host, port):
        """Scan individual port for open services"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            if result == 0:
                self.open_ports.append(port)
                print(f"[+] Port {port}: Open")
            sock.close()
        except socket.gaierror:
            print(f"[-] Hostname {host} could not be resolved")
        except Exception as e:
            print(f"[-] Error scanning port {port}: {e}")
    
    def threaded_scan(self, host, port_range):
        """Multi-threaded port scanning for efficiency"""
        threads = []
        print(f"\n[*] Starting port scan on {host}")
        print(f"[*] Scanning ports 1-{port_range}")
        print("-" * 50)
        
        for port in range(1, port_range + 1):
            thread = threading.Thread(target=self.port_scan, args=(host, port))
            threads.append(thread)
            thread.start()
            
        for thread in threads:
            thread.join()
    
    def service_detection(self, host, port):
        """Detect services running on open ports"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((host, port))
            
            # Send HTTP request for web services
            if port in [80, 443, 8080, 8443]:
                sock.send(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                return banner.split('\r\n')[0] if banner else "Unknown HTTP Service"
            
            # Banner grabbing for other services
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            return banner.strip() if banner else f"Service on port {port}"
            
        except Exception as e:
            return f"Service detection failed: {e}"
    
    def vulnerability_check(self, host, port):
        """Basic vulnerability checks for common ports"""
        vulnerabilities = []
        
        # Check for common vulnerable services
        if port == 21:  # FTP
            vulnerabilities.append("FTP service detected - Check for anonymous access")
        elif port == 22:  # SSH
            vulnerabilities.append("SSH service detected - Ensure strong authentication")
        elif port == 23:  # Telnet
            vulnerabilities.append("CRITICAL: Telnet detected - Unencrypted protocol")
        elif port == 53:  # DNS
            vulnerabilities.append("DNS service detected - Check for zone transfers")
        elif port in [80, 443]:  # HTTP/HTTPS
            vulnerabilities.append("Web service detected - Check for common web vulnerabilities")
        elif port == 3389:  # RDP
            vulnerabilities.append("RDP service detected - Ensure strong passwords and NLA")
        
        return vulnerabilities
    
    def generate_report(self, host):
        """Generate comprehensive security report"""
        report = {
            "target": host,
            "scan_time": datetime.now().isoformat(),
            "open_ports": len(self.open_ports),
            "services": {},
            "vulnerabilities": [],
            "recommendations": []
        }
        
        print(f"\n{'='*60}")
        print(f"SECURITY ASSESSMENT REPORT - {host}")
        print(f"{'='*60}")
        print(f"Scan completed: {report['scan_time']}")
        print(f"Open ports found: {len(self.open_ports)}")
        
        if self.open_ports:
            print("\nOPEN PORTS AND SERVICES:")
            print("-" * 30)
            
            for port in sorted(self.open_ports):
                service = self.service_detection(host, port)
                vulnerabilities = self.vulnerability_check(host, port)
                
                print(f"Port {port}: {service}")
                report["services"][port] = service
                
                if vulnerabilities:
                    for vuln in vulnerabilities:
                        print(f"  ⚠️  {vuln}")
                        report["vulnerabilities"].append(f"Port {port}: {vuln}")
        
        # Add general recommendations
        report["recommendations"] = [
            "Implement firewall rules to restrict unnecessary port access",
            "Regular security updates and patch management",
            "Strong authentication mechanisms for all services",
            "Network segmentation and access controls",
            "Regular vulnerability assessments and penetration testing"
        ]
        
        print(f"\nRECOMMENDATIONS:")
        print("-" * 15)
        for rec in report["recommendations"]:
            print(f"• {rec}")
        
        return report
    
    def save_report(self, report, filename=None):
        """Save report to JSON file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"security_report_{report['target']}_{timestamp}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\n[+] Report saved to: {filename}")
        except Exception as e:
            print(f"[-] Error saving report: {e}")

def main():
    """Main execution function"""
    scanner = SecurityScanner()
    
    print("Advanced Security Scanner v1.0")
    print("Author: Edwyn Moss")
    print("=" * 40)
    
    if len(sys.argv) != 2:
        print("Usage: python3 security_scanner.py <target_host>")
        print("Example: python3 security_scanner.py 192.168.1.1")
        sys.exit(1)
    
    target_host = sys.argv[1]
    port_range = 1000  # Scan first 1000 ports
    
    try:
        # Resolve hostname
        ip = socket.gethostbyname(target_host)
        print(f"Target: {target_host} ({ip})")
        
        # Perform scan
        scanner.threaded_scan(ip, port_range)
        
        # Generate and save report
        report = scanner.generate_report(target_host)
        scanner.save_report(report)
        
    except socket.gaierror:
        print(f"[-] Error: Could not resolve hostname {target_host}")
    except KeyboardInterrupt:
        print("\n[-] Scan interrupted by user")
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    main() 