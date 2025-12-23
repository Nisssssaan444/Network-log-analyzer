import time
import re
import os
from datetime import datetime

class NetworkLogAnalyzer:
    def __init__(self, log_file):
        self.log_file = log_file
        # Regex for Common Log Format (CLF) / Combined Log Format
        # Structure: IP - - [Date] "Request" Status Bytes "Referrer" "UserAgent"
        self.log_pattern = re.compile(
            r'(?P<ip>[\d\.]+) - - \[(?P<timestamp>.*?)\] "(?P<request>.*?)" (?P<status>\d{3}) (?P<bytes>\d+|-) "(?P<referer>.*?)" "(?P<ua>.*?)"'
        )
        
        # Simple signatures for threat detection
        self.suspicious_keywords = ['UNION SELECT', 'OR 1=1', '<script>', '/etc/passwd', '..']
        self.scanner_uas = ['sqlmap', 'nikto', 'nmap']

    def follow(self):
        """Generator that yields new lines from the log file in real-time."""
        if not os.path.exists(self.log_file):
            print(f"[!] File {self.log_file} not found. Waiting for it to be created...")
            while not os.path.exists(self.log_file):
                time.sleep(1)

        with open(self.log_file, 'r') as file:
            # Start from the beginning for analysis demo (remove seek(0,2) to see existing logs)
            # In a real live 'tail' scenario, you would uncomment the next line:
            # file.seek(0, 2) 
            print(f"[*] SOC Monitor active. Analyzing {self.log_file}...")
            
            while True:
                line = file.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                yield line.strip()

    def parse(self, line):
        """Parses a raw log line into a structured dictionary."""
        match = self.log_pattern.match(line)
        if match:
            return match.groupdict()
        return None

    def analyze_threats(self, data):
        """Analyzes parsed data for potential security incidents."""
        alerts = []
        
        status = int(data['status'])
        request = data['request']
        ua = data['ua']
        ip = data['ip']

        # 1. Status Code Analysis
        if status == 404:
            alerts.append(f"[SCANNING] 404 Not Found - Potential Probe: {request}")
        elif status == 401 or status == 403:
            alerts.append(f"[AUTH] Failed Access Attempt (Status {status})")
        elif status >= 500:
            alerts.append(f"[ERROR] Server Error (Status {status}) - check for exploit attempts")

        # 2. SQL Injection / LFI Detection
        for keyword in self.suspicious_keywords:
            if keyword.lower() in request.lower():
                alerts.append(f"[CRITICAL] Potential Injection Attack Detected: '{keyword}' in request")

        # 3. User-Agent Analysis
        for scanner in self.scanner_uas:
            if scanner.lower() in ua.lower():
                alerts.append(f"[WARN] Automated Scanner Detected: {scanner}")

        return alerts

    def run(self):
        print(f"[*] Starting Network Activity Monitoring on: {self.log_file}")
        print("-" * 60)
        
        try:
            for line in self.follow():
                data = self.parse(line)
                if not data:
                    continue

                alerts = self.analyze_threats(data)
                
                # Output Logic
                if alerts:
                    print(f"\n[!] ALERT from {data['ip']} at {data['timestamp']}")
                    for alert in alerts:
                        print(f"    -> {alert}")
                    print(f"    RAW: {data['request']}")
                else:
                    # Optional: Print 'safe' traffic differently or skip
                    # print(f"[OK] {data['ip']} - {data['request'][:50]}...")
                    pass
                    
        except KeyboardInterrupt:
            print("\n[*] Stopping SOC Monitor.")

if __name__ == "__main__":
    # Use the local access.log we created (simulating /var/log/apache2/access.log)
    LOG_FILE = "access.log" 
    
    analyzer = NetworkLogAnalyzer(LOG_FILE)
    analyzer.run()
