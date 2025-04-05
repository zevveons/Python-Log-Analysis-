import re
import ipaddress
from datetime import datetime
from collections import defaultdict, deque
from datetime import datetime, timedelta
from urllib.parse import unquote


#Log Analzyer Works!

class LogAnalyzer:


    def read_log_file(filepath):
        try:
            with open(filepath, 'r') as file:
                lines = file.readlines()
                print("Log file contents:\n")
                for line in lines:
                    print(line.strip())
        except FileNotFoundError:
            print(f"Error: File '{filepath}' not found.")
        except Exception as e:
            print(f"An error occurred: {e}")


    def parse_log_line(line):
        pattern = r'(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "(GET|POST|PUT|DELETE) (.*?) HTTP/1.1" (\d{3}) (\d+)'
        
        match = re.match(pattern, line)
        if match:
            ip_address = match.group(1)
            timestamp = match.group(2)
            method = match.group(3)
            url = match.group(4)
            status_code = int(match.group(5))
            byte_size = int(match.group(6))

            return {
                "ip": ip_address,
                "timestamp": timestamp,
                "method": method,
                "url": url,
                "statuscode": status_code,
                "size": byte_size
            }
        else:
            return None


    def count_ip_request(parsed_logs):
        ip_counts = {}
        for log in parsed_logs:
            if log:
                ip = log['ip']
                ip_counts[ip] = ip_counts.get(ip, 0) + 1
        return ip_counts


    def count_iprequest_per_hour(parsed_logs):
        hour_counts = {}
        for log in parsed_logs:
            timestamp = log['timestamp']

            try:
                dt = datetime.strptime(timestamp.split(' ')[0], "%d/%b/%Y:%H:%M:%S")
                hour = dt.strftime('%H:00')
                hour_counts[hour] = hour_counts.get(hour, 0) + 1
            except Exception as e: 
                print(f"[Error parsing timestamp] {timestamp} - {e}")
                continue
        return hour_counts


    def detect_failed_logins(parsed_logs, threshold=3):
        failed_attempts = {}
        for log in parsed_logs:
            if log['statuscode'] in [401, 403]:
                ip = log['ip']
                failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
        return {ip: count for ip, count in failed_attempts.items() if count >= threshold}


    def detect_404_scanners(parsed_logs, threshold=5):
        ip_404s = {}

        for log in parsed_logs:
            if log['statuscode'] == 404:
                ip = log['ip']
                ip_404s[ip] = ip_404s.get(ip, 0) + 1
        return {ip: count for ip, count in ip_404s.items() if count > threshold}


    def most_requested_urls(parse_logs, top_n=5):
        url_counts = {}
        for log in parse_logs:
            url = log['url']
            url_counts[url] = url_counts.get(url, 0) + 1
        return sorted(url_counts.items(), key=lambda x: x[1], reverse=True)[:top_n]


    def detect_login_targetting(parsed_logs, keywords=["login", "admin", "signin"], threshold=3):
        login_hits = {}
        for log in parsed_logs:
            url = log['url'].lower()
            if any(keyword in url for keyword in keywords):
                ip = log['ip']
                login_hits[ip] = login_hits.get(ip, 0) + 1

        return {ip: count for ip, count in login_hits.items() if count >= threshold}


    def flag_ip_range(parsed_logs, bad_ranges):
        flagged = {}

        for log in parsed_logs:
            try:
                ip = ipaddress.ip_address(log['ip'])
                for cidr in bad_ranges:
                    if ip in ipaddress.ip_network(cidr):
                        flagged[ip.exploded] = flagged.get(ip.exploded, 0) + 1
            except Exception as e:
                print(f"Error with IP {log['ip']}: {e}")
                continue
        return flagged

    
    def generate_summary_report(parsed_logs):
        print("\n===== LOG ANALYZER SUMMARY REPORT =====")
        print(f"\n📄 Total Parsed Log Entries: {len(parsed_logs)}")

        # Status code breakdown
        print("\n📊 Status Code Summary:")
        status_counts = {}
        for log in parsed_logs:
            code = log['statuscode']
            status_counts[code] = status_counts.get(code, 0) + 1
        for code, count in status_counts.items():
            print(f"  {code}: {count} requests")

        # Top IPs
        print("\n🌐 Top 5 IPs:")
        ip_counts = LogAnalyzer.count_ip_request(parsed_logs)
        top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        for ip, count in top_ips:
            print(f"  {ip}: {count} requests")

        # Requests per hour
        print("\n🕒 Requests Per Hour:")
        hour_counts = LogAnalyzer.count_iprequest_per_hour(parsed_logs)
        for hour, count in sorted(hour_counts.items()):
            print(f"  {hour}: {count} requests")

        # Top URLs
        print("\n🔗 Top 5 Requested URLs:")
        top_urls = LogAnalyzer.most_requested_urls(parsed_logs)
        for url, count in top_urls:
            print(f"  {url}: {count} hits")

        # Failed login attempts
        print("\n🔐 Failed Login Attempts (401/403):")
        failed_logins = LogAnalyzer.detect_failed_logins(parsed_logs)
        for ip, count in failed_logins.items():
            print(f"  🚨 {ip}: {count} failed attempts")

        # 404 scanners
        print("\n🕵️ 404 Scanners:")
        scanners = LogAnalyzer.detect_404_scanners(parsed_logs)
        for ip, count in scanners.items():
            print(f"  🔍 {ip}: {count} 404s")

    

        # Login targeting
        print("\n🎯 Login Page Targeting:")
        login_hits = LogAnalyzer.detect_login_targetting(parsed_logs)
        for ip, count in login_hits.items():
            print(f"  ⚠️ {ip}: {count} login/admin attempts")

        # IPs from known bad ranges
        print("\n🚩 IPs from Known Bad Ranges:")
        bad_ranges = ['192.168.0.0/16', '10.0.0.0/8']
        flagged = LogAnalyzer.flag_ip_range(parsed_logs, bad_ranges)
        for ip, count in flagged.items():
            print(f"  ⚠️ {ip}: {count} requests")

        print("\n===== END OF REPORT =====\n")


#DDoS Detector Works!
class DDoSDetector:
    log_pattern = re.compile(
        r'(?P<ip>\S+) - - \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<url>\S+) \S+" (?P<status>\d{3}) \d+'
    )

    def __init__(self, threshold=100, window=5):
        self.threshold = threshold
        self.window = timedelta(seconds=window)
        self.ip_log = defaultdict(deque)

    def parse_line(self, line):
        match = self.log_pattern.match(line)
        if not match:
            return None
        try:
            timestamp = datetime.strptime(match.group("timestamp"), "%d/%b/%Y:%H:%M:%S %z")
            return {"ip": match.group("ip"), "timestamp": timestamp}
        except ValueError:
            return None

    def analyze(self, entry):
        ip = entry["ip"]
        now = entry["timestamp"]
        times = self.ip_log[ip]
        while times and now - times[0] > self.window:
            times.popleft()
        times.append(now)
        if len(times) > self.threshold:
            return {
                "ip": ip,
                "timestamp": now.isoformat(),
                "alert": f"{len(times)} requests in {self.window.seconds}s — Possible DDoS"
            }
        return None

    def scan_file(self, path):
        with open(path, "r") as f:
            for line in f:
                entry = self.parse_line(line)
                if not entry:
                    continue
                alert = self.analyze(entry)
                if alert:
                    print("🚨", alert)

#Class SQLiDetector Works!
class SQLiDetector:
    """Specialized class for detecting SQL injection attempts in web logs"""

    SQL_PATTERNS = [
        (r"(\%27)|(\')|(\-\-)|(\%23)|(#)", "Basic SQL metacharacters"),
        (r"(\%22)|(\")", "Double quotes"),
        (r"\b(OR|AND)\b\s+\d+=\d+", "Boolean logic (OR/AND 1=1)"),
        (r"UNION\s+SELECT", "UNION SELECT"),
        (r"INSERT\s+INTO", "INSERT INTO"),
        (r"DROP\s+TABLE", "DROP TABLE"),
        (r"SELECT\s+\*\s+FROM", "SELECT * FROM"),
        (r"UPDATE\s+\w+\s+SET", "UPDATE SET"),
        (r"EXEC(\s|\+)+(s|x)p\w+", "EXEC stored procedures"),
        (r"sleep\(\d+\)", "Time-based injection (SLEEP)"),
        (r"benchmark\(\d+", "MySQL benchmark()"),
        (r"waitfor\s+delay", "SQL Server WAITFOR DELAY"),
        (r"pg_sleep\(\d+\)", "PostgreSQL pg_sleep()")
    ]

    def __init__(self, threshold=3):
        self.threshold = threshold

    def scan_log_entry(self, log_entry):
        """Scan a single log entry for SQLi patterns and return pattern label if matched"""
        if not log_entry or 'url' not in log_entry:
            return None
        
        url = log_entry['url'].lower()
        for pattern, label in self.SQL_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                return label
        return None

    def detect_attacks(self, parsed_logs):
        """Detect SQLi attempts across logs and record matched pattern labels"""
        attack_counts = {}
        pattern_matches = {}

        for log in parsed_logs:
            if not log:
                continue

            pattern_label = self.scan_log_entry(log)
            if pattern_label:
                ip = log['ip']
                attack_counts[ip] = attack_counts.get(ip, 0) + 1
                if ip not in pattern_matches:
                    pattern_matches[ip] = []
                pattern_matches[ip].append(pattern_label)

        # Filter based on threshold
        filtered = {
            ip: {
                'count': count,
                'patterns': pattern_matches[ip]
            }
            for ip, count in attack_counts.items()
            if count >= self.threshold
        }

        return filtered

    def generate_sqli_report(self, parsed_logs):
        """Generate a dedicated SQL injection report"""
        attacks = self.detect_attacks(parsed_logs)

        print("\n===== SQL INJECTION DETECTION REPORT =====")
        print(f"Scanning {len(parsed_logs)} log entries...")
        print(f"Detection threshold: {self.threshold} attempts\n")

        if attacks:
            print("🚨 DETECTED POTENTIAL SQL INJECTION ATTEMPTS:")
            for ip, info in attacks.items():
                print(f"  • {ip}: {info['count']} attempts")
                unique_patterns = set(info['patterns'])
                for pattern in unique_patterns:
                    count = info['patterns'].count(pattern)
                    print(f"     ↳ {pattern} ({count}x)")
        else:
            print("✅ No SQL injection attempts detected")

        print("\n===== END OF REPORT =====\n")
        return attacks

# Class XSS Detector WORKS!
class XSSDetector:
    """Specialized class for detecting Cross-Site Scripting (XSS) attempts in web logs"""

    XSS_PATTERNS = [
        (r"<script[^>]*>.*?</script>", "Basic script tag injection"),
        (r"javascript:", "JavaScript protocol handler"),
        (r"on(load|click|error|mouseover)\s*=", "HTML event handler"),
        (r"eval\s*\(.+\)", "JavaScript eval() function"),
        (r"alert\s*\(.+\)", "JavaScript alert() function"),
        (r"document\.(cookie|location)", "Document object access"),
        (r"window\.location", "Window location access"),
        (r"<img[^>]+onerror\s*=", "IMG tag with onerror"),
        (r"<svg[^>]*>.*?</svg>", "SVG tag injection"),
        (r"<iframe[^>]*>.*?</iframe>", "IFrame injection"),
        (r"<body[^>]*onload\s*=", "Body onload injection"),
        (r"%3Cscript%3E.*?%3C/script%3E", "URL-encoded script tags"),
        (r"&#x?\d+;", "HTML entity encoding"),
        (r"fromCharCode\s*\(", "String.fromCharCode() obfuscation"),
        (r"\.innerHTML\s*=", "innerHTML manipulation"),
        (r"document\.write\s*\(", "document.write() injection"),
        (r"<meta[^>]*http-equiv\s*=\s*['\"]?refresh['\"]?", "Meta refresh redirect")
    ]

    def __init__(self, threshold=3):
        """Initialize with detection threshold"""
        self.threshold = threshold
        self.parsed_logs = []

    def load_logs(self, log_file):
        """Load and parse logs from a file"""
        with open(log_file, "r") as file:
            raw_logs = file.readlines()
        
        for line in raw_logs:
            parsed = LogAnalyzer.parse_log_line(line)
            if parsed:
                self.parsed_logs.append(parsed)

    def scan_log_entry(self, log_entry):
        """Scan a single log entry for XSS patterns and return pattern label if matched"""
        if not log_entry or 'url' not in log_entry:
            return None

        # Check both URL and decoded URL
        url = log_entry['url'].lower()
        decoded_url = unquote(url).lower()
        
        for pattern, label in self.XSS_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE) or re.search(pattern, decoded_url, re.IGNORECASE):
                return label
        return None

    def detect_attacks(self):
        """Detect XSS attempts across loaded logs and record matched pattern labels"""
        if not self.parsed_logs:
            return {}

        attack_counts = {}
        pattern_matches = {}

        for log in self.parsed_logs:
            pattern_label = self.scan_log_entry(log)
            if pattern_label:
                ip = log['ip']
                attack_counts[ip] = attack_counts.get(ip, 0) + 1
                if ip not in pattern_matches:
                    pattern_matches[ip] = []
                pattern_matches[ip].append(pattern_label)

        # Filter based on threshold
        filtered = {
            ip: {
                'count': count,
                'patterns': pattern_matches[ip]
            }
            for ip, count in attack_counts.items()
            if count >= self.threshold
        }

        return filtered

    def generate_report(self):
        """Generate a dedicated XSS detection report"""
        attacks = self.detect_attacks()

        print("\n===== CROSS-SITE SCRIPTING DETECTION REPORT =====")
        print(f"Scanning {len(self.parsed_logs)} log entries...")
        print(f"Detection threshold: {self.threshold} attempts\n")

        if attacks:
            print("🚨 DETECTED POTENTIAL XSS ATTEMPTS:")
            for ip, info in attacks.items():
                print(f"  • {ip}: {info['count']} attempts")
                unique_patterns = set(info['patterns'])
                for pattern in unique_patterns:
                    count = info['patterns'].count(pattern)
                    print(f"     ↳ {pattern} ({count}x)")
        else:
            print("✅ No Cross-Site Scripting attempts detected")

        print("\n===== END OF REPORT =====")
        return attacks


#XSS Detector Working:
"""
if __name__ == "__main__":
    # Initialize detector
    xss_detector = XSSDetector(threshold=3)
    # Load logs
    xss_detector.load_logs("testing.txt") 
    # Generate report
    xss_detector.generate_report()
"""


#SQLiDetector working:
"""
if __name__ == "__main__":
    # Load raw log lines
    with open("testing.txt", "r") as file:
        raw_logs = file.readlines()

    # Parse logs
    parsed_logs = []
    for line in raw_logs:
        parsed = LogAnalyzer.parse_log_line(line)  # Make sure LogAnalyzer is defined
        if parsed:
            parsed_logs.append(parsed)

    # Run SQL injection detection
    sqliDetector = SQLiDetector(threshold=3)
    sqliDetector.generate_sqli_report(parsed_logs)
"""

#DDoSDetector working:
"""
if __name__ == "__main__":
    detector = DDoSDetector(threshold=5, window=5)
    detector.scan_file("testing.txt")
"""

#LogAnalyzer working:

"""
if __name__ == "__main__":
    with open("testing.txt", "r") as file:
        raw_logs = file.readlines()

    parsed_logs = []
    for line in raw_logs:
        parsed = LogAnalyzer.parse_log_line(line)
        if parsed:
            parsed_logs.append(parsed)

    LogAnalyzer.generate_summary_report(parsed_logs)
"""
