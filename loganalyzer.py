import re 
from datetime import datetime 
import ipaddress

""" 
Simple File Reader Project 



File I/O: Reading and parsing structured text files

Data structures: Dictionaries, lists, sorting

Control flow: Loops, conditionals, function-based modularity

Regex (re): Pattern matching to extract structured data

Data Analysis: Grouped and summarized data by IP, time, URL, and status code

PyLogAnalyzer

"""


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
logfile = "server_log.txt"
#read_log_file(logfile)

def parse_log_line(line):
    with open("server_log.txt", "r") as file:
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
            "timestamp" : timestamp,
            "method" : method,
            "url" : url,
            "statuscode" : status_code,
            "size": byte_size
        }


    else:
        return None

def count_ip_request (parsed_logs):
    ip_counts = {}
    for log in parsed_logs:
        if log:
            ip = log['ip']
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
    return ip_counts

def count_iprequest_per_hour (parsed_logs):
    hour_counts = {}
    for log in parsed_logs:
        timestamp = log['timestamp']

        try:
            dt = datetime.strptime(timestamp.split(' ')[0],"%d/%b/%Y:%H:%M:%S")
            hour =  dt.strftime('%H:00')
            hour_counts[hour] = hour_counts.get(hour, 0) + 1
        except Exception as e: 
            print(f"[Error parsing timestamp] {timestamp} - {e}")

            continue
    return hour_counts

def detect_failed_logins(parsed_logs, threshold = 3):
    failed_attempts = {}
    for log in parsed_logs:
        if log['statuscode'] in [401, 403]:
            ip = log['ip']
            failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
    return{ip: count for ip, count in failed_attempts.items() if count >=threshold}

def detect_404_scanners(parsed_logs, threshold =5):
    ip_404s = {}

    for log in parsed_logs:
        if log['statuscode'] == 404:
            ip = log['ip']
            ip_404s[ip] = ip_404s.get(ip, 0) + 1
    return{ip: count for ip, count in ip_404s.items() if count > threshold}

def most_requested_urls(parse_logs, top_n=5):
    url_counts={}
    for log in parse_logs:
        url = log['url']
        url_counts[url] = url_counts.get(url, 0) + 1
    return sorted(url_counts.items(), key = lambda x: x[1], reverse = True)[:top_n]

def detect_login_targetting(parsed_logs, keywords=["login","admin", "signin"], threshold=3):
    login_hits ={}
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
                    flagged[ip.exploded] = flagged.get(ip.exploded, 0)+ 1
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
    ip_counts = count_ip_request(parsed_logs)
    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    for ip, count in top_ips:
        print(f"  {ip}: {count} requests")

    # Requests per hour
    print("\n🕒 Requests Per Hour:")
    hour_counts = count_iprequest_per_hour(parsed_logs)
    for hour, count in sorted(hour_counts.items()):
        print(f"  {hour}: {count} requests")

    # Top URLs
    print("\n🔗 Top 5 Requested URLs:")
    top_urls = most_requested_urls(parsed_logs)
    for url, count in top_urls:
        print(f"  {url}: {count} hits")

    # Failed login attempts
    print("\n🔐 Failed Login Attempts (401/403):")
    failed_logins = detect_failed_logins(parsed_logs)
    for ip, count in failed_logins.items():
        print(f"  🚨 {ip}: {count} failed attempts")

    # 404 scanners
    print("\n🕵️ 404 Scanners:")
    scanners = detect_404_scanners(parsed_logs)
    for ip, count in scanners.items():
        print(f"  🔍 {ip}: {count} 404s")

    # Login targeting
    print("\n🎯 Login Page Targeting:")
    login_hits = detect_login_targetting(parsed_logs)
    for ip, count in login_hits.items():
        print(f"  ⚠️ {ip}: {count} login/admin attempts")

    # IPs from known bad ranges
    print("\n🚩 IPs from Known Bad Ranges:")
    bad_ranges = ['192.168.0.0/16', '10.0.0.0/8']
    flagged = flag_ip_range(parsed_logs, bad_ranges)
    for ip, count in flagged.items():
        print(f"  ⚠️ {ip}: {count} requests")

    print("\n===== END OF REPORT =====\n")




#Main Running the Log Analyzer 


parsed_logs = []
with open("server_log.txt", "r") as file:
    for line in file:
        parsed = parse_log_line(line)
        if parsed:
            parsed_logs.append(parsed)

generate_summary_report(parsed_logs)


