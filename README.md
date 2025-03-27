# Python-Log-Analysis-
📂 Reads and Parses Log File 🧠 Processes Each Log Entry into a Dictionary lines  📊 Performs Log Analysis


Reads each line and uses regex to extract:
IP address

Timestamp

HTTP method

URL path

Status code (200, 404, etc.)

Response size in bytes

Converts each valid log line into a structured Python dictionary, Skips malformed or unmatched lines



📋 Prints Full Summary Report Including 
🚩 Flags Known Bad IP Ranges
🎯 Login/Admin Page Targeting
🕵️ 404 Scanner Detection
🔐 Failed Login Detection
⏰ Requests Per Hour🔗
Top Requested URLs
🌐Top IPs




HOW IT WORKS:
Both Files function together, download both and run the loganalyzer.py to make it scan the text file add any additional HTTP request or change the request do whatever you please!

If you run it this will be the output:


===== LOG ANALYZER SUMMARY REPORT =====

📄 Total Parsed Log Entries: 29

📊 Status Code Summary:
  200: 11 requests
  401: 4 requests
  403: 7 requests
  404: 7 requests

🌐 Top 5 IPs:
  192.168.1.1: 9 requests
  127.0.0.1: 5 requests
  8.8.8.8: 4 requests
  192.168.0.5: 2 requests
  192.168.10.7: 2 requests

🕒 Requests Per Hour:
  08:00: 19 requests
  09:00: 4 requests
  10:00: 6 requests

🔗 Top 5 Requested URLs:
  /index.html: 5 hits
  /login: 5 hits
  /admin: 5 hits
  /home: 3 hits
  /dashboard: 2 hits

🔐 Failed Login Attempts (401/403):
  🚨 192.168.1.1: 3 failed attempts
  🚨 8.8.8.8: 3 failed attempts

🕵️ 404 Scanners:
  🔍 192.168.1.1: 6 404s

🎯 Login Page Targeting:
  ⚠️ 192.168.1.1: 6 login/admin attempts
  ⚠️ 8.8.8.8: 3 login/admin attempts

🚩 IPs from Known Bad Ranges:
  ⚠️ 192.168.1.1: 9 requests
  ⚠️ 10.0.0.5: 1 requests
  ⚠️ 192.168.0.5: 2 requests
  ⚠️ 192.168.10.7: 2 requests
  ⚠️ 192.168.100.99: 2 requests
  ⚠️ 10.0.0.1: 1 requests
  ⚠️ 10.10.10.10: 1 requests
  ⚠️ 10.255.255.254: 1 requests

===== END OF REPORT =====

