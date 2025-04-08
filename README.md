# Python-Log-Analysis-
What does it do? 
- 🚨 DDoS attacks
- 🛡️ SQL Injection attempts
- 🧪 Cross-Site Scripting (XSS)
- 🔐 Brute-force login attempts
- 🕵️ 404 scanning bots
- 🚩 Suspicious IP activity from known bad ranges

Skills Demonstrated:
- 🧩 Regular Expressions (log parsing, pattern detection)
- 🧠 Security Analysis (DDoS, SQLi, XSS detection heuristics)
- 📊 Data Aggregation (requests/hour, top IPs, URL hits)
- 🕵️ Threat Intelligence (404 scanning, brute-force detection, login targeting)
- 📁 File I/O & Stream Processing
- 🧼 Clean OOP Design (modular classes per detection type)
- 🕰️ Time Windowing & Rate Limiting Logic (DDoSDetector)
- 🔍 Encoded payload inspection (XSS and SQLi decoding logic)

Breakdown:
- `LogAnalyzer`: Core log parser + report generator
- `DDoSDetector`: Detects burst requests from single IPs within a time window
- `SQLiDetector`: Finds patterns indicating SQL injection attempts
- `XSSDetector`: Detects reflected/script-based injection in URLs


# 1. Clone this repo
git clone https://github.com/yourusername/log-threat-intel-suite.git
cd log-threat-intel-suite

# 2. Run any detector
python xss_detector.py
python sqli_detector.py
python ddos_detector.py
python log_analyzer.py

# 3. Logs
Replace "testing.txt" with your own Apache-style log file. Or see the results for yourself!
