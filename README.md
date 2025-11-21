# website-security-vapt-project
Vulnerability Assessment and Penetration Testing Project
A Python-based security scanning tool that checks websites for common vulnerabilities, misconfigurations, and security headers. Built using Requests, BeautifulSoup, and regular expressions, this tool helps security beginners and developers quickly assess basic security hygiene of a website.

⭐ Features

✔️ Fetch and analyze website metadata

✔️ Check for missing or weak security headers

✔️ Detect common vulnerabilities (basic XSS patterns, open redirects, etc.)

✔️ Analyze technology stack from HTTP headers

✔️ Scan for broken links

✔️ Lightweight, fast, and beginner-friendly
How to Run
1️⃣ Clone the repo
git clone https://github.com/your-username/website-security-scanner.git
cd website-security-scanner

2️⃣ Install dependencies
pip install -r requirements.txt

3️⃣ Run the scanner
python scanner.py

🧪 Sample Output
Scanning: https://example.com

[+] Security Headers:
    - X-Frame-Options: MISSING
    - Content-Security-Policy: MISSING
    - Strict-Transport-Security: Present

[+] Vulnerability Checks:
    - XSS test payload reflected? NO
    - Open Redirect? POSSIBLY VULNERABLE

[+] Broken Links:
    - 2 broken links found

Scan Completed ✔️

📚 Tech Stack

Python 3

Requests

BeautifulSoup

Regex

🧩 Use Cases

Students learning cybersecurity basics

Developers testing their websites

Security beginners practicing scanning concepts

Project submission for internships/jobs

🛠️ Future Improvements

Add full XSS & SQLi payload testing

Add multi-threading for faster scans

Export scan results as PDF/CSV

Include full domain crawling

✨ Author

Shreya Swarup Srivastava

Cybersecurity & Python Automation Enthusiast

GitHub: https://github.com/shreya-sri25
