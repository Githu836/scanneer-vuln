# [1] IMPORT LIBRARIES
import re
import os
import argparse
import requests
from bs4 import BeautifulSoup
import threading
import queue
from urllib.parse import urljoin, urlparse, parse_qs
import json
import warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Disable warnings
warnings.filterwarnings("ignore", category=UserWarning)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# [2] MAIN SCANNER CLASS
class WebVulnerabilityScanner:
    def __init__(self):
        self.VULN_PATTERNS = {
            "SQL Injection": [
                r"(SELECT|INSERT|UPDATE|DELETE).*(\%s|\+\s*\w+|\|\|)",
                r"exec\(.*\%s.*\)",
                r"execute\(.*\+.*\)",
            ],
            "XSS": [
                r"innerHTML\s*=\s*.*\+.*",
                r"document\.write\(.*\+.*\)",
                r"<script>.*eval\(.*\).*</script>",
            ],
            "Command Injection": [
                r"os\.system\(.*\+.*\)",
                r"subprocess\.(call|Popen|run)\(.*\+.*\)",
            ],
            "Sensitive Data Exposure": [
                r"(password|secret|api_key|token)\s*=\s*['\"].+['\"]",
                r"BEGIN\sPRIVATE\sKEY",
            ],
            "Path Traversal": [
                r"open\(.*\.\./.*\)",
                r"os\.path\.join\(.*,.*\.\./.*\)",
            ]
        }

        self.WEB_VULN_CHECKS = {
            "SQLi": ["'", "\"", "1=1", "1=0", "OR 1=1"],
            "XSS": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
            "Directory Traversal": ["../../../../etc/passwd", "../..././../etc/passwd"],
            "Command Injection": ["; ls", "| cat /etc/passwd", "`whoami`"]
        }

        self.headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
        }
        self.max_pages = 100
        self.timeout = 5
        self.verify_ssl = False

    # [3] FILE SCANNING METHODS
    def scan_file(self, filepath):
        findings = []
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
            
            for idx, line in enumerate(lines, 1):
                for vuln, patterns in self.VULN_PATTERNS.items():
                    for pattern in patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            findings.append({
                                "type": vuln,
                                "file": filepath,
                                "line": idx,
                                "code": line.strip(),
                                "severity": self.get_severity(vuln)
                            })
        except Exception as e:
            print(f"[!] Error scanning {filepath}: {str(e)}")
        return findings

    def scan_directory(self, root):
        result = []
        for dirpath, _, filenames in os.walk(root):
            for filename in filenames:
                if filename.endswith((".py", ".js", ".php", ".rb", ".go", ".java", ".html", ".htm")):
                    filepath = os.path.join(dirpath, filename)
                    result.extend(self.scan_file(filepath))
        return result

    # [4] WEB SCANNING METHODS
    def scan_website(self, url, output_file=None):
        print(f"\n[+] Scanning website: {url}")
        results = []
        links = self.crawl_website(url)
        
        q = queue.Queue()
        for link in links:
            q.put(link)
        
        lock = threading.Lock()
        threads = []
        for _ in range(5):
            t = threading.Thread(target=self.worker, args=(q, results, lock))
            t.start()
            threads.append(t)
        
        for t in threads:
            t.join()
        
        if output_file:
            self.save_results(results, output_file)
        return results

    def crawl_website(self, base_url):
        visited = set()
        to_visit = {base_url}
        links_found = set()

        while to_visit and len(visited) < self.max_pages:
            url = to_visit.pop()
            if url in visited:
                continue
            
            try:
                response = requests.get(
                    url, 
                    headers=self.headers, 
                    timeout=self.timeout, 
                    verify=self.verify_ssl
                )
                soup = BeautifulSoup(response.text, 'html.parser')
                
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    absolute_url = urljoin(url, href)
                    if base_url in absolute_url and absolute_url not in visited:
                        links_found.add(absolute_url)
                        to_visit.add(absolute_url)
                
                visited.add(url)
            except Exception as e:
                print(f"[!] Error crawling {url}: {str(e)}")
                continue
        
        return links_found

    def worker(self, q, results, lock):
        while not q.empty():
            url = q.get()
            try:
                temp_results = []
                print(f"[*] Scanning {url}")
                
                params = self.extract_parameters(url)
                for param in params:
                    temp_results.extend(self.check_sqli(url, param))
                    temp_results.extend(self.check_xss(url, param))
                    temp_results.extend(self.check_directory_traversal(url, param))
                    temp_results.extend(self.check_command_injection(url, param))
                
                with lock:
                    results.extend(temp_results)
            except Exception as e:
                print(f"[!] Error scanning {url}: {str(e)}")
            finally:
                q.task_done()

    # [5] VULNERABILITY CHECK METHODS
    def check_sqli(self, url, param):
        results = []
        for payload in self.WEB_VULN_CHECKS["SQLi"]:
            try:
                test_url = f"{url}?{param}=1{payload}"
                response = requests.get(
                    test_url,
                    headers=self.headers,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
                if "error" in response.text.lower() or "syntax" in response.text.lower():
                    results.append({
                        "type": "Possible SQL Injection",
                        "url": test_url,
                        "payload": payload,
                        "severity": "High"
                    })
            except Exception as e:
                print(f"[!] Error in check_sqli: {e}")
                continue
        return results

    def check_xss(self, url, param):
        results = []
        for payload in self.WEB_VULN_CHECKS["XSS"]:
            try:
                test_url = f"{url}?{param}={payload}"
                response = requests.get(
                    test_url,
                    headers=self.headers,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
                if payload in response.text:
                    results.append({
                        "type": "Possible XSS",
                        "url": test_url,
                        "payload": payload,
                        "severity": "Medium"
                    })
            except Exception as e:
                print(f"[!] Error in check_xss: {e}")
                continue
        return results

    def check_directory_traversal(self, url, param):
        results = []
        for payload in self.WEB_VULN_CHECKS["Directory Traversal"]:
            try:
                test_url = f"{url}?{param}={payload}"
                response = requests.get(
                    test_url,
                    headers=self.headers,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
                if "root:" in response.text:
                    results.append({
                        "type": "Possible Directory Traversal",
                        "url": test_url,
                        "payload": payload,
                        "severity": "High"
                    })
            except Exception as e:
                print(f"[!] Error in check_directory_traversal: {e}")
                continue
        return results

    def check_command_injection(self, url, param):
        results = []
        for payload in self.WEB_VULN_CHECKS["Command Injection"]:
            try:
                test_url = f"{url}?{param}={payload}"
                response = requests.get(
                    test_url,
                    headers=self.headers,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
                if "bin/bash" in response.text.lower() or "Permission denied" in response.text:
                    results.append({
                        "type": "Possible Command Injection",
                        "url": test_url,
                        "payload": payload,
                        "severity": "Critical"
                    })
            except Exception as e:
                print(f"[!] Error in check_command_injection: {e}")
                continue
        return results

    # [6] UTILITY METHODS
    def extract_parameters(self, url):
        parsed = urlparse(url)
        return list(parse_qs(parsed.query).keys()) or ["q"]

    def get_severity(self, vuln_type):
        severity_map = {
            "SQL Injection": "High",
            "Command Injection": "Critical",
            "Sensitive Data Exposure": "Critical",
            "XSS": "Medium",
            "Path Traversal": "High"
        }
        return severity_map.get(vuln_type, "Low")

    def save_results(self, results, filename):
        json_file = filename.replace(".txt", ".json")
        with open(json_file, "w") as f:
            json.dump(results, f, indent=2)
        
        with open(filename, "w") as f:
            for result in results:
                if "file" in result:
                    f.write(f"[{result['severity']}] {result['type']} in {result['file']}:{result['line']}\n")
                    f.write(f"Code: {result['code']}\n\n")
                else:
                    f.write(f"[{result['severity']}] {result['type']} at {result['url']}\n")
                    f.write(f"Payload: {result['payload']}\n\n")
        
        print(f"[+] Results saved to {filename} and {json_file}")

# [7] MAIN FUNCTION
def main():
    parser = argparse.ArgumentParser(description="🔥 WEB VULNERABILITY SCANNER PRO MAX 🔥")
    parser.add_argument("-t", "--target", help="Website URL to scan")
    parser.add_argument("-d", "--directory", help="Directory to scan for code vulnerabilities")
    parser.add_argument("-o", "--output", help="Output file (default: results.txt)", default="results.txt")
    parser.add_argument("--threads", type=int, default=5, help="Number of threads (default: 5)")
    args = parser.parse_args()

    scanner = WebVulnerabilityScanner()
    results = []

    if args.directory:
        print(f"[+] Scanning directory: {args.directory}")
        results.extend(scanner.scan_directory(args.directory))
    
    if args.target:
        results.extend(scanner.scan_website(args.target, args.output))
    
    if not args.target and not args.directory:
        print("[!] No target specified. Running demo scan on current directory...")
        results.extend(scanner.scan_directory("."))
    
    if results:
        print("\n[+] SCAN COMPLETE! Found vulnerabilities:")
        for result in results:
            if "file" in result:
                print(f"[{result['severity']}] {result['type']} in {result['file']}:{result['line']}")
                print(f"Code: {result['code']}\n")
            else:
                print(f"[{result['severity']}] {result['type']} at {result['url']}")
                print(f"Payload: {result['payload']}\n")
        
        if args.output:
            scanner.save_results(results, args.output)
    else:
        print("[-] No vulnerabilities found.")

if __name__ == "__main__":
    main()
