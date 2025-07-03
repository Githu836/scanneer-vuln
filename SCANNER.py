import re
import os
import argparse
import requests
from bs4 import BeautifulSoup
import threading
import queue
from urllib.parse import urljoin

class WebVulnerabilityScanner:
    def __init__(self):
        self.VULN_PATTERNS = {
            "SQL Injection": [
                r"(SELECT|INSERT|UPDATE|DELETE).*(\%s|\+\s*\w+|\|\|)",  # SQLi patterns
                r"exec\(.*\%s.*\)",  # SQL execution with string formatting
                r"execute\(.*\+.*\)",  # String concatenation in execute
            ],
            "XSS": [
                r"innerHTML\s*=\s*.*\+.*",  # Unsafe DOM manipulation
                r"document\.write\(.*\+.*\)",  # Direct document writing
                r"<script>.*eval\(.*\).*</script>",  # Eval usage
            ],
            "Command Injection": [
                r"os\.system\(.*\+.*\)",  # OS command execution
                r"subprocess\.(call|Popen|run)\(.*\+.*\)",  # Subprocess calls
            ],
            "Sensitive Data Exposure": [
                r"(password|secret|api_key|token)\s*=\s*['\"].+['\"]",  # Hardcoded credentials
                r"BEGIN\sPRIVATE\sKEY",  # Private keys in code
            ],
            "Path Traversal": [
                r"open\(.*\.\./.*\)",  # Directory traversal
                r"os\.path\.join\(.*,.*\.\./.*\)",  # Unsafe path joining
            ]
        }

        self.WEB_VULN_CHECKS = {
            "SQLi": ["'", "\"", "1=1", "1=0", "OR 1=1"],
            "XSS": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
            "Directory Traversal": ["../../../../etc/passwd", "../..././../etc/passwd"],
            "Command Injection": ["; ls", "| cat /etc/passwd", "`whoami`"]
        }

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
            print(f"Error scanning {filepath}: {str(e)}")
        return findings

    def get_severity(self, vuln_type):
        severity_map = {
            "SQL Injection": "High",
            "Command Injection": "High",
            "Sensitive Data Exposure": "Critical",
            "XSS": "Medium",
            "Path Traversal": "Medium"
        }
        return severity_map.get(vuln_type, "Low")

    def scan_directory(self, root):
        result = []
        for dirpath, _, filenames in os.walk(root):
            for filename in filenames:
                if filename.endswith((".py", ".js", ".php", ".rb", ".go", ".java", ".html", ".htm")):
                    filepath = os.path.join(dirpath, filename)
                    result.extend(self.scan_file(filepath))
        return result

    def scan_website(self, url, output_file=None):
        print(f"\n[+] Scanning website: {url}")
        results = []
        
        # Check for common vulnerabilities
        results.extend(self.check_sqli(url))
        results.extend(self.check_xss(url))
        results.extend(self.check_directory_traversal(url))
        
        # Crawl the website and check all pages
        print("[+] Crawling website...")
        links = self.crawl_website(url)
        print(f"[+] Found {len(links)} pages to scan")
        
        # Multi-threaded scanning
        q = queue.Queue()
        for link in links:
            q.put(link)
        
        threads = []
        for i in range(5):  # 5 threads
            t = threading.Thread(target=self.worker, args=(q, results))
            t.start()
            threads.append(t)
        
        for t in threads:
            t.join()
        
        # Save results if output file specified
        if output_file:
            self.save_results(results, output_file)
        
        return results

    def worker(self, q, results):
        while not q.empty():
            url = q.get()
            try:
                print(f"[*] Scanning {url}")
                results.extend(self.check_sqli(url))
                results.extend(self.check_xss(url))
                results.extend(self.check_directory_traversal(url))
            except Exception as e:
                print(f"Error scanning {url}: {str(e)}")
            finally:
                q.task_done()

    def crawl_website(self, base_url):
        visited = set()
        to_visit = {base_url}
        links_found = set()

        while to_visit:
            url = to_visit.pop()
            if url in visited:
                continue
            
            try:
                response = requests.get(url, timeout=5)
                soup = BeautifulSoup(response.text, 'html.parser')
                
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    absolute_url = urljoin(url, href)
                    if base_url in absolute_url and absolute_url not in visited:
                        links_found.add(absolute_url)
                        to_visit.add(absolute_url)
                
                visited.add(url)
            except:
                continue
        
        return links_found

    def check_sqli(self, url):
        results = []
        for payload in self.WEB_VULN_CHECKS["SQLi"]:
            try:
                test_url = f"{url}?id=1{payload}"
                response = requests.get(test_url, timeout=5)
                if "error" in response.text.lower() or "syntax" in response.text.lower():
                    results.append({
                        "type": "Possible SQL Injection",
                        "url": test_url,
                        "payload": payload,
                        "severity": "High"
                    })
            except:
                continue
        return results

    def check_xss(self, url):
        results = []
        for payload in self.WEB_VULN_CHECKS["XSS"]:
            try:
                test_url = f"{url}?search={payload}"
                response = requests.get(test_url, timeout=5)
                if payload in response.text:
                    results.append({
                        "type": "Possible XSS",
                        "url": test_url,
                        "payload": payload,
                        "severity": "Medium"
                    })
            except:
                continue
        return results

    def check_directory_traversal(self, url):
        results = []
        for payload in self.WEB_VULN_CHECKS["Directory Traversal"]:
            try:
                test_url = f"{url}?file={payload}"
                response = requests.get(test_url, timeout=5)
                if "root:" in response.text:
                    results.append({
                        "type": "Possible Directory Traversal",
                        "url": test_url,
                        "payload": payload,
                        "severity": "High"
                    })
            except:
                continue
        return results

    def save_results(self, results, filename):
        with open(filename, "w") as f:
            for result in results:
                if "file" in result:  # Static analysis result
                    f.write(f"[{result['severity']}] {result['type']} found in {result['file']}:{result['line']}\n")
                    f.write(f"Code: {result['code']}\n\n")
                else:  # Web scan result
                    f.write(f"[{result['severity']}] {result['type']} found at {result['url']}\n")
                    f.write(f"Payload: {result['payload']}\n\n")

def main():
    parser = argparse.ArgumentParser(description="Advanced Web Vulnerability Scanner")
    parser.add_argument("-t", "--target", help="Website URL to scan")
    parser.add_argument("-d", "--directory", help="Directory to scan for code vulnerabilities")
    parser.add_argument("-o", "--output", help="Output file to save results")
    parser.add_argument("--threads", type=int, default=5, help="Number of threads to use (default: 5)")
    
    args = parser.parse_args()
    scanner = WebVulnerabilityScanner()
    
    if not args.target and not args.directory:
        parser.print_help()
        return
    
    results = []
    
    if args.directory:
        print(f"[+] Scanning directory: {args.directory}")
        results.extend(scanner.scan_directory(args.directory))
    
    if args.target:
        results.extend(scanner.scan_website(args.target, args.output))
    
    if results:
        print("\n[+] Scan Results:")
        for result in results:
            if "file" in result:  # Static analysis result
                print(f"[{result['severity']}] {result['type']} found in {result['file']}:{result['line']}")
                print(f"Code: {result['code']}\n")
            else:  # Web scan result
                print(f"[{result['severity']}] {result['type']} found at {result['url']}")
                print(f"Payload: {result['payload']}\n")
        
        if args.output:
            scanner.save_results(results, args.output)
            print(f"[+] Results saved to {args.output}")
    else:
        print("[-] No vulnerabilities found")

if __name__ == "__main__":
    main()
