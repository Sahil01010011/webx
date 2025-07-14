import requests
import os
import time
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import sys
from datetime import datetime
from dotenv import load_dotenv
load_dotenv()  # Loads before other imports

def setup_environment(self):
    """Load .env settings with safety checks"""
    self.user_agent = os.getenv("USER_AGENT", "WebX/1.0")
    self.delay = max(0.3, float(os.getenv("REQUEST_DELAY", 0.5)))  # Minimum 0.3s delay
    self.max_threads = min(int(os.getenv("MAX_THREADS", 5)), 10)  # Max 10 threads

class WebXScanner:
    def __init__(self):
        self.target_url = ""
        self.domain = ""
        self.session = requests.Session()
        self.vulnerabilities = []
        self.discovered_endpoints = set()
        self.checked_urls = set()
        self.payload_dirs = {
            'sqli': 'payloads/sql.txt',
            'xss': 'payloads/xss.txt',
            'redirect': 'payloads/redirect.txt',
            'traversal': 'payloads/traversal.txt',
            'ssrf': 'payloads/ssrf.txt',
            'cors': 'payloads/cors.txt',
            'jwt': 'payloads/jwt.txt'
        }
        self.setup_session()
        self.ensure_payload_dirs()

    def ensure_payload_dirs(self):
        """Create payloads directory and default files if they don't exist"""
        if not os.path.exists('payloads'):
            os.makedirs('payloads')
            
        for payload_type, filepath in self.payload_dirs.items():
            if not os.path.exists(filepath):
                with open(filepath, 'w') as f:
                    if payload_type == 'sqli':
                        f.write("\n".join([
                            "' OR '1'='1",
                            "' OR 1=1--",
                            "1' UNION SELECT null,version()--"
                        ]))
                    elif payload_type == 'xss':
                        f.write("\n".join([
                            "<script>alert(1)</script>",
                            "<img src=x onerror=alert(1)>",
                            "javascript:alert(1)"
                        ]))
                    elif payload_type == 'redirect':
                        f.write("\n".join([
                            "https://evil.com",
                            "//evil.com",
                            "http://localhost"
                        ]))
                    elif payload_type == 'traversal':
                        f.write("\n".join([
                            "../../../../etc/passwd",
                            "..%2F..%2Fetc%2Fpasswd"
                        ]))

    def load_payloads(self, payload_type):
        """Load payloads from the specified file with UTF-8 encoding"""
        filepath = self.payload_dirs.get(payload_type)
        if not filepath or not os.path.exists(filepath):
            return []
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:  # Explicit UTF-8
                return [line.strip() for line in f if line.strip()]
        except UnicodeDecodeError:
            # Fallback to latin-1 if UTF-8 fails
            with open(filepath, 'r', encoding='latin-1') as f:
                return [line.strip() for line in f if line.strip()]

    def setup_session(self):
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5'
        })

    def print_banner(self):
        banner = """
        ██╗    ██╗███████╗██████╗ ██╗  ██╗
        ██║    ██║██╔════╝██╔══██╗╚██╗██╔╝
        ██║ █╗ ██║█████╗  ██████╔╝ ╚███╔╝ 
        ██║███╗██║██╔══╝  ██╔══██╗ ██╔██╗ 
        ╚███╔███╔╝███████╗██████╔╝██╔╝ ██╗
         ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═╝  ╚═╝
                                           
        WebX - Professional Web Vulnerability Scanner
        """
        print(banner)
        print("Note: Only use this tool on websites you have permission to scan")
        print("="*60)

    def get_target_url(self):
        while True:
            print("\n[+] Enter target URL (e.g., https://example.com):")
            url = input("> ").strip()
            
            if not url.startswith(('http://', 'https://')):
                print("[-] Please include http:// or https://")
                continue
                
            try:
                response = self.session.get(url, timeout=5)
                if response.status_code < 400:
                    self.target_url = url
                    self.domain = urlparse(url).netloc
                    print(f"[+] Target set to: {self.target_url}")
                    return
                else:
                    print(f"[-] Received HTTP {response.status_code} for URL")
            except Exception as e:
                print(f"[-] Error connecting to {url}: {str(e)}")

    def show_scan_options(self):
        print("\n[+] Select vulnerabilities to scan (comma-separated):")
        print(" 1. SQL Injection (SQLi)")
        print(" 2. Cross-Site Scripting (XSS)")
        print(" 3. Open Redirection")
        print(" 4. Path Traversal")
        print(" 5. Server-Side Request Forgery (SSRF)")
        print(" 6. CORS Misconfigurations")
        print(" 7. JWT Issues")
        print(" 8. Full Comprehensive Scan")
        print("\n[+] Enter 'q' to quit")

    def get_scan_choices(self):
        while True:
            choice = input("\n> ").strip().lower()
            
            if choice == 'q':
                sys.exit(0)
                
            selected = [c.strip() for c in choice.split(',')]
            valid_choices = []
            
            for c in selected:
                if c in ['1', '2', '3', '4', '5', '6', '7', '8']:
                    valid_choices.append(c)
                else:
                    print(f"[-] Invalid option: {c}")
            
            if valid_choices:
                return valid_choices
            else:
                print("[-] Please select at least one valid option")

    def run_selected_scans(self, choices):
        print(f"\n[+] Starting scan for {len(choices)} selected vulnerabilities")
        
        # First crawl the site to discover endpoints
        self.crawl(self.target_url, depth=1)
        
        # Run selected scans
        if '8' in choices:  # Full scan
            self.test_sqli()
            self.test_xss()
            self.test_open_redirection()
            self.test_path_traversal()
            self.test_ssrf()
            self.test_cors()
            self.test_jwt()
        else:
            if '1' in choices:
                self.test_sqli()
            if '2' in choices:
                self.test_xss()
            if '3' in choices:
                self.test_open_redirection()
            if '4' in choices:
                self.test_path_traversal()
            if '5' in choices:
                self.test_ssrf()
            if '6' in choices:
                self.test_cors()
            if '7' in choices:
                self.test_jwt()
        
        self.show_results()

    def crawl(self, url, depth=1):
        if depth == 0 or url in self.checked_urls:
            return
            
        self.checked_urls.add(url)
        print(f"[*] Crawling: {url}")
        
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract links
            for link in soup.find_all('a', href=True):
                full_url = urljoin(url, link['href'])
                if self.domain in full_url and full_url not in self.discovered_endpoints:
                    self.discovered_endpoints.add(full_url)
                    self.crawl(full_url, depth-1)
            
            # Extract forms
            for form in soup.find_all('form'):
                action = form.get('action', '')
                if action:
                    full_url = urljoin(url, action)
                    if self.domain in full_url and full_url not in self.discovered_endpoints:
                        self.discovered_endpoints.add(full_url)
                        self.crawl(full_url, depth-1)
            
            time.sleep(0.5)
        except Exception as e:
            print(f"[-] Error crawling {url}: {str(e)}")

    def test_sqli(self):
        print("\n[*] Testing for SQL Injection vulnerabilities...")
        payloads = self.load_payloads('sqli')
        if not payloads:
            print("[-] No SQLi payloads found in payloads/sql.txt")
            return
            
        test_urls = [u for u in self.discovered_endpoints if '?' in u] + [self.target_url]
        
        for url in test_urls[:20]:  # Limit to 20 URLs for demo
            if '?' in url:
                base_url, params = url.split('?', 1)
                param_pairs = params.split('&')
                
                for param in param_pairs:
                    if '=' in param:
                        param_name, param_value = param.split('=', 1)
                        for payload in payloads:
                            test_url = f"{base_url}?{param_name}={payload}"
                            try:
                                response = self.session.get(test_url, timeout=10)
                                
                                error_messages = [
                                    "SQL syntax", "MySQL server", "syntax error",
                                    "unclosed quotation mark", "ORA-00933",
                                    "Microsoft OLE DB Provider", "PostgreSQL"
                                ]
                                
                                if any(error.lower() in response.text.lower() for error in error_messages):
                                    self.add_vulnerability(
                                        "SQL Injection",
                                        test_url,
                                        f"Parameter '{param_name}' appears vulnerable to SQLi"
                                    )
                                    break
                                    
                            except Exception as e:
                                print(f"[-] Error testing {test_url}: {str(e)}")
                            
                            time.sleep(0.3)

    def test_xss(self):
        print("\n[*] Testing for Cross-Site Scripting (XSS)...")
        payloads = self.load_payloads('xss')
        if not payloads:
            print("[-] No XSS payloads found in payloads/xss.txt")
            return
            
        test_urls = [u for u in self.discovered_endpoints if '?' in u] + [self.target_url]
        
        for url in test_urls[:20]:  # Limit to 20 URLs for demo
            if '?' in url:
                base_url, params = url.split('?', 1)
                param_pairs = params.split('&')
                
                for param in param_pairs:
                    if '=' in param:
                        param_name, param_value = param.split('=', 1)
                        for payload in payloads:
                            test_url = f"{base_url}?{param_name}={payload}"
                            try:
                                response = self.session.get(test_url, timeout=5)
                                if payload in response.text:
                                    self.add_vulnerability(
                                        "Cross-Site Scripting (XSS)",
                                        test_url,
                                        f"Reflected XSS in parameter '{param_name}'"
                                    )
                                    break
                            except Exception as e:
                                print(f"[-] Error testing {test_url}: {str(e)}")
                            
                            time.sleep(0.3)

    def test_open_redirection(self):
        print("\n[*] Testing for Open Redirection vulnerabilities...")
        payloads = self.load_payloads('redirect')
        if not payloads:
            print("[-] No redirection payloads found in payloads/redirect.txt")
            return
            
        test_urls = [u for u in self.discovered_endpoints if any(k in u.lower() for k in ['url=', 'redirect=', 'next='])]
        
        for url in test_urls[:10]:  # Limit to 10 URLs for demo
            if '?' in url:
                base_url, params = url.split('?', 1)
                param_pairs = params.split('&')
                
                for param in param_pairs:
                    if '=' in param and any(k in param.lower() for k in ['url=', 'redirect=', 'next=']):
                        param_name, param_value = param.split('=', 1)
                        for payload in payloads:
                            test_url = f"{base_url}?{param_name}={payload}"
                            try:
                                response = self.session.get(test_url, allow_redirects=False, timeout=5)
                                if response.status_code in (301, 302, 303, 307, 308):
                                    location = response.headers.get('Location', '')
                                    if payload in location:
                                        self.add_vulnerability(
                                            "Open Redirection",
                                            test_url,
                                            f"Unvalidated redirect in parameter '{param_name}'"
                                        )
                                        break
                            except Exception as e:
                                print(f"[-] Error testing {test_url}: {str(e)}")
                            
                            time.sleep(0.3)

    def test_path_traversal(self):
        print("\n[*] Testing for Path Traversal vulnerabilities...")
        payloads = self.load_payloads('traversal')
        if not payloads:
            print("[-] No traversal payloads found in payloads/traversal.txt")
            return
            
        test_urls = [u for u in self.discovered_endpoints if any(k in u.lower() for k in ['file=', 'path=', 'page='])]
        
        for url in test_urls[:10]:  # Limit to 10 URLs for demo
            if '?' in url:
                base_url, params = url.split('?', 1)
                param_pairs = params.split('&')
                
                for param in param_pairs:
                    if '=' in param and any(k in param.lower() for k in ['file=', 'path=', 'page=']):
                        param_name, param_value = param.split('=', 1)
                        for payload in payloads:
                            test_url = f"{base_url}?{param_name}={payload}"
                            try:
                                response = self.session.get(test_url, timeout=5)
                                if "root:" in response.text or "[extensions]" in response.text:
                                    self.add_vulnerability(
                                        "Path Traversal",
                                        test_url,
                                        f"Directory traversal via parameter '{param_name}'"
                                    )
                                    break
                            except Exception as e:
                                print(f"[-] Error testing {test_url}: {str(e)}")
                            
                            time.sleep(0.3)

    def test_ssrf(self):
        print("\n[*] Testing for Server-Side Request Forgery (SSRF)...")
        payloads = self.load_payloads('ssrf')
        if not payloads:
            print("[-] No SSRF payloads found in payloads/ssrf.txt")
            return
            
        # Implementation would be similar to other tests
        print("[+] SSRF testing would be implemented here")

    def test_cors(self):
        print("\n[*] Testing for CORS Misconfigurations...")
        payloads = self.load_payloads('cors')
        if not payloads:
            print("[-] No CORS payloads found in payloads/cors.txt")
            return
            
        # Implementation would be similar to other tests
        print("[+] CORS testing would be implemented here")

    def test_jwt(self):
        print("\n[*] Testing for JWT Issues...")
        payloads = self.load_payloads('jwt')
        if not payloads:
            print("[-] No JWT payloads found in payloads/jwt.txt")
            return
            
        # Implementation would be similar to other tests
        print("[+] JWT testing would be implemented here")

    def add_vulnerability(self, vuln_type, url, details):
        self.vulnerabilities.append({
            'type': vuln_type,
            'url': url,
            'details': details,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })

    def show_results(self):
        if not self.vulnerabilities:
            print("\n[+] No vulnerabilities found!")
        else:
            print("\n[!] Found Vulnerabilities:")
            print("="*60)
            for i, vuln in enumerate(self.vulnerabilities, 1):
                print(f"{i}. {vuln['type']}")
                print(f"   URL: {vuln['url']}")
                print(f"   Details: {vuln['details']}")
                print(f"   Time: {vuln['timestamp']}")
                print("-"*60)
            
            print(f"\nTotal vulnerabilities found: {len(self.vulnerabilities)}")

    def run(self):
        self.print_banner()
        self.get_target_url()
        self.show_scan_options()
        choices = self.get_scan_choices()
        self.run_selected_scans(choices)

if __name__ == "__main__":
    try:
        scanner = WebXScanner()
        scanner.run()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(0)