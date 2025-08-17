# core/http_client.py - Production-Grade Enhanced HTTP Client with Complete Template Support
import requests
import time
import random
import logging
import json
import ssl
import socket
import numpy as np
from urllib.parse import urlparse, parse_qs, urlencode
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
from requests.auth import HTTPBasicAuth, HTTPDigestAuth
from typing import Dict, List, Optional, Any, Union, Tuple
from dataclasses import dataclass, field
import threading
from collections import defaultdict, deque
import hashlib
import base64
import xml.etree.ElementTree as ET
import asyncio

# Setup logging
logger = logging.getLogger(__name__)

@dataclass
class RequestMetrics:
    """Request performance and security metrics"""
    url: str
    method: str
    status_code: int
    response_time: float
    content_length: int
    server_header: str = ''
    waf_detected: bool = False
    ssl_info: Dict[str, Any] = field(default_factory=dict)
    redirect_chain: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)
    vulnerability_type: str = 'unknown'
    template_id: str = ''

@dataclass
class SecurityHeaders:
    """Security-focused header analysis"""
    csp: Optional[str] = None
    hsts: Optional[str] = None
    x_frame_options: Optional[str] = None
    x_content_type_options: Optional[str] = None
    x_xss_protection: Optional[str] = None
    referrer_policy: Optional[str] = None
    permissions_policy: Optional[str] = None
    security_score: float = 0.0
    expect_ct: Optional[str] = None
    feature_policy: Optional[str] = None
    x_permitted_cross_domain_policies: Optional[str] = None

class AdvancedRequestBuilder:
    """Build complex requests for advanced templates"""

    @staticmethod
    def build_multipart_request(data: Dict[str, Any], files: Dict[str, Any] = None) -> Tuple[str, str]:
        """Build multipart/form-data request"""
        import uuid
        boundary = f"----WebKitFormBoundary{uuid.uuid4().hex[:16]}"
        
        body_parts = []
        
        for key, value in data.items():
            part = f'--{boundary}\r\n'
            part += f'Content-Disposition: form-data; name="{key}"\r\n\r\n'
            part += f'{value}\r\n'
            body_parts.append(part)
        
        if files:
            for field_name, file_info in files.items():
                filename = file_info.get('filename', 'test.txt')
                content_type = file_info.get('content_type', 'text/plain')
                content = file_info.get('content', 'test content')
                
                part = f'--{boundary}\r\n'
                part += f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"\r\n'
                part += f'Content-Type: {content_type}\r\n\r\n'
                part += f'{content}\r\n'
                body_parts.append(part)
        
        body_parts.append(f'--{boundary}--\r\n')
        
        body = ''.join(body_parts)
        content_type = f'multipart/form-data; boundary={boundary}'
        
        return body, content_type

    @staticmethod
    def build_soap_request(action: str, body: str) -> Tuple[str, Dict[str, str]]:
        """Build SOAP XML request"""
        soap_body = f"""<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Header/>
    <soap:Body>
        {body}
    </soap:Body>
</soap:Envelope>"""
        
        headers = {
            'Content-Type': 'text/xml; charset=utf-8',
            'SOAPAction': f'"{action}"'
        }
        
        return soap_body, headers

    @staticmethod
    def build_graphql_request(query: str, variables: Dict = None, operation_name: str = None) -> str:
        """Build GraphQL request body"""
        request_body = {"query": query}
        
        if variables:
            request_body["variables"] = variables
        if operation_name:
            request_body["operationName"] = operation_name
        
        return json.dumps(request_body)

    @staticmethod
    def build_jwt_request(payload: Dict[str, Any], secret: str = "secret", algorithm: str = "HS256") -> str:
        """Build JWT token for testing"""
        import jwt
        try:
            if algorithm == "none":
                header = {"typ": "JWT", "alg": "none"}
                header_b64 = base64.b64encode(json.dumps(header).encode()).decode().rstrip('=')
                payload_b64 = base64.b64encode(json.dumps(payload).encode()).decode().rstrip('=')
                return f"{header_b64}.{payload_b64}."
            else:
                return jwt.encode(payload, secret, algorithm=algorithm)
        except ImportError:
            header = {"typ": "JWT", "alg": algorithm}
            header_b64 = base64.b64encode(json.dumps(header).encode()).decode().rstrip('=')
            payload_b64 = base64.b64encode(json.dumps(payload).encode()).decode().rstrip('=')
            return f"{header_b64}.{payload_b64}.signature"

class RateLimiter:
    """Intelligent rate limiting with adaptive delays"""

    def __init__(self, max_requests_per_second: float = 10.0):
        self.max_rps = max_requests_per_second
        self.min_delay = 1.0 / max_requests_per_second
        self.request_times = defaultdict(deque)
        self.adaptive_delays = defaultdict(lambda: self.min_delay)
        self.waf_detected_hosts = set()
        self.vulnerability_type_delays = defaultdict(lambda: self.min_delay)
        self.lock = threading.Lock()

    async def wait_if_needed(self, host: str, vulnerability_type: str = 'unknown'):
        """Apply intelligent rate limiting based on host behavior and vulnerability type"""
        with self.lock:
            current_time = time.time()
            host_times = self.request_times[host]
            
            while host_times and current_time - host_times[0] > 1.0:
                host_times.popleft()
            
            base_delay = self.adaptive_delays[host]
            vuln_multiplier = self._get_vulnerability_delay_multiplier(vulnerability_type)
            
            if len(host_times) >= self.max_rps:
                sleep_time = base_delay * vuln_multiplier
                
                if host in self.waf_detected_hosts:
                    sleep_time *= random.uniform(2.0, 4.0)
                
                logger.debug(f"Rate limiting: sleeping {sleep_time:.2f}s for {host} ({vulnerability_type})")
                time.sleep(sleep_time) # Note: time.sleep is blocking, consider asyncio.sleep if called from async context
            
            host_times.append(current_time)

    def _get_vulnerability_delay_multiplier(self, vulnerability_type: str) -> float:
        """Get delay multiplier based on vulnerability type sensitivity"""
        sensitive_types = {
            'sqli': 2.0,
            'command-injection': 2.5,
            'xxe': 1.8,
            'ssti': 1.5,
            'deserialization': 2.0,
            'ldap-injection': 1.3,
            'nosql': 1.2,
        }
        return sensitive_types.get(vulnerability_type, 1.0)

    def report_waf_detection(self, host: str, vulnerability_type: str = 'unknown'):
        """Report WAF detection to increase delays"""
        with self.lock:
            self.waf_detected_hosts.add(host)
            self.adaptive_delays[host] = max(self.adaptive_delays[host] * 2, 5.0)
            
            self.vulnerability_type_delays[vulnerability_type] *= 1.5
            
            logger.warning(f"WAF detected for {host} ({vulnerability_type}) - "
                           f"increasing delays to {self.adaptive_delays[host]:.2f}s")

    def report_success(self, host: str, vulnerability_type: str = 'unknown'):
        """Report successful request to potentially decrease delays"""
        with self.lock:
            if host in self.waf_detected_hosts:
                current_delay = self.adaptive_delays[host]
                self.adaptive_delays[host] = max(current_delay * 0.95, self.min_delay)

class UserAgentRotator:
    """Advanced User-Agent rotation for stealth"""

    def __init__(self):
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/120.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
            "curl/7.88.1",
            "PostmanRuntime/7.33.0",
            "python-requests/2.31.0",
            "Apache-HttpClient/4.5.14",
        ]
        self.current_index = 0
        
        self.vuln_user_agents = {
            'api': ['PostmanRuntime/7.33.0', 'curl/7.88.1', 'python-requests/2.31.0'],
            'graphql': ['Apollo/3.0', 'PostmanRuntime/7.33.0'],
            'jwt': ['python-requests/2.31.0', 'Apache-HttpClient/4.5.14'],
            'soap': ['Apache-HttpClient/4.5.14', 'Axis/1.4'],
        }

    def get_user_agent_for_vulnerability(self, vulnerability_type: str) -> str:
        """Get appropriate user agent for vulnerability type"""
        if vulnerability_type in self.vuln_user_agents:
            return random.choice(self.vuln_user_agents[vulnerability_type])
        return self.get_random_user_agent()

    def get_random_user_agent(self) -> str:
        """Get a random user agent"""
        return random.choice(self.user_agents)

    def get_next_user_agent(self) -> str:
        """Get next user agent in rotation"""
        user_agent = self.user_agents[self.current_index]
        self.current_index = (self.current_index + 1) % len(self.user_agents)
        return user_agent

class WAFDetector:
    """Advanced WAF detection and classification"""

    def __init__(self):
        self.waf_signatures = {
            'cloudflare': {
                'headers': ['cf-ray', 'cf-cache-status', 'cf-request-id'],
                'response_patterns': ['attention required!', 'cloudflare', 'please enable javascript', 'ddos protection by cloudflare', 'checking your browser'],
                'status_codes': [403, 429, 503]
            },
            'akamai': {
                'headers': ['akamai-ghost', 'akamai-edgescape'],
                'response_patterns': ['reference #', 'unauthorized', 'akamai', 'access denied', 'request blocked'],
                'status_codes': [403, 406]
            },
            'aws_waf': {
                'headers': ['x-amzn-requestid', 'x-amz-cf-id'],
                'response_patterns': ['the request could not be satisfied', 'bad request', 'cloudfront', 'generated by cloudfront'],
                'status_codes': [403, 400]
            },
            'incapsula': {
                'headers': ['x-iinfo', 'incap_ses', 'visid_incap'],
                'response_patterns': ['incapsula incident id', 'generated by incapsula', 'request unsucessful', 'security violation'],
                'status_codes': [403, 406]
            },
            'sucuri': {
                'headers': ['x-sucuri-id', 'x-sucuri-cache'],
                'response_patterns': ['access denied - sucuri', 'blocked by sucuri', 'sucuri cloudproxy', 'request blocked'],
                'status_codes': [403]
            },
            'f5_bigip': {
                'headers': ['x-f5-cache', 'f5-cache-status'],
                'response_patterns': ['f5 application security manager', 'bigip', 'the requested url was rejected', 'blocked by f5'],
                'status_codes': [403, 406]
            },
            'modsecurity': {
                'headers': ['x-mod-security', 'x-modsecurity'],
                'response_patterns': ['mod_security', 'modsecurity', 'not acceptable', 'security filter', 'request was blocked'],
                'status_codes': [403, 406, 501]
            },
            'barracuda': {
                'headers': ['x-barracuda'],
                'response_patterns': ['barracuda', 'barra'],
                'status_codes': [403, 406]
            },
            'fortinet': {
                'headers': ['x-fortinet'],
                'response_patterns': ['fortinet', 'fortigate', 'fortiweb'],
                'status_codes': [403]
            },
            'imperva': {
                'headers': ['x-iinfo'],
                'response_patterns': ['imperva', 'incapsula'],
                'status_codes': [403, 406]
            }
        }
        
        self.vuln_waf_patterns = {
            'sqli': ['sql', 'injection', 'union', 'select'],
            'xss': ['script', 'javascript', 'onerror', 'alert'],
            'xxe': ['xml', 'entity', 'doctype'],
            'ssti': ['template', 'jinja', 'twig'],
            'command-injection': ['command', 'exec', 'system'],
            'ldap-injection': ['ldap', 'directory'],
            'graphql': ['graphql', 'query', 'mutation'],
            'nosql': ['mongodb', 'nosql', 'where'],
        }

    def detect_waf(self, response_data: Dict[str, Any], vulnerability_type: str = 'unknown') -> Optional[Tuple[str, float]]:
        """Detect WAF type with confidence score and vulnerability-specific patterns"""
        headers = response_data.get('headers', {})
        body = response_data.get('body', '').lower()
        status = response_data.get('status', 200)
        
        detection_results = []
        
        for waf_type, signatures in self.waf_signatures.items():
            confidence = 0.0
            
            header_matches = 0
            for header_sig in signatures['headers']:
                if any(header_sig.lower() in str(header).lower() for header in headers.keys()):
                    header_matches += 1
            if header_matches > 0:
                confidence += 0.8 * (header_matches / len(signatures['headers']))
            
            pattern_matches = 0
            for pattern in signatures['response_patterns']:
                if pattern in body:
                    pattern_matches += 1
            if pattern_matches > 0:
                confidence += 0.6 * (pattern_matches / len(signatures['response_patterns']))
            
            if vulnerability_type in self.vuln_waf_patterns:
                vuln_patterns = self.vuln_waf_patterns[vulnerability_type]
                vuln_matches = sum(1 for pattern in vuln_patterns if pattern in body)
                if vuln_matches > 0:
                    confidence += 0.3 * (vuln_matches / len(vuln_patterns))
            
            if status in signatures['status_codes']:
                confidence += 0.3
            
            if confidence > 0.3:
                detection_results.append((waf_type, confidence))
        
        if detection_results:
            return max(detection_results, key=lambda x: x[1])
        
        return None

class SSLAnalyzer:
    """SSL/TLS security analysis"""

    @staticmethod
    def analyze_ssl_info(hostname: str, port: int = 443) -> Dict[str, Any]:
        """Analyze SSL/TLS configuration"""
        ssl_info = {
            'certificate_valid': False,
            'protocol_version': None,
            'cipher_suite': None,
            'certificate_chain_length': 0,
            'has_sni': False,
            'vulnerabilities': [],
            'certificate_info': {}
        }
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    ssl_info['certificate_valid'] = True
                    ssl_info['protocol_version'] = ssock.version()
                    ssl_info['cipher_suite'] = ssock.cipher()[0] if ssock.cipher() else None
                    ssl_info['has_sni'] = True
                    
                    cert = ssock.getpeercert()
                    if cert:
                        ssl_info['certificate_info'] = {
                            'subject': dict(x[0] for x in cert.get('subject', [])),
                            'issuer': dict(x[0] for x in cert.get('issuer', [])),
                            'not_after': cert.get('notAfter'),
                            'not_before': cert.get('notBefore'),
                            'serial_number': cert.get('serialNumber'),
                        }
                    
                    cert_chain = ssock.getpeercert_chain()
                    if cert_chain:
                        ssl_info['certificate_chain_length'] = len(cert_chain)
                    
                    if ssl_info['protocol_version'] in ['TLSv1', 'TLSv1.1']:
                        ssl_info['vulnerabilities'].append('Deprecated TLS version')
                    
                    if ssl_info['cipher_suite']:
                        cipher = ssl_info['cipher_suite']
                        if 'RC4' in cipher:
                            ssl_info['vulnerabilities'].append('Weak cipher suite (RC4)')
                        if 'MD5' in cipher:
                            ssl_info['vulnerabilities'].append('Weak hash algorithm (MD5)')
                        if 'DES' in cipher or '3DES' in cipher:
                            ssl_info['vulnerabilities'].append('Weak encryption (DES/3DES)')
        
        except Exception as e:
            logger.debug(f"SSL analysis failed for {hostname}:{port}: {e}")
            ssl_info['error'] = str(e)
        
        return ssl_info

class EnhancedHTTPClient:
    """Production-grade HTTP client with elite security features"""

    def __init__(self, max_requests_per_second: float = 10.0, enable_stealth: bool = True):
        self.rate_limiter = RateLimiter(max_requests_per_second)
        self.user_agent_rotator = UserAgentRotator()
        self.waf_detector = WAFDetector()
        self.ssl_analyzer = SSLAnalyzer()
        self.request_builder = AdvancedRequestBuilder()
        
        self.enable_stealth = enable_stealth
        self.enable_ssl_analysis = True
        self.max_redirects = 10
        self.default_timeout = 30
        self.max_retries = 3
        
        self.request_count = 0
        self.error_count = 0
        self.waf_detections = defaultdict(int)
        self.request_metrics = []
        self.vulnerability_type_stats = defaultdict(int)
        
        self.session_config = {
            'max_retries': Retry(
                total=3,
                backoff_factor=1,
                status_forcelist=[429, 500, 502, 503, 504],
                respect_retry_after_header=True
            ),
            'pool_connections': 100,
            'pool_maxsize': 100
        }

    def _create_enhanced_session(self, base_session: requests.Session = None) -> requests.Session:
        """Create or enhance a requests session with advanced configuration"""
        session = base_session or requests.Session()
        session.trust_env = False
        
        retry_strategy = self.session_config['max_retries']
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=self.session_config['pool_connections'],
            pool_maxsize=self.session_config['pool_maxsize']
        )
        
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        if self.enable_stealth:
            session.headers.update({
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate, br',
                'DNT': '1',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            })
        
        return session

    def _analyze_security_headers(self, headers: Dict[str, str]) -> SecurityHeaders:
        """Analyze response headers for security configurations"""
        security_headers = SecurityHeaders()
        
        for header_name, header_value in headers.items():
            header_lower = header_name.lower()
            
            if header_lower == 'content-security-policy':
                security_headers.csp = header_value
            elif header_lower == 'strict-transport-security':
                security_headers.hsts = header_value
            elif header_lower == 'x-frame-options':
                security_headers.x_frame_options = header_value
            elif header_lower == 'x-content-type-options':
                security_headers.x_content_type_options = header_value
            elif header_lower == 'x-xss-protection':
                security_headers.x_xss_protection = header_value
            elif header_lower == 'referrer-policy':
                security_headers.referrer_policy = header_value
            elif header_lower == 'permissions-policy':
                security_headers.permissions_policy = header_value
            elif header_lower == 'expect-ct':
                security_headers.expect_ct = header_value
            elif header_lower == 'feature-policy':
                security_headers.feature_policy = header_value
            elif header_lower == 'x-permitted-cross-domain-policies':
                security_headers.x_permitted_cross_domain_policies = header_value
        
        score = 0.0
        if security_headers.csp: score += 2.0
        if security_headers.hsts: score += 2.0
        if security_headers.x_frame_options: score += 1.0
        if security_headers.x_content_type_options: score += 1.0
        if security_headers.x_xss_protection: score += 0.5
        if security_headers.referrer_policy: score += 0.5
        if security_headers.permissions_policy: score += 1.0
        if security_headers.expect_ct: score += 0.5
        
        security_headers.security_score = min(score, 8.5)
        return security_headers

    def _generate_stealth_headers(self, url: str, method: str, vulnerability_type: str = 'unknown',
                                  custom_headers: Dict[str, str] = None) -> Dict[str, str]:
        """Generate stealth-focused headers with vulnerability-type awareness"""
        headers = {}
        
        if self.enable_stealth:
            headers['User-Agent'] = self.user_agent_rotator.get_user_agent_for_vulnerability(vulnerability_type)
            
            if vulnerability_type == 'graphql':
                headers['Accept'] = 'application/json'
                headers['Content-Type'] = 'application/json'
            elif vulnerability_type in ['soap', 'xxe', 'xml-injection']:
                headers['Accept'] = 'text/xml, application/xml'
                headers['Content-Type'] = 'text/xml; charset=utf-8'
            elif vulnerability_type in ['jwt', 'api']:
                headers['Accept'] = 'application/json'
                headers['Authorization'] = 'Bearer placeholder'
            elif method.upper() == 'POST' and vulnerability_type not in ['graphql', 'soap', 'xxe', 'file-upload']:
                headers['Content-Type'] = 'application/x-www-form-urlencoded'
            
            if random.random() < 0.3:
                parsed_url = urlparse(url)
                headers['Referer'] = f"{parsed_url.scheme}://{parsed_url.netloc}/"
            
            if random.random() < 0.2:
                headers['Cache-Control'] = random.choice(['no-cache', 'max-age=0', 'no-store'])
            
            if vulnerability_type == 'cors' and random.random() < 0.5:
                headers['Origin'] = 'https://evil.com'
        
        if custom_headers:
            headers.update(custom_headers)
        
        return headers

    def _prepare_request_data(self, method: str, data: Any, vulnerability_type: str = 'unknown') -> Tuple[Any, Dict[str, str]]:
        """Prepare request data based on vulnerability type"""
        additional_headers = {}
        
        if data is None:
            return data, additional_headers
        
        if vulnerability_type == 'graphql' and isinstance(data, dict):
            if 'query' in data:
                data = self.request_builder.build_graphql_request(
                    data['query'], data.get('variables'), data.get('operationName')
                )
                additional_headers['Content-Type'] = 'application/json'
        
        elif vulnerability_type in ['soap', 'xxe', 'xml-injection'] and isinstance(data, str):
            if '<soap:' in data or 'soap:Envelope' in data:
                additional_headers['Content-Type'] = 'text/xml; charset=utf-8'
                additional_headers['SOAPAction'] = '""'
            else:
                additional_headers['Content-Type'] = 'application/xml'
        
        elif vulnerability_type == 'file-upload' and isinstance(data, dict):
            if 'files' in data or any(isinstance(v, dict) and 'filename' in v for v in data.values()):
                files = {k: v for k, v in data.items() if isinstance(v, dict) and 'filename' in v}
                form_data = {k: v for k, v in data.items() if k not in files}
                
                body, content_type = self.request_builder.build_multipart_request(form_data, files)
                data = body
                additional_headers['Content-Type'] = content_type
        
        elif vulnerability_type == 'jwt' and isinstance(data, dict):
            if 'jwt_payload' in data:
                token = self.request_builder.build_jwt_request(
                    data['jwt_payload'], data.get('secret', 'secret'), data.get('algorithm', 'HS256')
                )
                additional_headers['Authorization'] = f'Bearer {token}'
                data = None
        
        return data, additional_headers

    async def send_request(self, session: requests.Session, method: str, url: str,
                           headers: Dict[str, str] = None, data: Any = None,
                           proxy: str = None, follow_redirects: bool = True,
                           timeout: int = None, auth: Tuple[str, str] = None,
                           cookies: Dict[str, str] = None, vulnerability_type: str = 'unknown',
                           template_id: str = '') -> Optional[Dict[str, Any]]:
        """Enhanced request sending with complete template support"""
        
        start_time = time.time()
        hostname = urlparse(url).netloc
        timeout = timeout or self.default_timeout
        
        await self.rate_limiter.wait_if_needed(hostname, vulnerability_type)
        
        if not hasattr(session, '_enhanced'):
            session = self._create_enhanced_session(session)
            session._enhanced = True
        
        processed_data, data_headers = self._prepare_request_data(method, data, vulnerability_type)
        
        request_headers = self._generate_stealth_headers(url, method, vulnerability_type, headers)
        request_headers.update(data_headers)
        
        proxies = {"http": proxy, "https": proxy} if proxy else None
        
        if auth:
            session.auth = HTTPBasicAuth(auth[0], auth[1])
        
        if cookies:
            session.cookies.update(cookies)
        
        loop = asyncio.get_running_loop()
        
        try:
            self.request_count += 1
            self.vulnerability_type_stats[vulnerability_type] += 1
            
            # The actual request is a blocking I/O call, so we run it in an executor
            response = await loop.run_in_executor(
                None,
                lambda: session.request(
                    method=method,
                    url=url,
                    headers=request_headers,
                    data=processed_data,
                    proxies=proxies,
                    verify=False,
                    timeout=timeout,
                    allow_redirects=follow_redirects,
                    stream=False
                )
            )
            
            response_time = time.time() - start_time
            
            redirect_chain = [r.url for r in response.history] if response.history else []
            
            response_data = {
                'status': response.status_code,
                'headers': dict(response.headers),
                'body': response.text,
                'url': response.url,
                'response_time': response_time,
                'redirect_chain': redirect_chain,
                'cookies': dict(response.cookies),
                'vulnerability_type': vulnerability_type,
                'template_id': template_id
            }
            
            waf_detection = self.waf_detector.detect_waf(response_data, vulnerability_type)
            if waf_detection:
                waf_type, confidence = waf_detection
                response_data['waf_detected'] = {'type': waf_type, 'confidence': confidence}
                self.waf_detections[waf_type] += 1
                self.rate_limiter.report_waf_detection(hostname, vulnerability_type)
                logger.warning(f"WAF detected: {waf_type} (confidence: {confidence:.2f}, vuln: {vulnerability_type})")
            else:
                response_data['waf_detected'] = None
                self.rate_limiter.report_success(hostname, vulnerability_type)
            
            security_headers = self._analyze_security_headers(response.headers)
            response_data['security_headers'] = {
                'csp': security_headers.csp,
                'hsts': security_headers.hsts,
                'x_frame_options': security_headers.x_frame_options,
                'x_content_type_options': security_headers.x_content_type_options,
                'security_score': security_headers.security_score,
                'expect_ct': security_headers.expect_ct
            }
            
            if url.startswith('https://') and self.enable_ssl_analysis:
                try:
                    parsed_url = urlparse(url)
                    ssl_info = self.ssl_analyzer.analyze_ssl_info(parsed_url.hostname)
                    response_data['ssl_info'] = ssl_info
                except Exception as e:
                    logger.debug(f"SSL analysis failed: {e}")
                    response_data['ssl_info'] = {'error': str(e)}
            
            metrics = RequestMetrics(
                url=url, method=method, status_code=response.status_code,
                response_time=response_time, content_length=len(response.content),
                server_header=response.headers.get('Server', ''), waf_detected=bool(waf_detection),
                redirect_chain=redirect_chain, vulnerability_type=vulnerability_type,
                template_id=template_id
            )
            self.request_metrics.append(metrics)
            
            if len(self.request_metrics) > 1000:
                self.request_metrics = self.request_metrics[-1000:]
            
            return response_data
            
        except requests.exceptions.RequestException as e:
            self.error_count += 1
            logger.error(f"Non-retryable network error for {url} ({vulnerability_type}): {e}")
            return None
        
        except Exception as e:
            self.error_count += 1
            logger.error(f"Unexpected error for {url} ({vulnerability_type}): {e}")
            return None

    def get_statistics(self) -> Dict[str, Any]:
        """Get enhanced client performance and security statistics"""
        if not self.request_metrics:
            return {'message': 'No requests made yet'}
        
        response_times = [m.response_time for m in self.request_metrics]
        status_codes = [m.status_code for m in self.request_metrics]
        waf_detections = sum(1 for m in self.request_metrics if m.waf_detected)
        
        vuln_type_distribution = dict(self.vulnerability_type_stats)
        
        waf_by_vuln = defaultdict(int)
        for metric in self.request_metrics:
            if metric.waf_detected:
                waf_by_vuln[metric.vulnerability_type] += 1
        
        return {
            'total_requests': self.request_count,
            'total_errors': self.error_count,
            'success_rate': (self.request_count - self.error_count) / max(self.request_count, 1) * 100,
            'average_response_time': sum(response_times) / len(response_times) if response_times else 0,
            'min_response_time': min(response_times) if response_times else 0,
            'max_response_time': max(response_times) if response_times else 0,
            'status_code_distribution': {str(k): int(v) for k, v in zip(*np.unique(status_codes, return_counts=True))} if status_codes else {},
            'waf_detections': dict(self.waf_detections),
            'waf_detection_rate': (waf_detections / len(self.request_metrics) * 100) if self.request_metrics else 0,
            'vulnerability_type_distribution': vuln_type_distribution,
            'waf_detections_by_vulnerability': dict(waf_by_vuln)
        }

# Global enhanced HTTP client instance
enhanced_http_client = EnhancedHTTPClient(max_requests_per_second=10.0, enable_stealth=True)

# This is the single, authoritative function for sending requests.
async def send_request(session: requests.Session, method: str, url: str,
                       headers: Dict[str, str] = None, data: Any = None,
                       proxy: str = None, follow_redirects: bool = True,
                       timeout: int = None, auth: Tuple[str, str] = None,
                       vulnerability_type: str = 'unknown', template_id: str = '') -> Optional[Dict[str, Any]]:
    """Primary async function to send HTTP requests via the enhanced client."""
    
    global enhanced_http_client
    
    return await enhanced_http_client.send_request(
        session=session, method=method, url=url, headers=headers, data=data,
        proxy=proxy, follow_redirects=follow_redirects, timeout=timeout, auth=auth,
        vulnerability_type=vulnerability_type, template_id=template_id
    )

def get_client_statistics() -> Dict[str, Any]:
    """Get enhanced HTTP client statistics"""
    global enhanced_http_client
    return enhanced_http_client.get_statistics()

def reset_client_statistics():
    """Reset client statistics"""
    global enhanced_http_client
    enhanced_http_client.request_count = 0
    enhanced_http_client.error_count = 0
    enhanced_http_client.waf_detections.clear()
    enhanced_http_client.request_metrics.clear()
    enhanced_http_client.vulnerability_type_stats.clear()