# core/oast_client.py - Production-Grade Advanced OAST Client with AI Integration
import requests
import base64
import logging
import time
import random
import json
import threading
import hashlib
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from collections import defaultdict, deque
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ed25519
from urllib.parse import urlparse, parse_qs

# Setup logging
logger = logging.getLogger(__name__)

# Enhanced OAST server list with priority and capabilities
OAST_SERVERS = [
    {
        "url": "https://oast.pro",
        "priority": 1,
        "capabilities": ["http", "dns", "smtp", "ldap"],
        "rate_limit": 100,
        "free": True
    },
    {
        "url": "https://oast.interact.sh",
        "priority": 2,
        "capabilities": ["http", "dns", "smtp"],
        "rate_limit": 50,
        "free": True
    },
    {
        "url": "https://oast.burpcollaborator.net",
        "priority": 3,
        "capabilities": ["http", "dns", "smtp", "ftp"],
        "rate_limit": 200,
        "free": False
    },
    # Custom OAST servers can be added here
]

@dataclass
class OASTInteraction:
    """Structured OAST interaction data"""
    interaction_id: str
    domain: str
    protocol: str
    remote_ip: str
    timestamp: float
    content: str = ""
    raw_content: bytes = b""
    request_headers: Dict[str, str] = field(default_factory=dict)
    vulnerability_type: str = "unknown"
    template_id: str = ""
    confidence_score: float = 0.5

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for reporting"""
        return {
            "interaction_id": self.interaction_id,
            "domain": self.domain,
            "protocol": self.protocol,
            "remote_ip": self.remote_ip,
            "timestamp": self.timestamp,
            "datetime": datetime.fromtimestamp(self.timestamp).isoformat(),
            "content": self.content,
            "vulnerability_type": self.vulnerability_type,
            "template_id": self.template_id,
            "confidence_score": self.confidence_score
        }

@dataclass
class OASTStats:
    """Comprehensive OAST statistics"""
    registration_attempts: int = 0
    successful_registrations: int = 0
    failed_registrations: int = 0
    total_domains_generated: int = 0
    poll_counts: int = 0
    interactions_received: int = 0
    interactions_by_protocol: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    interactions_by_vulnerability: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    server_latencies: Dict[str, List[float]] = field(default_factory=lambda: defaultdict(list))
    server_success_rates: Dict[str, float] = field(default_factory=lambda: defaultdict(float))
    false_positive_rate: float = 0.0
    unique_ips_detected: set = field(default_factory=set)

class AdvancedPatternAnalyzer:
    """AI-enhanced pattern analysis for OAST interactions"""

    def __init__(self):
        self.vulnerability_patterns = {
            'ssrf': {
                'user_agents': ['java', 'python', 'curl', 'wget', 'httpclient'],
                'headers': ['x-forwarded-for', 'x-real-ip', 'forwarded'],
                'content_patterns': ['127.0.0.1', 'localhost', 'metadata', 'internal']
            },
            'xxe': {
                'content_patterns': ['xml', 'doctype', 'entity', 'external'],
                'protocols': ['http', 'file', 'ftp'],
                'headers': ['content-type: application/xml', 'content-type: text/xml']
            },
            'ssti': {
                'content_patterns': ['template', 'render', 'jinja', 'twig', 'expression'],
                'user_agents': ['python', 'java'],
                'protocols': ['http']
            },
            'deserialization': {
                'content_patterns': ['java.', 'pickle', 'serialize', 'objectinputstream'],
                'user_agents': ['java', 'python'],
                'protocols': ['http', 'ldap']
            },
            'ldap_injection': {
                'protocols': ['ldap', 'ldaps'],
                'content_patterns': ['ldap://', 'cn=', 'ou=', 'dc='],
                'user_agents': ['java', 'python']
            },
            'command_injection': {
                'content_patterns': ['wget', 'curl', 'nslookup', 'ping', 'dig'],
                'user_agents': ['curl', 'wget', 'python', 'bash'],
                'protocols': ['http', 'dns']
            }
        }

    def analyze_interaction(self, interaction: OASTInteraction) -> Tuple[str, float]:
        """Analyze interaction and classify vulnerability type with confidence"""
        best_match = "unknown"
        highest_confidence = 0.0

        for vuln_type, patterns in self.vulnerability_patterns.items():
            confidence = 0.0

            # Protocol matching
            if interaction.protocol.lower() in patterns.get('protocols', []):
                confidence += 0.4

            # User-Agent analysis
            if interaction.request_headers:
                user_agent = interaction.request_headers.get('user-agent', '').lower()
                for ua_pattern in patterns.get('user_agents', []):
                    if ua_pattern in user_agent:
                        confidence += 0.3
                        break

            # Content pattern matching
            content_lower = interaction.content.lower()
            content_matches = 0
            for pattern in patterns.get('content_patterns', []):
                if pattern in content_lower:
                    content_matches += 1

            if content_matches > 0:
                confidence += 0.5 * (content_matches / len(patterns.get('content_patterns', [1])))

            # Header analysis
            if interaction.request_headers:
                for header_pattern in patterns.get('headers', []):
                    for header_name, header_value in interaction.request_headers.items():
                        if header_pattern in f"{header_name}: {header_value}".lower():
                            confidence += 0.2
                            break

            if confidence > highest_confidence:
                highest_confidence = confidence
                best_match = vuln_type

        return best_match, min(highest_confidence, 1.0)

class MultiDomainManager:
    """Manage multiple OAST domains for concurrent testing"""

    def __init__(self):
        self.domains = {}  # domain -> {client, vulnerability_type, template_id, created_at}
        self.domain_lock = threading.Lock()

    def register_domain(self, vulnerability_type: str, template_id: str, client) -> Optional[str]:
        """Register a new domain for specific vulnerability type"""
        domain = client.register()
        if domain:
            with self.domain_lock:
                self.domains[domain] = {
                    'client': client,
                    'vulnerability_type': vulnerability_type,
                    'template_id': template_id,
                    'created_at': time.time()
                }
            logger.info(f"Registered OAST domain {domain} for {vulnerability_type}")
        return domain

    def get_domain_info(self, domain: str) -> Optional[Dict[str, Any]]:
        """Get information about a registered domain"""
        with self.domain_lock:
            return self.domains.get(domain)

    def cleanup_expired_domains(self, max_age_hours: int = 24):
        """Clean up expired domains"""
        current_time = time.time()
        expired_domains = []

        with self.domain_lock:
            for domain, info in self.domains.items():
                if current_time - info['created_at'] > (max_age_hours * 3600):
                    expired_domains.append(domain)

        for domain in expired_domains:
            self.cleanup_domain(domain)

    def cleanup_domain(self, domain: str):
        """Clean up a specific domain"""
        with self.domain_lock:
            if domain in self.domains:
                try:
                    self.domains[domain]['client'].close()
                except Exception as e:
                    logger.debug(f"Error closing domain {domain}: {e}")
                del self.domains[domain]
                logger.info(f"Cleaned up OAST domain {domain}")

class EnhancedOASTClient:
    """Production-grade OAST client with advanced capabilities"""

    def __init__(self, server_index: int = 0, custom_server: str = None,
                 vulnerability_type: str = "unknown", template_id: str = "", proxy: str = None):
        self.available_servers = [{"url": custom_server, "priority": 0}] if custom_server else OAST_SERVERS
        self.current_server_index = server_index % len(self.available_servers)
        self.current_server = self.available_servers[self.current_server_index]

        # Request session with enhanced configuration
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'WebX-Elite-OAST/10.0',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        })
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

        # Cryptographic keys
        self.secret_key = None
        self.public_key = None
        self.correlation_id = None
        self.unique_domain = None

        # Context information
        self.vulnerability_type = vulnerability_type
        self.template_id = template_id

        # Enhanced statistics
        self.stats = OASTStats()

        # Advanced features
        self.pattern_analyzer = AdvancedPatternAnalyzer()
        self.interaction_history = deque(maxlen=1000)  # Keep last 1000 interactions
        self.domain_cache = {}  # Cache domains for reuse

        # Configuration
        self.poll_interval = random.uniform(5, 10)  # Randomized polling
        self.max_poll_attempts = 3
        self.connection_timeout = 15
        self.read_timeout = 30

        # Rate limiting
        self.last_poll_time = 0
        self.min_poll_interval = 2.0

        logger.info(f"Enhanced OAST client initialized for {vulnerability_type} ({template_id})")

    def _generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate Ed25519 keypair for secure communication"""
        try:
            private_key = ed25519.Ed25519PrivateKey.generate()
            public_key = private_key.public_key()

            private_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )

            public_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )

            return private_bytes, public_bytes

        except Exception as e:
            logger.error(f"Keypair generation failed: {e}")
            raise

    def _rotate_server(self):
        """Intelligently rotate to next available server"""
        original_index = self.current_server_index

        # Try servers in order of priority
        available_servers = sorted(self.available_servers, key=lambda x: x.get('priority', 99))

        for server in available_servers:
            server_index = self.available_servers.index(server)
            if server_index != self.current_server_index:
                self.current_server_index = server_index
                self.current_server = server
                logger.info(f"Rotated OAST server to: {server['url']}")
                return True

        # No rotation possible
        logger.warning("No alternative OAST servers available for rotation")
        return False

    def _calculate_server_score(self, server_url: str) -> float:
        """Calculate server reliability score"""
        latencies = self.stats.server_latencies[server_url]
        success_rate = self.stats.server_success_rates.get(server_url, 0.0)

        if not latencies:
            return 0.5  # Unknown server

        avg_latency = sum(latencies) / len(latencies)
        latency_score = max(0, 1.0 - (avg_latency / 10.0))  # Penalize high latency

        return (success_rate * 0.7) + (latency_score * 0.3)

    def register(self) -> Optional[str]:
        """Enhanced registration with server failover and performance tracking"""
        for attempt in range(len(self.available_servers)):
            server = self.current_server
            server_url = server['url']

            self.stats.registration_attempts += 1

            try:
                # Generate fresh keypair
                self.secret_key, public_key_bytes = self._generate_keypair()
                self.public_key = public_key_bytes

                # Prepare registration request
                public_key_b64 = base64.b64encode(public_key_bytes).decode()
                register_data = {
                    "public-key": public_key_b64,
                    "client-info": {
                        "scanner": "WebX-Elite",
                        "version": "10.0",
                        "vulnerability-type": self.vulnerability_type,
                        "template-id": self.template_id
                    }
                }

                # Make registration request with timing
                start_time = time.time()
                response = self.session.post(
                    f"{server_url}/register",
                    json=register_data,
                    timeout=(self.connection_timeout, self.read_timeout),
                    verify=True
                )

                latency = time.time() - start_time
                self.stats.server_latencies[server_url].append(latency)

                if response.status_code == 200:
                    # Parse response
                    if response.headers.get('content-type', '').startswith('application/json'):
                        result = response.json()
                        self.unique_domain = result.get('domain', response.text.strip('"'))
                    else:
                        self.unique_domain = response.text.strip('"')

                    if self.unique_domain:
                        self.correlation_id = self.unique_domain.split('.')[0]

                        # Update statistics
                        self.stats.successful_registrations += 1
                        self.stats.total_domains_generated += 1

                        current_success = self.stats.server_success_rates.get(server_url, 0.0)
                        total_attempts = len(self.stats.server_latencies[server_url])
                        self.stats.server_success_rates[server_url] = (
                            (current_success * (total_attempts - 1) + 1.0) / total_attempts
                        )

                        logger.info(f"OAST registration successful: {self.unique_domain} "
                                    f"(latency: {latency:.2f}s, server: {server_url})")

                        return self.unique_domain

                else:
                    logger.warning(f"OAST registration failed: {response.status_code} from {server_url}")
                    self.stats.failed_registrations += 1

            except Exception as e:
                logger.error(f"OAST registration error with {server_url}: {e}")
                self.stats.failed_registrations += 1

            # Try next server
            if not self._rotate_server():
                break

        logger.error("OAST registration failed on all available servers")
        return None

    def poll(self, decode_content: bool = True, enhanced_analysis: bool = True) -> List[OASTInteraction]:
        """Enhanced polling with advanced analysis and classification"""
        if not self.secret_key or not self.correlation_id:
            logger.warning("OAST polling attempted without valid registration")
            return []

        # Rate limiting
        current_time = time.time()
        if current_time - self.last_poll_time < self.min_poll_interval:
            time.sleep(self.min_poll_interval - (current_time - self.last_poll_time))

        interactions = []
        server_url = self.current_server['url']

        # Prepare poll request
        poll_params = {
            'id': self.correlation_id,
            'secret': self.secret_key.hex(),
            'format': 'detailed'  # Request detailed interaction data
        }

        for attempt in range(self.max_poll_attempts):
            try:
                self.stats.poll_counts += 1

                start_time = time.time()
                response = self.session.get(
                    f"{server_url}/poll",
                    params=poll_params,
                    timeout=(self.connection_timeout, self.read_timeout)
                )

                latency = time.time() - start_time
                self.stats.server_latencies[server_url].append(latency)

                if response.status_code == 200:
                    result = response.json() if response.text else {"data": []}
                    raw_interactions = result.get("data", [])

                    for raw_interaction in raw_interactions:
                        interaction = self._parse_interaction(raw_interaction, decode_content, enhanced_analysis)
                        if interaction:
                            interactions.append(interaction)
                            self.interaction_history.append(interaction)

                            # Update statistics
                            self.stats.interactions_received += 1
                            self.stats.interactions_by_protocol[interaction.protocol] += 1
                            self.stats.interactions_by_vulnerability[interaction.vulnerability_type] += 1
                            self.stats.unique_ips_detected.add(interaction.remote_ip)

                    if interactions:
                        logger.info(f"OAST poll retrieved {len(interactions)} interactions")

                    self.last_poll_time = time.time()
                    return interactions

                else:
                    logger.warning(f"OAST poll failed: {response.status_code}")

            except Exception as e:
                logger.error(f"OAST polling error (attempt {attempt + 1}): {e}")
                if attempt < self.max_poll_attempts - 1:
                    time.sleep(self.poll_interval * (attempt + 1))

        return []

    def _parse_interaction(self, raw_data: Dict[str, Any], decode_content: bool,
                           enhanced_analysis: bool) -> Optional[OASTInteraction]:
        """Parse raw interaction data into structured format"""
        try:
            # Extract basic information
            interaction_id = raw_data.get('interaction-id', str(uuid.uuid4()))
            protocol = raw_data.get('protocol', 'http').lower()
            remote_ip = raw_data.get('remote-address', 'unknown')
            timestamp = raw_data.get('timestamp', time.time())

            # Process content
            content = ""
            raw_content = b""

            if 'content' in raw_data and decode_content:
                try:
                    if raw_data.get('content-encoding') == 'base64':
                        raw_content = base64.b64decode(raw_data['content'])
                        content = raw_content.decode('utf-8', errors='replace')
                    else:
                        content = str(raw_data['content'])
                        raw_content = content.encode('utf-8', errors='replace')
                except Exception as e:
                    logger.debug(f"Content decoding error: {e}")
                    content = str(raw_data.get('content', ''))

            # Parse request headers
            request_headers = {}
            if 'request' in raw_data and isinstance(raw_data['request'], dict):
                request_headers = raw_data['request'].get('headers', {})
            elif 'headers' in raw_data:
                request_headers = raw_data['headers']

            # Create interaction object
            interaction = OASTInteraction(
                interaction_id=interaction_id,
                domain=self.unique_domain or 'unknown',
                protocol=protocol,
                remote_ip=remote_ip,
                timestamp=timestamp,
                content=content,
                raw_content=raw_content,
                request_headers=request_headers,
                vulnerability_type=self.vulnerability_type,
                template_id=self.template_id
            )

            # Enhanced analysis
            if enhanced_analysis:
                detected_vuln, confidence = self.pattern_analyzer.analyze_interaction(interaction)
                if confidence > interaction.confidence_score:
                    interaction.vulnerability_type = detected_vuln
                    interaction.confidence_score = confidence

            return interaction

        except Exception as e:
            logger.error(f"Interaction parsing error: {e}")
            return None

    def generate_domain_for_payload(self, payload: str) -> Optional[str]:
        """Generate a payload-specific domain for tracking"""
        if not self.unique_domain:
            return None

        # Create unique subdomain based on payload hash
        payload_hash = hashlib.md5(payload.encode()).hexdigest()[:8]
        return f"{payload_hash}.{self.unique_domain}"

    def analyze_response_for_oast_evidence(self, response: Dict[str, Any],
                                           expected_domain: str = None) -> List[Dict[str, Any]]:
        """Advanced analysis of HTTP responses for OAST evidence"""
        evidence = []
        domain_to_check = expected_domain or self.unique_domain

        if not domain_to_check:
            return evidence

        # Check response body
        body = response.get('body', '')
        if domain_to_check in body:
            evidence.append({
                'type': 'domain_leak',
                'location': 'response_body',
                'evidence': domain_to_check,
                'confidence': 0.9,
                'context': body[max(0, body.find(domain_to_check) - 50):body.find(domain_to_check) + 100]
            })

        # Check response headers
        for header_name, header_value in response.get('headers', {}).items():
            if domain_to_check in str(header_value):
                evidence.append({
                    'type': 'domain_leak',
                    'location': f'response_header:{header_name}',
                    'evidence': domain_to_check,
                    'confidence': 0.8,
                    'context': f"{header_name}: {header_value}"
                })

        # Check for DNS resolution attempts in timing
        response_time = response.get('response_time', 0)
        if response_time > 5.0:  # Potentially DNS timeout
            evidence.append({
                'type': 'timing_anomaly',
                'location': 'response_time',
                'evidence': f'{response_time}s delay',
                'confidence': 0.3,
                'context': 'Potential DNS resolution delay'
            })

        # Advanced pattern detection
        self._detect_advanced_oast_patterns(response, evidence)

        return evidence

    def _detect_advanced_oast_patterns(self, response: Dict[str, Any], evidence: List[Dict[str, Any]]):
        """Detect advanced OAST patterns in responses"""
        body = response.get('body', '').lower()

        # Error messages that might indicate OAST activity
        error_patterns = [
            'connection refused',
            'name resolution',
            'dns lookup',
            'network unreachable',
            'timeout',
            'connection timeout'
        ]

        for pattern in error_patterns:
            if pattern in body:
                evidence.append({
                    'type': 'error_pattern',
                    'location': 'response_body',
                    'evidence': pattern,
                    'confidence': 0.4,
                    'context': f'Error pattern suggesting network activity: {pattern}'
                })

    def get_comprehensive_stats(self) -> Dict[str, Any]:
        """Get comprehensive statistics including analysis results"""
        stats_dict = {
            'registration_stats': {
                'attempts': self.stats.registration_attempts,
                'successful': self.stats.successful_registrations,
                'failed': self.stats.failed_registrations,
                'success_rate': (self.stats.successful_registrations / max(self.stats.registration_attempts, 1)) * 100
            },
            'polling_stats': {
                'total_polls': self.stats.poll_counts,
                'interactions_received': self.stats.interactions_received,
                'interactions_per_poll': self.stats.interactions_received / max(self.stats.poll_counts, 1)
            },
            'interaction_analysis': {
                'by_protocol': dict(self.stats.interactions_by_protocol),
                'by_vulnerability': dict(self.stats.interactions_by_vulnerability),
                'unique_source_ips': len(self.stats.unique_ips_detected),
                'false_positive_rate': self.stats.false_positive_rate
            },
            'server_performance': {},
            'context': {
                'vulnerability_type': self.vulnerability_type,
                'template_id': self.template_id,
                'current_domain': self.unique_domain
            }
        }

        # Server performance analysis
        for server_url, latencies in self.stats.server_latencies.items():
            if latencies:
                stats_dict['server_performance'][server_url] = {
                    'average_latency': sum(latencies) / len(latencies),
                    'min_latency': min(latencies),
                    'max_latency': max(latencies),
                    'success_rate': self.stats.server_success_rates.get(server_url, 0.0) * 100,
                    'reliability_score': self._calculate_server_score(server_url)
                }

        return stats_dict

    def close(self):
        """Enhanced cleanup with comprehensive deregistration"""
        if self.secret_key and self.correlation_id:
            server_url = self.current_server['url']

            try:
                deregister_data = {
                    "secret-key": self.secret_key.hex(),
                    "correlation-id": self.correlation_id,
                    "cleanup-info": {
                        "interactions_processed": self.stats.interactions_received,
                        "session_duration": time.time() - (self.stats.server_latencies.get(server_url, [time.time()])[0] if self.stats.server_latencies.get(server_url) else time.time())
                    }
                }

                response = self.session.post(
                    f"{server_url}/deregister",
                    json=deregister_data,
                    timeout=(5, 10)
                )

                if response.status_code == 200:
                    logger.info(f"OAST client cleanup successful for domain {self.unique_domain}")
                else:
                    logger.warning(f"OAST deregistration returned {response.status_code}")

            except Exception as e:
                logger.error(f"OAST deregistration error: {e}")

            finally:
                # Clear sensitive data
                self.secret_key = None
                self.public_key = None
                self.correlation_id = None

        # Close session
        try:
            self.session.close()
        except Exception:
            pass

        logger.info("OAST client closed")

# Global multi-domain manager
multi_domain_manager = MultiDomainManager()

# Backward compatibility class
class OASTClient(EnhancedOASTClient):
    """Backward compatible OAST client"""

    def __init__(self, server_index: int = 0, custom_server: str = None, logger=None):
        super().__init__(server_index, custom_server or None, "unknown", "")
        if logger:
            logger.info("Legacy OAST client initialized")

    def _log(self, msg: str):
        """Legacy logging method"""
        logger.info(msg)

    def get_stats(self) -> Dict[str, Any]:
        """Legacy stats method"""
        stats = self.get_comprehensive_stats()
        return {
            "registration_attempts": stats['registration_stats']['attempts'],
            "successful_registration": stats['registration_stats']['successful'],
            "failed_registrations": stats['registration_stats']['failed'],
            "login_latency": [l for latencies in self.stats.server_latencies.values() for l in latencies],
            "poll_counts": stats['polling_stats']['total_polls'],
            "interactions_received": stats['polling_stats']['interactions_received']
        }

    def analyze_response_for_oast(self, response: Dict[str, Any], known_domain: str = None) -> List[Dict[str, str]]:
        """Legacy response analysis method"""
        evidence = self.analyze_response_for_oast_evidence(response, known_domain)
        return [{"type": e["type"], "loc": e["location"]} for e in evidence]

# Utility functions for template integration
def create_oast_client_for_template(vulnerability_type: str, template_id: str) -> EnhancedOASTClient:
    """Create OAST client optimized for specific template"""
    return EnhancedOASTClient(
        vulnerability_type=vulnerability_type,
        template_id=template_id
    )

def get_oast_domain_for_payload(client: EnhancedOASTClient, payload: str) -> str:
    """Get OAST domain customized for specific payload"""
    return client.generate_domain_for_payload(payload) or client.unique_domain or "no-domain"

def poll_all_active_domains() -> Dict[str, List[OASTInteraction]]:
    """Poll all active OAST domains and return interactions"""
    results = {}

    for domain, info in multi_domain_manager.domains.items():
        try:
            client = info['client']
            interactions = client.poll(enhanced_analysis=True)
            if interactions:
                results[domain] = interactions
        except Exception as e:
            logger.error(f"Error polling domain {domain}: {e}")

    return results

def cleanup_expired_oast_domains(max_age_hours: int = 24):
    """Clean up expired OAST domains"""
    multi_domain_manager.cleanup_expired_domains(max_age_hours)