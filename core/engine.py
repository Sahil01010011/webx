# core/engine.py - Production-Grade Enhanced Version with Complete Template Support
import asyncio
import requests
import re
import time
import logging
import json
import yaml
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from .http_client import send_request
from .encoders import ENCODERS, get_intelligent_payloads
from .ai_provider import get_ai_provider, TaskType

# Setup logging
logger = logging.getLogger(__name__)

@dataclass
class VulnerabilityContext:
    """Context information for AI decision making"""
    severity: str = 'medium'
    confidence: float = 0.5
    waf_detected: bool = False
    failed_payloads: List[str] = None
    vulnerability_type: str = 'unknown'

    def __post_init__(self):
        if self.failed_payloads is None:
            self.failed_payloads = []

class TemplateProcessor:
    """Processes template variables."""
    @staticmethod
    def _generate_random_string(length: int = 8) -> str:
        import secrets
        import string
        return ''.join(secrets.choice(string.ascii_lowercase) for _ in range(length))

    def process_variables(self, template: Dict, context: Dict) -> Dict:
        template_str = json.dumps(template)
        replacements = {
            '{{BaseURL}}': context.get('base_url', ''),
            '{{parameter}}': context.get('parameter', ''),
            '{{OAST}}': context.get('oast_domain', ''),
            '{{randstr}}': self._generate_random_string(),
        }
        for placeholder, value in replacements.items():
            template_str = template_str.replace(placeholder, str(value))
        try:
            return json.loads(template_str)
        except json.JSONDecodeError:
            return template

class Matcher:
    """Handles response matching based on template rules."""
    def check(self, response: Dict, template: Dict, payload: str) -> Tuple[bool, float]:
        req_template = template.get('request', [{}])[0]
        matchers = req_template.get('matchers', [])
        if not matchers:
            return True, 0.5

        condition = req_template.get('matchers-condition', 'or').lower()
        results = [self._evaluate(response, m, payload) for m in matchers]
        
        match_scores = [score for _, score in results]
        overall_confidence = sum(match_scores) / len(match_scores) if match_scores else 0.0
        
        match_result = all(res[0] for res in results) if condition == 'and' else any(res[0] for res in results)
        
        if not match_result:
            logger.debug(f"[{template.get('id')}] Matcher failed. Condition: {condition}, Results: {[r[0] for r in results]}")

        return match_result, overall_confidence

    def _evaluate(self, response: Dict, matcher: Dict, payload: str) -> Tuple[bool, float]:
        match_type = matcher['type']
        is_negative = matcher.get('negative', False)
        
        if match_type == 'status':
            match_found = response['status'] in matcher.get('status', [])
            confidence = 0.8 if match_found else 0.0
        elif match_type in ('word', 'regex'):
            part_to_check = str(response.get(matcher.get('part', 'body'), ''))
            
            if match_type == 'word':
                words = matcher.get('words', [])
                word_condition = matcher.get('condition', 'or').lower()
                matches = [w.lower() in part_to_check.lower() for w in words]
                match_found = all(matches) if word_condition == 'and' else any(matches)
            else: # regex
                match_found = any(re.search(r, part_to_check, re.IGNORECASE) for r in matcher.get('regex', []))

            if match_found:
                confidence = 0.9 if payload.lower() in part_to_check.lower() else 0.7
            else:
                confidence = 0.0
        else:
            return False, 0.0

        final_match = not match_found if is_negative else match_found
        return final_match, confidence


class RequestBuilder:
    """Builds HTTP requests from templates."""
    def __init__(self):
        self.processor = TemplateProcessor()

    def build(self, template: Dict, injection_point: Dict, payload: str, oast_domain: str = None) -> List[Dict]:
        requests_config = template.get('request', [])
        built_requests = []
        context = {
            'base_url': injection_point['url'],
            'parameter': injection_point['param'],
            'oast_domain': oast_domain or '',
            'payload': payload
        }
        for req_config in requests_config:
            processed_config = self.processor.process_variables(req_config, context)
            request = self._build_single(processed_config, injection_point, payload)
            if request:
                built_requests.append(request)
        return built_requests

    def _build_single(self, req_config: Dict, injection_point: Dict, payload: str) -> Optional[Dict]:
        method = req_config.get('method', injection_point['method'])
        base_url = injection_point['url']
        param = injection_point['param']
        
        headers = req_config.get('headers', {})
        data = None
        url = base_url
        
        path_list = req_config.get('path', [])
        path = path_list[0] if path_list else ''
        
        if path:
            url = urljoin(base_url, path.replace('{{payload}}', payload))
        elif method.upper() == 'GET':
            parsed_url = urlparse(base_url)
            params = parse_qs(parsed_url.query)
            params[param] = [payload]
            url = parsed_url._replace(query=urlencode(params, doseq=True)).geturl()
        elif method.upper() == 'POST':
            data = req_config.get('body', f"{param}={payload}")
            if isinstance(data, str):
                data = data.replace('{{payload}}', payload)
        
        return {
            'method': method,
            'url': url,
            'headers': headers,
            'data': data
        }


class FuzzingEngine:
    """Orchestrates the fuzzing process for a single template."""
    def __init__(self):
        self.matcher = Matcher()
        self.request_builder = RequestBuilder()
        self.ai_provider = get_ai_provider()

    async def execute(self, session: requests.Session, injection_point: Dict, template: Dict,
                      delay: int, proxy: str, oast_domain: str) -> List[Dict]:
        findings = []
        template_id = template.get('id', 'unknown')
        vuln_type = template.get('vulnerability_type', 'unknown')
        base_payloads = template.get('payloads', [])

        if not base_payloads:
            return []

        # Use intelligent encoders based on vulnerability type
        all_payloads = set(base_payloads)
        for payload in base_payloads:
            encoded_payloads = await get_intelligent_payloads(payload, vuln_type=vuln_type)
            all_payloads.update(encoded_payloads)

        for payload in all_payloads:
            if delay > 0:
                await asyncio.sleep(delay / 1000)

            requests_to_send = self.request_builder.build(template, injection_point, payload, oast_domain)

            for request_config in requests_to_send:
                try:
                    response = await send_request(session, **request_config, proxy=proxy, vulnerability_type=vuln_type, template_id=template_id)
                    
                    if not response:
                        continue

                    match_result, confidence = self.matcher.check(response, template, payload)
                    
                    if match_result:
                        finding = {
                            'id': template_id,
                            'info': template['info'],
                            'vulnerability_type': vuln_type,
                            'details': {
                                'url': request_config['url'],
                                'payload': payload,
                                'parameter': injection_point['param'],
                                'method': request_config['method'],
                                'response_status': response['status'],
                                'confidence': confidence
                            }
                        }
                        findings.append(finding)
                        # Break after first match for this injection point to be efficient
                        return findings

                except Exception as e:
                    logger.error(f"Error during request for template {template_id}: {e}")
        return findings


async def run_scan(targets: List[Dict], templates: List[Dict], user_agent: str,
                   delay: int, concurrency: int = 10, proxy: str = None, oast_domain: str = None) -> List[Dict]:
    """Main entry point for the scanning engine."""
    session = requests.Session()
    session.headers.update({'User-Agent': user_agent})
    
    fuzzer = FuzzingEngine()
    
    logger.info(f"Starting scan with concurrency: {concurrency}")
    
    semaphore = asyncio.Semaphore(concurrency)
    
    async def bounded_fuzzing(target, template):
        async with semaphore:
            return await fuzzer.execute(
                session, target, template, delay, proxy, oast_domain
            )
    
    # Create a task for each target-template pair
    tasks = [
        bounded_fuzzing(target, template)
        for target in targets
        for template in templates
    ]
    
    all_findings = []
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    for result in results:
        if isinstance(result, Exception):
            logger.error(f"A scan task failed: {result}")
        elif result:
            all_findings.extend(result)
            
    return all_findings