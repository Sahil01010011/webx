# core/heuristics.py - Simplified Heuristics Engine for WebX Elite
import asyncio
import re
import logging
import time
from typing import Dict, List, Any # <--- FIX: Added 'Any' to the import
from urllib.parse import urlparse, parse_qs, urlencode
from .http_client import send_request

logger = logging.getLogger(__name__)

# Heuristic patterns for parameter name categorization
VULNERABILITY_PATTERNS = {
    'sqli': {'id', 'uid', 'cat', 'category', 'prod', 'product', 'user', 'name', 'search', 'query'},
    'xss': {'q', 's', 'search', 'query', 'name', 'comment', 'msg', 'message', 'text', 'url', 'redirect'},
    'lfi': {'file', 'path', 'page', 'include', 'document', 'dir', 'folder'},
    'rfi': {'file', 'path', 'page', 'include', 'url', 'site'},
    'ssrf': {'url', 'uri', 'site', 'host', 'domain', 'dest', 'destination', 'redirect', 'feed', 'proxy'},
    'redirect': {'url', 'uri', 'redirect', 'next', 'goto', 'return', 'dest', 'destination'},
    'command-injection': {'cmd', 'exec', 'ping', 'query', 'run', 'cmdline'},
    'xxe': {'xml', 'data', 'content', 'doc'},
    'ssti': {'template', 'view', 'name', 'preview'},
    'csrf': {'action', 'confirm', 'delete', 'update', 'add'},
}

def categorize_by_name(injection_points: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """
    Categorizes injection points based on parameter names.
    """
    categorized = {vuln: [] for vuln in VULNERABILITY_PATTERNS}
    
    for point in injection_points:
        param_name = point.get('param', '').lower()
        if not param_name:
            continue
            
        for vuln_type, keywords in VULNERABILITY_PATTERNS.items():
            if param_name in keywords:
                categorized[vuln_type].append(point)
    
    # Return only categories that have potential targets
    return {k: v for k, v in categorized.items() if v}

async def categorize_by_reflection(session, injection_points: List[Dict[str, Any]], proxy: str = None) -> List[Dict[str, Any]]:
    """
    Identifies potential XSS candidates by checking if a unique string is reflected in the response.
    """
    xss_candidates = []
    
    async def test_reflection(point):
        param = point['param']
        if not param:
            return

        unique_str = f"webx{int(time.time())}"
        
        if point['method'].upper() == 'GET':
            parsed_url = urlparse(point['url'])
            params = parse_qs(parsed_url.query)
            params[param] = [unique_str]
            final_url = parsed_url._replace(query=urlencode(params, doseq=True)).geturl()
            data = None
        else: # POST
            final_url = point['url']
            data = {param: unique_str}
        
        try:
            response = await send_request(session, point['method'], final_url, data=data, proxy=proxy)
            if response and response.get('body') and unique_str in response['body']:
                xss_candidates.append(point)
        except Exception as e:
            logger.debug(f"Reflection test failed for {point['url']}: {e}")

    tasks = [test_reflection(point) for point in injection_points]
    await asyncio.gather(*tasks)
    
    return xss_candidates

async def comprehensive_vulnerability_analysis(session, injection_points: List[Dict[str, Any]],
                                               proxy: str = None, enable_ai: bool = False) -> Dict[str, Any]:
    """
    Main analysis function. Combines name-based and reflection-based heuristics.
    The 'enable_ai' flag is kept for future AI integration at this stage.
    """
    logger.info("Starting heuristic analysis...")
    
    # Run name-based categorization
    categorized_parameters = categorize_by_name(injection_points)
    
    # Run reflection testing to find potential XSS candidates
    xss_candidates = await categorize_by_reflection(session, injection_points, proxy)
    
    if xss_candidates:
        # Ensure 'xss' category exists and add unique candidates
        if 'xss' not in categorized_parameters:
            categorized_parameters['xss'] = []
        
        existing_xss_urls = {p['url'] for p in categorized_parameters['xss']}
        for candidate in xss_candidates:
            if candidate['url'] not in existing_xss_urls:
                categorized_parameters['xss'].append(candidate)

    logger.info("Heuristic analysis complete.")
    
    return {
        'categorized_parameters': categorized_parameters,
        'xss_candidates': xss_candidates # Kept for potential specific use later
    }