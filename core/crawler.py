# core/crawler.py - Production-Grade AI-Enhanced Web Crawler
import asyncio
import json
import logging
import time
import hashlib
import re
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, unquote
from urllib.robotparser import RobotFileParser
from typing import Dict, List, Set, Optional, Tuple, Any
from dataclasses import dataclass, field
from bs4 import BeautifulSoup, Comment
from bs4.exceptions import FeatureNotFound
from .http_client import send_request
from .ai_provider import get_ai_provider, TaskType

# Advanced imports for JavaScript support
try:
    from playwright.async_api import async_playwright, Browser, BrowserContext, Page, Playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    logging.warning("Playwright not installed. JavaScript crawling disabled. Install with: pip install playwright")

# Setup logging
logger = logging.getLogger(__name__)

@dataclass
class CrawlResult:
    """Enhanced crawl result with metadata"""
    url: str
    param: str
    method: str
    param_type: str = 'unknown'  # query, form, header, cookie, json
    form_data: Dict[str, Any] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    confidence: float = 1.0
    technology_stack: List[str] = field(default_factory=list)
    javascript_generated: bool = False

@dataclass
class AuthenticationConfig:
    """Authentication configuration"""
    auth_type: str = 'none'  # none, form, jwt, api_key, oauth
    login_url: str = ''
    username_field: str = 'username'
    password_field: str = 'password'
    username: str = ''
    password: str = ''
    jwt_token: str = ''
    api_key: str = ''
    api_key_header: str = 'Authorization'
    custom_headers: Dict[str, str] = field(default_factory=dict)

class TechnologyDetector:
    """Advanced technology stack detection"""

    def __init__(self):
        self.signatures = {
            'frameworks': {
                'react': [r'react', r'__REACT_DEVTOOLS_GLOBAL_HOOK__', r'_reactListening'],
                'angular': [r'ng-', r'angular', r'__ngContext'],
                'vue': [r'vue', r'__vue__', r'v-'],
                'django': [r'csrfmiddlewaretoken', r'django', r'__admin_media_prefix__'],
                'flask': [r'flask', r'werkzeug'],
                'rails': [r'rails', r'csrf-token', r'authenticity_token'],
                'spring': [r'spring', r'jsessionid', r'org.springframework'],
                'asp.net': [r'__viewstate', r'__eventvalidation', r'aspxerrorpath'],
                'php': [r'phpsessid', r'<?php', r'index.php'],
                'wordpress': [r'wp-content', r'wp-admin', r'wp-includes'],
                'drupal': [r'drupal', r'sites/default', r'/node/'],
                'joomla': [r'joomla', r'administrator', r'/component/']
            },
            'web_servers': {
                'apache': [r'apache', r'server:\s*apache'],
                'nginx': [r'nginx', r'server:\s*nginx'],
                'iis': [r'iis', r'server:\s*microsoft-iis'],
                'tomcat': [r'tomcat', r'jsessionid']
            },
            'databases': {
                'mysql': [r'mysql', r'phpmyadmin'],
                'postgresql': [r'postgresql', r'postgres'],
                'mongodb': [r'mongodb', r'mongo'],
                'oracle': [r'oracle', r'ora-'],
                'mssql': [r'microsoft sql server', r'mssql']
            }
        }

    def detect_technologies(self, response_body: str, headers: Dict[str, str]) -> List[str]:
        """Detect technology stack from response"""
        detected = []
        content = (response_body + str(headers)).lower()

        for category, techs in self.signatures.items():
            for tech_name, patterns in techs.items():
                if any(re.search(pattern, content, re.IGNORECASE) for pattern in patterns):
                    detected.append(f"{category}:{tech_name}")

        return detected

class JavaScriptCrawler:
    """Advanced JavaScript-aware crawler using Playwright"""

    def __init__(self):
        self.playwright: Optional[Playwright] = None
        self.browser: Optional[Browser] = None
        self.context: Optional[BrowserContext] = None
        self.discovered_endpoints = set()

    async def initialize(self, user_agent: str = None, proxy: str = None):
        """Initialize browser context"""
        if not PLAYWRIGHT_AVAILABLE:
            logger.warning("JavaScript crawling unavailable - Playwright not installed")
            return False

        try:
            self.playwright = await async_playwright().start()
            launch_options = {
                'headless': True,
                'args': ['--no-sandbox', '--disable-blink-features=AutomationControlled']
            }

            if proxy:
                launch_options['proxy'] = {
                    'server': proxy
                }

            self.browser = await self.playwright.chromium.launch(**launch_options)

            context_options = {
                'ignore_https_errors': True,
                'java_script_enabled': True
            }

            if user_agent:
                context_options['user_agent'] = user_agent

            self.context = await self.browser.new_context(**context_options)

            # Intercept network requests to discover API endpoints
            self.context.on('request', self._handle_request)
            self.context.on('response', self._handle_response)

            logger.info("JavaScript crawler initialized successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to initialize JavaScript crawler: {e}")
            return False

    async def _handle_request(self, request):
        """Handle intercepted network requests"""
        try:
            url = request.url
            method = request.method

            # Extract parameters from different sources
            if method == 'GET':
                parsed = urlparse(url)
                if parsed.query:
                    params = parse_qs(parsed.query)
                    for param_name in params:
                        self.discovered_endpoints.add((url, param_name, method, 'query'))

            elif method in ['POST', 'PUT', 'PATCH']:
                # Analyze request body for parameters
                if request.post_data:
                    try:
                        # Try JSON
                        json_data = json.loads(request.post_data)
                        for key in self._flatten_json_keys(json_data):
                            self.discovered_endpoints.add((url, key, method, 'json'))
                    except:
                        # Try form data
                        if 'application/x-www-form-urlencoded' in request.headers.get('content-type', ''):
                            params = parse_qs(request.post_data)
                            for param_name in params:
                                self.discovered_endpoints.add((url, param_name, method, 'form'))

        except Exception as e:
            logger.debug(f"Request handler error: {e}")

    async def _handle_response(self, response):
        """Handle intercepted network responses"""
        try:
            # Detect API endpoints from response patterns
            if response.headers.get('content-type', '').startswith('application/json'):
                url = response.url
                if '/api/' in url or url.endswith('.json'):
                    # This is likely an API endpoint
                    parsed = urlparse(url)
                    if parsed.query:
                        params = parse_qs(parsed.query)
                        for param_name in params:
                            self.discovered_endpoints.add((url, param_name, 'GET', 'api'))

        except Exception as e:
            logger.debug(f"Response handler error: {e}")

    def _flatten_json_keys(self, data, prefix='') -> List[str]:
        """Flatten nested JSON to extract all parameter names"""
        keys = []

        if isinstance(data, dict):
            for key, value in data.items():
                full_key = f"{prefix}.{key}" if prefix else key
                keys.append(full_key)
                if isinstance(value, (dict, list)):
                    keys.extend(self._flatten_json_keys(value, full_key))

        elif isinstance(data, list) and data:
            if isinstance(data[0], dict):
                keys.extend(self._flatten_json_keys(data[0], prefix))

        return keys

    async def crawl_spa(self, url: str, max_depth: int = 3, wait_time: int = 2) -> List[CrawlResult]:
        """Crawl Single Page Application with JavaScript execution"""
        if not self.context:
            logger.warning("JavaScript crawler not initialized")
            return []

        discovered_results = []

        try:
            page = await self.context.new_page()

            # Navigate and wait for JavaScript execution
            await page.goto(url, wait_until='networkidle', timeout=30000)
            await page.wait_for_timeout(wait_time * 1000)

            # Extract forms and inputs after JavaScript execution
            forms = await page.query_selector_all('form')
            for form in forms:
                try:
                    action = await form.get_attribute('action') or url
                    method = (await form.get_attribute('method') or 'GET').upper()

                    inputs = await form.query_selector_all('input, textarea, select')
                    for input_elem in inputs:
                        name = await input_elem.get_attribute('name')
                        if name:
                            discovered_results.append(CrawlResult(
                                url=urljoin(url, action),
                                param=name,
                                method=method,
                                param_type='form',
                                javascript_generated=True
                            ))
                except Exception as e:
                    logger.debug(f"Form extraction error: {e}")

            # Extract links and trigger JavaScript interactions
            links = await page.query_selector_all('a[href], button[onclick]')
            for link in links[:20]:  # Limit to prevent excessive crawling
                try:
                    href = await link.get_attribute('href')
                    onclick = await link.get_attribute('onclick')

                    if href and not href.startswith(('javascript:', 'mailto:', 'tel:')):
                        # Click link to trigger JavaScript and discover new endpoints
                        try:
                            await link.click(timeout=5000)
                            await page.wait_for_timeout(1000)  # Wait for new content
                        except:
                            pass  # Continue if click fails

                    elif onclick:
                        # Execute onclick JavaScript
                        try:
                            await page.evaluate(f"({onclick})()")
                            await page.wait_for_timeout(1000)
                        except:
                            pass

                except Exception as e:
                    logger.debug(f"Link interaction error: {e}")

            await page.close()

            # Convert discovered endpoints from network interception
            for endpoint_data in self.discovered_endpoints:
                url_found, param, method, param_type = endpoint_data
                discovered_results.append(CrawlResult(
                    url=url_found,
                    param=param,
                    method=method,
                    param_type=param_type,
                    javascript_generated=True
                ))

            logger.info(f"JavaScript crawler found {len(discovered_results)} injection points")

        except Exception as e:
            logger.error(f"JavaScript crawling failed: {e}")

        return discovered_results

    async def close(self):
        """Clean up browser resources"""
        try:
            if self.context:
                await self.context.close()
            if self.browser:
                await self.browser.close()
            if self.playwright:
                await self.playwright.stop()
        except Exception as e:
            logger.debug(f"Browser cleanup error: {e}")

class AuthenticationManager:
    """Handle various authentication mechanisms"""

    def __init__(self, config: AuthenticationConfig):
        self.config = config
        self.authenticated_session = None
        self.auth_headers = {}
        self.auth_cookies = {}

    async def authenticate(self, session) -> bool:
        """Perform authentication based on configuration"""
        if self.config.auth_type == 'none':
            return True

        try:
            if self.config.auth_type == 'form':
                return await self._form_authentication(session)
            elif self.config.auth_type == 'jwt':
                return await self._jwt_authentication(session)
            elif self.config.auth_type == 'api_key':
                return await self._api_key_authentication(session)
            else:
                logger.warning(f"Unsupported authentication type: {self.config.auth_type}")
                return False

        except Exception as e:
            logger.error(f"Authentication failed: {e}")
            return False

    async def _form_authentication(self, session) -> bool:
        """Handle form-based authentication"""
        if not self.config.login_url or not self.config.username or not self.config.password:
            logger.error("Form authentication requires login_url, username, and password")
            return False

        # Get login page to extract CSRF tokens
        response = await send_request(session, 'GET', self.config.login_url, None, None, None)

        if not response:
            logger.error("Failed to fetch login page")
            return False

        # Parse login form
        soup = BeautifulSoup(response['body'], 'html.parser')
        login_form = soup.find('form')

        if not login_form:
            logger.error("No login form found")
            return False

        # Prepare login data
        login_data = {
            self.config.username_field: self.config.username,
            self.config.password_field: self.config.password
        }

        # Extract hidden fields (CSRF tokens, etc.)
        for hidden_input in login_form.find_all('input', type='hidden'):
            name = hidden_input.get('name')
            value = hidden_input.get('value', '')
            if name:
                login_data[name] = value

        # Perform login
        login_url = urljoin(self.config.login_url, login_form.get('action', ''))
        method = login_form.get('method', 'POST').upper()

        auth_response = await send_request(session, method, login_url, None, login_data, None)

        if auth_response and auth_response['status'] in [200, 302]:
            # Store authentication cookies
            if hasattr(session, 'cookies'):
                self.auth_cookies = dict(session.cookies)
            logger.info("Form authentication successful")
            return True

        logger.error("Form authentication failed")
        return False

    async def _jwt_authentication(self, session) -> bool:
        """Handle JWT token authentication"""
        if not self.config.jwt_token:
            logger.error("JWT authentication requires jwt_token")
            return False

        self.auth_headers['Authorization'] = f"Bearer {self.config.jwt_token}"
        session.headers.update(self.auth_headers)
        logger.info("JWT authentication configured")
        return True

    async def _api_key_authentication(self, session) -> bool:
        """Handle API key authentication"""
        if not self.config.api_key:
            logger.error("API key authentication requires api_key")
            return False

        self.auth_headers[self.config.api_key_header] = self.config.api_key
        session.headers.update(self.auth_headers)
        logger.info("API key authentication configured")
        return True

class ProductionCrawler:
    """Production-grade web crawler with AI intelligence"""

    def __init__(self):
        # Core state management
        self.crawled_urls: Set[str] = set()
        self.discovered_injection_points: List[CrawlResult] = []
        self.seen_points: Set[Tuple[str, str, str]] = set()

        # Advanced features
        self.tech_detector = TechnologyDetector()
        self.js_crawler: Optional[JavaScriptCrawler] = None
        self.auth_manager: Optional[AuthenticationManager] = None
        self.ai_provider = None

        # Configuration
        self.max_depth = 5
        self.max_pages = 200
        self.delay_between_requests = 0.1
        self.respect_robots_txt = True
        self.robots_cache = {}
        self.base_domain = "" # To store the initial target domain

        # Extensions to ignore
        self.ignored_extensions = {
            '.jpg', '.jpeg', '.png', '.gif', '.pdf', '.css', '.js', '.zip',
            '.mp3', '.mp4', '.avi', '.mov', '.doc', '.docx', '.xls', '.xlsx',
            '.ppt', '.pptx', '.svg', '.ico', '.woff', '.woff2', '.ttf', '.eot'
        }

        # Patterns for interesting endpoints
        self.api_patterns = [
            r'/api/', r'/rest/', r'/graphql', r'/ajax/', r'/json/',
            r'\.json$', r'\.xml$', r'/v\d+/', r'/admin/', r'/dashboard/'
        ]

    async def initialize(self, base_url: str, enable_js: bool = True, user_agent: str = None,
                         proxy: str = None, auth_config: Optional[AuthenticationConfig] = None):
        """Initialize crawler with advanced capabilities"""

        self.base_domain = urlparse(base_url).netloc

        # Initialize AI provider if available
        self.ai_provider = get_ai_provider()

        # Initialize JavaScript crawler
        if enable_js and PLAYWRIGHT_AVAILABLE:
            self.js_crawler = JavaScriptCrawler()
            await self.js_crawler.initialize(user_agent, proxy)

        # Initialize authentication
        if auth_config and auth_config.auth_type != 'none':
            self.auth_manager = AuthenticationManager(auth_config)

        logger.info(f"Production crawler initialized - JS: {bool(self.js_crawler)}, "
                    f"Auth: {bool(self.auth_manager)}, AI: {bool(self.ai_provider)}")

    async def check_robots_txt(self, base_url: str, user_agent: str) -> bool:
        """Check robots.txt compliance"""
        if not self.respect_robots_txt:
            return True

        domain = urlparse(base_url).netloc
        if domain in self.robots_cache:
            return self.robots_cache[domain]

        try:
            robots_url = f"{urlparse(base_url).scheme}://{domain}/robots.txt"
            rp = RobotFileParser()
            rp.set_url(robots_url)
            await asyncio.to_thread(rp.read) # Run blocking read in a thread
            
            allowed = rp.can_fetch(user_agent, base_url)
            self.robots_cache[domain] = allowed
            return allowed

        except Exception:
            self.robots_cache[domain] = True  # Allow if robots.txt unavailable
            return True

    async def analyze_framework_with_ai(self, technologies: List[str], response_body: str) -> Dict[str, Any]:
        """Use AI to analyze unknown or custom frameworks"""
        if not self.ai_provider or not technologies:
            return {}

        framework_data = {
            "detected_technologies": technologies,
            "response_sample": response_body[:2000],  # Limited sample for analysis
            "has_custom_patterns": len([t for t in technologies if 'unknown' in t]) > 0
        }

        # Only use AI for complex/unknown frameworks to save budget
        needs_ai_analysis = any(
            'unknown' in tech or 'custom' in tech.lower()
            for tech in technologies
        )

        if needs_ai_analysis:
            ai_result = await self.ai_provider.ai_request_with_fallback(
                TaskType.FRAMEWORK_ANALYSIS,
                {"framework_data": str(framework_data)},
                {"unknown_framework": True, "custom_framework": True}
            )

            if ai_result and ai_result.get("success"):
                logger.info(f"AI framework analysis completed (Cost: ${ai_result.get('cost', 0):.3f})")
                return {
                    "ai_analysis": ai_result["response"],
                    "custom_endpoints": self._extract_endpoints_from_ai(ai_result["response"]),
                    "recommended_parameters": self._extract_parameters_from_ai(ai_result["response"])
                }

        return {}

    def _extract_endpoints_from_ai(self, ai_response: str) -> List[str]:
        """Extract endpoint recommendations from AI response"""
        endpoints = []
        # Look for endpoint patterns in AI response
        endpoint_patterns = [
            r'/[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+',
            r'api/[a-zA-Z0-9_-]+',
            r'admin/[a-zA-Z0-9_-]+'
        ]

        for pattern in endpoint_patterns:
            matches = re.findall(pattern, ai_response)
            endpoints.extend(matches)

        return list(set(endpoints))  # Remove duplicates

    def _extract_parameters_from_ai(self, ai_response: str) -> List[str]:
        """Extract parameter recommendations from AI response"""
        parameters = []
        # Look for parameter patterns in AI response
        param_patterns = [
            r'\b[a-zA-Z_][a-zA-Z0-9_]*\b(?=.*(?:param|field|input))',
            r'"[a-zA-Z_][a-zA-Z0-9_]*"',
            r"'[a-zA-Z_][a-zA-Z0-9_]*'"
        ]

        for pattern in param_patterns:
            matches = re.findall(pattern, ai_response)
            parameters.extend([m.strip('"\'') for m in matches])

        return list(set(parameters))

    async def crawl_page(self, session, url: str, depth: int = 0, proxy: str = None) -> List[CrawlResult]:
        """Crawl a single page with advanced analysis"""

        if depth > self.max_depth or len(self.crawled_urls) > self.max_pages:
            return []

        # Normalize URL
        parsed_url = urlparse(url)
        normalized_url = parsed_url._replace(fragment="").geturl()

        if normalized_url in self.crawled_urls:
            return []

        # Check file extension
        if any(parsed_url.path.lower().endswith(ext) for ext in self.ignored_extensions):
            return []

        # Check robots.txt
        if not await self.check_robots_txt(url, session.headers.get('User-Agent', '*')):
            logger.debug(f"Robots.txt disallows crawling: {url}")
            return []

        logger.info(f"[{depth}] Crawling: {normalized_url}")
        self.crawled_urls.add(normalized_url)

        # Apply delay to avoid overwhelming server
        if self.delay_between_requests > 0:
            await asyncio.sleep(self.delay_between_requests)

        # Fetch page
        response = await send_request(session, 'GET', normalized_url, None, None, proxy)

        if not response or not response.get('body'):
            logger.debug(f"No response or empty body for: {normalized_url}")
            return []

        page_results = []

        # Detect technology stack
        technologies = self.tech_detector.detect_technologies(
            response['body'], response.get('headers', {})
        )

        # AI-powered framework analysis for unknown technologies
        ai_analysis = await self.analyze_framework_with_ai(technologies, response['body'])

        # Parse HTML
        try:
            soup = BeautifulSoup(response['body'], 'lxml')
        except FeatureNotFound:
            soup = BeautifulSoup(response['body'], 'html.parser')

        # Extract URL parameters
        query_params = parse_qs(parsed_url.query)
        for param_name in query_params:
            point = (normalized_url, param_name, 'GET')
            if point not in self.seen_points:
                page_results.append(CrawlResult(
                    url=normalized_url,
                    param=param_name,
                    method='GET',
                    param_type='query',
                    technology_stack=technologies,
                    confidence=0.9
                ))
                self.seen_points.add(point)

        # Extract form parameters
        for form in soup.find_all('form'):
            action = form.get('action', '')
            method = form.get('method', 'GET').upper()
            form_url = urljoin(normalized_url, action)
            
            # SCOPE CHECK: Only process forms that submit to the same domain
            if urlparse(form_url).netloc != self.base_domain:
                continue

            # Extract all form inputs
            form_data = {}
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                param_name = input_tag.get('name')
                if param_name:
                    input_type = input_tag.get('type', 'text')
                    default_value = input_tag.get('value', '')

                    form_data[param_name] = {
                        'type': input_type,
                        'default': default_value,
                        'required': input_tag.has_attr('required')
                    }

                    point = (form_url, param_name, method)
                    if point not in self.seen_points:
                        page_results.append(CrawlResult(
                            url=form_url,
                            param=param_name,
                            method=method,
                            param_type='form',
                            form_data=form_data,
                            technology_stack=technologies,
                            confidence=0.95
                        ))
                        self.seen_points.add(point)

        # Extract links for recursive crawling
        links_to_crawl = []
        for link in soup.find_all('a', href=True):
            href = link['href']
            if href.startswith(('javascript:', 'mailto:', 'tel:', '#')):
                continue
            
            full_url = urljoin(normalized_url, href)
            # SCOPE CHECK: Only follow links on the same domain
            if urlparse(full_url).netloc == self.base_domain:
                links_to_crawl.append(full_url)
        
        # Look for API endpoints and interesting paths (still within scope)
        script_content = "".join(str(s.string) for s in soup.find_all('script') if s.string)
        for pattern in self.api_patterns:
            for match in re.findall(pattern, script_content):
                api_url = urljoin(normalized_url, match)
                if urlparse(api_url).netloc == self.base_domain and api_url not in self.crawled_urls:
                    links_to_crawl.append(api_url)

        # Recursive crawling with depth control
        if depth < self.max_depth and links_to_crawl:
            semaphore = asyncio.Semaphore(10) # Increased concurrency for crawling
            
            async def bounded_crawl(link_url):
                async with semaphore:
                    return await self.crawl_page(session, link_url, depth + 1, proxy)

            tasks = [bounded_crawl(link) for link in links_to_crawl]
            
            try:
                batch_results = await asyncio.gather(*tasks, return_exceptions=True)
                for result in batch_results:
                    if isinstance(result, list):
                        page_results.extend(result)
            except Exception as e:
                logger.error(f"Batch crawling error: {e}")

        return page_results

    async def crawl(self, session, base_url: str, proxy: str = None,
                    enable_javascript: bool = True) -> List[Dict]:
        """Main crawling entry point with all advanced features"""

        # Authenticate if required
        if self.auth_manager:
            auth_success = await self.auth_manager.authenticate(session)
            if not auth_success:
                logger.error("Authentication failed - continuing with unauthenticated crawling")

        # Clear previous state
        self.crawled_urls.clear()
        self.discovered_injection_points.clear()
        self.seen_points.clear()

        all_results = []

        # Traditional HTML crawling
        logger.info("Starting traditional HTML crawling...")
        html_results = await self.crawl_page(session, base_url, 0, proxy)
        all_results.extend(html_results)

        # JavaScript-aware crawling
        if enable_javascript and self.js_crawler:
            logger.info("Starting JavaScript-aware crawling...")
            try:
                js_results = await self.js_crawler.crawl_spa(base_url)
                # SCOPE CHECK for JS-discovered endpoints
                scoped_js_results = [r for r in js_results if urlparse(r.url).netloc == self.base_domain]
                all_results.extend(scoped_js_results)
            except Exception as e:
                logger.error(f"JavaScript crawling failed: {e}")

        # Remove duplicates based on (url, param, method)
        unique_results = {}
        for result in all_results:
            key = (result.url, result.param, result.method)
            if key not in unique_results or result.confidence > unique_results[key].confidence:
                unique_results[key] = result

        final_results = list(unique_results.values())

        # Convert to legacy format for backward compatibility
        legacy_results = []
        for result in final_results:
            legacy_results.append({
                'url': result.url,
                'param': result.param,
                'method': result.method,
                'metadata': {
                    'param_type': result.param_type,
                    'confidence': result.confidence,
                    'technologies': result.technology_stack,
                    'javascript_generated': result.javascript_generated
                }
            })

        logger.info(f"Crawling completed: {len(final_results)} unique injection points discovered")

        # Log AI usage if available
        if self.ai_provider:
            try:
                usage_stats = self.ai_provider.get_usage_stats()
                logger.info(f"AI Usage: ${usage_stats['current_usage']:.2f}/${usage_stats['monthly_budget']}")
            except Exception as e:
                logger.debug(f"AI usage stats error: {e}")

        return legacy_results

    async def cleanup(self):
        """Clean up crawler resources"""
        if self.js_crawler:
            await self.js_crawler.close()

# Global crawler instance
production_crawler = ProductionCrawler()

# Backward compatibility wrapper
async def crawl(session, base_url: str, proxy: str = None,
                auth_config: Optional[AuthenticationConfig] = None,
                enable_javascript: bool = True) -> List[Dict]:
    """Enhanced crawl function with production-grade capabilities"""

    global production_crawler

    # Initialize crawler if needed
    try:
        await production_crawler.initialize(
            base_url=base_url,
            enable_js=enable_javascript,
            user_agent=session.headers.get('User-Agent'),
            proxy=proxy,
            auth_config=auth_config
        )

        # Perform crawling
        results = await production_crawler.crawl(session, base_url, proxy, enable_javascript)

        return results

    except Exception as e:
        logger.error(f"Production crawler failed: {e}", exc_info=True)

        # Fallback to basic crawling
        logger.info("Falling back to basic crawling...")
        return await basic_crawl_fallback(session, base_url, proxy)

    finally:
        # Cleanup resources
        try:
            await production_crawler.cleanup()
        except Exception as e:
            logger.debug(f"Crawler cleanup error: {e}")

async def basic_crawl_fallback(session, base_url: str, proxy: str = None) -> List[Dict]:
    """Fallback basic crawler for when advanced features fail"""
    crawled_urls = set()
    discovered_points = []
    seen_points = set()
    base_domain = urlparse(base_url).netloc
    
    async def basic_crawl_page(url, depth=0):
        if depth > 3 or len(crawled_urls) > 50:
            return

        parsed_url = urlparse(url)
        normalized_url = parsed_url._replace(fragment="").geturl()

        if normalized_url in crawled_urls:
            return

        crawled_urls.add(normalized_url)

        try:
            response = await send_request(session, 'GET', normalized_url, None, None, proxy)

            if not response or not response.get('body'):
                return

            soup = BeautifulSoup(response['body'], 'html.parser')

            # Extract parameters
            query_params = parse_qs(parsed_url.query)
            for param_name in query_params:
                point = (normalized_url, param_name, 'GET')
                if point not in seen_points:
                    discovered_points.append({
                        'url': normalized_url,
                        'param': param_name,
                        'method': 'GET'
                    })
                    seen_points.add(point)

            # Extract forms
            for form in soup.find_all('form'):
                action = form.get('action', '')
                method = form.get('method', 'GET').upper()
                form_url = urljoin(normalized_url, action)

                if urlparse(form_url).netloc != base_domain:
                    continue

                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    param_name = input_tag.get('name')
                    if param_name:
                        point = (form_url, param_name, method)
                        if point not in seen_points:
                            discovered_points.append({
                                'url': form_url,
                                'param': param_name,
                                'method': method
                            })
                            seen_points.add(point)

            # Recursive crawling
            if depth < 2:
                tasks = []
                for link in soup.find_all('a', href=True)[:20]:  # Limit links
                    href = link['href']
                    if not href.startswith(('javascript:', 'mailto:', 'tel:')):
                        full_url = urljoin(normalized_url, href)
                        if urlparse(full_url).netloc == base_domain:
                            tasks.append(basic_crawl_page(full_url, depth + 1))

                if tasks:
                    await asyncio.gather(*tasks, return_exceptions=True)

        except Exception as e:
            logger.debug(f"Basic crawl error: {e}")

    await basic_crawl_page(base_url)
    return discovered_points