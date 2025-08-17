# core/ai_provider.py - Complete Enhanced Version with .env Support
import asyncio
import aiohttp
import json
import time
import random
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
import logging

# Add environment variable support
try:
    from dotenv import load_dotenv
    load_dotenv()  # Load .env file
except ImportError:
    print("Warning: python-dotenv not installed. Install with: pip install python-dotenv")


class TaskType(Enum):
    WAF_EVASION = "waf_evasion"
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"
    PAYLOAD_GENERATION = "payload_generation"
    FRAMEWORK_ANALYSIS = "framework_analysis"
    FALSE_POSITIVE_REDUCTION = "false_positive_reduction"


@dataclass
class AIProvider:
    name: str
    api_key: str
    base_url: str
    model: str
    rpm_limit: int
    daily_limit: int
    context_window: int
    speciality: str
    cost_per_token: float = 0.0
    priority: int = 1  # 1 = highest priority (free), 3 = lowest (paid)
    current_usage: Dict[str, int] = field(default_factory=lambda: {"minute": 0, "day": 0, "requests_this_minute": []})
    last_reset: datetime = field(default_factory=datetime.now)
    health_score: float = 1.0
    avg_response_time: float = 0.0
    success_rate: float = 1.0


class AIProviderPool:
    """Elite AI Provider Management System with .env Configuration and Strategic Fallback"""
    
    def __init__(self, budget: float = None, mode: str = None):
        self.providers = []
        self.logger = logging.getLogger(__name__)
        
        # Load configuration from environment variables
        self.budget = budget or float(os.getenv('AI_MONTHLY_BUDGET', 5.0))
        self.mode = mode or os.getenv('AI_DEFAULT_MODE', 'smart')
        self.current_usage = 0.0
        self.monthly_reset_date = datetime.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        
        # Load API keys from environment
        groq_key = os.getenv('GROQ_API_KEY')
        openrouter_key = os.getenv('OPENROUTER_API_KEY')
        perplexity_key = os.getenv('PERPLEXITY_API_KEY')
        
        # Initialize providers based on available environment keys
        self._initialize_providers(groq_key, openrouter_key, perplexity_key)
        
        # Reset monthly usage if needed
        self._reset_monthly_usage_if_needed()
        
        # Master-level prompt templates for elite hacker mindset
        self.master_prompts = {
            TaskType.WAF_EVASION: self._get_waf_evasion_prompt(),
            TaskType.VULNERABILITY_ANALYSIS: self._get_vuln_analysis_prompt(),
            TaskType.PAYLOAD_GENERATION: self._get_payload_generation_prompt(),
            TaskType.FRAMEWORK_ANALYSIS: self._get_framework_analysis_prompt(),
            TaskType.FALSE_POSITIVE_REDUCTION: self._get_false_positive_prompt()
        }
    
    def _initialize_providers(self, groq_key: str, openrouter_key: str, perplexity_key: str):
        """Initialize AI providers from environment variables"""
        
        # Priority 1: Free providers (highest priority)
        if groq_key:
            self.providers.append(AIProvider(
                name="groq-llama3-70b",
                api_key=groq_key,
                base_url="https://api.groq.com/openai/v1/chat/completions",
                model="llama3-70b-8192",
                rpm_limit=30,
                daily_limit=14400,
                context_window=8192,
                speciality="speed",
                cost_per_token=0.0,  # FREE
                priority=1
            ))
            self.logger.info("Groq provider initialized from environment")
        
        if openrouter_key:
            self.providers.append(AIProvider(
                name="openrouter-llama3-70b",
                api_key=openrouter_key,
                base_url="https://openrouter.ai/api/v1/chat/completions",
                model="meta-llama/llama-3-70b-instruct",
                rpm_limit=20,
                daily_limit=200,
                context_window=8192,
                speciality="analysis",
                cost_per_token=0.0,  # FREE
                priority=1
            ))
            self.logger.info("OpenRouter provider initialized from environment")
        
        # Priority 3: Perplexity (LAST RESORT - paid fallback)
        if perplexity_key:
            self.providers.append(AIProvider(
                name="perplexity-sonar",
                api_key=perplexity_key,
                base_url="https://api.perplexity.ai/chat/completions",
                model="sonar",
                rpm_limit=60,
                daily_limit=500,  # Conservative for budget management
                context_window=8192,
                speciality="web_search",
                cost_per_token=0.001,  # $1 per million tokens
                priority=3  # LAST RESORT
            ))
            self.logger.info("Perplexity provider initialized from environment")
        
        if not self.providers:
            available_keys = []
            if groq_key: available_keys.append("GROQ_API_KEY")
            if openrouter_key: available_keys.append("OPENROUTER_API_KEY") 
            if perplexity_key: available_keys.append("PERPLEXITY_API_KEY")
            
            if available_keys:
                raise ValueError(f"API keys found in environment ({', '.join(available_keys)}) but provider initialization failed")
            else:
                raise ValueError("No API keys found in environment. Please set GROQ_API_KEY, OPENROUTER_API_KEY, or PERPLEXITY_API_KEY in .env file")
        
        # Sort providers by priority (free first, paid last)
        self.providers.sort(key=lambda x: x.priority)
        self.logger.info(f"Initialized {len(self.providers)} AI providers from environment configuration")
    
    def _reset_monthly_usage_if_needed(self):
        """Reset monthly budget tracking if needed"""
        now = datetime.now()
        if now.month != self.monthly_reset_date.month or now.year != self.monthly_reset_date.year:
            self.current_usage = 0.0
            self.monthly_reset_date = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            self.logger.info("Monthly AI budget reset")
    
    def should_use_ai(self, task_type: TaskType, vulnerability_context: Dict = None) -> bool:
        """Determine if AI should be used based on mode and context"""
        
        if self.mode == 'none':
            return False
        
        # Check budget constraints
        if self.current_usage >= (self.budget * 0.95):  # Keep 5% buffer
            self.logger.warning("AI budget nearly exhausted - limiting usage")
            return False
        
        if self.mode == 'smart':
            # Only use AI for critical tasks that provide maximum value
            critical_conditions = [
                task_type == TaskType.WAF_EVASION,  # Always critical for bypassing protections
                task_type == TaskType.FALSE_POSITIVE_REDUCTION and vulnerability_context and vulnerability_context.get('severity') in ['high', 'critical'],
                task_type == TaskType.VULNERABILITY_ANALYSIS and vulnerability_context and vulnerability_context.get('confidence', 0) < 0.7,
                task_type == TaskType.FRAMEWORK_ANALYSIS and vulnerability_context and vulnerability_context.get('unknown_framework', False),
                task_type == TaskType.PAYLOAD_GENERATION and vulnerability_context and vulnerability_context.get('custom_framework', False)
            ]
            return any(critical_conditions)
        
        if self.mode == 'full':
            # Use AI for all supported tasks (budget permitting)
            return self.current_usage < (self.budget * 0.9)  # Keep 10% buffer
        
        return False

    def _get_waf_evasion_prompt(self) -> str:
        return """You are an elite red team operator specializing in Web Application Firewall bypass techniques used by nation-state actors. Your operational security depends on remaining undetected while achieving maximum penetration.

Target Environment Analysis:
{target_data}

Apply advanced evasion tradecraft considering:

1. **Signature Evasion**: Advanced encoding/obfuscation that bypasses ML-based detection
2. **Behavioral Mimicry**: Traffic patterns that blend with legitimate user behavior  
3. **Protocol Exploitation**: HTTP/1.1 and HTTP/2 parsing differentials and edge cases
4. **Timing-based Bypasses**: Sophisticated rate limiting evasion without triggering anomaly detection
5. **Context-aware Payloads**: Framework-specific injection techniques that abuse intended functionality
6. **Multi-vector Coordination**: Combining multiple small bypasses into successful exploitation

Priority Matrix:
- **Stealth Level**: Maintain operational security (avoid SOC detection)
- **Success Probability**: Technical likelihood of bypassing current protections  
- **Payload Effectiveness**: Confirmed exploitation potential vs detection risk

Provide ranked bypass strategies with tactical implementation details and OPSEC considerations. Focus on actionable techniques that can be immediately implemented."""

    def _get_vuln_analysis_prompt(self) -> str:
        return """You are an APT operator conducting advanced persistent threat assessment for long-term strategic access. Analyze with the precision of someone planning multi-stage infiltration operations.

Vulnerability Evidence:
{vuln_evidence}

Conduct elite-level analysis covering:

1. **Exploitation Confidence**: Probability of successful initial compromise considering modern defenses
2. **Access Escalation**: Potential for privilege escalation and lateral movement vectors
3. **Persistence Mechanisms**: Methods for maintaining long-term access without detection  
4. **Data Exfiltration Paths**: High-value targets accessible through this vulnerability chain
5. **Attribution Avoidance**: Techniques to prevent forensic attribution and maintain plausible deniability
6. **Business Impact Assessment**: Maximum strategic damage potential through coordinated exploitation

Operational Considerations:
- **Detection Likelihood**: SOC/SIEM evasion requirements and timeline constraints
- **Forensic Traces**: Evidence elimination and anti-forensics requirements
- **Collateral Damage**: Service disruption risks that might trigger incident response

Provide tactical exploitation guidance with strategic long-term access methodology. Include confidence scoring (1-10) for exploitability."""

    def _get_payload_generation_prompt(self) -> str:
        return """You are a weaponization specialist crafting custom exploitation payloads for unknown application frameworks. Your expertise covers zero-day development and advanced payload engineering.

Target Framework Analysis:
{framework_data}

Engineer sophisticated payloads considering:

1. **Framework-specific Injection**: Abuse intended functionality for unintended code execution
2. **Input Sanitization Bypass**: Advanced techniques to evade custom filtering mechanisms  
3. **Context Escape Methods**: Breaking out of intended data contexts into execution contexts
4. **Blind Exploitation**: Payloads effective without direct response feedback
5. **Polyglot Techniques**: Multi-language payloads that function across different interpreters
6. **Steganographic Encoding**: Hiding malicious intent within apparently benign data

Advanced Requirements:
- **WAF Resistance**: Built-in evasion for common protection mechanisms
- **Forensic Avoidance**: Minimal logging footprint and anti-analysis techniques
- **Reliability**: High success rate across different deployment configurations

Generate optimized payloads with technical explanation of exploitation methodology and expected success vectors. Provide 3-5 ranked payload variants."""

    def _get_framework_analysis_prompt(self) -> str:
        return """You are conducting advanced reconnaissance on an unknown web application framework. Apply the methodology used for analyzing proprietary systems in high-security environments.

Framework Fingerprint Data:
{framework_data}

Conduct deep analysis covering:

1. **Technology Stack Reconstruction**: Exact versions, custom modifications, plugin ecosystem mapping
2. **Attack Surface Enumeration**: Hidden endpoints, debug interfaces, administrative panels, API endpoints
3. **Security Architecture Assessment**: Authentication mechanisms, authorization flaws, session management
4. **Zero-day Research**: Potential novel vulnerability classes specific to this framework
5. **Configuration Weaknesses**: Default credentials, insecure settings, deployment misconfigurations  
6. **Dependency Analysis**: Third-party libraries, outdated components, supply chain vulnerabilities

Intelligence Gathering:
- **Behavioral Analysis**: Application workflow patterns and business logic flaws
- **Data Flow Mapping**: How sensitive information moves through the application
- **Privilege Boundaries**: User role separation and potential escalation paths

Provide comprehensive intelligence briefing with prioritized attack vectors and custom exploitation recommendations. Include technology confidence assessment."""

    def _get_false_positive_prompt(self) -> str:
        return """You are a senior penetration tester validating vulnerability findings with the precision required for executive-level reporting. Your reputation depends on accurate assessment of genuine security risks.

Vulnerability Assessment Data:
{assessment_data}

Apply expert validation methodology:

1. **Exploitability Confirmation**: Technical verification of actual security impact vs theoretical risk
2. **Business Context Analysis**: Real-world exploitation scenarios and practical attack vectors  
3. **False Positive Elimination**: Distinguishing genuine vulnerabilities from scanner artifacts
4. **Risk Quantification**: CVSS scoring with environmental and temporal considerations
5. **Remediation Complexity**: Development effort required vs security improvement gained
6. **Compensating Controls**: Existing protections that mitigate or eliminate risk

Evidence Evaluation Criteria:
- **Response Analysis**: Distinguishing error conditions from actual exploitation evidence
- **Timing Correlation**: Separating causation from coincidence in timing-based tests  
- **Context Validation**: Confirming vulnerability exists in actual application context

Provide definitive assessment with confidence scoring (1-10) and recommended next steps for confirmed vulnerabilities. Include EXPLOITABLE/NOT_EXPLOITABLE classification."""

    def _can_use_provider(self, provider: AIProvider) -> bool:
        """Check if provider is available considering rate limits and health"""
        now = datetime.now()
        
        # Reset counters if needed
        if now - provider.last_reset > timedelta(minutes=1):
            provider.current_usage["minute"] = 0
            provider.current_usage["requests_this_minute"] = []
            provider.last_reset = now
        
        if now - provider.last_reset > timedelta(days=1):
            provider.current_usage["day"] = 0
        
        # Check limits
        if provider.current_usage["minute"] >= provider.rpm_limit:
            return False
        if provider.current_usage["day"] >= provider.daily_limit:
            return False
        if provider.health_score < 0.3:  # Provider is unhealthy
            return False
        
        return True
    
    def _select_optimal_provider(self, task_type: TaskType, context_size: int) -> Optional[AIProvider]:
        """Enhanced provider selection with priority-based fallback logic"""
        available_providers = [p for p in self.providers if self._can_use_provider(p)]
        
        if not available_providers:
            return None
        
        # For smart mode, strongly prefer free providers
        if self.mode == 'smart':
            free_providers = [p for p in available_providers if p.cost_per_token == 0.0]
            if free_providers:
                # Among free providers, select based on task type
                if task_type == TaskType.WAF_EVASION:
                    return min(free_providers, key=lambda x: x.avg_response_time or 0)
                elif task_type == TaskType.VULNERABILITY_ANALYSIS:
                    return max(free_providers, key=lambda x: x.context_window)
                else:
                    return max(free_providers, key=lambda x: x.success_rate * x.health_score)
        
        # Sort by priority (1 = highest priority = free providers first)
        available_providers.sort(key=lambda x: (x.priority, -x.success_rate * x.health_score))
        
        # For context-heavy tasks, ensure provider can handle it
        if context_size > 4000:
            suitable = [p for p in available_providers if p.context_window >= context_size]
            if suitable:
                return suitable[0]
        
        return available_providers[0]
    
    def _estimate_request_cost(self, prompt: str, expected_response: int = 500) -> float:
        """Estimate cost of AI request"""
        # Rough token estimation (more accurate than simple word count)
        input_tokens = len(prompt.split()) * 1.3  # Words to tokens approximation
        output_tokens = expected_response
        total_tokens = input_tokens + output_tokens
        
        # Cost per million tokens (Perplexity pricing)
        return (total_tokens / 1_000_000) * 1.0  # $1 per million tokens
    
    def _update_provider_stats(self, provider: AIProvider, response_time: float, success: bool, cost: float = 0.0):
        """Update provider performance statistics and costs"""
        provider.current_usage["minute"] += 1
        provider.current_usage["day"] += 1
        provider.current_usage["requests_this_minute"].append(time.time())
        
        # Update cost tracking
        if cost > 0:
            self.current_usage += cost
        
        # Update performance metrics
        if provider.avg_response_time == 0:
            provider.avg_response_time = response_time
        else:
            provider.avg_response_time = (provider.avg_response_time * 0.8) + (response_time * 0.2)
        
        # Update success rate (rolling average)
        provider.success_rate = (provider.success_rate * 0.9) + (0.1 if success else 0.0)
        
        # Update health score based on recent performance
        if success:
            provider.health_score = min(1.0, provider.health_score + 0.1)
        else:
            provider.health_score = max(0.0, provider.health_score - 0.2)

    async def _make_request(self, provider: AIProvider, messages: List[Dict]) -> Dict:
        """Make actual API request to provider"""
        headers = {
            "Authorization": f"Bearer {provider.api_key}",
            "Content-Type": "application/json"
        }
        
        # Provider-specific headers
        if "openrouter" in provider.name:
            headers["HTTP-Referer"] = "https://webx-scanner.com"
            headers["X-Title"] = "WebX Elite Security Scanner"
        elif "perplexity" in provider.name:
            # Perplexity-specific headers if needed
            headers["User-Agent"] = "WebX-Scanner/9.0-AI"
        
        payload = {
            "model": provider.model,
            "messages": messages,
            "temperature": 0.1,  # Low temperature for consistent, focused analysis
            "max_tokens": 2048
        }
        
        start_time = time.time()
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(provider.base_url, headers=headers, json=payload, timeout=30) as response:
                    response_time = time.time() - start_time
                    
                    if response.status == 200:
                        result = await response.json()
                        
                        # Calculate actual cost for paid providers
                        cost = 0.0
                        if provider.cost_per_token > 0:
                            # Estimate tokens from response
                            response_content = result.get("choices", [{}])[0].get("message", {}).get("content", "")
                            estimated_tokens = len(response_content.split()) * 1.3
                            cost = (estimated_tokens / 1_000_000) * provider.cost_per_token
                        
                        self._update_provider_stats(provider, response_time, True, cost)
                        return result
                    
                    elif response.status == 429:
                        # Rate limit hit
                        self._update_provider_stats(provider, response_time, False)
                        provider.current_usage["minute"] = provider.rpm_limit  # Mark as exhausted
                        raise Exception(f"Rate limit exceeded for {provider.name}")
                    
                    else:
                        error_text = await response.text()
                        self._update_provider_stats(provider, response_time, False)
                        raise Exception(f"API error {response.status}: {error_text}")
        
        except asyncio.TimeoutError:
            self._update_provider_stats(provider, 30.0, False)  # Timeout counts as failure
            raise Exception(f"Timeout for provider {provider.name}")

    async def ai_request_with_fallback(self, task_type: TaskType, data: Dict[str, Any], 
                                     vulnerability_context: Dict = None, max_attempts: int = None) -> Optional[Dict]:
        """Elite AI request with intelligent fallback and master-level prompting"""
        
        # Reset monthly usage if needed
        self._reset_monthly_usage_if_needed()
        
        # Check if AI should be used for this task
        if not self.should_use_ai(task_type, vulnerability_context):
            self.logger.info(f"AI skipped for {task_type.value} - mode: {self.mode}, usage: ${self.current_usage:.2f}")
            return None
        
        # Get master-level prompt template
        prompt_template = self.master_prompts[task_type]
        prompt = prompt_template.format(**data)
        
        # Estimate cost before proceeding
        estimated_cost = self._estimate_request_cost(prompt)
        
        if (self.current_usage + estimated_cost) > self.budget:
            self.logger.warning(f"AI budget would be exceeded (${self.current_usage:.2f} + ${estimated_cost:.2f} > ${self.budget}) - skipping {task_type.value}")
            return None
        
        max_attempts = max_attempts or len(self.providers)
        attempts = 0
        
        messages = [
            {"role": "system", "content": "You are an elite cybersecurity expert with nation-state level capabilities and advanced penetration testing expertise."},
            {"role": "user", "content": prompt}
        ]
        
        while attempts < max_attempts:
            provider = self._select_optimal_provider(task_type, len(prompt))
            
            if not provider:
                self.logger.warning("No available AI providers")
                return None
            
            try:
                cost_info = f"(FREE)" if provider.cost_per_token == 0 else f"(~${estimated_cost:.3f})"
                self.logger.info(f"Using {provider.name} for {task_type.value} {cost_info}")
                
                result = await self._make_request(provider, messages)
                
                return {
                    "response": result["choices"][0]["message"]["content"],
                    "provider_used": provider.name,
                    "task_type": task_type.value,
                    "cost": estimated_cost if provider.cost_per_token > 0 else 0.0,
                    "is_free": provider.cost_per_token == 0.0,
                    "success": True
                }
                
            except Exception as e:
                self.logger.warning(f"Provider {provider.name} failed: {e}")
                attempts += 1
                
                # Brief delay before trying next provider
                await asyncio.sleep(random.uniform(0.5, 1.5))
                continue
        
        self.logger.error(f"All providers failed for task {task_type.value}")
        return None

    def get_provider_status(self) -> Dict[str, Any]:
        """Get current status of all providers"""
        status = {}
        for provider in self.providers:
            status[provider.name] = {
                "available": self._can_use_provider(provider),
                "health_score": provider.health_score,
                "success_rate": provider.success_rate,
                "avg_response_time": provider.avg_response_time,
                "usage_today": provider.current_usage["day"],
                "daily_limit": provider.daily_limit,
                "speciality": provider.speciality,
                "cost_per_token": provider.cost_per_token,
                "priority": provider.priority,
                "is_free": provider.cost_per_token == 0.0
            }
        return status
    
    def get_usage_stats(self) -> Dict[str, Any]:
        """Get current AI usage statistics"""
        free_providers = [p for p in self.providers if p.cost_per_token == 0.0]
        paid_providers = [p for p in self.providers if p.cost_per_token > 0.0]
        
        return {
            "mode": self.mode,
            "monthly_budget": self.budget,
            "current_usage": self.current_usage,
            "remaining_budget": self.budget - self.current_usage,
            "budget_percentage_used": (self.current_usage / self.budget) * 100,
            "provider_count": len(self.providers),
            "free_providers": len(free_providers),
            "paid_providers": len(paid_providers),
            "free_provider_names": [p.name for p in free_providers],
            "paid_provider_names": [p.name for p in paid_providers],
            "monthly_reset_date": self.monthly_reset_date.isoformat()
        }

    def can_afford_request(self, estimated_cost: float) -> bool:
        """Check if we can afford a request within budget"""
        return (self.current_usage + estimated_cost) <= (self.budget * 0.95)  # 5% buffer


# Global AI provider instance
ai_provider_pool = None


def initialize_ai_providers(budget: float = None, mode: str = None):
    """Initialize AI providers from environment variables"""
    global ai_provider_pool
    try:
        ai_provider_pool = AIProviderPool(budget, mode)
        return ai_provider_pool
    except ValueError as e:
        logging.error(f"AI initialization failed: {e}")
        return None


def get_ai_provider() -> Optional[AIProviderPool]:
    """Get the global AI provider pool"""
    return ai_provider_pool


def check_env_configuration() -> Dict[str, Any]:
    """Check which API keys are available in environment"""
    config_status = {
        "groq_available": bool(os.getenv('GROQ_API_KEY')),
        "openrouter_available": bool(os.getenv('OPENROUTER_API_KEY')),
        "perplexity_available": bool(os.getenv('PERPLEXITY_API_KEY')),
        "budget": float(os.getenv('AI_MONTHLY_BUDGET', 5.0)),
        "default_mode": os.getenv('AI_DEFAULT_MODE', 'smart'),
        "env_file_exists": os.path.exists('.env')
    }
    
    config_status["total_providers"] = sum([
        config_status["groq_available"],
        config_status["openrouter_available"], 
        config_status["perplexity_available"]
    ])
    
    return config_status
