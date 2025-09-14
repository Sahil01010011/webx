

*\# WebX Elite Configuration*

*\# General Scanner Settings*
*USER\_AGENT*=Mozilla/5.0 (Windows NT 10.0*; Win64; x64) AppleWebKit/537.36*
*REQUEST\_DELAY*=0.5                     *\# Delay between requests in seconds (float allowed)*
*MAX\_THREADS*=10                       *\# Max concurrent threads or async tasks*
*STEALTH\_MODE*=false                   *\# Enable stealth mode if applicable (true/false)*
*AI\_ENHANCEMENT*=true                  *\# Enable AI enhanced analysis (true/false)*

*\# Proxy Settings (Optional)*
*\# HTTP\_PROXY=                         \# Example:&#32;[http://127.0.0.1:8080](http://127.0.0.1:8080)
*\# HTTPS\_PROXY=                        \# Example:&#32;[https://127.0.0.1:8080](https://127.0.0.1:8080)

*\# Database Settings***
*DATABASE\_PATH*=webx\_results.db       *\# SQLite DB file path for storing scan results*

*\# AI Providers \& API Keys*
*\# Keep keys secret, do NOT commit .env to source control!*

*\# Free AI Providers (Primary)*
*GROQ\_API\_KEY*=your\_groq\_api\_key\_here
*OPENROUTER\_API\_KEY*=your\_openrouter\_api\_key\_here

*\# Paid AI Provider (Fallback)*
*PERPLEXITY\_API\_KEY*=your\_perplexity\_api\_key\_here

*\# AI Global Settings*
*AI\_MONTHLY\_BUDGET*=5.0               *\# USD budget controlling AI usage per month*
*AI\_DEFAULT\_MODE*=smart               *\# Options: none, smart, full*

*\# Additional Options (Optional - uncomment if needed)*

*\# JavaScript crawling via Playwright/Selenium (if applicable)*
*\# ENABLE\_JS=true*

*\# OAST Configuration (if you run your own server or use a custom domain)*
*\# OAST\_SERVER\_URL=http://your-oast-server.com*

*\# Logging Level (DEBUG, INFO, WARNING, ERROR)*
*\# LOG\_LEVEL=INFO*

Here's the updated README.md file with the environment configuration section included:

***

# **WebX Elite Security Assessment Platform v10.0**

**WebX Elite** is a next-generation security assessment tool for web applications. With advanced crawling, AI-driven vulnerability analysis, out-of-band detection, and template-driven extensibility, it's designed for security professionals and penetration testers who need robust, customizable, and efficient web security scans.

***

## **Features**

- **Interactive \& Non-Interactive Scanning:** Choose guided interactive workflows or automated batch scans.
- **Template-Based Vulnerability Detection:** Easily extendable template support (.json/.yaml/.yml) for custom or community detection.
- **AI-Enhanced Analysis:** Supports Groq, OpenRouter, Perplexity for deeper heuristic analysis and smart triage (*requires API keys*).
- **Out-of-Band Testing (OAST):** Detects vulnerabilities requiring external callbacks.
- **Heuristic Categorization:** Automatic detection and prioritization of likely vulnerable entry points.
- **Concurrent, Production-Grade Engine:** Scans with configurable concurrency, delay, timeout.
- **Colorized Output:** Intuitive CLI feedback with visuals and banners.
- **Professional HTML Reporting:** Generates detailed, styled summary reports after scans.
- **Flexible Configuration:** Custom user-agent, proxy, scan control, and modular reporting.

***

## **Installation**

1. **Clone the repository**

```bash
git clone https://github.com/Sahil01010011/webx.git
cd webx-elite
```

2. **Install dependencies**

```bash
pip install -r requirements.txt
```

*Recommended:*

```bash
pip install pyfiglet
```

3. **Set up environment configuration**

```bash
cp .env.example .env
# Edit .env with your preferred settings and API keys
```


***

## **Configuration**

WebX Elite uses a `.env` file for configuration. Create one based on the template below:

```bash
# WebX Elite Configuration

# General Scanner Settings
USER_AGENT=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
REQUEST_DELAY=0.5                     # Delay between requests in seconds (float allowed)
MAX_THREADS=10                       # Max concurrent threads or async tasks
STEALTH_MODE=false                   # Enable stealth mode if applicable (true/false)
AI_ENHANCEMENT=true                  # Enable AI enhanced analysis (true/false)

# Proxy Settings (Optional)
# HTTP_PROXY=                         # Example: http://127.0.0.1:8080
# HTTPS_PROXY=                        # Example: https://127.0.0.1:8080

# Database Settings
DATABASE_PATH=webx_results.db       # SQLite DB file path for storing scan results

# AI Providers & API Keys
# Keep keys secret, do NOT commit .env to source control!

# Free AI Providers (Primary)
GROQ_API_KEY=your_groq_api_key_here
OPENROUTER_API_KEY=your_openrouter_api_key_here

# Paid AI Provider (Fallback)
PERPLEXITY_API_KEY=your_perplexity_api_key_here

# AI Global Settings
AI_MONTHLY_BUDGET=5.0               # USD budget controlling AI usage per month
AI_DEFAULT_MODE=smart               # Options: none, smart, full

# Additional Options (Optional - uncomment if needed)

# JavaScript crawling via Playwright/Selenium (if applicable)
# ENABLE_JS=true

# OAST Configuration (if you run your own server or use a custom domain)
# OAST_SERVER_URL=http://your-oast-server.com

# Logging Level (DEBUG, INFO, WARNING, ERROR)
# LOG_LEVEL=INFO
```


### **AI Provider Setup**

To get the most out of WebX Elite's AI capabilities, obtain API keys from:

- **Groq (Free):** Visit [https://console.groq.com/](https://console.groq.com/) to get your free API key
- **OpenRouter (Free):** Sign up at [https://openrouter.ai/](https://openrouter.ai/) for free credits
- **Perplexity (Paid):** Get your API key from [https://www.perplexity.ai/settings/api](https://www.perplexity.ai/settings/api)

**⚠️ Security Note:** Never commit your `.env` file to version control. Add it to your `.gitignore`.

***

## **Quick Start**

**Interactive scan:**

```bash
python webx.py -u https://testphp.vulnweb.com
```

**Automated scan for specific vulnerabilities:**

```bash
python webx.py -u https://api.example.com --scan-vuln sqli xss
```

**Full scan, all vulnerability types:**

```bash
python webx.py -u https://example.com --scan-all
```

**Scan with custom AI mode:**

```bash
python webx.py -u https://example.com --ai-mode full --scan-all
```


***

## **Command-Line Options**

| Argument | Description |
| :-- | :-- |
| -u, --url | Target base URL (required) |
| -t, --templates | Templates directory (default: templates/) |
| --scan-vuln | Specific vulnerabilities to scan for (e.g. sqli xss) |
| --scan-all | Scan all detected vulnerability categories |
| --user-agent | Custom User-Agent string |
| --proxy | Proxy URL (e.g., http://127.0.0.1:8080) |
| --delay | Delay (ms) between requests |
| --timeout | Request timeout per scan (default: 30s) |
| -c, --concurrency | Number of concurrent scan tasks |
| --ai-mode | AI analysis: none, smart, or full |
| -o, --output | Output base file for HTML report |


***

## **Template System**

Templates let you describe new vulnerabilities in JSON/YAML. Each template requires:

- `id`: Unique template identifier
- `info`: Dictionary with `name` (string), `severity` (info, low, medium, high, critical), plus optional `description`, `tags`, `category`
- `request`: Dictionary describing the HTTP interaction

**Example template:**

```json
{
  "id": "basic-xss",
  "info": {
    "name": "Basic Reflected XSS",
    "severity": "medium",
    "description": "Detects traditional reflected XSS.",
    "tags": ["xss", "injection"]
  },
  "request": {
    "method": "GET",
    "path": "/search",
    "params": {
      "q": "{{payload}}"
    }
  }
}
```

Place templates in the `templates/` directory, organized by category if desired.

***

## **AI Integration**

WebX Elite supports three AI enhancement modes:

- **none**: Disable AI analysis
- **smart** (default): AI-powered heuristic analysis for target prioritization
- **full**: Complete AI analysis including vulnerability assessment and payload optimization

The AI system respects your monthly budget settings and will automatically throttle usage to stay within limits.

***

## **Reporting**

- **Real-time findings:** Print as soon as vulnerabilities are discovered
- **HTML reports:** Saved automatically in the `reports/` directory at the end of each scan
- **Coverage statistics:** Breakdown by vulnerability type and severity
- **Database storage:** Results stored in SQLite database for historical tracking

***

## **Contributing**

Contributions welcome! Submit PRs for scanners, templates, or features.

- Fork the repo and branch from `main`
- Submit a pull request with a clear description

***

## **License**

MIT License (see `LICENSE` for full details).

***

## **Credits**

Developed by **shadowxp**.
For bug reports or feature requests, open a GitHub Issue.

***

**WebX Elite:** Next-generation web security assessment for professionals.

***

This updated README now includes comprehensive configuration information and makes it clear how users should set up their environment for optimal performance with AI features.

