<p align="center">
    <img src="https://i.imgur.com/JQ9w8bU.png" alt="WebX Logo" width="300"/>
</p>

<h1 align="center">WebX</h1>
<p align="center">
    <b>Professional Web Vulnerability Scanner</b><br>
    <i>Automated, payload-driven security testing for web applications</i>
</p>

---

## 🚀 Overview

**WebX** is an advanced web vulnerability scanner designed for security professionals and bug bounty hunters. It automates the detection of common web vulnerabilities using a payload-driven approach.

---

## ✨ Features

- **Multiple Vulnerability Detection**
    - 🐞 SQL Injection (SQLi)
    - 🛡️ Cross-Site Scripting (XSS)
    - 🔗 Open Redirection
    - 📁 Path Traversal
    - 🌐 Server-Side Request Forgery (SSRF)
    - 🔒 CORS Misconfigurations
    - 🔑 JWT Issues

- **Payload-Driven Architecture**
    - Easy-to-update payload files
    - Customizable testing scenarios
    - Organized by vulnerability type

- **User-Friendly Interface**
    - Interactive CLI menu
    - Clear vulnerability reporting
    - Configurable scan options

---

## 🛠️ Installation

### Prerequisites

- Python 3.8+
- `pip` package manager

### Setup

```bash
git clone https://github.com/yourusername/WebX.git
cd WebX
pip install -r requirements.txt
```

Payload files are automatically created on first run:

```bash
mkdir -p payloads
```

---

## ⚡ Usage

### Basic Scan

```bash
python webx.py
```

Follow the interactive menu to:

- Enter target URL (e.g., `http://example.com`)
- Select vulnerabilities to test
- View results

### Command Line Options

```bash
python webx.py --help
```

---

## ⚙️ Environment Variables

Create a `.env` file to customize:

```ini
USER_AGENT="WebX/1.0 (+https://github.com/yourusername/WebX)" # use while doing bug bounty
USER_AGENT="Mozilla/5.0" # use while testing 
REQUEST_DELAY=0.5  # Seconds between requests
MAX_THREADS=5      # Concurrent requests
```

---

## 🧩 Payload Customization

Edit payload files in the `payloads/` directory:

- `sql.txt` - SQL injection payloads
- `xss.txt` - XSS payloads
- `redirect.txt` - Open redirection payloads
- `traversal.txt` - Path traversal payloads
- `ssrf.txt` - SSRF testing endpoints
- `cors.txt` - CORS misconfiguration tests
- `jwt.txt` - JWT attack vectors

---

## 📋 Example Output    

```

██╗    ██╗███████╗██████╗ ██╗  ██╗
██║    ██║██╔════╝██╔══██╗╚██╗██╔╝
██║ █╗ ██║█████╗  ██████╔╝ ╚███╔╝ 
██║███╗██║██╔══╝  ██╔══██╗ ██╔██╗ 
╚███╔███╔╝███████╗██████╔╝██╔╝ ██╗
╚══╝╚══╝ ╚══════╝╚═════╝ ╚═╝  ╚═╝

[!] Found Vulnerabilities:
============================================================
1. SQL Injection
     URL: http://testphp.vulnweb.com/artists.php?artist=1'
     Details: Parameter 'artist' appears vulnerable to SQLi
     Time: 2023-11-15 14:30:22
------------------------------------------------------------
2. XSS
     URL: http://testphp.vulnweb.com/search.php?query=<script>
     Details: Reflected XSS in parameter 'query'
     Time: 2023-11-15 14:31:05
============================================================
Total vulnerabilities found: 2
```

---

## 📄 License

Distributed under the MIT License. See [`LICENSE`](LICENSE) for more information.

---

## ⚠️ Disclaimer

> This tool is intended for security testing and educational purposes only. Only use on systems you own or have permission to test. The developers assume no liability for misuse of this software.

---

