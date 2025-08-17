#!/usr/bin/env python3
# webx.py - WebX Elite Security Assessment Platform v10.0

import argparse
import asyncio
import time
import sys
import os
import requests
import urllib3
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
from colorama import init, Fore, Style, Back
from typing import Dict, List, Any
import logging

# Banner specific imports
import shutil
import math
import random

try:
    from pyfiglet import Figlet
except Exception:
    Figlet = None

# Core imports for advanced modules
from core.template_parser import (
    load_templates_by_category,
    get_template_statistics,
)
from core.heuristics import (
    comprehensive_vulnerability_analysis
)
from core.engine import run_scan
from core.reporter import AdvancedReporter
from core.crawler import crawl, production_crawler
from core.oast_client import EnhancedOASTClient
from core.ai_provider import (
    initialize_ai_providers,
    check_env_configuration
)
from core.http_client import reset_client_statistics

# .env
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

# Configure logging
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO').upper()
logging.basicConfig(
    level=LOG_LEVEL,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('webx.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
# Quieten noisy libraries
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("asyncio").setLevel(logging.WARNING)

logger = logging.getLogger(__name__)


# --- Start of Integrated Banner Code ---

ESC = "\033["

def rgb(r, g, b):
    return f"{ESC}38;2;{r};{g};{b}m"

def reset():
    return f"{ESC}0m"

def make_figlet_text(text: str, font: str = "doom") -> str:
    if Figlet:
        try:
            f = Figlet(font=font)
            return f.renderText(text)
        except Exception:
            # Fallback if the font is not found
            f = Figlet(font="slant")
            return f.renderText(text)
            
    # Fallback if pyfiglet is not installed
    lines = [
        " __      __   ______   __  __ ",
        " \\ \\    / /  |  ____| |  \\/  |",
        "  \\ \\  / /   | |__    | \\  / |",
        "   \\ \\/ /    |  __|   | |\\/| |",
        "    \\  /     | |____  | |  | |",
        "     \\/      |______| |_|  |_|",
    ]
    return "\n".join(lines) + "\n"

def gradient_for_pos(start_rgb, end_rgb, t):
    return (
        int(start_rgb[0] + (end_rgb[0] - start_rgb[0]) * t),
        int(start_rgb[1] + (end_rgb[1] - start_rgb[1]) * t),
        int(start_rgb[2] + (end_rgb[2] - start_rgb[2]) * t),
    )

def colored_gradient_text(ascii_text: str, start_rgb, end_rgb, width=None):
    """Apply a horizontal gradient across the rendered ascii art."""
    lines = ascii_text.rstrip("\n").splitlines()
    if not lines:
        return []
    if width is None:
        width = max(len(l) for l in lines)
    out_lines = []
    for line in lines:
        padded = line.ljust(width)
        colored = []
        for i, ch in enumerate(padded):
            t = i / max(1, width - 1)
            r, g, b = gradient_for_pos(start_rgb, end_rgb, t)
            colored.append(f"{rgb(r,g,b)}{ch}")
        out_lines.append("".join(colored) + reset())
    return out_lines

def print_elite_banner():
    """
    Prints the integrated, styled banner for WebX Elite.
    """
    text = "WEBX"
    tagline = "v10.0 Elite :: A Next-Generation Web Security Scanner By shadowxp"
    font = "doom"
    
    # Terminal width
    try:
        term_w = shutil.get_terminal_size().columns
    except Exception:
        term_w = 100

    ascii_text = make_figlet_text(text, font=font)
    lines = ascii_text.rstrip("\n").splitlines()
    
    # Fallback for empty figlet generation
    if not lines:
        print("WEBX Elite v10.0")
        return

    width = max(len(l) for l in lines)

    # Optional: restrict the figure size a bit if it's too wide
    if width > term_w - 4 and Figlet:
        ascii_text = make_figlet_text(text, font="slant")
        lines = ascii_text.rstrip("\n").splitlines()
        width = max(len(l) for l in lines) if lines else 0

    # Define the original red-themed color scheme
    start_rgb = (255, 80, 60)      # Bright Red-Orange
    end_rgb = (140, 0, 10)         # Deep Crimson
    tag_color = (255, 120, 120)    # Light Red
    underline_color = (200, 50, 50) # Strong Red

    colored_lines = colored_gradient_text(ascii_text, start_rgb, end_rgb, width=width)
    
    # Center and print each line of the banner
    pad = (term_w - width) // 2
    for line in colored_lines:
        print(" " * pad + line)

    # Tagline
    # Note: The tagline is now also red to match the theme.
    tag_colored = f"{rgb(*tag_color)}{tagline.center(term_w)}{reset()}"
    print(tag_colored)

    # Underline
    underline = f"{rgb(*underline_color)}" + ("═" * min(term_w - 2, 80)).center(term_w) + reset()
    print(underline)

# --- End of Integrated Banner Code ---


def print_system_info():
    # This function uses the original colorama Fore colors, which is fine.
    print(f"\n{Fore.CYAN}🔧 SYSTEM CONFIGURATION:{Style.RESET_ALL}")
    print("─" * 40)
    env_config = check_env_configuration()
    if env_config["env_file_exists"]:
        print(f"{Fore.GREEN}✓ Configuration file: .env loaded")
    else:
        print(f"{Fore.YELLOW}⚠ Configuration file: .env not found")
    ai_providers = []
    if env_config["groq_available"]:
        ai_providers.append("Groq (FREE)")
    if env_config["openrouter_available"]:
        ai_providers.append("OpenRouter (FREE)")
    if env_config["perplexity_available"]:
        ai_providers.append("Perplexity (PAID)")
    if ai_providers:
        print(f"{Fore.GREEN}✓ AI Providers: {', '.join(ai_providers)}")
    else:
        print(f"{Fore.RED}✗ AI Providers: None configured")
    try:
        template_stats = get_template_statistics("templates/")
        print(f"{Fore.GREEN}✓ Templates: {template_stats.get('templates_loaded', 0)} loaded")
        print(f"   └─ Categories: {len(template_stats.get('category_distribution', {}))}")
    except:
        print(f"{Fore.YELLOW}⚠ Templates: Directory not found or empty")
    print()

def print_finding_immediately(finding: Dict):
    """Prints a single finding to the console as soon as it's discovered."""
    info = finding.get('info', {})
    details = finding.get('details', {})
    severity = info.get('severity', 'info').upper()
    
    severity_colors = {
        'CRITICAL': Fore.RED + Style.BRIGHT,
        'HIGH': Fore.LIGHTRED_EX,
        'MEDIUM': Fore.YELLOW,
        'LOW': Fore.LIGHTBLUE_EX,
        'INFO': Fore.WHITE
    }
    color = severity_colors.get(severity, Fore.WHITE)

    print(f"\n\n{color}[🔥 VULNERABILITY FOUND!]--------------------------------{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}Name:      {Style.BRIGHT}{info.get('name', 'N/A')}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}Severity:  {color}{severity}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}URL:       {details.get('url', 'N/A')}")
    print(f"  {Fore.WHITE}Parameter: {details.get('parameter', 'N/A')}")
    print(f"  {Fore.WHITE}Payload:   {Fore.YELLOW}{details.get('payload', 'N/A')}{Style.RESET_ALL}")
    print(f"{color}------------------------------------------------------{Style.RESET_ALL}\n")


def create_argument_parser():
    parser = argparse.ArgumentParser(
        description="WebX Elite v10.0 - A Next-Generation Web Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Fore.CYAN}EXAMPLES:{Style.RESET_ALL}
  # Run in interactive mode (recommended)
  python webx.py -u http://testphp.vulnweb.com

  # Run a non-interactive scan for specific vulnerabilities
  python webx.py -u https://api.example.com --scan-vuln sqli xss

  # Run a full, non-interactive scan for all detected vulnerability types
  python webx.py -u https://example.com --scan-all
        """
    )
    # Target and scan options
    target_group = parser.add_argument_group('Target Configuration')
    target_group.add_argument("-u", "--url", required=True, help="Target base URL")
    target_group.add_argument("-t", "--templates", default="templates/", help="Path to templates directory")
    target_group.add_argument("--user-agent", default="WebX-Elite/10.0", help="Custom User-Agent")
    target_group.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")
    
    scan_group = parser.add_argument_group('Scan Control')
    scan_group.add_argument("--scan-vuln", nargs='+', help="Run a non-interactive scan for specific vulnerability types (e.g., xss, sqli)")
    scan_group.add_argument("--scan-all", action="store_true", help="Run a non-interactive scan for all detected vulnerability types")
    
    config_group = parser.add_argument_group('Scan Configuration')
    config_group.add_argument("--delay", type=int, default=0, help="Delay in milliseconds between requests")
    config_group.add_argument("--timeout", type=int, default=30, help="Request timeout in seconds")
    config_group.add_argument("-c", "--concurrency", type=int, default=10, help="Number of concurrent tasks (default: 10)")

    ai_group = parser.add_argument_group('AI Enhancement')
    ai_group.add_argument("--ai-mode", choices=['none', 'smart', 'full'],
                          default=os.getenv('AI_DEFAULT_MODE', 'smart'),
                          help="AI analysis mode")
    
    output_group = parser.add_argument_group('Output Configuration')
    output_group.add_argument("-o", "--output", help="Base filename for the final HTML report")
    
    return parser


async def main():
    parser = create_argument_parser()
    args = parser.parse_args()
    
    print_elite_banner()
    print_system_info()

    # --- Initialization ---
    session = requests.Session()
    session.headers.update({'User-Agent': args.user_agent})
    reporter = AdvancedReporter()
    session_findings = []
    
    original_base_url = args.url
    if not original_base_url.startswith(('http://', 'https://')):
        original_base_url = f"http://{original_base_url}"
    
    print(f"{Fore.WHITE}🎯 Target: {Style.BRIGHT}{original_base_url}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}🤖 AI Mode: {args.ai_mode.upper()}{Style.RESET_ALL}")

    initialize_ai_providers(mode=args.ai_mode)
    
    # --- Phase 1: Discovery & Analysis ---
    print(f"\n{Fore.CYAN}{'═' * 20} PHASE 1: DISCOVERY & ANALYSIS {'═' * 20}{Style.RESET_ALL}")
    print("[*] Discovering injection points with advanced crawling...")
    start_time = time.time()
    injection_points = await crawl(session, original_base_url, proxy=args.proxy)
    
    if not injection_points:
        print(f"{Fore.RED}[-] No injection points found. Exiting.{Style.RESET_ALL}")
        return

    print(f"\n[+] Discovery complete in {time.time() - start_time:.1f}s. Found {len(injection_points)} unique injection points.")
    print("[*] Running heuristic analysis to identify potential vulnerabilities...")
    
    heuristic_results = await comprehensive_vulnerability_analysis(session, injection_points, proxy=args.proxy, enable_ai=(args.ai_mode != 'none'))
    categorized_points = heuristic_results.get('categorized_parameters', {})
    
    print(f"[+] {Fore.GREEN}Analysis complete.{Style.RESET_ALL} Potential targets identified.")

    # --- Phase 2: Interactive or Non-Interactive Scanning ---
    scan_list = []
    if args.scan_all:
        scan_list = list(categorized_points.keys())
    elif args.scan_vuln:
        scan_list = args.scan_vuln
    else:
        # Interactive Mode Loop
        while True:
            print(f"\n{Fore.CYAN}{'═' * 25} TACTICAL SCANNING MENU {'═' * 25}{Style.RESET_ALL}")
            
            scan_options = {}
            option_num = 1
            sorted_categories = sorted(categorized_points.items(), key=lambda item: len(item[1]), reverse=True)

            for vuln_type, targets in sorted_categories:
                if targets:
                    scan_options[str(option_num)] = vuln_type
                    print(f"  {Style.BRIGHT}[{option_num}]{Style.NORMAL} {vuln_type.upper():<20} ({len(targets)} potential targets)")
                    option_num += 1

            if not scan_options:
                print(f"{Fore.YELLOW}[-] No potential vulnerabilities identified by heuristics.{Style.RESET_ALL}")
                break

            print(f"\n  {Style.BRIGHT}[A]{Style.NORMAL} Scan All Detected Categories")
            print(f"  {Style.BRIGHT}[Q]{Style.NORMAL} Quit and Generate Report")
            
            choice = input(f"\n{Style.BRIGHT}Select an option to scan: {Style.RESET_ALL}").strip().lower()

            if choice == 'q':
                break
            
            if choice == 'a':
                scan_list = list(scan_options.values())
            elif choice in scan_options:
                scan_list = [scan_options[choice]]
            else:
                print(f"{Fore.RED}[-] Invalid selection.{Style.RESET_ALL}")
                continue # Go back to showing the menu

            # --- This block runs the selected scan(s) inside the loop ---
            print(f"\n{Fore.CYAN}{'═' * 20} PHASE 2: ASSESSMENT {'═' * 20}{Style.RESET_ALL}")
            for vuln_type in scan_list:
                targets = categorized_points.get(vuln_type)
                if not targets:
                    print(f"\n{Fore.YELLOW}[-] No potential targets found for {vuln_type.upper()}, skipping.{Style.RESET_ALL}")
                    continue

                print(f"\n{Fore.YELLOW}[*] Loading templates for {vuln_type.upper()}...{Style.RESET_ALL}")
                templates = load_templates_by_category(args.templates, vuln_type)
                if not templates:
                    print(f"{Fore.YELLOW}[-] No templates found for {vuln_type}.{Style.RESET_ALL}")
                    continue
                
                print(f"[+] Loaded {len(templates)} templates. Starting scan on {len(targets)} targets.")
                
                scan_findings = await run_scan(targets, templates, args.user_agent, args.delay, args.concurrency, args.proxy)
                
                if scan_findings:
                    for finding in scan_findings:
                        print_finding_immediately(finding)
                        session_findings.append(finding)
                
                print(f"\n{Fore.GREEN}[+] {vuln_type.upper()} scan complete.{Style.RESET_ALL}")
            scan_list = [] # Clear the list to loop back to the menu
    
    # This block runs for non-interactive scans
    if scan_list:
        print(f"\n{Fore.CYAN}{'═' * 20} PHASE 2: ASSESSMENT {'═' * 20}{Style.RESET_ALL}")
        for vuln_type in scan_list:
            targets = categorized_points.get(vuln_type)
            if not targets:
                print(f"\n{Fore.YELLOW}[-] No potential targets found for {vuln_type.upper()}, skipping.{Style.RESET_ALL}")
                continue

            print(f"\n{Fore.YELLOW}[*] Loading templates for {vuln_type.upper()}...{Style.RESET_ALL}")
            templates = load_templates_by_category(args.templates, vuln_type)
            if not templates:
                print(f"{Fore.YELLOW}[-] No templates found for {vuln_type}.{Style.RESET_ALL}")
                continue
            
            print(f"[+] Loaded {len(templates)} templates. Starting scan on {len(targets)} targets.")
            
            scan_findings = await run_scan(targets, templates, args.user_agent, args.delay, args.concurrency, args.proxy)
            
            if scan_findings:
                for finding in scan_findings:
                    print_finding_immediately(finding)
                    session_findings.append(finding)
            
            print(f"\n{Fore.GREEN}[+] {vuln_type.upper()} scan complete.{Style.RESET_ALL}")

    # --- Phase 3: Reporting and Cleanup ---
    print(f"\n{Fore.CYAN}{'═' * 20} FINAL SUMMARY {'═' * 20}{Style.RESET_ALL}")
    
    if session_findings:
        # Automatic report generation on quit
        print(f"\n[*] Generating final HTML report...")
        report_args = argparse.Namespace(**vars(args))
        
        if not report_args.output:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            domain = urlparse(original_base_url).netloc.replace(':', '_')
            report_args.output = f"webx_report_{domain}_{timestamp}"
        
        report_args.output_formats = ['html']
        
        scan_info = {
            'target_url': original_base_url,
            'scan_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'scan_duration': time.time() - start_time,
            'ai_mode': args.ai_mode,
        }
        
        # Create a reports directory if it doesn't exist for the reporter
        Path("reports").mkdir(exist_ok=True)
        
        report_paths = await reporter.generate_comprehensive_report(
            findings=session_findings,
            scan_info=scan_info,
            formats=report_args.output_formats
        )
        if report_paths.get('html'):
            print(f"{Fore.GREEN}[+] Report saved to: {report_paths['html']}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[-] Failed to generate HTML report.{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}[+] No vulnerabilities were found during the session.{Style.RESET_ALL}")

    await production_crawler.cleanup()
    print(f"\n{Fore.CYAN}✨ Scan session complete. ✨{Style.RESET_ALL}")


if __name__ == "__main__":
    try:
        # For the best banner experience, install pyfiglet: pip install pyfiglet
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}\n[!] Application terminated by user.{Style.RESET_ALL}")
    except Exception as e:
        logger.error(f"A fatal error occurred: {e}", exc_info=True)
        print(f"\n{Fore.RED}[-] A fatal error occurred: {e}{Style.RESET_ALL}")
        sys.exit(1)