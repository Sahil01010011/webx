# core/reporter.py - Production-Grade Advanced Reporting Engine for WebX Elite
import json
import csv
import xml.etree.ElementTree as ET
from xml.dom import minidom
import html
import time
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field
from collections import defaultdict
import base64
import hashlib

# Setup logging
logger = logging.getLogger(__name__)

@dataclass
class FindingMetadata:
    """Enhanced finding metadata with comprehensive details"""
    finding_id: str
    template_id: str
    vulnerability_type: str
    severity: str
    confidence: float
    timestamp: float
    scan_duration: float = 0.0
    ai_analysis: Optional[Dict[str, Any]] = None
    oast_interactions: List[Dict[str, Any]] = field(default_factory=list)
    template_metadata: Dict[str, Any] = field(default_factory=dict)
    risk_score: float = 0.0

@dataclass
class ScanStatistics:
    """Comprehensive scan statistics"""
    total_targets: int = 0
    total_templates: int = 0
    total_requests: int = 0
    total_findings: int = 0
    scan_start_time: float = 0.0
    scan_end_time: float = 0.0
    scan_duration: float = 0.0
    findings_by_severity: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    findings_by_type: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    template_coverage: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    false_positive_rate: float = 0.0
    ai_usage_stats: Dict[str, Any] = field(default_factory=dict)
    oast_statistics: Dict[str, Any] = field(default_factory=dict)

class AdvancedReporter:
    """Production-grade reporting engine with comprehensive format support"""
    
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Severity scoring for risk calculation
        self.severity_scores = {
            'info': 1,
            'low': 3,
            'medium': 6,
            'high': 8,
            'critical': 10
        }
        
        # CVSS-like risk calculation weights
        self.risk_weights = {
            'confidence': 0.3,
            'severity': 0.4,
            'exploitability': 0.2,
            'impact': 0.1
        }
        
        # Report templates
        self.report_formats = {
            'json': self._generate_json_report,
            'html': self._generate_html_report,
            'csv': self._generate_csv_report,
            'xml': self._generate_xml_report,
            'txt': self._generate_text_report,
            'markdown': self._generate_markdown_report
        }
    
    def generate_comprehensive_report(self, findings: List[Dict[str, Any]], 
                                      scan_info: Dict[str, Any] = None,
                                      formats: List[str] = None,
                                      include_statistics: bool = True,
                                      include_ai_analysis: bool = True,
                                      include_oast_data: bool = True) -> Dict[str, str]:
        """Generate comprehensive reports in multiple formats"""
        
        # Default formats if none specified
        if formats is None:
            formats = ['json', 'html', 'csv']
        
        # Process findings and generate metadata
        processed_findings = self._process_findings(findings)
        statistics = self._calculate_statistics(processed_findings, scan_info or {})
        
        # Prepare comprehensive report data
        report_data = {
            'scan_info': self._enhance_scan_info(scan_info or {}),
            'findings': processed_findings,
            'statistics': statistics.__dict__ if include_statistics else {},
            'metadata': {
                'report_generated': datetime.now(timezone.utc).isoformat(),
                'webx_version': '10.0',
                'report_formats': formats,
                'total_findings': len(processed_findings),
                'scan_summary': self._generate_scan_summary(processed_findings, statistics)
            }
        }
        
        # Generate reports in all requested formats
        generated_reports = {}
        
        for report_format in formats:
            if report_format in self.report_formats:
                try:
                    report_path = self.report_formats[report_format](report_data)
                    generated_reports[report_format] = str(report_path)
                    logger.info(f"Generated {report_format.upper()} report: {report_path}")
                except Exception as e:
                    logger.error(f"Failed to generate {report_format} report: {e}")
                    generated_reports[report_format] = f"ERROR: {e}"
            else:
                logger.warning(f"Unsupported report format: {report_format}")
        
        return generated_reports
    
    def _process_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Process and enhance findings with metadata"""
        processed_findings = []
        
        for i, finding in enumerate(findings):
            try:
                # Create unique finding ID
                finding_id = self._generate_finding_id(finding, i)
                
                # Extract core information
                template_id = finding.get('id', f'unknown_{i}')
                info = finding.get('info', {})
                details = finding.get('details', {})
                
                # Calculate risk score
                risk_score = self._calculate_risk_score(finding)
                
                # Create enhanced finding
                enhanced_finding = {
                    'finding_id': finding_id,
                    'template_id': template_id,
                    'vulnerability_type': finding.get('vulnerability_type', info.get('name', 'Unknown')),
                    'severity': info.get('severity', 'info').lower(),
                    'confidence': details.get('confidence', 0.5),
                    'risk_score': risk_score,
                    
                    # Core vulnerability details
                    'url': details.get('url', ''),
                    'parameter': details.get('parameter', ''),
                    'method': details.get('method', 'GET'),
                    'payload': details.get('payload', ''),
                    
                    # Response information
                    'response_status': details.get('response_status', 0),
                    'response_time': details.get('response_time', 0.0),
                    'response_body_sample': details.get('response_body', '')[:500],  # Truncated
                    
                    # Metadata
                    'info': info,
                    'details': details,
                    'timestamp': time.time(),
                    
                    # Advanced features
                    'ai_analysis': finding.get('ai_analysis'),
                    'oast_interactions': self._extract_oast_interactions(finding),
                    'template_metadata': self._extract_template_metadata(finding),
                    
                    # Classification
                    'exploitability': self._assess_exploitability(finding),
                    'impact': self._assess_impact(finding),
                    'false_positive_likelihood': self._assess_false_positive_likelihood(finding)
                }
                
                processed_findings.append(enhanced_finding)
                
            except Exception as e:
                logger.error(f"Error processing finding {i}: {e}")
                # Add minimal finding to avoid losing data
                processed_findings.append({
                    'finding_id': f'error_{i}',
                    'error': str(e),
                    'raw_finding': finding
                })
        
        return processed_findings
    
    def _generate_finding_id(self, finding: Dict[str, Any], index: int) -> str:
        """Generate unique finding ID"""
        # Create hash based on key finding attributes
        key_data = {
            'template_id': finding.get('id', ''),
            'url': finding.get('details', {}).get('url', ''),
            'parameter': finding.get('details', {}).get('parameter', ''),
            'payload': finding.get('details', {}).get('payload', ''),
            'index': index
        }
        
        hash_input = json.dumps(key_data, sort_keys=True)
        finding_hash = hashlib.md5(hash_input.encode()).hexdigest()[:8]
        
        return f"WX-{finding_hash.upper()}"
    
    def _calculate_risk_score(self, finding: Dict[str, Any]) -> float:
        """Calculate comprehensive risk score (0-10)"""
        info = finding.get('info', {})
        details = finding.get('details', {})
        
        # Base severity score
        severity = info.get('severity', 'info').lower()
        severity_score = self.severity_scores.get(severity, 1)
        
        # Confidence factor
        confidence = details.get('confidence', 0.5)
        
        # Exploitability assessment
        exploitability = self._assess_exploitability(finding)
        
        # Impact assessment  
        impact = self._assess_impact(finding)
        
        # Calculate weighted risk score
        risk_score = (
            severity_score * self.risk_weights['severity'] +
            confidence * 10 * self.risk_weights['confidence'] +
            exploitability * self.risk_weights['exploitability'] +
            impact * self.risk_weights['impact']
        )
        
        return min(risk_score, 10.0)
    
    def _assess_exploitability(self, finding: Dict[str, Any]) -> float:
        """Assess exploitability (0-10)"""
        details = finding.get('details', {})
        vuln_type = finding.get('vulnerability_type', '').lower()
        
        # Base exploitability by vulnerability type
        exploitability_map = {
            'sqli': 9.0,
            'command_injection': 9.5,
            'deserialization': 8.5,
            'xxe': 8.0,
            'ssti': 8.0,
            'xss': 7.0,
            'csrf': 6.0,
            'lfi': 7.5,
            'jwt': 6.5,
            'graphql': 5.5,
            'nosql': 7.0,
            'cors': 4.0,
            'redirect': 3.0
        }
        
        base_score = exploitability_map.get(vuln_type, 5.0)
        
        # Adjust based on response status
        status = details.get('response_status', 0)
        if status == 200:
            base_score += 1.0  # Successful response increases exploitability
        elif status >= 500:
            base_score += 0.5  # Error responses may indicate success
        
        # Adjust based on reflection
        if details.get('response_body', '') and details.get('payload', '') in details['response_body']:
            base_score += 1.5  # Reflection increases exploitability
        
        return min(base_score, 10.0)
    
    def _assess_impact(self, finding: Dict[str, Any]) -> float:
        """Assess potential impact (0-10)"""
        vuln_type = finding.get('vulnerability_type', '').lower()
        
        # Impact scoring by vulnerability type
        impact_map = {
            'sqli': 9.0,
            'command_injection': 10.0,
            'deserialization': 9.5,
            'xxe': 8.5,
            'ssti': 8.5,
            'xss': 6.0,
            'csrf': 7.0,
            'lfi': 7.5,
            'jwt': 8.0,
            'ldap_injection': 7.0,
            'xpath_injection': 6.0,
            'nosql': 7.0,
            'cors': 4.0,
            'redirect': 3.0,
            'file_upload': 8.0,
            'mass_assignment': 6.5,
            'business_logic': 5.0
        }
        
        return impact_map.get(vuln_type, 5.0)
    
    def _assess_false_positive_likelihood(self, finding: Dict[str, Any]) -> float:
        """Assess likelihood of false positive (0-1)"""
        confidence = finding.get('details', {}).get('confidence', 0.5)
        
        # AI analysis can reduce false positive likelihood
        ai_analysis = finding.get('ai_analysis')
        if ai_analysis:
            ai_classification = ai_analysis.get('ai_classification', '')
            if ai_classification == 'NOT_EXPLOITABLE':
                return 0.9
            elif ai_classification == 'EXPLOITABLE':
                return 0.1
        
        # Base false positive likelihood inversely related to confidence
        return 1.0 - confidence
    
    def _extract_oast_interactions(self, finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract OAST interactions from finding"""
        oast_interactions = []
        
        # Check for OAST data in various locations
        details = finding.get('details', {})
        
        if 'oast_interactions' in details:
            oast_interactions = details['oast_interactions']
        elif 'oast_data' in finding:
            oast_interactions = finding['oast_data']
        
        return oast_interactions
    
    def _extract_template_metadata(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Extract template metadata from finding"""
        template_metadata = {}
        
        # Extract from various sources
        if 'template_metadata' in finding:
            template_metadata = finding['template_metadata']
        
        # Add info section metadata
        info = finding.get('info', {})
        template_metadata.update({
            'author': info.get('author', 'unknown'),
            'tags': info.get('tags', []),
            'classification': info.get('classification', {}),
            'references': info.get('references', [])
        })
        
        return template_metadata
    
    def _calculate_statistics(self, findings: List[Dict[str, Any]], scan_info: Dict[str, Any]) -> ScanStatistics:
        """Calculate comprehensive scan statistics"""
        stats = ScanStatistics()
        
        # Basic counts
        stats.total_findings = len(findings)
        stats.total_targets = scan_info.get('total_targets', 0)
        stats.total_templates = scan_info.get('total_templates', 0)
        stats.total_requests = scan_info.get('total_requests', 0)
        
        # Timing
        stats.scan_start_time = scan_info.get('scan_start_time', time.time())
        stats.scan_end_time = scan_info.get('scan_end_time', time.time())
        stats.scan_duration = stats.scan_end_time - stats.scan_start_time
        
        # Findings analysis
        for finding in findings:
            severity = finding.get('severity', 'info')
            vuln_type = finding.get('vulnerability_type', 'unknown')
            template_id = finding.get('template_id', 'unknown')
            
            stats.findings_by_severity[severity] += 1
            stats.findings_by_type[vuln_type] += 1
            stats.template_coverage[template_id] += 1
        
        # False positive rate calculation
        if findings:
            false_positives = sum(1 for f in findings if f.get('false_positive_likelihood', 0) > 0.7)
            stats.false_positive_rate = (false_positives / len(findings)) * 100
        
        # AI usage statistics
        ai_enhanced_findings = sum(1 for f in findings if f.get('ai_analysis'))
        stats.ai_usage_stats = {
            'ai_enhanced_findings': ai_enhanced_findings,
            'ai_usage_percentage': (ai_enhanced_findings / max(len(findings), 1)) * 100
        }
        
        # OAST statistics
        oast_findings = sum(1 for f in findings if f.get('oast_interactions'))
        stats.oast_statistics = {
            'oast_enabled_findings': oast_findings,
            'total_oast_interactions': sum(len(f.get('oast_interactions', [])) for f in findings)
        }
        
        return stats
    
    def _enhance_scan_info(self, scan_info: Dict[str, Any]) -> Dict[str, Any]:
        """Enhance scan info with additional metadata"""
        enhanced_info = scan_info.copy()
        
        # Add default values if missing
        enhanced_info.setdefault('webx_version', '10.0')
        enhanced_info.setdefault('scan_type', 'comprehensive')
        enhanced_info.setdefault('scan_start_time', time.time())
        enhanced_info.setdefault('scan_end_time', time.time())
        
        # Add system information
        enhanced_info['system_info'] = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'timezone': 'UTC'
        }
        
        return enhanced_info
    
    def _generate_scan_summary(self, findings: List[Dict[str, Any]], statistics: ScanStatistics) -> Dict[str, Any]:
        """Generate executive scan summary"""
        if not findings:
            return {
                'status': 'No vulnerabilities found',
                'risk_level': 'low',
                'recommendations': ['Continue regular security testing']
            }
        
        # Calculate overall risk level
        avg_risk_score = sum(f.get('risk_score', 0) for f in findings) / len(findings)
        
        if avg_risk_score >= 8.0 or statistics.findings_by_severity.get('critical', 0) > 0:
            risk_level = 'critical'
        elif avg_risk_score >= 6.0 or statistics.findings_by_severity.get('high', 0) > 2:
            risk_level = 'high'
        elif avg_risk_score >= 4.0 or statistics.findings_by_severity.get('medium', 0) > 3:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        # Generate recommendations
        recommendations = []
        
        if statistics.findings_by_severity.get('critical', 0) > 0:
            recommendations.append('IMMEDIATE: Address critical vulnerabilities immediately')
        
        if statistics.findings_by_severity.get('high', 0) > 0:
            recommendations.append('HIGH PRIORITY: Remediate high-severity findings within 7 days')
        
        if statistics.false_positive_rate > 20:
            recommendations.append('Review findings for false positives to optimize scanning')
        
        if not recommendations:
            recommendations.append('Continue regular security monitoring and testing')
        
        return {
            'total_findings': len(findings),
            'average_risk_score': round(avg_risk_score, 2),
            'risk_level': risk_level,
            'scan_duration': round(statistics.scan_duration, 2),
            'recommendations': recommendations,
            'top_vulnerability_types': list(dict(sorted(
                statistics.findings_by_type.items(), 
                key=lambda x: x[1], 
                reverse=True
            )).keys())[:5]
        }
    
    def _generate_json_report(self, report_data: Dict[str, Any]) -> Path:
        """Generate comprehensive JSON report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.output_dir / f"webx_report_{timestamp}.json"
        
        # Create a clean copy for JSON serialization
        json_data = self._prepare_json_data(report_data)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(json_data, f, indent=2, ensure_ascii=False, default=str)
        
        return output_file
    
    def _prepare_json_data(self, data: Any) -> Any:
        """Prepare data for JSON serialization"""
        if isinstance(data, dict):
            return {k: self._prepare_json_data(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._prepare_json_data(item) for item in data]
        elif hasattr(data, '__dict__'):
            return self._prepare_json_data(data.__dict__)
        else:
            return data
    
    def _generate_html_report(self, report_data: Dict[str, Any]) -> Path:
        """Generate comprehensive HTML report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.output_dir / f"webx_report_{timestamp}.html"
        
        findings = report_data['findings']
        statistics = report_data['statistics']
        scan_info = report_data['scan_info']
        metadata = report_data['metadata']
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebX Elite Security Report</title>
    <style>
        {self._get_html_styles()}
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <h1>🛡️ WebX Elite Security Report</h1>
            <div class="report-meta">
                <span>Generated: {metadata['report_generated']}</span>
                <span>Findings: {len(findings)}</span>
                <span>Risk Level: <span class="risk-{metadata['scan_summary']['risk_level']}">{metadata['scan_summary']['risk_level'].upper()}</span></span>
            </div>
        </header>
        
        {self._generate_html_executive_summary(metadata['scan_summary'], statistics)}
        {self._generate_html_statistics_section(statistics)}
        {self._generate_html_findings_section(findings)}
        {self._generate_html_scan_details(scan_info)}
        
        <footer class="footer">
            <p>Generated by WebX Elite v{scan_info.get('webx_version', '10.0')} - Advanced Web Vulnerability Scanner</p>
        </footer>
    </div>
    
    <script>
        {self._get_html_scripts()}
    </script>
</body>
</html>"""
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return output_file
    
    def _get_html_styles(self) -> str:
        """Get CSS styles for HTML report"""
        return """
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; background: white; box-shadow: 0 0 20px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 30px; padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border-radius: 10px; }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .report-meta { font-size: 1.1em; }
        .report-meta span { margin: 0 15px; padding: 5px 10px; background: rgba(255,255,255,0.2); border-radius: 5px; }
        .risk-critical { background: #dc3545 !important; color: white; padding: 3px 8px; border-radius: 4px; }
        .risk-high { background: #fd7e14 !important; color: white; padding: 3px 8px; border-radius: 4px; }
        .risk-medium { background: #ffc107 !important; color: black; padding: 3px 8px; border-radius: 4px; }
        .risk-low { background: #28a745 !important; color: white; padding: 3px 8px; border-radius: 4px; }
        .section { margin-bottom: 30px; padding: 20px; border: 1px solid #ddd; border-radius: 8px; background: #fafafa; }
        .section h2 { color: #333; margin-bottom: 15px; border-bottom: 2px solid #667eea; padding-bottom: 5px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }
        .stat-card { background: white; padding: 15px; border-radius: 8px; text-align: center; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .stat-number { font-size: 2em; font-weight: bold; color: #667eea; }
        .stat-label { color: #666; margin-top: 5px; }
        .finding { background: white; margin-bottom: 20px; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .finding-header { padding: 15px; background: #f8f9fa; border-bottom: 1px solid #dee2e6; cursor: pointer; }
        .finding-header:hover { background: #e9ecef; }
        .finding-title { font-size: 1.2em; font-weight: bold; margin-bottom: 5px; }
        .finding-meta { display: flex; gap: 10px; flex-wrap: wrap; }
        .finding-meta span { padding: 3px 8px; border-radius: 4px; font-size: 0.9em; }
        .finding-body { padding: 15px; display: none; }
        .finding-body.show { display: block; }
        .finding-details { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; margin-bottom: 15px; }
        .detail-group { background: #f8f9fa; padding: 10px; border-radius: 5px; }
        .detail-group h4 { color: #495057; margin-bottom: 8px; }
        .code-block { background: #2d3748; color: #e2e8f0; padding: 15px; border-radius: 5px; overflow-x: auto; font-family: 'Courier New', monospace; font-size: 0.9em; }
        .severity-critical { background: #dc3545; color: white; }
        .severity-high { background: #fd7e14; color: white; }
        .severity-medium { background: #ffc107; color: black; }
        .severity-low { background: #17a2b8; color: white; }
        .severity-info { background: #6c757d; color: white; }
        .confidence-high { background: #28a745; color: white; }
        .confidence-medium { background: #ffc107; color: black; }
        .confidence-low { background: #dc3545; color: white; }
        .footer { text-align: center; margin-top: 40px; padding: 20px; color: #666; border-top: 1px solid #ddd; }
        .collapsible { cursor: pointer; user-select: none; }
        .collapsible:hover { opacity: 0.8; }
        """
    
    def _generate_html_executive_summary(self, summary: Dict[str, Any], statistics: Dict[str, Any]) -> str:
        """Generate executive summary section"""
        return f"""
        <div class="section">
            <h2>📊 Executive Summary</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number">{summary['total_findings']}</div>
                    <div class="stat-label">Total Findings</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number risk-{summary['risk_level']}">{summary['risk_level'].upper()}</div>
                    <div class="stat-label">Risk Level</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{summary['average_risk_score']}/10</div>
                    <div class="stat-label">Avg Risk Score</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{summary['scan_duration']}s</div>
                    <div class="stat-label">Scan Duration</div>
                </div>
            </div>
            
            <div class="recommendations">
                <h3>🎯 Key Recommendations</h3>
                <ul>
                    {''.join(f'<li>{rec}</li>' for rec in summary['recommendations'])}
                </ul>
            </div>
        </div>
        """
    
    def _generate_html_statistics_section(self, statistics: Dict[str, Any]) -> str:
        """Generate statistics section"""
        severity_dist = statistics.get('findings_by_severity', {})
        type_dist = statistics.get('findings_by_type', {})
        
        severity_chart = ""
        for severity, count in severity_dist.items():
            if count > 0:
                severity_chart += f'<div class="stat-card"><div class="stat-number severity-{severity}">{count}</div><div class="stat-label">{severity.title()}</div></div>'
        
        return f"""
        <div class="section">
            <h2>📈 Detailed Statistics</h2>
            
            <h3>Findings by Severity</h3>
            <div class="stats-grid">
                {severity_chart}
            </div>
            
            <h3>Top Vulnerability Types</h3>
            <div class="stats-grid">
                {''.join(f'<div class="stat-card"><div class="stat-number">{count}</div><div class="stat-label">{vuln_type.title()}</div></div>' 
                          for vuln_type, count in list(type_dist.items())[:6])}
            </div>
        </div>
        """
    
    def _generate_html_findings_section(self, findings: List[Dict[str, Any]]) -> str:
        """Generate findings section"""
        if not findings:
            return '<div class="section"><h2>🎉 No vulnerabilities found!</h2></div>'
        
        findings_html = '<div class="section"><h2>🔍 Detailed Findings</h2>'
        
        # Sort findings by risk score
        sorted_findings = sorted(findings, key=lambda x: x.get('risk_score', 0), reverse=True)
        
        for i, finding in enumerate(sorted_findings):
            finding_id = finding.get('finding_id', f'finding_{i}')
            title = finding.get('vulnerability_type', 'Unknown Vulnerability')
            severity = finding.get('severity', 'info')
            confidence = finding.get('confidence', 0.5)
            risk_score = finding.get('risk_score', 0)
            
            # Confidence level
            if confidence >= 0.8:
                conf_class = 'confidence-high'
                conf_text = 'High'
            elif confidence >= 0.5:
                conf_class = 'confidence-medium' 
                conf_text = 'Medium'
            else:
                conf_class = 'confidence-low'
                conf_text = 'Low'
            
            findings_html += f"""
            <div class="finding">
                <div class="finding-header collapsible" onclick="toggleFinding('{finding_id}')">
                    <div class="finding-title">{html.escape(title)}</div>
                    <div class="finding-meta">
                        <span class="severity-{severity}">{severity.upper()}</span>
                        <span class="{conf_class}">{conf_text} Confidence</span>
                        <span>Risk: {risk_score:.1f}/10</span>
                        <span>ID: {finding_id}</span>
                    </div>
                </div>
                <div class="finding-body" id="{finding_id}_body">
                    <div class="finding-details">
                        <div class="detail-group">
                            <h4>🎯 Target Information</h4>
                            <p><strong>URL:</strong> {html.escape(finding.get('url', 'N/A'))}</p>
                            <p><strong>Parameter:</strong> {html.escape(finding.get('parameter', 'N/A'))}</p>
                            <p><strong>Method:</strong> {finding.get('method', 'N/A')}</p>
                        </div>
                        
                        <div class="detail-group">
                            <h4>🔬 Technical Details</h4>
                            <p><strong>Template ID:</strong> {finding.get('template_id', 'N/A')}</p>
                            <p><strong>Response Status:</strong> {finding.get('response_status', 'N/A')}</p>
                            <p><strong>Response Time:</strong> {finding.get('response_time', 0):.3f}s</p>
                        </div>
                        
                        <div class="detail-group">
                            <h4>⚡ Exploitability Assessment</h4>
                            <p><strong>Exploitability:</strong> {finding.get('exploitability', 0):.1f}/10</p>
                            <p><strong>Impact:</strong> {finding.get('impact', 0):.1f}/10</p>
                            <p><strong>False Positive Likelihood:</strong> {finding.get('false_positive_likelihood', 0):.1%}</p>
                        </div>
                    </div>
                    
                    {self._generate_finding_payload_section(finding)}
                    {self._generate_finding_ai_section(finding)}
                    {self._generate_finding_oast_section(finding)}
                </div>
            </div>
            """
        
        findings_html += '</div>'
        return findings_html
    
    def _generate_finding_payload_section(self, finding: Dict[str, Any]) -> str:
        """Generate payload section for finding"""
        payload = finding.get('payload', '')
        if not payload:
            return ''
        
        return f"""
        <div class="detail-group">
            <h4>🎪 Payload</h4>
            <div class="code-block">{html.escape(payload)}</div>
        </div>
        """
    
    def _generate_finding_ai_section(self, finding: Dict[str, Any]) -> str:
        """Generate AI analysis section for finding"""
        ai_analysis = finding.get('ai_analysis')
        if not ai_analysis:
            return ''
        
        return f"""
        <div class="detail-group">
            <h4>🤖 AI Analysis</h4>
            <p><strong>Classification:</strong> {ai_analysis.get('ai_classification', 'N/A')}</p>
            <p><strong>AI Confidence:</strong> {ai_analysis.get('ai_confidence', 0):.1%}</p>
            <p><strong>Analysis:</strong></p>
            <div class="code-block">{html.escape(str(ai_analysis.get('ai_analysis', 'No analysis available')))}</div>
        </div>
        """
    
    def _generate_finding_oast_section(self, finding: Dict[str, Any]) -> str:
        """Generate OAST section for finding"""
        oast_interactions = finding.get('oast_interactions', [])
        if not oast_interactions:
            return ''
        
        oast_html = '<div class="detail-group"><h4>🌐 OAST Interactions</h4>'
        
        for i, interaction in enumerate(oast_interactions):
            oast_html += f"""
            <div style="margin-bottom: 10px; padding: 10px; background: rgba(0,0,0,0.05); border-radius: 5px;">
                <strong>Interaction {i+1}:</strong><br>
                Protocol: {interaction.get('protocol', 'N/A')}<br>
                Domain: {interaction.get('domain', 'N/A')}<br>
                Timestamp: {interaction.get('timestamp', 'N/A')}
            </div>
            """
        
        oast_html += '</div>'
        return oast_html
    
    def _generate_html_scan_details(self, scan_info: Dict[str, Any]) -> str:
        """Generate scan details section"""
        return f"""
        <div class="section">
            <h2>ℹ️ Scan Details</h2>
            <div class="finding-details">
                <div class="detail-group">
                    <h4>Configuration</h4>
                    <p><strong>WebX Version:</strong> {scan_info.get('webx_version', 'N/A')}</p>
                    <p><strong>Scan Type:</strong> {scan_info.get('scan_type', 'N/A')}</p>
                    <p><strong>Total Targets:</strong> {scan_info.get('total_targets', 'N/A')}</p>
                    <p><strong>Total Templates:</strong> {scan_info.get('total_templates', 'N/A')}</p>
                </div>
                
                <div class="detail-group">
                    <h4>Timing</h4>
                    <p><strong>Start Time:</strong> {datetime.fromtimestamp(scan_info.get('scan_start_time', time.time())).isoformat()}</p>
                    <p><strong>End Time:</strong> {datetime.fromtimestamp(scan_info.get('scan_end_time', time.time())).isoformat()}</p>
                    <p><strong>Duration:</strong> {scan_info.get('scan_end_time', time.time()) - scan_info.get('scan_start_time', time.time()):.2f} seconds</p>
                </div>
            </div>
        </div>
        """
    
    def _get_html_scripts(self) -> str:
        """Get JavaScript for HTML report"""
        return """
        function toggleFinding(findingId) {
            const body = document.getElementById(findingId + '_body');
            if (body.classList.contains('show')) {
                body.classList.remove('show');
            } else {
                body.classList.add('show');
            }
        }
        
        // Auto-expand first finding
        document.addEventListener('DOMContentLoaded', function() {
            const firstFinding = document.querySelector('.finding-body');
            if (firstFinding) {
                firstFinding.classList.add('show');
            }
        });
        """
    
    def _generate_csv_report(self, report_data: Dict[str, Any]) -> Path:
        """Generate CSV report for spreadsheet analysis"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.output_dir / f"webx_report_{timestamp}.csv"
        
        findings = report_data['findings']
        
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            if not findings:
                csvfile.write("No vulnerabilities found\n")
                return output_file
            
            fieldnames = [
                'finding_id', 'vulnerability_type', 'severity', 'confidence', 'risk_score',
                'url', 'parameter', 'method', 'payload', 'response_status', 'response_time',
                'exploitability', 'impact', 'false_positive_likelihood', 'template_id', 'timestamp'
            ]
            
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for finding in findings:
                row = {field: finding.get(field, '') for field in fieldnames}
                # Convert timestamp to readable format
                if row['timestamp']:
                    row['timestamp'] = datetime.fromtimestamp(float(row['timestamp'])).isoformat()
                writer.writerow(row)
        
        return output_file
    
    def _generate_xml_report(self, report_data: Dict[str, Any]) -> Path:
        """Generate XML report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.output_dir / f"webx_report_{timestamp}.xml"
        
        # Create root element
        root = ET.Element("webx_security_report")
        root.set("version", "10.0")
        root.set("generated", datetime.now(timezone.utc).isoformat())
        
        # Scan info
        scan_info_elem = ET.SubElement(root, "scan_info")
        for key, value in report_data['scan_info'].items():
            if isinstance(value, (str, int, float)):
                scan_elem = ET.SubElement(scan_info_elem, key.replace(' ', '_'))
                scan_elem.text = str(value)
        
        # Statistics
        stats_elem = ET.SubElement(root, "statistics")
        for key, value in report_data['statistics'].items():
            if isinstance(value, (str, int, float)):
                stat_elem = ET.SubElement(stats_elem, key)
                stat_elem.text = str(value)
        
        # Findings
        findings_elem = ET.SubElement(root, "findings")
        findings_elem.set("count", str(len(report_data['findings'])))
        
        for finding in report_data['findings']:
            finding_elem = ET.SubElement(findings_elem, "finding")
            finding_elem.set("id", finding.get('finding_id', ''))
            
            for key, value in finding.items():
                if isinstance(value, (str, int, float)):
                    elem = ET.SubElement(finding_elem, key)
                    elem.text = str(value)
                elif isinstance(value, list) and key == 'oast_interactions':
                    oast_elem = ET.SubElement(finding_elem, "oast_interactions")
                    for interaction in value:
                        interaction_elem = ET.SubElement(oast_elem, "interaction")
                        for k, v in interaction.items():
                            if isinstance(v, (str, int, float)):
                                inter_elem = ET.SubElement(interaction_elem, k)
                                inter_elem.text = str(v)
        
        # Write to file with pretty formatting
        xml_str = ET.tostring(root, encoding='utf-8')
        dom = minidom.parseString(xml_str)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(dom.toprettyxml(indent="  "))
        
        return output_file
    
    def _generate_text_report(self, report_data: Dict[str, Any]) -> Path:
        """Generate plain text report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.output_dir / f"webx_report_{timestamp}.txt"
        
        findings = report_data['findings']
        statistics = report_data['statistics']
        scan_info = report_data['scan_info']
        
        content = f"""
==========================================================================
                      WebX Elite Security Report
==========================================================================

Generated: {datetime.now(timezone.utc).isoformat()}
WebX Version: {scan_info.get('webx_version', '10.0')}
Total Findings: {len(findings)}

==========================================================================
                           EXECUTIVE SUMMARY
==========================================================================

Risk Level: {report_data['metadata']['scan_summary']['risk_level'].upper()}
Average Risk Score: {report_data['metadata']['scan_summary']['average_risk_score']}/10
Scan Duration: {report_data['metadata']['scan_summary']['scan_duration']} seconds

Key Recommendations:
{chr(10).join(f"- {rec}" for rec in report_data['metadata']['scan_summary']['recommendations'])}

==========================================================================
                              STATISTICS
==========================================================================

Findings by Severity:
{chr(10).join(f"- {severity.title()}: {count}" for severity, count in statistics.get('findings_by_severity', {}).items())}

Top Vulnerability Types:
{chr(10).join(f"- {vuln_type}: {count}" for vuln_type, count in list(statistics.get('findings_by_type', {}).items())[:5])}

==========================================================================
                           DETAILED FINDINGS
==========================================================================

"""
        
        if not findings:
            content += "🎉 No vulnerabilities found!\n"
        else:
            # Sort by risk score
            sorted_findings = sorted(findings, key=lambda x: x.get('risk_score', 0), reverse=True)
            
            for i, finding in enumerate(sorted_findings, 1):
                content += f"""
Finding #{i}: {finding.get('vulnerability_type', 'Unknown')}
--------------------------------------------------------------------------
ID: {finding.get('finding_id', 'N/A')}
Severity: {finding.get('severity', 'info').upper()}
Confidence: {finding.get('confidence', 0):.1%}
Risk Score: {finding.get('risk_score', 0):.1f}/10

Target:
- URL: {finding.get('url', 'N/A')}
- Parameter: {finding.get('parameter', 'N/A')}
- Method: {finding.get('method', 'N/A')}

Technical Details:
- Template ID: {finding.get('template_id', 'N/A')}
- Response Status: {finding.get('response_status', 'N/A')}
- Response Time: {finding.get('response_time', 0):.3f}s
- Exploitability: {finding.get('exploitability', 0):.1f}/10
- Impact: {finding.get('impact', 0):.1f}/10

Payload:
{finding.get('payload', 'N/A')}
"""
                
                # Add AI analysis if available
                ai_analysis = finding.get('ai_analysis')
                if ai_analysis:
                    content += f"""
AI Analysis:
- Classification: {ai_analysis.get('ai_classification', 'N/A')}
- AI Confidence: {ai_analysis.get('ai_confidence', 0):.1%}
"""
                
                # Add OAST interactions if available
                oast_interactions = finding.get('oast_interactions', [])
                if oast_interactions:
                    content += f"\nOAST Interactions: {len(oast_interactions)} interactions detected"
        
        content += f"""

==========================================================================
                              SCAN DETAILS
==========================================================================

Configuration:
- Total Targets: {scan_info.get('total_targets', 'N/A')}
- Total Templates: {scan_info.get('total_templates', 'N/A')}
- Scan Type: {scan_info.get('scan_type', 'N/A')}

Timing:
- Start Time: {datetime.fromtimestamp(scan_info.get('scan_start_time', time.time())).isoformat()}
- End Time: {datetime.fromtimestamp(scan_info.get('scan_end_time', time.time())).isoformat()}

==========================================================================
                     End of WebX Elite Security Report
==========================================================================
"""
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(content)
        
        return output_file
    
    def _generate_markdown_report(self, report_data: Dict[str, Any]) -> Path:
        """Generate Markdown report for documentation"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.output_dir / f"webx_report_{timestamp}.md"
        
        findings = report_data['findings']
        statistics = report_data['statistics']
        scan_summary = report_data['metadata']['scan_summary']
        
        content = f"""# 🛡️ WebX Elite Security Report

**Generated:** {datetime.now(timezone.utc).isoformat()}  
**Version:** WebX Elite v{report_data['scan_info'].get('webx_version', '10.0')}  
**Total Findings:** {len(findings)}  
**Risk Level:** **{scan_summary['risk_level'].upper()}** ## 📊 Executive Summary

| Metric | Value |
|--------|-------|
| Total Findings | {len(findings)} |
| Average Risk Score | {scan_summary['average_risk_score']}/10 |
| Scan Duration | {scan_summary['scan_duration']}s |
| Risk Level | **{scan_summary['risk_level'].upper()}** |

### 🎯 Key Recommendations

{chr(10).join(f"- {rec}" for rec in scan_summary['recommendations'])}

## 📈 Statistics

### Findings by Severity

{chr(10).join(f"- **{severity.title()}:** {count}" for severity, count in statistics.get('findings_by_severity', {}).items())}

### Top Vulnerability Types

{chr(10).join(f"- **{vuln_type}:** {count}" for vuln_type, count in list(statistics.get('findings_by_type', {}).items())[:5])}

## 🔍 Detailed Findings

"""
        
        if not findings:
            content += "### 🎉 No vulnerabilities found!\n\nYour application appears to be secure against the tested attack vectors.\n"
        else:
            sorted_findings = sorted(findings, key=lambda x: x.get('risk_score', 0), reverse=True)
            
            for i, finding in enumerate(sorted_findings, 1):
                severity = finding.get('severity', 'info').upper()
                severity_emoji = {'CRITICAL': '🚨', 'HIGH': '🔴', 'MEDIUM': '🟡', 'LOW': '🔵', 'INFO': 'ℹ️'}.get(severity, 'ℹ️')
                
                content += f"""### {severity_emoji} Finding #{i}: {finding.get('vulnerability_type', 'Unknown')}

**Finding ID:** `{finding.get('finding_id', 'N/A')}`  
**Severity:** **{severity}** **Confidence:** {finding.get('confidence', 0):.1%}  
**Risk Score:** {finding.get('risk_score', 0):.1f}/10  

#### Target Information
- **URL:** `{finding.get('url', 'N/A')}`
- **Parameter:** `{finding.get('parameter', 'N/A')}`
- **Method:** `{finding.get('method', 'N/A')}`

#### Technical Details
- **Template ID:** `{finding.get('template_id', 'N/A')}`
- **Response Status:** {finding.get('response_status', 'N/A')}
- **Response Time:** {finding.get('response_time', 0):.3f}s
- **Exploitability:** {finding.get('exploitability', 0):.1f}/10
- **Impact:** {finding.get('impact', 0):.1f}/10

#### Payload
"""