# core/template_parser.py - Concise production-grade template loader for WebX 
import os, json, logging
from pathlib import Path
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

REQUIRED_FIELDS = ("id","info","request")
INFO_REQUIRED = ("name","severity")
SUPPORTED_EXT = (".yaml",".yml",".json")

def _load_file(path: Path) -> Dict[str, Any]:
    try:
        if path.suffix.lower() in (".yaml",".yml"):
            try:
                import yaml
                with path.open("r", encoding="utf-8") as f: 
                    return yaml.safe_load(f) or {}
            except ImportError:
                logger.warning(f"YAML support not available, skipping {path}")
                return {}
        with path.open("r", encoding="utf-8") as f: 
            return json.load(f)
    except Exception as e:
        logger.warning(f"Template load failed: {path} -> {e}")
        return {}

def _validate_template(t: Dict[str, Any]) -> bool:
    """Validate template has required fields and normalize vulnerability type"""
    if not all(k in t for k in REQUIRED_FIELDS): 
        return False
    
    info = t.get("info", {})
    if not all(k in info for k in INFO_REQUIRED): 
        return False
    
    # Determine vulnerability type from multiple sources
    vt = (t.get("vulnerability_type") or 
          t.get("type") or 
          (info.get("tags", [None])[0] if info.get("tags") else None) or
          info.get("category") or
          "unknown")
    
    t["vulnerability_type"] = str(vt).lower().replace("-", "_").replace(" ", "_")
    
    # Set OAST compatibility flag
    request_data = str(t.get("request", {})).lower()
    t["oast_compatible"] = any(keyword in request_data for keyword in ["oast", "{{interactsh", "{{dns", "callback"])
    
    return True

def load_all_templates(root: str) -> List[Dict[str, Any]]:
    """Load all templates from directory tree"""
    rootp = Path(root)
    templates: List[Dict[str, Any]] = []
    
    if not rootp.exists(): 
        logger.warning(f"Templates directory missing: {root}")
        return templates
    
    for path in rootp.rglob("*"):
        if path.is_file() and path.suffix.lower() in SUPPORTED_EXT:
            template = _load_file(path)
            if template and _validate_template(template):
                template["_source_file"] = str(path)
                templates.append(template)
    
    logger.info(f"Templates loaded: {len(templates)} from {root}")
    return templates

def load_templates_by_category(root: str, category: str) -> List[Dict[str, Any]]:
    """Load templates filtered by vulnerability category"""
    category = str(category).lower().replace("-", "_").replace(" ", "_")
    all_templates = load_all_templates(root)
    filtered = [t for t in all_templates if t.get("vulnerability_type") == category]
    logger.debug(f"Category '{category}': {len(filtered)} templates")
    return filtered

def load_templates_by_severity(root: str, min_severity: str = "medium") -> List[Dict[str, Any]]:
    """Load templates filtered by minimum severity level"""
    severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    min_level = severity_order.get(min_severity.lower(), 2)
    
    all_templates = load_all_templates(root)
    filtered = [t for t in all_templates 
                if severity_order.get(t.get("info", {}).get("severity", "info").lower(), 0) >= min_level]
    
    logger.debug(f"Severity >= '{min_severity}': {len(filtered)} templates")
    return filtered

def get_oast_templates(templates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Filter templates that support OAST (out-of-band) testing"""
    return [t for t in templates if t.get("oast_compatible", False)]

def get_template_statistics(root: str) -> Dict[str, Any]:
    """Get comprehensive statistics about loaded templates"""
    templates = load_all_templates(root)
    
    # Category distribution
    categories = {}
    severities = {}
    oast_count = 0
    
    for template in templates:
        # Count by category
        cat = template.get("vulnerability_type", "unknown")
        categories[cat] = categories.get(cat, 0) + 1
        
        # Count by severity
        sev = template.get("info", {}).get("severity", "info").lower()
        severities[sev] = severities.get(sev, 0) + 1
        
        # Count OAST-compatible
        if template.get("oast_compatible", False):
            oast_count += 1
    
    return {
        "templates_loaded": len(templates),
        "category_distribution": categories,
        "severity_distribution": severities,
        "oast_compatible_count": oast_count,
        "categories_count": len(categories),
        "most_common_category": max(categories.items(), key=lambda x: x[1])[0] if categories else None
    }

def search_templates(root: str, query: str) -> List[Dict[str, Any]]:
    """Search templates by name, description, or tags"""
    all_templates = load_all_templates(root)
    query = query.lower()
    
    results = []
    for template in all_templates:
        info = template.get("info", {})
        
        # Search in name, description, tags
        searchable_text = " ".join([
            info.get("name", ""),
            info.get("description", ""),
            " ".join(info.get("tags", [])),
            template.get("vulnerability_type", "")
        ]).lower()
        
        if query in searchable_text:
            results.append(template)
    
    logger.debug(f"Search '{query}': {len(results)} matches")
    return results

def validate_template_format(template: Dict[str, Any]) -> tuple[bool, List[str]]:
    """Validate template format and return validation results"""
    errors = []
    
    # Check required top-level fields
    for field in REQUIRED_FIELDS:
        if field not in template:
            errors.append(f"Missing required field: {field}")
    
    # Check info section
    info = template.get("info", {})
    if not isinstance(info, dict):
        errors.append("'info' must be a dictionary")
    else:
        for field in INFO_REQUIRED:
            if field not in info:
                errors.append(f"Missing required info field: {field}")
    
    # Check request section
    request = template.get("request", {})
    if not isinstance(request, dict):
        errors.append("'request' must be a dictionary")
    
    # Validate severity
    valid_severities = ["info", "low", "medium", "high", "critical"]
    severity = info.get("severity", "").lower()
    if severity not in valid_severities:
        errors.append(f"Invalid severity: {severity}. Must be one of {valid_severities}")
    
    return len(errors) == 0, errors

# Convenience function for backwards compatibility
def production_advanced_template_parser():
    """Production template parser - placeholder for backwards compatibility"""
    class AdvancedParser:
        @staticmethod
        def load_all(root: str): return load_all_templates(root)
        @staticmethod
        def load_by_category(root: str, cat: str): return load_templates_by_category(root, cat)
        @staticmethod
        def get_statistics(root: str): return get_template_statistics(root)
    
    return AdvancedParser()
