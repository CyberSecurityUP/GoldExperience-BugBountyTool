"""
Normalization utilities for ReconTool

Provides URL, domain, IP, and parameter normalization
for consistent output handling.
"""

import re
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse


def normalize_url(url: str, remove_fragments: bool = True) -> str:
    """
    Normalize a URL to a canonical form.

    - Lowercase scheme and hostname
    - Remove default ports (80 for http, 443 for https)
    - Sort query parameters
    - Remove fragments (optional)
    - Remove trailing slashes from paths

    Args:
        url: URL to normalize
        remove_fragments: Whether to remove URL fragments

    Returns:
        Normalized URL string
    """
    if not url:
        return ""

    # Add scheme if missing
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"

    try:
        parsed = urlparse(url)
    except Exception:
        return url

    # Lowercase scheme and hostname
    scheme = parsed.scheme.lower()
    hostname = (parsed.hostname or "").lower()

    # Handle port (remove default ports)
    port = parsed.port
    if port:
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            port = None

    # Build netloc
    netloc = hostname
    if port:
        netloc = f"{hostname}:{port}"
    if parsed.username:
        user_info = parsed.username
        if parsed.password:
            user_info = f"{user_info}:{parsed.password}"
        netloc = f"{user_info}@{netloc}"

    # Normalize path (remove trailing slashes, but keep root /)
    path = parsed.path
    if path and path != "/":
        path = path.rstrip("/")
    if not path:
        path = "/"

    # Sort query parameters
    query = ""
    if parsed.query:
        params = parse_qs(parsed.query, keep_blank_values=True)
        # Sort by key, then by values
        sorted_params = sorted(params.items())
        sorted_params = [(k, sorted(v)) for k, v in sorted_params]
        query = urlencode(
            [(k, val) for k, vals in sorted_params for val in vals],
            safe="",
        )

    # Handle fragment
    fragment = "" if remove_fragments else parsed.fragment

    # Rebuild URL
    return urlunparse((scheme, netloc, path, "", query, fragment))


def normalize_domain(domain: str) -> str:
    """
    Normalize a domain to lowercase without protocol or path.

    Args:
        domain: Domain to normalize

    Returns:
        Normalized domain string
    """
    if not domain:
        return ""

    # Remove protocol
    domain = re.sub(r"^https?://", "", domain, flags=re.IGNORECASE)

    # Remove path and query
    domain = domain.split("/")[0].split("?")[0].split("#")[0]

    # Remove port
    domain = domain.split(":")[0]

    # Lowercase
    domain = domain.lower().strip()

    # Remove trailing dots
    domain = domain.rstrip(".")

    return domain


def normalize_ip(ip: str) -> str:
    """
    Normalize an IP address.

    Args:
        ip: IP address to normalize

    Returns:
        Normalized IP address string
    """
    if not ip:
        return ""

    # Remove any protocol prefix
    ip = re.sub(r"^https?://", "", ip)

    # Remove port and path
    ip = ip.split(":")[0].split("/")[0]

    # Basic validation
    parts = ip.split(".")
    if len(parts) != 4:
        return ip

    try:
        # Remove leading zeros, validate range
        normalized_parts = []
        for part in parts:
            num = int(part)
            if not 0 <= num <= 255:
                return ip
            normalized_parts.append(str(num))
        return ".".join(normalized_parts)
    except ValueError:
        return ip


def extract_params(url: str) -> Dict[str, List[str]]:
    """
    Extract parameters from a URL.

    Args:
        url: URL to extract parameters from

    Returns:
        Dictionary of parameter names to values
    """
    if not url:
        return {}

    try:
        parsed = urlparse(url)
        return parse_qs(parsed.query, keep_blank_values=True)
    except Exception:
        return {}


def extract_unique_params(urls: List[str]) -> Set[str]:
    """
    Extract unique parameter names from a list of URLs.

    Args:
        urls: List of URLs

    Returns:
        Set of unique parameter names
    """
    params = set()
    for url in urls:
        params.update(extract_params(url).keys())
    return params


def extract_endpoints(urls: List[str]) -> Set[str]:
    """
    Extract unique endpoints (path without params) from URLs.

    Args:
        urls: List of URLs

    Returns:
        Set of unique endpoints
    """
    endpoints = set()
    for url in urls:
        try:
            parsed = urlparse(url)
            endpoint = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            endpoints.add(normalize_url(endpoint))
        except Exception:
            continue
    return endpoints


def extract_root_domain(domain: str) -> str:
    """
    Extract the root domain from a subdomain.

    Args:
        domain: Full domain (e.g., sub.example.com)

    Returns:
        Root domain (e.g., example.com)
    """
    domain = normalize_domain(domain)
    if not domain:
        return ""

    parts = domain.split(".")

    # Handle common TLDs
    if len(parts) >= 2:
        # Check for country code TLDs with secondary level (e.g., .co.uk, .com.au)
        common_secondary = {"co", "com", "org", "net", "gov", "edu", "ac"}
        if len(parts) >= 3 and parts[-2] in common_secondary:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])

    return domain


def parse_url_components(url: str) -> Dict[str, str]:
    """
    Parse a URL into its components.

    Args:
        url: URL to parse

    Returns:
        Dictionary with scheme, host, port, path, query, fragment
    """
    if not url:
        return {}

    # Add scheme if missing
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"

    try:
        parsed = urlparse(url)
        return {
            "scheme": parsed.scheme,
            "host": parsed.hostname or "",
            "port": str(parsed.port) if parsed.port else "",
            "path": parsed.path,
            "query": parsed.query,
            "fragment": parsed.fragment,
            "netloc": parsed.netloc,
        }
    except Exception:
        return {"url": url}


def categorize_url(url: str) -> str:
    """
    Categorize a URL based on its path/extension.

    Args:
        url: URL to categorize

    Returns:
        Category string (js, api, static, page, etc.)
    """
    url_lower = url.lower()
    path = urlparse(url_lower).path

    # JavaScript files
    if path.endswith(".js") or "/js/" in path:
        return "javascript"

    # API endpoints
    api_indicators = ["/api/", "/v1/", "/v2/", "/v3/", "/rest/", "/graphql"]
    if any(ind in url_lower for ind in api_indicators):
        return "api"

    # Static assets
    static_extensions = [
        ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
        ".woff", ".woff2", ".ttf", ".eot", ".map"
    ]
    if any(path.endswith(ext) for ext in static_extensions):
        return "static"

    # Documents
    doc_extensions = [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx"]
    if any(path.endswith(ext) for ext in doc_extensions):
        return "document"

    # Configuration/sensitive
    sensitive_indicators = [
        ".env", ".git", ".svn", "config", "admin", "backup",
        ".sql", ".bak", ".log"
    ]
    if any(ind in url_lower for ind in sensitive_indicators):
        return "sensitive"

    # Default to page
    return "page"


def is_valid_url(url: str) -> bool:
    """
    Check if a URL is valid and well-formed.

    Args:
        url: URL to validate

    Returns:
        True if valid, False otherwise
    """
    if not url:
        return False

    try:
        # Add scheme if missing
        if not url.startswith(("http://", "https://")):
            url = f"http://{url}"

        parsed = urlparse(url)
        return all([parsed.scheme, parsed.netloc])
    except Exception:
        return False


def is_valid_domain(domain: str) -> bool:
    """
    Check if a domain is valid.

    Args:
        domain: Domain to validate

    Returns:
        True if valid, False otherwise
    """
    if not domain:
        return False

    domain = normalize_domain(domain)

    # Basic pattern check
    pattern = r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$"
    return bool(re.match(pattern, domain, re.IGNORECASE))
