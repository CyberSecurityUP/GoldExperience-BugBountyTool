"""
Passive Sources Module - API-based Subdomain Enumeration

Collects subdomains from various passive sources via APIs:
- crt.sh (Certificate Transparency)
- RapidDNS
- BufferOver
- AlienVault OTX
- HackerTarget
- ThreatCrowd
- URLScan
- Archive.org (Wayback)
- JLDC
- Omnisint/Sonar

Output structure:
  passive_sources/
    ├── raw/
    │   ├── crtsh.txt
    │   ├── rapiddns.txt
    │   ├── bufferover.txt
    │   └── ...
    ├── all_subdomains.txt
    └── passive_sources_summary.json
"""

import json
import re
import time
import urllib.request
import urllib.parse
import ssl
from pathlib import Path
from typing import List, Optional, Dict, Set
from concurrent.futures import ThreadPoolExecutor, as_completed

from .base import PassiveModule, ModuleResult
from ..utils.dedup import deduplicate_lines


class PassiveSourcesModule(PassiveModule):
    """Collect subdomains from passive API sources."""

    name = "passive_sources"
    description = "Enumerate subdomains from passive API sources (crt.sh, RapidDNS, etc.)"
    tools = []  # No external tools needed, pure API calls
    output_dir = "passive_sources"

    # API endpoints configuration
    SOURCES = {
        "crtsh": {
            "url": "https://crt.sh/?q=%.{domain}&output=json",
            "type": "json",
            "extract": lambda data, domain: PassiveSourcesModule._extract_crtsh(data, domain),
        },
        "rapiddns": {
            "url": "https://rapiddns.io/subdomain/{domain}?full=1",
            "type": "html",
            "pattern": r'<td><a[^>]*>([^<]+\.{domain})</a></td>',
        },
        "bufferover": {
            "url": "https://dns.bufferover.run/dns?q=.{domain}",
            "type": "json",
            "extract": lambda data, domain: PassiveSourcesModule._extract_bufferover(data, domain),
        },
        "hackertarget": {
            "url": "https://api.hackertarget.com/hostsearch/?q={domain}",
            "type": "text",
            "extract": lambda data, domain: PassiveSourcesModule._extract_hackertarget(data, domain),
        },
        "threatcrowd": {
            "url": "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}",
            "type": "json",
            "extract": lambda data, domain: PassiveSourcesModule._extract_threatcrowd(data, domain),
        },
        "urlscan": {
            "url": "https://urlscan.io/api/v1/search/?q=domain:{domain}",
            "type": "json",
            "extract": lambda data, domain: PassiveSourcesModule._extract_urlscan(data, domain),
        },
        "otx": {
            "url": "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
            "type": "json",
            "extract": lambda data, domain: PassiveSourcesModule._extract_otx(data, domain),
        },
        "wayback": {
            "url": "https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey",
            "type": "text",
            "extract": lambda data, domain: PassiveSourcesModule._extract_wayback(data, domain),
        },
        "jldc": {
            "url": "https://jldc.me/anubis/subdomains/{domain}",
            "type": "json",
            "extract": lambda data, domain: data if isinstance(data, list) else [],
        },
        "certspotter": {
            "url": "https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names",
            "type": "json",
            "extract": lambda data, domain: PassiveSourcesModule._extract_certspotter(data, domain),
        },
    }

    def run(
        self,
        targets: List[str],
        resume: bool = True,
        input_file: Optional[Path] = None,
        **kwargs,
    ) -> ModuleResult:
        """
        Collect subdomains from passive sources.

        Args:
            targets: List of domains to enumerate
            resume: Skip if output exists
            input_file: Optional file containing domains

        Returns:
            ModuleResult with discovered subdomains
        """
        start_time = time.time()
        self.ensure_output_dir()

        result = ModuleResult(
            module_name=self.name,
            success=True,
            duration=0.0,
        )

        # Create directories
        raw_dir = self.output_path / "raw"
        raw_dir.mkdir(parents=True, exist_ok=True)

        # Get domains from targets (extract root domains)
        domains = self._extract_domains(targets)

        if not domains:
            self.logger.warning("No domains for passive source enumeration")
            result.success = False
            result.duration = time.time() - start_time
            return result

        self.logger.info(f"{'='*50}")
        self.logger.info(f"Querying passive sources for {len(domains)} domain(s)")
        self.logger.info(f"{'='*50}")

        # Output file
        all_subdomains_file = self.output_path / "all_subdomains.txt"

        if resume and all_subdomains_file.exists() and all_subdomains_file.stat().st_size > 0:
            self.logger.info("Resuming: Using existing passive source results")
            subs = self.read_input_file(all_subdomains_file)
            result.stats["total_subdomains"] = len(subs)
            result.duration = time.time() - start_time
            return result

        all_subdomains: Set[str] = set()

        # Query each source for each domain
        for domain in domains:
            self.logger.info(f"Querying sources for: {domain}")
            domain_subs = self._query_all_sources(domain, raw_dir, result)
            all_subdomains.update(domain_subs)

        # Filter scope and deduplicate
        all_subs_list = list(all_subdomains)
        all_subs_list = self.filter_scope(all_subs_list)
        all_subs_list = deduplicate_lines(all_subs_list)

        # Write output
        if all_subs_list:
            self.write_output_file(all_subdomains_file, sorted(all_subs_list))
            result.output_files["all_subdomains"] = all_subdomains_file
            result.stats["total_subdomains"] = len(all_subs_list)
            self.logger.info(f"Total unique subdomains from passive sources: {len(all_subs_list)}")

        # Save summary
        self._save_json_summary(result)

        result.duration = time.time() - start_time
        return result

    def _extract_domains(self, targets: List[str]) -> List[str]:
        """Extract root domains from targets."""
        domains = set()
        for target in targets:
            # Remove protocol
            target = re.sub(r'^https?://', '', target)
            # Remove path
            target = target.split('/')[0]
            # Remove port
            target = target.split(':')[0]
            # Get root domain (last 2 parts for most TLDs)
            parts = target.split('.')
            if len(parts) >= 2:
                # Handle common 2-part TLDs
                if parts[-1] in ['com', 'org', 'net', 'io', 'co', 'me', 'info', 'biz', 'xyz'] or len(parts[-1]) <= 3:
                    if len(parts) >= 2:
                        domains.add('.'.join(parts[-2:]))
                else:
                    domains.add(target)
        return list(domains)

    def _query_all_sources(
        self,
        domain: str,
        raw_dir: Path,
        result: ModuleResult,
    ) -> Set[str]:
        """Query all passive sources for a domain."""
        all_subs: Set[str] = set()

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {}
            for source_name, config in self.SOURCES.items():
                future = executor.submit(
                    self._query_source, source_name, config, domain
                )
                futures[future] = source_name

            for future in as_completed(futures):
                source_name = futures[future]
                try:
                    subs = future.result()
                    if subs:
                        # Write raw output
                        raw_file = raw_dir / f"{source_name}.txt"
                        with open(raw_file, "a") as f:
                            f.write("\n".join(subs) + "\n")

                        all_subs.update(subs)
                        result.stats[f"{source_name}_count"] = result.stats.get(f"{source_name}_count", 0) + len(subs)
                        self.logger.info(f"  {source_name}: {len(subs)} subdomains")
                except Exception as e:
                    self.logger.debug(f"  {source_name}: failed - {e}")

        return all_subs

    def _query_source(
        self,
        source_name: str,
        config: Dict,
        domain: str,
    ) -> List[str]:
        """Query a single passive source."""
        try:
            url = config["url"].format(domain=domain)

            # Create SSL context that doesn't verify (for reliability)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            # Make request
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Accept": "application/json, text/html, */*",
                }
            )

            with urllib.request.urlopen(req, timeout=30, context=ctx) as response:
                content = response.read().decode('utf-8', errors='ignore')

            if config["type"] == "json":
                try:
                    data = json.loads(content)
                    return config["extract"](data, domain)
                except json.JSONDecodeError:
                    return []

            elif config["type"] == "html":
                pattern = config["pattern"].replace("{domain}", re.escape(domain))
                matches = re.findall(pattern, content, re.IGNORECASE)
                return [m.lower() for m in matches if self._is_valid_subdomain(m, domain)]

            elif config["type"] == "text":
                return config["extract"](content, domain)

        except Exception as e:
            self.logger.debug(f"Error querying {source_name}: {e}")
            return []

        return []

    def _is_valid_subdomain(self, subdomain: str, domain: str) -> bool:
        """Check if subdomain is valid."""
        subdomain = subdomain.lower().strip()
        domain = domain.lower()

        if not subdomain.endswith(domain):
            return False
        if not re.match(r'^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?$', subdomain):
            return False
        if '..' in subdomain:
            return False
        return True

    @staticmethod
    def _extract_crtsh(data: list, domain: str) -> List[str]:
        """Extract subdomains from crt.sh response."""
        subs = set()
        if isinstance(data, list):
            for entry in data:
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lower()
                    if sub.endswith(domain) and not sub.startswith("*"):
                        subs.add(sub)
        return list(subs)

    @staticmethod
    def _extract_bufferover(data: dict, domain: str) -> List[str]:
        """Extract subdomains from BufferOver response."""
        subs = set()
        for key in ["FDNS_A", "RDNS"]:
            records = data.get(key, []) or []
            for record in records:
                if "," in record:
                    parts = record.split(",")
                    for part in parts:
                        part = part.strip().lower()
                        if part.endswith(domain):
                            subs.add(part)
        return list(subs)

    @staticmethod
    def _extract_hackertarget(data: str, domain: str) -> List[str]:
        """Extract subdomains from HackerTarget response."""
        subs = set()
        for line in data.strip().split("\n"):
            if "," in line:
                sub = line.split(",")[0].strip().lower()
                if sub.endswith(domain):
                    subs.add(sub)
        return list(subs)

    @staticmethod
    def _extract_threatcrowd(data: dict, domain: str) -> List[str]:
        """Extract subdomains from ThreatCrowd response."""
        subs = data.get("subdomains", []) or []
        return [s.lower() for s in subs if s.lower().endswith(domain)]

    @staticmethod
    def _extract_urlscan(data: dict, domain: str) -> List[str]:
        """Extract subdomains from URLScan response."""
        subs = set()
        results = data.get("results", []) or []
        for result in results:
            page = result.get("page", {})
            sub = page.get("domain", "").lower()
            if sub.endswith(domain):
                subs.add(sub)
        return list(subs)

    @staticmethod
    def _extract_otx(data: dict, domain: str) -> List[str]:
        """Extract subdomains from AlienVault OTX response."""
        subs = set()
        passive_dns = data.get("passive_dns", []) or []
        for entry in passive_dns:
            hostname = entry.get("hostname", "").lower()
            if hostname.endswith(domain):
                subs.add(hostname)
        return list(subs)

    @staticmethod
    def _extract_wayback(data: str, domain: str) -> List[str]:
        """Extract subdomains from Wayback Machine response."""
        subs = set()
        for line in data.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            # Extract domain from URL
            match = re.search(r'https?://([^/]+)', line)
            if match:
                sub = match.group(1).lower().split(":")[0]
                if sub.endswith(domain):
                    subs.add(sub)
        return list(subs)

    @staticmethod
    def _extract_certspotter(data: list, domain: str) -> List[str]:
        """Extract subdomains from CertSpotter response."""
        subs = set()
        if isinstance(data, list):
            for entry in data:
                dns_names = entry.get("dns_names", []) or []
                for name in dns_names:
                    name = name.lower().strip()
                    if name.endswith(domain) and not name.startswith("*"):
                        subs.add(name)
        return list(subs)

    def _save_json_summary(self, result: ModuleResult) -> None:
        """Save JSON summary."""
        summary = {
            "module": self.name,
            "stats": result.stats,
            "output_files": {k: str(v) for k, v in result.output_files.items()},
            "sources_queried": list(self.SOURCES.keys()),
        }

        json_file = self.output_path / "passive_sources_summary.json"
        with open(json_file, "w") as f:
            json.dump(summary, f, indent=2)

        result.output_files["json_summary"] = json_file
