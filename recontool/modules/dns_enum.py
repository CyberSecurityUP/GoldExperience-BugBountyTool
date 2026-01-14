"""
DNS Enumeration Module

DNS record enumeration and bruteforcing:
- dnsx
- shuffledns
- puredns
- massdns
- dnsgen
"""

import time
from pathlib import Path
from typing import List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from .base import PassiveModule, ModuleResult
from ..utils.dedup import merge_files
from ..utils.normalize import normalize_domain


class DnsEnumModule(PassiveModule):
    """DNS enumeration and record discovery."""

    name = "dns_enum"
    description = "Enumerate DNS records and resolve subdomains"
    tools = ["dnsx", "shuffledns", "puredns", "massdns", "dnsgen"]
    output_dir = "dns"

    # Common resolvers
    DEFAULT_RESOLVERS = [
        "8.8.8.8", "8.8.4.4",  # Google
        "1.1.1.1", "1.0.0.1",  # Cloudflare
        "9.9.9.9",  # Quad9
    ]

    def run(
        self,
        targets: List[str],
        resume: bool = True,
        input_file: Optional[Path] = None,
        wordlist: Optional[Path] = None,
        resolvers_file: Optional[Path] = None,
        **kwargs,
    ) -> ModuleResult:
        """
        Run DNS enumeration on targets.

        Args:
            targets: List of domains or subdomains
            resume: Skip if output exists
            input_file: File containing targets
            wordlist: DNS bruteforce wordlist
            resolvers_file: File containing DNS resolvers

        Returns:
            ModuleResult with DNS records
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
            self.logger.warning("No targets provided for DNS enumeration")
            result.duration = time.time() - start_time
            return result

        # Normalize and deduplicate
        targets = [normalize_domain(t) for t in targets if normalize_domain(t)]
        targets = list(set(targets))

        self.logger.info(f"Running DNS enumeration on {len(targets)} targets")

        # Write targets
        targets_file = self.get_output_file("targets.txt")
        self.write_output_file(targets_file, targets)

        # Setup resolvers
        resolvers_path = self._setup_resolvers(resolvers_file)

        # Output files
        resolved_output = self.get_output_file("resolved.txt")
        dns_records = self.get_output_file("dns_records.txt")

        if resume and self.check_resume(resolved_output):
            result.duration = time.time() - start_time
            return result

        # Run dnsx for resolution and records
        if "dnsx" in self.available_tools:
            dnsx_result = self._run_dnsx(targets_file, resolved_output, dns_records, resolvers_path)
            result.add_tool_result(dnsx_result)
            if dnsx_result.success:
                result.output_files["resolved"] = resolved_output
                result.output_files["dns_records"] = dns_records
                self._parse_dns_records(dns_records, result)

        # Run dnsgen for permutations (if wordlist available)
        if "dnsgen" in self.available_tools:
            dnsgen_out = self.get_output_file("permutations.txt")
            dnsgen_result = self._run_dnsgen(targets_file, dnsgen_out)
            result.add_tool_result(dnsgen_result)
            if dnsgen_result.success and dnsgen_out.exists():
                result.output_files["permutations"] = dnsgen_out

                # Resolve permutations
                if "dnsx" in self.available_tools:
                    perm_resolved = self.get_output_file("permutations_resolved.txt")
                    perm_result = self._run_dnsx(dnsgen_out, perm_resolved, None, resolvers_path)
                    if perm_result.success:
                        result.output_files["permutations_resolved"] = perm_resolved

        # Run massdns/puredns for bruteforcing
        if wordlist and wordlist.exists():
            if "puredns" in self.available_tools:
                brute_out = self.get_output_file("bruteforce.txt")
                brute_result = self._run_puredns(targets, wordlist, brute_out, resolvers_path)
                result.add_tool_result(brute_result)
                if brute_result.success:
                    result.output_files["bruteforce"] = brute_out

        result.duration = time.time() - start_time
        return result

    def _setup_resolvers(self, resolvers_file: Optional[Path]) -> Path:
        """Setup DNS resolvers file."""
        if resolvers_file and resolvers_file.exists():
            return resolvers_file

        # Create default resolvers file
        resolvers_path = self.get_output_file("resolvers.txt")
        resolvers_path.write_text("\n".join(self.DEFAULT_RESOLVERS))
        return resolvers_path

    def _run_dnsx(
        self,
        input_file: Path,
        output_file: Path,
        records_file: Optional[Path],
        resolvers_file: Path,
    ):
        """Run dnsx for DNS resolution and records."""
        args = [
            "-l", str(input_file),
            "-o", str(output_file),
            "-r", str(resolvers_file),
            "-silent",
            "-threads", "100",
            "-retry", "3",
        ]

        if records_file:
            args.extend([
                "-a", "-aaaa", "-cname", "-mx", "-ns", "-txt", "-ptr",
                "-resp", "-resp-only",
                "-o", str(records_file),
            ])

        return self.run_tool("dnsx", args, timeout=600)

    def _run_dnsgen(self, input_file: Path, output_file: Path):
        """Run dnsgen for subdomain permutations."""
        input_data = input_file.read_text()
        args = []
        return self.run_tool(
            "dnsgen",
            args,
            input_data=input_data,
            output_file=output_file,
            timeout=300,
        )

    def _run_puredns(
        self,
        domains: List[str],
        wordlist: Path,
        output_file: Path,
        resolvers_file: Path,
    ):
        """Run puredns for DNS bruteforcing."""
        # Puredns works on single domain at a time
        all_results = []

        for domain in domains[:5]:  # Limit to prevent slowness
            args = [
                "bruteforce", str(wordlist), domain,
                "-r", str(resolvers_file),
                "--wildcard-tests", "10",
                "-q",
            ]
            result = self.run_tool("puredns", args, timeout=600)
            if result.success and result.stdout:
                all_results.extend(result.stdout.strip().split("\n"))

        if all_results:
            output_file.write_text("\n".join(all_results))
            result.result_count = len(all_results)

        return result

    def _parse_dns_records(self, records_file: Path, result: ModuleResult) -> None:
        """Parse DNS records for interesting findings."""
        if not records_file.exists():
            return

        record_types = {}
        ips = set()
        cnames = []
        txt_records = []

        for line in self.read_input_file(records_file):
            parts = line.split()
            if len(parts) >= 2:
                record_type = parts[0] if parts[0] in ["A", "AAAA", "CNAME", "MX", "NS", "TXT"] else "OTHER"
                record_types[record_type] = record_types.get(record_type, 0) + 1

                if record_type == "A":
                    ips.add(parts[-1])
                elif record_type == "CNAME":
                    cnames.append(line)
                elif record_type == "TXT":
                    txt_records.append(line)

        # Save stats
        result.stats["record_types"] = record_types
        result.stats["unique_ips"] = len(ips)

        # Write IPs to file
        if ips:
            ips_file = self.get_output_file("ips.txt")
            self.write_output_file(ips_file, sorted(ips))
            result.output_files["ips"] = ips_file

        # Check TXT records for interesting data
        for txt in txt_records:
            txt_lower = txt.lower()
            if any(kw in txt_lower for kw in ["spf", "dkim", "dmarc", "google-site", "v="]):
                result.findings.append({
                    "type": "dns_txt_record",
                    "value": txt[:200],
                })

        self.logger.info(
            f"Resolved to {len(ips)} unique IPs, {sum(record_types.values())} total records"
        )
