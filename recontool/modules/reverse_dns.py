"""
Reverse DNS Module

Reverse DNS lookups and IP range enumeration:
- hakrevdns
- prips
"""

import time
from pathlib import Path
from typing import List, Optional

from .base import PassiveModule, ModuleResult


class ReverseDnsModule(PassiveModule):
    """Reverse DNS lookups for IP address enumeration."""

    name = "reverse_dns"
    description = "Perform reverse DNS lookups on IP addresses and ranges"
    tools = ["hakrevdns", "prips"]
    output_dir = "dns"

    def run(
        self,
        targets: List[str],
        resume: bool = True,
        input_file: Optional[Path] = None,
        **kwargs,
    ) -> ModuleResult:
        """
        Run reverse DNS lookups.

        Args:
            targets: List of IPs or CIDR ranges
            resume: Skip if output exists
            input_file: File containing IPs

        Returns:
            ModuleResult with reverse DNS results
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
            self.logger.warning("No targets provided for reverse DNS")
            result.duration = time.time() - start_time
            return result

        # Filter to IPs
        ips = self._extract_ips(targets)

        if not ips:
            self.logger.warning("No valid IPs found for reverse DNS")
            result.duration = time.time() - start_time
            return result

        self.logger.info(f"Running reverse DNS on {len(ips)} IPs")

        # Write IPs
        ips_file = self.get_output_file("ips_to_resolve.txt")
        self.write_output_file(ips_file, ips)

        # Output file
        rdns_output = self.get_output_file("reverse_dns.txt")

        if resume and self.check_resume(rdns_output):
            result.duration = time.time() - start_time
            return result

        # Run hakrevdns
        if "hakrevdns" in self.available_tools:
            hakrev_result = self._run_hakrevdns(ips_file, rdns_output)
            result.add_tool_result(hakrev_result)
            if hakrev_result.success:
                result.output_files["reverse_dns"] = rdns_output
                self._parse_results(rdns_output, result)

        result.duration = time.time() - start_time
        return result

    def _extract_ips(self, targets: List[str]) -> List[str]:
        """Extract valid IPs from targets."""
        import ipaddress

        ips = []
        for target in targets:
            try:
                # Try as IP
                ip = ipaddress.ip_address(target)
                ips.append(str(ip))
            except ValueError:
                try:
                    # Try as CIDR
                    network = ipaddress.ip_network(target, strict=False)
                    # Limit expansion for large networks
                    if network.num_addresses <= 65536:
                        ips.extend(str(ip) for ip in network.hosts())
                    else:
                        self.logger.warning(f"Network {target} too large, skipping")
                except ValueError:
                    continue

        return list(set(ips))

    def _run_hakrevdns(self, input_file: Path, output_file: Path):
        """Run hakrevdns for reverse DNS lookups."""
        input_data = input_file.read_text()
        args = [
            "-r", "1.1.1.1",  # Use Cloudflare
            "-t", "50",
        ]
        return self.run_tool(
            "hakrevdns",
            args,
            input_data=input_data,
            output_file=output_file,
            timeout=600,
        )

    def _parse_results(self, results_file: Path, result: ModuleResult) -> None:
        """Parse reverse DNS results."""
        if not results_file.exists():
            return

        domains_found = []
        for line in self.read_input_file(results_file):
            if line and " " in line:
                parts = line.split()
                if len(parts) >= 2:
                    domains_found.append(parts[1])

        if domains_found:
            result.stats["domains_discovered"] = len(domains_found)

            # Write domains
            domains_file = self.get_output_file("discovered_domains.txt")
            self.write_output_file(domains_file, domains_found)
            result.output_files["discovered_domains"] = domains_file

            self.logger.info(f"Discovered {len(domains_found)} domains via reverse DNS")
