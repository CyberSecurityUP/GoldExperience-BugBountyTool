"""
Certificate Monitoring Module

Certificate transparency monitoring:
- certstream
"""

import json
import time
import threading
from pathlib import Path
from typing import List, Optional

from .base import PassiveModule, ModuleResult
from ..utils.normalize import normalize_domain


class CertMonitoringModule(PassiveModule):
    """Certificate transparency log monitoring."""

    name = "cert_monitoring"
    description = "Monitor certificate transparency logs for new certificates"
    tools = ["certstream"]
    output_dir = "certs"

    def run(
        self,
        targets: List[str],
        resume: bool = True,
        duration: int = 60,
        **kwargs,
    ) -> ModuleResult:
        """
        Monitor certificate transparency logs.

        Args:
            targets: List of domains to monitor for
            resume: Skip if output exists
            duration: How long to monitor in seconds

        Returns:
            ModuleResult with discovered certificates
        """
        start_time = time.time()
        self.ensure_output_dir()

        result = ModuleResult(
            module_name=self.name,
            success=True,
            duration=0.0,
        )

        # Extract domains to watch
        watch_domains = []
        for target in targets:
            domain = normalize_domain(target)
            if domain:
                watch_domains.append(domain)
                # Also watch for subdomains
                parts = domain.split(".")
                if len(parts) >= 2:
                    watch_domains.append(parts[-2])  # Company name

        if not watch_domains:
            self.logger.warning("No domains to monitor")
            result.duration = time.time() - start_time
            return result

        self.logger.info(
            f"Monitoring certificate logs for {len(watch_domains)} patterns "
            f"(duration: {duration}s)"
        )

        # Write watch domains
        watch_file = self.get_output_file("watch_patterns.txt")
        self.write_output_file(watch_file, watch_domains)

        # Output file
        certs_output = self.get_output_file("certificates.txt")

        if resume and self.check_resume(certs_output):
            result.duration = time.time() - start_time
            return result

        # Run certstream
        if "certstream" in self.available_tools:
            cs_result = self._run_certstream(watch_domains, certs_output, duration)
            result.add_tool_result(cs_result)
            if cs_result.success and certs_output.exists():
                result.output_files["certificates"] = certs_output

                # Parse results
                certs = self.read_input_file(certs_output)
                result.stats["certificates_found"] = len(certs)

                if certs:
                    self.logger.info(f"Discovered {len(certs)} new certificates")

                    # Add as findings
                    for cert in certs[:20]:
                        result.findings.append({
                            "type": "new_certificate",
                            "domain": cert,
                        })

        result.duration = time.time() - start_time
        return result

    def _run_certstream(
        self,
        watch_domains: List[str],
        output_file: Path,
        duration: int,
    ):
        """Run certstream to monitor certificate logs."""
        # Build grep pattern from watch domains
        pattern = "|".join(watch_domains)

        # certstream typically runs continuously, so we need to timeout
        args = [
            "--json",
        ]

        # Run with shorter timeout
        result = self.run_tool(
            "certstream",
            args,
            timeout=duration,
        )

        # Even if timeout (expected), process output
        if result.stdout:
            matches = []
            for line in result.stdout.strip().split("\n"):
                try:
                    data = json.loads(line)
                    domains = data.get("data", {}).get("leaf_cert", {}).get("all_domains", [])
                    for domain in domains:
                        if any(wd in domain.lower() for wd in watch_domains):
                            matches.append(domain)
                except:
                    continue

            if matches:
                output_file.write_text("\n".join(sorted(set(matches))))
                result.result_count = len(set(matches))

        return result
