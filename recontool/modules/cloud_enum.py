"""
Cloud Enumeration Module

Cloud resource discovery:
- cloud_enum
- s3scanner
"""

import time
from pathlib import Path
from typing import List, Optional

from .base import PassiveModule, ModuleResult
from ..utils.normalize import normalize_domain


class CloudEnumModule(PassiveModule):
    """Cloud resource enumeration (S3, Azure, GCP)."""

    name = "cloud_enum"
    description = "Enumerate cloud resources (S3 buckets, Azure blobs, GCP storage)"
    tools = ["cloud_enum", "s3scanner"]
    output_dir = "cloud"

    def run(
        self,
        targets: List[str],
        resume: bool = True,
        keyword_file: Optional[Path] = None,
        **kwargs,
    ) -> ModuleResult:
        """
        Run cloud resource enumeration.

        Args:
            targets: List of keywords/domains for cloud enumeration
            resume: Skip if output exists
            keyword_file: File containing keywords

        Returns:
            ModuleResult with discovered cloud resources
        """
        start_time = time.time()
        self.ensure_output_dir()

        result = ModuleResult(
            module_name=self.name,
            success=True,
            duration=0.0,
        )

        # Extract keywords from targets
        keywords = []
        for target in targets:
            domain = normalize_domain(target)
            if domain:
                # Extract company name from domain
                parts = domain.split(".")
                if len(parts) >= 2:
                    keywords.append(parts[-2])
                keywords.append(domain.replace(".", "-"))
                keywords.append(domain.replace(".", ""))

        if keyword_file and keyword_file.exists():
            keywords.extend(self.read_input_file(keyword_file))

        keywords = list(set(keywords))

        if not keywords:
            self.logger.warning("No keywords for cloud enumeration")
            result.duration = time.time() - start_time
            return result

        self.logger.info(f"Running cloud enumeration with {len(keywords)} keywords")

        # Write keywords
        keywords_file = self.get_output_file("keywords.txt")
        self.write_output_file(keywords_file, keywords)

        # Output file
        cloud_output = self.get_output_file("cloud_resources.txt")

        if resume and self.check_resume(cloud_output):
            result.duration = time.time() - start_time
            return result

        all_findings = []

        # Run cloud_enum
        if "cloud_enum" in self.available_tools:
            for keyword in keywords[:10]:  # Limit
                ce_out = self.get_output_file(f"cloud_enum_{keyword}.txt")
                ce_result = self._run_cloud_enum(keyword, ce_out)
                result.add_tool_result(ce_result)
                if ce_result.success and ce_out.exists():
                    findings = self.read_input_file(ce_out)
                    all_findings.extend(findings)

        # Run s3scanner
        if "s3scanner" in self.available_tools:
            s3_out = self.get_output_file("s3scanner.txt")
            s3_result = self._run_s3scanner(keywords_file, s3_out)
            result.add_tool_result(s3_result)
            if s3_result.success and s3_out.exists():
                findings = self.read_input_file(s3_out)
                all_findings.extend(findings)

        # Merge and save
        if all_findings:
            all_findings = list(set(all_findings))
            self.write_output_file(cloud_output, all_findings)
            result.output_files["cloud_resources"] = cloud_output
            result.stats["total_findings"] = len(all_findings)

            # Parse for severity
            self._categorize_findings(all_findings, result)

            self.logger.info(f"Found {len(all_findings)} cloud resources")

        result.duration = time.time() - start_time
        return result

    def _run_cloud_enum(self, keyword: str, output_file: Path):
        """Run cloud_enum for cloud resource discovery."""
        args = [
            "-k", keyword,
            "-l", str(output_file),
            "-t", "10",
        ]
        return self.run_tool("cloud_enum", args, timeout=300)

    def _run_s3scanner(self, input_file: Path, output_file: Path):
        """Run s3scanner for S3 bucket discovery."""
        args = [
            "-bucket-file", str(input_file),
            "-o", str(output_file),
        ]
        return self.run_tool("s3scanner", args, timeout=300)

    def _categorize_findings(self, findings: List[str], result: ModuleResult) -> None:
        """Categorize cloud findings by type and accessibility."""
        s3_buckets = []
        azure_blobs = []
        gcp_storage = []
        open_buckets = []

        for finding in findings:
            finding_lower = finding.lower()

            if "s3" in finding_lower or ".amazonaws." in finding_lower:
                s3_buckets.append(finding)
            elif "azure" in finding_lower or ".blob." in finding_lower:
                azure_blobs.append(finding)
            elif "storage.googleapis" in finding_lower:
                gcp_storage.append(finding)

            # Check for open/public indicators
            if any(ind in finding_lower for ind in ["open", "public", "listable", "readable"]):
                open_buckets.append(finding)
                result.findings.append({
                    "type": "open_cloud_storage",
                    "value": finding,
                    "severity": "high",
                })

        result.stats["s3_buckets"] = len(s3_buckets)
        result.stats["azure_blobs"] = len(azure_blobs)
        result.stats["gcp_storage"] = len(gcp_storage)
        result.stats["open_buckets"] = len(open_buckets)

        if open_buckets:
            self.logger.warning(f"Found {len(open_buckets)} potentially OPEN cloud storage!")
