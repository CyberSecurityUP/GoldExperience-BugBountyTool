"""
Git Reconnaissance Module

Git-based reconnaissance:
- trufflehog
- gitrob
- github-subdomains
"""

import json
import time
from pathlib import Path
from typing import List, Optional

from .base import PassiveModule, ModuleResult
from ..utils.normalize import normalize_domain


class GitReconModule(PassiveModule):
    """Git repository reconnaissance for secrets and subdomains."""

    name = "git_recon"
    description = "Scan Git repositories for secrets and enumerate GitHub subdomains"
    tools = ["trufflehog", "gitrob", "github-subdomains"]
    output_dir = "git"

    def run(
        self,
        targets: List[str],
        resume: bool = True,
        github_org: Optional[str] = None,
        repo_urls: Optional[List[str]] = None,
        **kwargs,
    ) -> ModuleResult:
        """
        Run Git reconnaissance.

        Args:
            targets: List of domains/organizations
            resume: Skip if output exists
            github_org: GitHub organization to scan
            repo_urls: Specific repository URLs to scan

        Returns:
            ModuleResult with secrets and subdomains found
        """
        start_time = time.time()
        self.ensure_output_dir()

        result = ModuleResult(
            module_name=self.name,
            success=True,
            duration=0.0,
        )

        # Extract organization names from domains
        orgs = []
        for target in targets:
            domain = normalize_domain(target)
            if domain:
                parts = domain.split(".")
                if len(parts) >= 2:
                    orgs.append(parts[-2])

        if github_org:
            orgs.append(github_org)

        orgs = list(set(orgs))

        self.logger.info(f"Running Git reconnaissance for {len(orgs)} organizations")

        # Output files
        secrets_output = self.get_output_file("secrets.txt")
        subdomains_output = self.get_output_file("github_subdomains.txt")

        if resume and self.check_resume(secrets_output):
            result.duration = time.time() - start_time
            return result

        all_secrets = []
        all_subdomains = []

        # Run trufflehog on repos
        if "trufflehog" in self.available_tools and repo_urls:
            for repo_url in repo_urls[:5]:  # Limit
                tf_out = self.get_output_file(f"trufflehog_{hash(repo_url) % 10000}.json")
                tf_result = self._run_trufflehog(repo_url, tf_out)
                result.add_tool_result(tf_result)
                if tf_result.success and tf_out.exists():
                    secrets = self._parse_trufflehog(tf_out)
                    all_secrets.extend(secrets)

        # Run github-subdomains
        if "github-subdomains" in self.available_tools:
            for org in orgs[:3]:
                ghs_out = self.get_output_file(f"github_subs_{org}.txt")
                ghs_result = self._run_github_subdomains(org, ghs_out)
                result.add_tool_result(ghs_result)
                if ghs_result.success and ghs_out.exists():
                    subs = self.read_input_file(ghs_out)
                    all_subdomains.extend(subs)

        # Save results
        if all_secrets:
            self.write_output_file(secrets_output, all_secrets)
            result.output_files["secrets"] = secrets_output
            result.stats["secrets_found"] = len(all_secrets)

            for secret in all_secrets[:20]:
                result.findings.append({
                    "type": "git_secret",
                    "value": secret[:200],
                    "severity": "high",
                })

            self.logger.warning(f"Found {len(all_secrets)} secrets in Git!")

        if all_subdomains:
            all_subdomains = list(set(all_subdomains))
            self.write_output_file(subdomains_output, all_subdomains)
            result.output_files["github_subdomains"] = subdomains_output
            result.stats["subdomains_from_github"] = len(all_subdomains)

        result.duration = time.time() - start_time
        return result

    def _run_trufflehog(self, repo_url: str, output_file: Path):
        """Run trufflehog for secret scanning."""
        args = [
            "git", repo_url,
            "--json",
            "--no-update",
        ]
        result = self.run_tool("trufflehog", args, timeout=600)
        if result.success and result.stdout:
            output_file.write_text(result.stdout)
        return result

    def _run_github_subdomains(self, org: str, output_file: Path):
        """Run github-subdomains for subdomain enumeration."""
        args = [
            "-d", org,
            "-o", str(output_file),
        ]
        return self.run_tool("github-subdomains", args, timeout=300)

    def _parse_trufflehog(self, output_file: Path) -> List[str]:
        """Parse trufflehog JSON output."""
        secrets = []
        if not output_file.exists():
            return secrets

        for line in output_file.read_text().strip().split("\n"):
            if not line:
                continue
            try:
                data = json.loads(line)
                secret_type = data.get("DetectorType", "unknown")
                raw = data.get("Raw", "")[:100]
                source = data.get("SourceMetadata", {}).get("Data", {}).get("Git", {}).get("file", "")

                secrets.append(f"{secret_type}: {raw} (in {source})")
            except json.JSONDecodeError:
                continue

        return secrets
