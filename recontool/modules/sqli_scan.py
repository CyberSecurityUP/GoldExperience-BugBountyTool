"""
SQL Injection Scanning Module

SQL injection vulnerability detection:
- sqlmap
- ghauri
"""

import json
import time
from pathlib import Path
from typing import List, Optional

from .base import ActiveModule, ModuleResult


class SqliScanModule(ActiveModule):
    """SQL injection vulnerability scanning."""

    name = "sqli_scan"
    description = "Scan for SQL injection vulnerabilities"
    tools = ["sqlmap", "ghauri"]
    output_dir = "sqli"

    def run(
        self,
        targets: List[str],
        resume: bool = True,
        input_file: Optional[Path] = None,
        level: int = 2,
        risk: int = 2,
        **kwargs,
    ) -> ModuleResult:
        """
        Run SQL injection scanning on URLs with parameters.

        Args:
            targets: List of URLs with parameters to test
            resume: Skip if output exists
            input_file: File containing URLs
            level: Testing level (1-5)
            risk: Risk level (1-3)

        Returns:
            ModuleResult with SQLi vulnerabilities
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

        # Filter to URLs with parameters
        targets = [t for t in targets if "?" in t and "=" in t]

        if not targets:
            self.logger.warning("No URLs with parameters for SQLi testing")
            result.duration = time.time() - start_time
            return result

        # Filter and limit
        targets = self.filter_scope(targets)
        targets = list(set(targets))

        # SQLi testing is intensive, limit targets
        if len(targets) > 50:
            self.logger.warning(f"Limiting to 50 URLs (had {len(targets)})")
            targets = targets[:50]

        self.logger.info(f"Testing {len(targets)} URLs for SQL injection")

        # Write targets
        targets_file = self.get_output_file("targets.txt")
        self.write_output_file(targets_file, targets)

        # Output files
        sqli_output = self.get_output_file("sqli_findings.txt")

        if resume and self.check_resume(sqli_output):
            result.duration = time.time() - start_time
            return result

        all_findings = []

        # Run ghauri (faster, good for initial detection)
        if "ghauri" in self.available_tools:
            ghauri_out = self.get_output_file("ghauri")
            ghauri_result = self._run_ghauri(targets_file, ghauri_out, level, risk)
            result.add_tool_result(ghauri_result)
            if ghauri_result.success:
                findings = self._parse_ghauri_output(ghauri_out, result)
                all_findings.extend(findings)

        # Run sqlmap on promising targets
        if "sqlmap" in self.available_tools and len(targets) <= 20:
            sqlmap_out = self.get_output_file("sqlmap")
            sqlmap_result = self._run_sqlmap(targets_file, sqlmap_out, level, risk)
            result.add_tool_result(sqlmap_result)
            if sqlmap_result.success:
                findings = self._parse_sqlmap_output(sqlmap_out, result)
                all_findings.extend(findings)

        # Write combined findings
        if all_findings:
            all_findings = list(set(all_findings))
            self.write_output_file(sqli_output, all_findings)
            result.output_files["sqli_findings"] = sqli_output
            result.stats["total_findings"] = len(all_findings)

            self.logger.warning(f"Found {len(all_findings)} potential SQLi vulnerabilities!")

        result.duration = time.time() - start_time
        return result

    def _run_ghauri(
        self,
        input_file: Path,
        output_dir: Path,
        level: int,
        risk: int,
    ):
        """Run ghauri SQL injection scanner."""
        output_dir.mkdir(parents=True, exist_ok=True)

        # Ghauri processes one URL at a time
        urls = self.read_input_file(input_file)
        all_stdout = []

        for url in urls[:30]:  # Limit for speed
            args = [
                "-u", url,
                "--batch",
                "--level", str(level),
                "--risk", str(risk),
                "--threads", "5",
                "--timeout", "15",
            ]

            result = self.run_tool("ghauri", args, timeout=120)
            if result.stdout:
                all_stdout.append(f"=== {url} ===\n{result.stdout}")

        # Write combined output
        if all_stdout:
            output_file = output_dir / "ghauri_output.txt"
            output_file.write_text("\n\n".join(all_stdout))
            result.result_count = len([s for s in all_stdout if "injectable" in s.lower()])

        return result

    def _run_sqlmap(
        self,
        input_file: Path,
        output_dir: Path,
        level: int,
        risk: int,
    ):
        """Run sqlmap SQL injection scanner."""
        output_dir.mkdir(parents=True, exist_ok=True)

        args = [
            "-m", str(input_file),
            "--batch",
            "--level", str(level),
            "--risk", str(risk),
            "--threads", "5",
            "--timeout", "15",
            "--output-dir", str(output_dir),
            "--smart",  # Smart heuristics
            "--answers=follow=Y",
        ]

        return self.run_tool("sqlmap", args, timeout=900)

    def _parse_ghauri_output(self, output_dir: Path, result: ModuleResult) -> List[str]:
        """Parse ghauri output for findings."""
        findings = []
        output_file = output_dir / "ghauri_output.txt"

        if not output_file.exists():
            return findings

        content = output_file.read_text()
        current_url = ""

        for line in content.split("\n"):
            if line.startswith("=== "):
                current_url = line.strip("= \n")
            elif "injectable" in line.lower() or "vulnerable" in line.lower():
                findings.append(f"{current_url} - {line.strip()}")
                result.findings.append({
                    "type": "sqli_vulnerability",
                    "url": current_url,
                    "detail": line.strip(),
                    "severity": "critical",
                })

        return findings

    def _parse_sqlmap_output(self, output_dir: Path, result: ModuleResult) -> List[str]:
        """Parse sqlmap output for findings."""
        findings = []

        if not output_dir.exists():
            return findings

        # SQLmap creates target directories
        for target_dir in output_dir.iterdir():
            if target_dir.is_dir():
                log_file = target_dir / "log"
                if log_file.exists():
                    content = log_file.read_text()

                    if "is vulnerable" in content.lower():
                        findings.append(f"{target_dir.name} - VULNERABLE")
                        result.findings.append({
                            "type": "sqli_vulnerability",
                            "url": target_dir.name,
                            "severity": "critical",
                            "source": "sqlmap",
                        })

                        # Extract injection type
                        for line in content.split("\n"):
                            if "Type:" in line:
                                result.metadata.setdefault("injection_types", []).append(
                                    line.strip()
                                )

        return findings
