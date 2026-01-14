"""
XSS Scanning Module

Cross-Site Scripting vulnerability detection:
- dalfox
- xsstrike
- kxss
- airixss
"""

import json
import time
from pathlib import Path
from typing import List, Optional

from .base import ActiveModule, ModuleResult
from ..utils.dedup import merge_files


class XssScanModule(ActiveModule):
    """XSS vulnerability scanning."""

    name = "xss_scan"
    description = "Scan for Cross-Site Scripting (XSS) vulnerabilities"
    tools = ["dalfox", "xsstrike", "kxss", "airixss"]
    output_dir = "xss"

    def run(
        self,
        targets: List[str],
        resume: bool = True,
        input_file: Optional[Path] = None,
        blind_xss_url: Optional[str] = None,
        **kwargs,
    ) -> ModuleResult:
        """
        Run XSS scanning on URLs with parameters.

        Args:
            targets: List of URLs with parameters to test
            resume: Skip if output exists
            input_file: File containing URLs
            blind_xss_url: Blind XSS callback URL

        Returns:
            ModuleResult with XSS vulnerabilities
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
            self.logger.warning("No URLs with parameters for XSS testing")
            result.duration = time.time() - start_time
            return result

        # Filter and limit
        targets = self.filter_scope(targets)
        targets = list(set(targets))

        if len(targets) > 200:
            self.logger.warning(f"Limiting to 200 URLs (had {len(targets)})")
            targets = targets[:200]

        self.logger.info(f"Testing {len(targets)} URLs for XSS")

        # Write targets
        targets_file = self.get_output_file("targets.txt")
        self.write_output_file(targets_file, targets)

        # Output files
        xss_output = self.get_output_file("xss_findings.txt")

        if resume and self.check_resume(xss_output):
            result.duration = time.time() - start_time
            return result

        tool_outputs = []

        # Run dalfox (primary XSS scanner)
        if "dalfox" in self.available_tools:
            dalfox_out = self.get_output_file("dalfox.txt")
            dalfox_json = self.get_output_file("dalfox.json")
            dalfox_result = self._run_dalfox(
                targets_file, dalfox_out, dalfox_json, blind_xss_url
            )
            result.add_tool_result(dalfox_result)
            if dalfox_result.success and dalfox_out.exists():
                tool_outputs.append(dalfox_out)
                self._parse_dalfox_output(dalfox_json, result)

        # Run kxss for reflection detection
        if "kxss" in self.available_tools:
            kxss_out = self.get_output_file("kxss.txt")
            kxss_result = self._run_kxss(targets_file, kxss_out)
            result.add_tool_result(kxss_result)
            if kxss_result.success and kxss_out.exists():
                tool_outputs.append(kxss_out)

        # Run airixss
        if "airixss" in self.available_tools:
            airixss_out = self.get_output_file("airixss.txt")
            airixss_result = self._run_airixss(targets_file, airixss_out)
            result.add_tool_result(airixss_result)
            if airixss_result.success and airixss_out.exists():
                tool_outputs.append(airixss_out)

        # Merge results
        if tool_outputs:
            count = merge_files(tool_outputs, xss_output, deduplicate=True)
            result.output_files["xss_findings"] = xss_output
            result.stats["total_findings"] = count

            self.logger.info(f"Found {count} potential XSS vulnerabilities")

        result.duration = time.time() - start_time
        return result

    def _run_dalfox(
        self,
        input_file: Path,
        output_file: Path,
        json_file: Path,
        blind_xss_url: Optional[str],
    ):
        """Run dalfox XSS scanner."""
        args = [
            "file", str(input_file),
            "-o", str(output_file),
            "--format", "json",
            "--output-all",
            "-w", "20",
            "--silence",
            "--no-color",
        ]

        if blind_xss_url:
            args.extend(["--blind", blind_xss_url])

        result = self.run_tool("dalfox", args, timeout=900)

        # Parse output for JSON
        if result.success and result.stdout:
            try:
                json_file.write_text(result.stdout)
            except:
                pass

        return result

    def _run_kxss(self, input_file: Path, output_file: Path):
        """Run kxss for reflection detection."""
        input_data = input_file.read_text()
        args = []
        return self.run_tool(
            "kxss",
            args,
            input_data=input_data,
            output_file=output_file,
            timeout=600,
        )

    def _run_airixss(self, input_file: Path, output_file: Path):
        """Run airixss scanner."""
        input_data = input_file.read_text()
        args = [
            "-payload", "'\"><img src=x onerror=alert(1)>",
        ]
        return self.run_tool(
            "airixss",
            args,
            input_data=input_data,
            output_file=output_file,
            timeout=600,
        )

    def _parse_dalfox_output(self, json_file: Path, result: ModuleResult) -> None:
        """Parse dalfox JSON output for findings."""
        if not json_file.exists():
            return

        try:
            content = json_file.read_text()
            if not content:
                return

            # Dalfox outputs one JSON per line
            for line in content.strip().split("\n"):
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    xss_type = data.get("type", "unknown")
                    url = data.get("data", "")
                    param = data.get("param", "")
                    payload = data.get("payload", "")

                    finding = {
                        "type": "xss_vulnerability",
                        "xss_type": xss_type,
                        "url": url,
                        "param": param,
                        "payload": payload[:100],  # Truncate
                        "severity": "high" if xss_type == "V" else "medium",
                    }

                    result.findings.append(finding)

                    # Categorize by type
                    if xss_type == "V":  # Verified
                        result.stats["verified_xss"] = result.stats.get("verified_xss", 0) + 1
                    elif xss_type == "R":  # Reflected
                        result.stats["reflected_xss"] = result.stats.get("reflected_xss", 0) + 1
                    elif xss_type == "G":  # Grep (potential)
                        result.stats["potential_xss"] = result.stats.get("potential_xss", 0) + 1

                except json.JSONDecodeError:
                    continue

            if result.stats.get("verified_xss", 0) > 0:
                self.logger.warning(
                    f"VERIFIED XSS: {result.stats['verified_xss']} confirmed vulnerabilities!"
                )

        except Exception as e:
            self.logger.error(f"Error parsing dalfox output: {e}")
