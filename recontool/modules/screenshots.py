"""
Screenshots Module

Web page screenshots:
- gowitness
- eyewitness
"""

import time
from pathlib import Path
from typing import List, Optional

from .base import ActiveModule, ModuleResult


class ScreenshotsModule(ActiveModule):
    """Capture screenshots of web applications."""

    name = "screenshots"
    description = "Capture screenshots of discovered web applications"
    tools = ["gowitness", "eyewitness"]
    output_dir = "screenshots"

    def run(
        self,
        targets: List[str],
        resume: bool = True,
        input_file: Optional[Path] = None,
        threads: int = 10,
        **kwargs,
    ) -> ModuleResult:
        """
        Capture screenshots of target URLs.

        Args:
            targets: List of URLs to screenshot
            resume: Skip if output exists
            input_file: File containing URLs
            threads: Number of concurrent threads

        Returns:
            ModuleResult with screenshot paths
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
            self.logger.warning("No targets for screenshots")
            result.duration = time.time() - start_time
            return result

        # Filter to HTTP URLs
        targets = [t for t in targets if t.startswith(("http://", "https://"))]
        targets = self.filter_scope(targets)
        targets = list(set(targets))

        self.logger.info(f"Capturing screenshots for {len(targets)} URLs")

        # Write targets
        targets_file = self.get_output_file("targets.txt")
        self.write_output_file(targets_file, targets)

        # Check resume
        gowitness_db = self.output_path / "gowitness.sqlite3"
        if resume and gowitness_db.exists():
            self.logger.info("Screenshots already captured")
            result.duration = time.time() - start_time
            return result

        # Run gowitness (preferred)
        if "gowitness" in self.available_tools:
            gw_result = self._run_gowitness(targets_file, threads)
            result.add_tool_result(gw_result)
            if gw_result.success:
                result.output_files["gowitness_db"] = gowitness_db
                result.output_files["screenshots_dir"] = self.output_path / "screenshots"

                # Count screenshots
                screenshots_dir = self.output_path / "screenshots"
                if screenshots_dir.exists():
                    count = len(list(screenshots_dir.glob("*.png")))
                    result.stats["screenshots_captured"] = count
                    self.logger.info(f"Captured {count} screenshots")

        # Run eyewitness as backup
        elif "eyewitness" in self.available_tools:
            ew_result = self._run_eyewitness(targets_file, threads)
            result.add_tool_result(ew_result)
            if ew_result.success:
                result.output_files["eyewitness_report"] = self.output_path / "report.html"

        result.duration = time.time() - start_time
        return result

    def _run_gowitness(self, input_file: Path, threads: int):
        """Run gowitness for screenshots."""
        screenshots_dir = self.output_path / "screenshots"
        screenshots_dir.mkdir(parents=True, exist_ok=True)

        args = [
            "file",
            "-f", str(input_file),
            "--screenshot-path", str(screenshots_dir),
            "--db-path", str(self.output_path / "gowitness.sqlite3"),
            "-t", str(threads),
            "--timeout", "30",
            "--delay", "2",
        ]
        return self.run_tool("gowitness", args, timeout=1800)

    def _run_eyewitness(self, input_file: Path, threads: int):
        """Run eyewitness for screenshots."""
        args = [
            "-f", str(input_file),
            "-d", str(self.output_path),
            "--threads", str(threads),
            "--timeout", "30",
            "--no-prompt",
        ]
        return self.run_tool("eyewitness", args, timeout=1800)
