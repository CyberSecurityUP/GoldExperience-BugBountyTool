"""
Port Scanning Module - Enhanced Version

Port scanning for service discovery:
- naabu (fast SYN scanner)

Output structure:
  ports/
    ├── raw/
    │   ├── naabu.txt
    │   └── naabu.jsonl
    ├── open_ports.txt (host:port format)
    ├── by_port/
    │   ├── 22.txt (hosts with SSH)
    │   ├── 80.txt
    │   ├── 443.txt
    │   └── ...
    ├── by_service/
    │   ├── web.txt (80,443,8080,etc)
    │   ├── database.txt (3306,5432,etc)
    │   ├── remote_access.txt (22,3389,etc)
    │   └── interesting.txt
    ├── hosts_with_ports.json
    └── port_scan_summary.json
"""

import json
import time
from pathlib import Path
from typing import List, Optional, Dict, Set
from collections import defaultdict
from urllib.parse import urlparse

from .base import ActiveModule, ModuleResult
from ..utils.process import ToolResult, check_tool_exists
from ..utils.dedup import deduplicate_lines


class PortScanModule(ActiveModule):
    """Enhanced port scanning with categorized output."""

    name = "port_scan"
    description = "Scan targets for open ports and services"
    tools = ["naabu"]
    output_dir = "ports"

    # Service categorization by port
    SERVICE_CATEGORIES = {
        "web": [80, 443, 8080, 8443, 8000, 8888, 9000, 9443, 3000, 5000],
        "database": [3306, 5432, 1433, 1521, 27017, 6379, 9200, 5984, 9042],
        "remote_access": [22, 23, 3389, 5900, 5901, 5902],
        "mail": [25, 110, 143, 465, 587, 993, 995],
        "file_transfer": [21, 69, 139, 445, 2049],
        "dns": [53],
        "ldap": [389, 636],
    }

    # Interesting/sensitive ports
    INTERESTING_PORTS = {
        21: ("FTP", "high"),
        22: ("SSH", "medium"),
        23: ("Telnet", "critical"),
        25: ("SMTP", "medium"),
        53: ("DNS", "medium"),
        110: ("POP3", "medium"),
        111: ("RPC", "high"),
        135: ("MSRPC", "high"),
        139: ("NetBIOS", "high"),
        143: ("IMAP", "medium"),
        389: ("LDAP", "high"),
        445: ("SMB", "critical"),
        512: ("rexec", "critical"),
        513: ("rlogin", "critical"),
        514: ("rsh", "critical"),
        1099: ("Java RMI", "high"),
        1433: ("MSSQL", "high"),
        1521: ("Oracle", "high"),
        2049: ("NFS", "high"),
        3306: ("MySQL", "high"),
        3389: ("RDP", "high"),
        5432: ("PostgreSQL", "high"),
        5900: ("VNC", "high"),
        6379: ("Redis", "critical"),
        8009: ("AJP", "high"),
        9200: ("Elasticsearch", "high"),
        11211: ("Memcached", "critical"),
        27017: ("MongoDB", "critical"),
    }

    def run(
        self,
        targets: List[str],
        resume: bool = True,
        input_file: Optional[Path] = None,
        ports: Optional[str] = None,
        top_ports: int = 1000,
        full_scan: bool = False,
        **kwargs,
    ) -> ModuleResult:
        """
        Run port scanning on targets.

        Args:
            targets: List of hosts/IPs to scan
            resume: Skip if output exists
            input_file: File containing targets
            ports: Specific ports to scan
            top_ports: Number of top ports to scan
            full_scan: Scan all 65535 ports

        Returns:
            ModuleResult with categorized open ports
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
        by_port_dir = self.output_path / "by_port"
        by_port_dir.mkdir(parents=True, exist_ok=True)
        by_service_dir = self.output_path / "by_service"
        by_service_dir.mkdir(parents=True, exist_ok=True)

        # Load targets
        if input_file and input_file.exists():
            targets = self.read_input_file(input_file)

        if not targets:
            self.logger.warning("No targets provided for port scanning")
            result.duration = time.time() - start_time
            return result

        # Extract hosts from URLs if needed
        targets = self._extract_hosts(targets)
        targets = self.filter_scope(targets)
        targets = list(set(targets))

        self.logger.info(f"{'='*50}")
        self.logger.info(f"Scanning {len(targets)} hosts for open ports")
        self.logger.info(f"{'='*50}")

        # Write targets
        targets_file = self.output_path / "targets.txt"
        self.write_output_file(targets_file, targets)

        # Output files
        ports_output = self.output_path / "open_ports.txt"

        if resume and ports_output.exists() and ports_output.stat().st_size > 0:
            self.logger.info("Resuming: Using existing port scan results")
            result.duration = time.time() - start_time
            return result

        # Run naabu
        if check_tool_exists("naabu"):
            naabu_output = raw_dir / "naabu.txt"
            naabu_json = raw_dir / "naabu.jsonl"

            naabu_result = self._run_naabu(
                targets_file,
                naabu_output,
                naabu_json,
                ports=ports,
                top_ports=top_ports,
                full_scan=full_scan,
            )
            result.add_tool_result(naabu_result)

            if naabu_result.success:
                result.output_files["naabu_raw"] = naabu_output
                result.output_files["naabu_json"] = naabu_json

                # Parse and categorize results
                self._parse_and_categorize_results(
                    naabu_output, naabu_json, ports_output,
                    by_port_dir, by_service_dir, result
                )
        else:
            result.success = False
            result.errors.append("naabu not available")

        # Save JSON summary
        self._save_json_summary(result)

        result.duration = time.time() - start_time
        return result

    def _extract_hosts(self, targets: List[str]) -> List[str]:
        """Extract hostnames/IPs from URLs."""
        hosts = set()
        for target in targets:
            if target.startswith(("http://", "https://")):
                parsed = urlparse(target)
                if parsed.hostname:
                    hosts.add(parsed.hostname)
            else:
                # Might be IP or hostname already
                host = target.split("/")[0].split(":")[0]
                if host:
                    hosts.add(host)
        return list(hosts)

    def _run_naabu(
        self,
        input_file: Path,
        output_file: Path,
        json_file: Path,
        ports: Optional[str],
        top_ports: int,
        full_scan: bool,
    ) -> ToolResult:
        """Run naabu port scanner."""
        args = [
            "-l", str(input_file),
            "-o", str(output_file),
            "-json",
            "-output", str(json_file),
            "-silent",
            "-c", "50",
            "-rate", "1000",
            "-retries", "2",
            "-warm-up-time", "2",
        ]

        if full_scan:
            args.extend(["-p", "-"])  # All ports
        elif ports:
            args.extend(["-p", ports])
        else:
            args.extend(["-top-ports", str(top_ports)])

        return self.run_tool("naabu", args, timeout=1800)

    def _parse_and_categorize_results(
        self,
        raw_output: Path,
        json_file: Path,
        ports_output: Path,
        by_port_dir: Path,
        by_service_dir: Path,
        result: ModuleResult,
    ) -> None:
        """Parse naabu results and categorize by port/service."""
        if not raw_output.exists():
            return

        # Data structures
        hosts_ports: Dict[str, List[int]] = defaultdict(list)
        ports_hosts: Dict[int, List[str]] = defaultdict(list)
        service_hosts: Dict[str, Set[str]] = defaultdict(set)
        interesting_findings: List[Dict] = []

        # Parse raw output (host:port format)
        lines = self.read_input_file(raw_output)
        for line in lines:
            if ":" in line:
                try:
                    host, port_str = line.rsplit(":", 1)
                    port = int(port_str)
                    hosts_ports[host].append(port)
                    ports_hosts[port].append(host)

                    # Check if interesting port
                    if port in self.INTERESTING_PORTS:
                        service_name, severity = self.INTERESTING_PORTS[port]
                        interesting_findings.append({
                            "host": host,
                            "port": port,
                            "service": service_name,
                            "severity": severity,
                        })

                    # Categorize by service
                    for service, service_ports in self.SERVICE_CATEGORIES.items():
                        if port in service_ports:
                            service_hosts[service].add(f"{host}:{port}")
                            break

                except (ValueError, IndexError):
                    continue

        # Write open_ports.txt (deduplicated)
        self.write_output_file(ports_output, deduplicate_lines(lines))
        result.output_files["open_ports"] = ports_output
        result.stats["total_open_ports"] = len(lines)
        result.stats["unique_hosts"] = len(hosts_ports)

        self.logger.info(f"Found {len(lines)} open ports on {len(hosts_ports)} hosts")

        # Write by-port files
        for port, hosts in ports_hosts.items():
            port_file = by_port_dir / f"{port}.txt"
            self.write_output_file(port_file, list(set(hosts)))
            result.stats[f"port_{port}_count"] = len(hosts)

        # Write by-service files
        for service, host_ports in service_hosts.items():
            if host_ports:
                service_file = by_service_dir / f"{service}.txt"
                self.write_output_file(service_file, sorted(host_ports))
                result.output_files[f"service_{service}"] = service_file
                result.stats[f"service_{service}_count"] = len(host_ports)
                self.logger.info(f"  {service}: {len(host_ports)} endpoints")

        # Write interesting findings
        if interesting_findings:
            interesting_file = by_service_dir / "interesting.txt"
            interesting_lines = [
                f"[{f['severity'].upper()}] {f['host']}:{f['port']} ({f['service']})"
                for f in interesting_findings
            ]
            self.write_output_file(interesting_file, interesting_lines)
            result.output_files["interesting_ports"] = interesting_file

            # Add to findings
            for finding in interesting_findings:
                result.findings.append({
                    "type": "interesting_port",
                    "host": finding["host"],
                    "port": finding["port"],
                    "service": finding["service"],
                    "severity": finding["severity"],
                })

            # Log critical/high severity
            critical_high = [f for f in interesting_findings if f["severity"] in ["critical", "high"]]
            if critical_high:
                self.logger.warning(f"Found {len(critical_high)} sensitive ports exposed!")

        # Write hosts_with_ports.json
        hosts_json = self.output_path / "hosts_with_ports.json"
        with open(hosts_json, "w") as f:
            json.dump({
                "hosts": {h: sorted(p) for h, p in hosts_ports.items()},
                "port_distribution": {str(p): len(h) for p, h in sorted(ports_hosts.items(), key=lambda x: -len(x[1]))[:20]},
            }, f, indent=2)
        result.output_files["hosts_json"] = hosts_json

        # Store metadata
        result.metadata["hosts_ports"] = dict(hosts_ports)
        result.metadata["port_distribution"] = {str(p): len(h) for p, h in ports_hosts.items()}

    def _save_json_summary(self, result: ModuleResult) -> None:
        """Save JSON summary."""
        summary = {
            "module": self.name,
            "stats": result.stats,
            "output_files": {k: str(v) for k, v in result.output_files.items()},
            "tools_used": list(self.available_tools),
            "port_distribution": result.metadata.get("port_distribution", {}),
            "findings_count": len(result.findings),
            "critical_findings": len([f for f in result.findings if f.get("severity") == "critical"]),
        }

        json_file = self.output_path / "port_scan_summary.json"
        with open(json_file, "w") as f:
            json.dump(summary, f, indent=2)

        result.output_files["json_summary"] = json_file
