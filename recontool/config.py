"""
Configuration loader and validator for ReconTool

Handles YAML configuration files with validation, defaults,
and runtime module enabling/disabling.
"""

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import yaml

from .utils.logging import get_logger
from .utils.scope import ScopeValidator

logger = get_logger("config")


# Default module configuration
DEFAULT_MODULES = {
    "subdomain_enum": True,
    "http_probe": True,
    "crawling": True,
    "url_collection": True,
    "js_analysis": True,
    "parameter_discovery": True,
    "fuzzing": False,  # Disabled by default (can be noisy)
    "nuclei_scan": True,
    "port_scan": True,
    "xss_scan": False,  # Disabled by default (active testing)
    "sqli_scan": False,  # Disabled by default (active testing)
    "cloud_enum": True,
    "git_recon": True,
    "osint": True,
    "screenshots": True,
    "cert_monitoring": False,  # Disabled by default (long running)
    "dns_enum": True,
    "reverse_dns": False,  # Disabled by default
}

# Tool configurations per module
MODULE_TOOLS = {
    "subdomain_enum": ["subfinder", "amass", "assetfinder", "findomain", "chaos"],
    "http_probe": ["httpx", "httprobe"],
    "crawling": ["katana", "gospider", "hakrawler", "cariddi"],
    "url_collection": ["gau", "waybackurls", "waymore"],
    "js_analysis": ["subjs", "linkfinder", "secretfinder", "jsubfinder"],
    "parameter_discovery": ["arjun", "x8", "paramspider"],
    "fuzzing": ["ffuf", "feroxbuster"],
    "nuclei_scan": ["nuclei", "jaeles"],
    "port_scan": ["naabu"],
    "xss_scan": ["dalfox", "xsstrike", "kxss", "airixss"],
    "sqli_scan": ["sqlmap", "ghauri"],
    "cloud_enum": ["cloud_enum", "s3scanner"],
    "git_recon": ["trufflehog", "gitrob", "github-subdomains"],
    "osint": ["shodan", "censys", "metabigor"],
    "screenshots": ["gowitness", "eyewitness"],
    "cert_monitoring": ["certstream"],
    "dns_enum": ["dnsx", "shuffledns", "puredns", "massdns", "dnsgen"],
    "reverse_dns": ["hakrevdns", "prips"],
}


@dataclass
class TargetConfig:
    """Configuration for the target."""
    type: str  # "domain", "url", "ip", "file"
    value: str
    targets: List[str] = field(default_factory=list)

    def __post_init__(self):
        """Load targets from file if type is file."""
        if self.type == "file":
            self._load_targets_from_file()
        elif not self.targets:
            self.targets = [self.value]

    def _load_targets_from_file(self) -> None:
        """Load targets from a file."""
        file_path = Path(self.value)
        if not file_path.exists():
            raise ValueError(f"Target file not found: {self.value}")

        content = file_path.read_text().strip()

        # Try JSON first
        if self.value.endswith(".json"):
            try:
                data = json.loads(content)
                if isinstance(data, list):
                    self.targets = [str(t) for t in data]
                elif isinstance(data, dict) and "targets" in data:
                    self.targets = [str(t) for t in data["targets"]]
                return
            except json.JSONDecodeError:
                pass

        # Fall back to line-by-line
        self.targets = [
            line.strip() for line in content.split("\n")
            if line.strip() and not line.startswith("#")
        ]


@dataclass
class ModuleConfig:
    """Configuration for modules."""
    enabled: Dict[str, bool] = field(default_factory=dict)
    tool_options: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    timeouts: Dict[str, int] = field(default_factory=dict)
    rate_limits: Dict[str, float] = field(default_factory=dict)

    def __post_init__(self):
        """Apply defaults for missing modules."""
        for module, default_enabled in DEFAULT_MODULES.items():
            if module not in self.enabled:
                self.enabled[module] = default_enabled

    def is_enabled(self, module_name: str) -> bool:
        """Check if a module is enabled."""
        return self.enabled.get(module_name, False)

    def enable(self, *module_names: str) -> None:
        """Enable modules."""
        for name in module_names:
            self.enabled[name] = True

    def disable(self, *module_names: str) -> None:
        """Disable modules."""
        for name in module_names:
            self.enabled[name] = False

    def get_timeout(self, module_name: str, default: int = 300) -> int:
        """Get timeout for a module."""
        return self.timeouts.get(module_name, default)

    def get_rate_limit(self, module_name: str, default: float = 0.0) -> float:
        """Get rate limit delay for a module."""
        return self.rate_limits.get(module_name, default)

    def get_tool_options(self, module_name: str, tool_name: str) -> Dict[str, Any]:
        """Get tool-specific options."""
        module_opts = self.tool_options.get(module_name, {})
        return module_opts.get(tool_name, {})


@dataclass
class OutputConfig:
    """Configuration for output handling."""
    base_dir: Path = field(default_factory=lambda: Path("recon"))
    save_raw: bool = True
    save_normalized: bool = True
    format: str = "txt"  # txt, json, csv

    def get_dir(self, category: str) -> Path:
        """Get directory for a category."""
        return self.base_dir / category

    def ensure_dirs(self) -> None:
        """Create all output directories."""
        directories = [
            "config", "targets", "subdomains/raw", "subdomains/resolved",
            "subdomains/alive", "http", "crawling", "urls", "js", "params",
            "fuzzing", "ports", "nuclei", "xss", "sqli", "cloud", "git",
            "osint", "screenshots", "dns", "certs", "logs", "context"
        ]
        for dir_name in directories:
            (self.base_dir / dir_name).mkdir(parents=True, exist_ok=True)


@dataclass
class Config:
    """Main configuration class for ReconTool."""
    target: TargetConfig
    scope: ScopeValidator
    modules: ModuleConfig
    output: OutputConfig
    parallel: bool = True
    max_workers: int = 5
    resume: bool = True
    verbose: bool = False
    api_keys: Dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_yaml(cls, config_path: Union[str, Path]) -> "Config":
        """
        Load configuration from a YAML file.

        Args:
            config_path: Path to the YAML configuration file

        Returns:
            Config instance
        """
        config_path = Path(config_path)
        if not config_path.exists():
            raise FileNotFoundError(f"Config file not found: {config_path}")

        logger.info(f"Loading configuration from {config_path}")

        with open(config_path, "r") as f:
            data = yaml.safe_load(f)

        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Config":
        """
        Create configuration from a dictionary.

        Args:
            data: Configuration dictionary

        Returns:
            Config instance
        """
        # Parse target
        target_data = data.get("target", {})
        target = TargetConfig(
            type=target_data.get("type", "domain"),
            value=target_data.get("value", ""),
        )

        # Parse scope
        scope_data = data.get("scope", {})
        scope = ScopeValidator(
            in_scope=scope_data.get("in_scope", []),
            out_of_scope=scope_data.get("out_of_scope", []),
        )

        # If no in_scope defined, use target as in_scope
        if not scope.in_scope and target.value:
            if target.type == "domain":
                scope.add_in_scope(f"*.{target.value}", target.value)
            elif target.type == "url":
                from urllib.parse import urlparse
                parsed = urlparse(target.value)
                if parsed.hostname:
                    scope.add_in_scope(f"*.{parsed.hostname}", parsed.hostname)
            else:
                scope.add_in_scope(target.value)

        # Parse modules
        modules_data = data.get("modules", {})
        modules = ModuleConfig(
            enabled={k: v for k, v in modules_data.items() if isinstance(v, bool)},
            tool_options=modules_data.get("tool_options", {}),
            timeouts=modules_data.get("timeouts", {}),
            rate_limits=modules_data.get("rate_limits", {}),
        )

        # Parse output
        output_data = data.get("output", {})
        output = OutputConfig(
            base_dir=Path(output_data.get("base_dir", "recon")),
            save_raw=output_data.get("save_raw", True),
            save_normalized=output_data.get("save_normalized", True),
            format=output_data.get("format", "txt"),
        )

        # Parse other options
        return cls(
            target=target,
            scope=scope,
            modules=modules,
            output=output,
            parallel=data.get("parallel", True),
            max_workers=data.get("max_workers", 5),
            resume=data.get("resume", True),
            verbose=data.get("verbose", False),
            api_keys=data.get("api_keys", {}),
        )

    @classmethod
    def from_args(
        cls,
        target: str,
        target_type: str = "domain",
        output_dir: str = "recon",
        **kwargs,
    ) -> "Config":
        """
        Create configuration from command-line arguments.

        Args:
            target: Target value
            target_type: Type of target (domain, url, ip, file)
            output_dir: Output directory
            **kwargs: Additional options

        Returns:
            Config instance
        """
        data = {
            "target": {
                "type": target_type,
                "value": target,
            },
            "output": {
                "base_dir": output_dir,
            },
            "modules": kwargs.get("modules", {}),
            "scope": kwargs.get("scope", {}),
            "parallel": kwargs.get("parallel", True),
            "max_workers": kwargs.get("max_workers", 5),
            "verbose": kwargs.get("verbose", False),
            "api_keys": kwargs.get("api_keys", {}),
        }
        return cls.from_dict(data)

    def save(self, path: Optional[Path] = None) -> Path:
        """
        Save configuration to a YAML file.

        Args:
            path: Output path (defaults to output/config/config.yaml)

        Returns:
            Path to saved file
        """
        if path is None:
            path = self.output.base_dir / "config" / "config.yaml"

        path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "target": {
                "type": self.target.type,
                "value": self.target.value,
            },
            "scope": {
                "in_scope": self.scope.in_scope,
                "out_of_scope": self.scope.out_of_scope,
            },
            "modules": self.modules.enabled,
            "output": {
                "base_dir": str(self.output.base_dir),
                "save_raw": self.output.save_raw,
                "save_normalized": self.output.save_normalized,
            },
            "parallel": self.parallel,
            "max_workers": self.max_workers,
            "resume": self.resume,
            "verbose": self.verbose,
        }

        with open(path, "w") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)

        logger.info(f"Configuration saved to {path}")
        return path

    def get_enabled_modules(self) -> List[str]:
        """Get list of enabled module names."""
        return [
            name for name, enabled in self.modules.enabled.items()
            if enabled
        ]

    def get_api_key(self, service: str) -> Optional[str]:
        """
        Get API key for a service.

        Checks config first, then environment variables.
        """
        # Check config
        if service in self.api_keys:
            return self.api_keys[service]

        # Check environment
        env_var = f"{service.upper()}_API_KEY"
        return os.environ.get(env_var)

    def validate(self) -> List[str]:
        """
        Validate configuration.

        Returns:
            List of validation error messages
        """
        errors = []

        # Check target
        if not self.target.value:
            errors.append("Target value is required")

        if self.target.type not in ["domain", "url", "ip", "file"]:
            errors.append(f"Invalid target type: {self.target.type}")

        if self.target.type == "file":
            if not Path(self.target.value).exists():
                errors.append(f"Target file not found: {self.target.value}")

        # Check output directory is writable
        try:
            test_file = self.output.base_dir / ".write_test"
            self.output.base_dir.mkdir(parents=True, exist_ok=True)
            test_file.touch()
            test_file.unlink()
        except Exception as e:
            errors.append(f"Output directory not writable: {e}")

        return errors

    def summary(self) -> str:
        """Get a summary of the configuration."""
        enabled = self.get_enabled_modules()
        return (
            f"Target: {self.target.type}={self.target.value}\n"
            f"Scope: {len(self.scope.in_scope)} in, {len(self.scope.out_of_scope)} out\n"
            f"Modules: {len(enabled)} enabled\n"
            f"Output: {self.output.base_dir}\n"
            f"Parallel: {self.parallel} (workers={self.max_workers})"
        )
