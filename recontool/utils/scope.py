"""
Scope validation utilities for ReconTool

Provides in-scope/out-of-scope validation for targets,
ensuring reconnaissance stays within authorized boundaries.
"""

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Set, Optional
from urllib.parse import urlparse

from .logging import get_logger

logger = get_logger("scope")


@dataclass
class ScopeValidator:
    """
    Validates targets against defined scope rules.

    Supports:
    - Wildcard domains (*.example.com)
    - Exact domain matches
    - IP addresses and CIDR ranges
    - URL patterns
    """
    in_scope: List[str] = field(default_factory=list)
    out_of_scope: List[str] = field(default_factory=list)

    # Compiled patterns for efficiency
    _in_scope_patterns: List[re.Pattern] = field(default_factory=list, repr=False)
    _out_scope_patterns: List[re.Pattern] = field(default_factory=list, repr=False)
    _in_scope_cidrs: List[ipaddress.IPv4Network] = field(default_factory=list, repr=False)
    _out_scope_cidrs: List[ipaddress.IPv4Network] = field(default_factory=list, repr=False)
    _initialized: bool = field(default=False, repr=False)

    def __post_init__(self):
        """Compile patterns after initialization."""
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        """Compile scope rules into regex patterns and CIDR ranges."""
        if self._initialized:
            return

        self._in_scope_patterns = []
        self._out_scope_patterns = []
        self._in_scope_cidrs = []
        self._out_scope_cidrs = []

        for rule in self.in_scope:
            self._add_rule(rule, is_in_scope=True)

        for rule in self.out_of_scope:
            self._add_rule(rule, is_in_scope=False)

        self._initialized = True

        logger.debug(f"Compiled {len(self._in_scope_patterns)} in-scope patterns")
        logger.debug(f"Compiled {len(self._out_scope_patterns)} out-of-scope patterns")
        logger.debug(f"Compiled {len(self._in_scope_cidrs)} in-scope CIDRs")
        logger.debug(f"Compiled {len(self._out_scope_cidrs)} out-of-scope CIDRs")

    def _add_rule(self, rule: str, is_in_scope: bool) -> None:
        """Add a single rule to the appropriate list."""
        rule = rule.strip()
        if not rule:
            return

        # Check if it's a CIDR notation
        if self._is_cidr(rule):
            try:
                network = ipaddress.ip_network(rule, strict=False)
                if is_in_scope:
                    self._in_scope_cidrs.append(network)
                else:
                    self._out_scope_cidrs.append(network)
                return
            except ValueError:
                pass

        # Check if it's a plain IP
        if self._is_ip(rule):
            try:
                network = ipaddress.ip_network(f"{rule}/32", strict=False)
                if is_in_scope:
                    self._in_scope_cidrs.append(network)
                else:
                    self._out_scope_cidrs.append(network)
                return
            except ValueError:
                pass

        # Convert wildcard domain to regex pattern
        pattern = self._domain_to_pattern(rule)
        if is_in_scope:
            self._in_scope_patterns.append(pattern)
        else:
            self._out_scope_patterns.append(pattern)

    def _is_cidr(self, value: str) -> bool:
        """Check if value is a CIDR notation."""
        return "/" in value and not value.startswith("http")

    def _is_ip(self, value: str) -> bool:
        """Check if value is an IP address."""
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def _domain_to_pattern(self, domain: str) -> re.Pattern:
        """
        Convert a domain with optional wildcards to a regex pattern.

        Examples:
            *.example.com -> matches sub.example.com, a.b.example.com
            example.com -> matches example.com exactly
            *.*.example.com -> matches a.b.example.com
        """
        # Escape special regex characters except *
        escaped = re.escape(domain).replace(r"\*", ".*")

        # Ensure we match the full domain
        if domain.startswith("*."):
            # Wildcard matches any subdomain, including nested
            pattern = f"^(.*\\.)?{escaped[4:]}$"
        else:
            pattern = f"^{escaped}$"

        return re.compile(pattern, re.IGNORECASE)

    def is_in_scope(self, target: str) -> bool:
        """
        Check if a target is in scope.

        Args:
            target: Domain, URL, or IP to check

        Returns:
            True if target is in scope, False otherwise
        """
        if not self._initialized:
            self._compile_patterns()

        # If no in_scope rules defined, everything is in scope
        if not self.in_scope:
            in_scope = True
        else:
            in_scope = self._matches_scope(target, is_in_scope=True)

        # Check out of scope (takes precedence)
        if self.out_of_scope:
            out_of_scope = self._matches_scope(target, is_in_scope=False)
            if out_of_scope:
                return False

        return in_scope

    def _matches_scope(self, target: str, is_in_scope: bool) -> bool:
        """Check if target matches scope rules."""
        # Extract domain/IP from URL if needed
        domain = self._extract_domain(target)
        ip = self._extract_ip(target)

        patterns = self._in_scope_patterns if is_in_scope else self._out_scope_patterns
        cidrs = self._in_scope_cidrs if is_in_scope else self._out_scope_cidrs

        # Check domain patterns
        if domain:
            for pattern in patterns:
                if pattern.match(domain):
                    return True

        # Check IP/CIDR ranges
        if ip:
            try:
                ip_obj = ipaddress.ip_address(ip)
                for cidr in cidrs:
                    if ip_obj in cidr:
                        return True
            except ValueError:
                pass

        return False

    def _extract_domain(self, target: str) -> Optional[str]:
        """Extract domain from a target (URL, domain, or IP)."""
        # If it's a URL, parse it
        if target.startswith(("http://", "https://")):
            parsed = urlparse(target)
            return parsed.hostname

        # If it contains /, treat as URL
        if "/" in target:
            # Try adding scheme
            parsed = urlparse(f"http://{target}")
            return parsed.hostname

        # Otherwise, it might be a domain or IP
        if self._is_ip(target):
            return None

        return target

    def _extract_ip(self, target: str) -> Optional[str]:
        """Extract IP from a target."""
        # If it's a URL, parse it
        if target.startswith(("http://", "https://")):
            parsed = urlparse(target)
            hostname = parsed.hostname
            if hostname and self._is_ip(hostname):
                return hostname
            return None

        # Check if target itself is an IP
        if self._is_ip(target):
            return target

        return None

    def filter_targets(self, targets: List[str]) -> List[str]:
        """
        Filter a list of targets, keeping only in-scope ones.

        Args:
            targets: List of targets to filter

        Returns:
            List of in-scope targets
        """
        in_scope_targets = []
        out_of_scope_count = 0

        for target in targets:
            if self.is_in_scope(target):
                in_scope_targets.append(target)
            else:
                out_of_scope_count += 1

        if out_of_scope_count > 0:
            logger.info(f"Filtered {out_of_scope_count} out-of-scope targets")

        return in_scope_targets

    def filter_file(self, input_file: Path, output_file: Path) -> int:
        """
        Filter a file of targets, writing in-scope ones to output.

        Args:
            input_file: File containing targets (one per line)
            output_file: File to write in-scope targets to

        Returns:
            Number of in-scope targets written
        """
        if not input_file.exists():
            logger.warning(f"Input file {input_file} does not exist")
            return 0

        targets = input_file.read_text().strip().split("\n")
        in_scope = self.filter_targets(targets)

        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text("\n".join(in_scope))

        return len(in_scope)

    def add_in_scope(self, *rules: str) -> None:
        """Add rules to in-scope list."""
        self.in_scope.extend(rules)
        self._initialized = False
        self._compile_patterns()

    def add_out_of_scope(self, *rules: str) -> None:
        """Add rules to out-of-scope list."""
        self.out_of_scope.extend(rules)
        self._initialized = False
        self._compile_patterns()

    def get_summary(self) -> dict:
        """Get a summary of scope configuration."""
        return {
            "in_scope_rules": len(self.in_scope),
            "out_of_scope_rules": len(self.out_of_scope),
            "in_scope_patterns": len(self._in_scope_patterns),
            "out_scope_patterns": len(self._out_scope_patterns),
            "in_scope_cidrs": len(self._in_scope_cidrs),
            "out_scope_cidrs": len(self._out_scope_cidrs),
        }
