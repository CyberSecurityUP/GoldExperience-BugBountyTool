"""
Recon modules for ReconTool

Each module encapsulates related recon tools and provides
a standardized interface for execution and output handling.
"""

from .base import BaseModule, ModuleResult
from .subdomain_enum import SubdomainEnumModule
from .http_probe import HttpProbeModule
from .crawling import CrawlingModule
from .url_collection import UrlCollectionModule
from .js_analysis import JsAnalysisModule
from .parameter_discovery import ParameterDiscoveryModule
from .fuzzing import FuzzingModule
from .port_scan import PortScanModule
from .vuln_scan import VulnScanModule
from .xss_scan import XssScanModule
from .sqli_scan import SqliScanModule
from .dns_enum import DnsEnumModule
from .reverse_dns import ReverseDnsModule
from .cloud_enum import CloudEnumModule
from .git_recon import GitReconModule
from .osint import OsintModule
from .screenshots import ScreenshotsModule
from .cert_monitoring import CertMonitoringModule
from .subdomain_takeover import SubdomainTakeoverModule
from .passive_sources import PassiveSourcesModule
from .cors_check import CorsCheckModule
from .vuln_patterns import VulnPatternsModule

# Module registry for dynamic loading
MODULE_REGISTRY = {
    "subdomain_enum": SubdomainEnumModule,
    "passive_sources": PassiveSourcesModule,
    "http_probe": HttpProbeModule,
    "crawling": CrawlingModule,
    "url_collection": UrlCollectionModule,
    "js_analysis": JsAnalysisModule,
    "parameter_discovery": ParameterDiscoveryModule,
    "fuzzing": FuzzingModule,
    "port_scan": PortScanModule,
    "nuclei_scan": VulnScanModule,
    "xss_scan": XssScanModule,
    "sqli_scan": SqliScanModule,
    "dns_enum": DnsEnumModule,
    "reverse_dns": ReverseDnsModule,
    "cloud_enum": CloudEnumModule,
    "git_recon": GitReconModule,
    "osint": OsintModule,
    "screenshots": ScreenshotsModule,
    "cert_monitoring": CertMonitoringModule,
    "subdomain_takeover": SubdomainTakeoverModule,
    "cors_check": CorsCheckModule,
    "vuln_patterns": VulnPatternsModule,
}

# Module dependencies (modules that should run before others)
MODULE_DEPENDENCIES = {
    "http_probe": ["subdomain_enum", "passive_sources"],
    "crawling": ["http_probe"],
    "url_collection": ["subdomain_enum"],
    "js_analysis": ["crawling", "url_collection"],
    "parameter_discovery": ["crawling", "url_collection"],
    "fuzzing": ["http_probe"],
    "nuclei_scan": ["http_probe"],
    "xss_scan": ["parameter_discovery"],
    "sqli_scan": ["parameter_discovery"],
    "screenshots": ["http_probe"],
    "dns_enum": ["subdomain_enum"],
    "reverse_dns": ["port_scan"],
    "subdomain_takeover": ["subdomain_enum"],
    "cors_check": ["http_probe"],
    "vuln_patterns": ["parameter_discovery", "crawling"],
}

__all__ = [
    "BaseModule",
    "ModuleResult",
    "MODULE_REGISTRY",
    "MODULE_DEPENDENCIES",
    "SubdomainEnumModule",
    "PassiveSourcesModule",
    "HttpProbeModule",
    "CrawlingModule",
    "UrlCollectionModule",
    "JsAnalysisModule",
    "ParameterDiscoveryModule",
    "FuzzingModule",
    "PortScanModule",
    "VulnScanModule",
    "XssScanModule",
    "SqliScanModule",
    "DnsEnumModule",
    "ReverseDnsModule",
    "CloudEnumModule",
    "GitReconModule",
    "OsintModule",
    "ScreenshotsModule",
    "CertMonitoringModule",
    "SubdomainTakeoverModule",
    "CorsCheckModule",
    "VulnPatternsModule",
]
