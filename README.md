# Gold Experience 

A production-grade, modular reconnaissance framework for bug bounty hunting, penetration testing, and red team operations. Built in Python with support for 22 specialized modules and 50+ security tools.

## Features

- Modular architecture with 22 reconnaissance modules
- Automatic tool detection and graceful fallbacks
- Parallel execution for independent modules
- Scope enforcement and output deduplication
- Resumable scans (skip completed steps)
- Consolidated output for LLM consumption
- YAML-based configuration

## Installation

### Prerequisites

- Python 3.8+
- Go 1.19+ (for Go-based tools)
- Git

### Install Dependencies

```bash
# Install Python dependencies
pip3 install -r requirements.txt

# Install reconnaissance tools
chmod +x install_tools.sh
./install_tools.sh
```

## Usage

### Basic Usage

```bash
# Scan a domain
python3 recon.py -t example.com

# Scan with custom config
python3 recon.py -t example.com -c config/myconfig.yaml

# Scan with custom output directory
python3 recon.py -t example.com -o ./results

# Resume a previous scan
python3 recon.py -t example.com --resume
```

### Configuration

Copy and modify the default configuration:

```bash
cp config/default_config.yaml config/myconfig.yaml
```

## Modules

ReconTool includes 22 modules organized by reconnaissance phase:

### Passive Reconnaissance

| Module | Description | Tools |
|--------|-------------|-------|
| `subdomain_enum` | Subdomain enumeration using multiple sources | subfinder, amass, assetfinder, findomain, chaos |
| `passive_sources` | API-based subdomain enumeration | crt.sh, RapidDNS, BufferOver, HackerTarget, ThreatCrowd, URLScan, AlienVault OTX, Wayback, CertSpotter |
| `url_collection` | Collect URLs from web archives | gau, waybackurls, waymore |
| `dns_enum` | DNS record enumeration and brute-forcing | dnsx, shuffledns, puredns, massdns, dnsgen |
| `osint` | Open source intelligence gathering | shodan, censys, metabigor |
| `git_recon` | Git repository and secrets scanning | trufflehog, gitrob, github-subdomains |
| `cloud_enum` | Cloud resource enumeration | cloud_enum, s3scanner |
| `cert_monitoring` | Certificate transparency monitoring | certstream |

### Active Reconnaissance

| Module | Description | Tools |
|--------|-------------|-------|
| `http_probe` | Probe hosts for live HTTP services | httpx, httprobe |
| `crawling` | Web crawling and spidering | katana, gospider, hakrawler, cariddi |
| `js_analysis` | JavaScript file analysis for secrets and endpoints | subjs, linkfinder, secretfinder, jsubfinder |
| `parameter_discovery` | Discover hidden parameters | arjun, x8, paramspider |
| `port_scan` | TCP port scanning | naabu |
| `screenshots` | Capture website screenshots | gowitness, eyewitness |
| `reverse_dns` | Reverse DNS lookups | hakrevdns, prips |
| `subdomain_takeover` | Subdomain takeover detection | subjack, nuclei |

### Vulnerability Scanning

| Module | Description | Tools |
|--------|-------------|-------|
| `nuclei_scan` | Template-based vulnerability scanning with CVE checks | nuclei, jaeles |
| `fuzzing` | Directory and file fuzzing | ffuf, feroxbuster |
| `cors_check` | CORS misconfiguration detection | Built-in (Python) |
| `vuln_patterns` | LFI, SSRF, Open Redirect, SSTI detection | Built-in (Python) |

### Active Testing (Intrusive)

| Module | Description | Tools |
|--------|-------------|-------|
| `xss_scan` | Cross-site scripting testing | dalfox, xsstrike, kxss |
| `sqli_scan` | SQL injection testing | sqlmap, ghauri |

## Module Details

### passive_sources

Queries multiple passive data sources without sending requests to the target:

- Certificate Transparency logs (crt.sh, CertSpotter)
- DNS aggregators (RapidDNS, BufferOver, HackerTarget)
- Threat intelligence (ThreatCrowd, AlienVault OTX)
- Web archives (Wayback Machine, URLScan)

### cors_check

Tests for CORS misconfigurations including:

- Reflected Origin headers
- Null Origin acceptance
- Subdomain bypass (evil.target.com)
- Pre-domain bypass (target.com.evil.com)
- Post-domain bypass (eviltarget.com)
- HTTP downgrade attacks

### vuln_patterns

Pattern-based vulnerability detection:

- Local File Inclusion (LFI) with path traversal payloads
- Server-Side Request Forgery (SSRF) targeting internal services and cloud metadata
- Open Redirect testing
- Server-Side Template Injection (SSTI)

### nuclei_scan

Enhanced Nuclei scanning with:

- Automatic severity-based categorization
- CVE-specific scans for high-impact vulnerabilities (Log4Shell, Spring4Shell, ProxyLogon, etc.)
- Technology-based template selection
- Output organized by severity and vulnerability type

## Output Structure

```
recon/
├── subdomains/
│   ├── raw/
│   ├── all_subdomains.txt
│   └── subdomain_summary.json
├── http/
│   ├── raw/
│   ├── alive.txt
│   ├── by_status/
│   └── technologies.json
├── crawling/
│   ├── all_urls.txt
│   ├── js_files.txt
│   ├── api_endpoints.txt
│   └── params_urls.txt
├── nuclei/
│   ├── by_severity/
│   ├── by_type/
│   └── prioritized.txt
├── context/
│   ├── subdomains.txt
│   ├── live_hosts.txt
│   ├── vulnerabilities.txt
│   └── context_for_llm.json
└── execution_summary.json
```

## Configuration Options

```yaml
target:
  type: domain          # domain, url, ip, or file
  value: example.com

scope:
  in_scope:
    - "*.example.com"
  out_of_scope:
    - "*.internal.example.com"

modules:
  subdomain_enum: true
  passive_sources: true
  http_probe: true
  nuclei_scan: true
  cors_check: true
  vuln_patterns: true
  # ... other modules

parallel: true
max_workers: 5
resume: true
```

## Cleaning Up

Remove scan outputs before sharing or uploading:

```bash
./clean.sh
```

This removes the `recon/` directory and log files while preserving source code.

## License

For authorized security testing only. Always obtain proper authorization before scanning targets.

## Credits

Built with the following open-source tools:

- ProjectDiscovery (nuclei, httpx, katana, subfinder, dnsx, naabu)
- OWASP (amass)
- tomnomnom (gau, httprobe, assetfinder)
- hahwul (dalfox)
- And many others from the security community
