#!/usr/bin/env python3
"""
ReconTool - Autonomous Reconnaissance Framework

CLI entry point for running reconnaissance operations.

Usage:
    python recon.py -t example.com
    python recon.py -c config.yaml
    python recon.py -t example.com -m subdomain_enum,http_probe
"""

import argparse
import json
import sys
from pathlib import Path

# Add package to path
sys.path.insert(0, str(Path(__file__).parent))

from recontool import Config, ReconRunner, __version__


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="ReconTool - Autonomous Reconnaissance Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run against a single domain
  python recon.py -t example.com

  # Run with a config file
  python recon.py -c config.yaml

  # Run specific modules only
  python recon.py -t example.com -m subdomain_enum,http_probe,nuclei_scan

  # Run against a file of targets
  python recon.py -t targets.txt --type file

  # Disable specific modules
  python recon.py -t example.com --disable xss_scan,sqli_scan

  # Run in sequential mode (for debugging)
  python recon.py -t example.com --sequential

For more information, see: https://github.com/example/recontool
        """
    )

    # Target specification
    target_group = parser.add_argument_group("Target")
    target_group.add_argument(
        "-t", "--target",
        help="Target domain, URL, IP, or file path",
    )
    target_group.add_argument(
        "--type",
        choices=["domain", "url", "ip", "file"],
        default="domain",
        help="Target type (default: domain)",
    )

    # Configuration
    config_group = parser.add_argument_group("Configuration")
    config_group.add_argument(
        "-c", "--config",
        help="Path to YAML configuration file",
    )
    config_group.add_argument(
        "-o", "--output",
        default="recon",
        help="Output directory (default: recon)",
    )

    # Module selection
    module_group = parser.add_argument_group("Modules")
    module_group.add_argument(
        "-m", "--modules",
        help="Comma-separated list of modules to enable",
    )
    module_group.add_argument(
        "--disable",
        help="Comma-separated list of modules to disable",
    )
    module_group.add_argument(
        "--list-modules",
        action="store_true",
        help="List all available modules and exit",
    )

    # Scope
    scope_group = parser.add_argument_group("Scope")
    scope_group.add_argument(
        "--in-scope",
        help="Comma-separated list of in-scope patterns (e.g., '*.example.com')",
    )
    scope_group.add_argument(
        "--out-of-scope",
        help="Comma-separated list of out-of-scope patterns",
    )

    # Execution options
    exec_group = parser.add_argument_group("Execution")
    exec_group.add_argument(
        "--sequential",
        action="store_true",
        help="Run modules sequentially instead of parallel",
    )
    exec_group.add_argument(
        "-w", "--workers",
        type=int,
        default=5,
        help="Maximum parallel workers (default: 5)",
    )
    exec_group.add_argument(
        "--no-resume",
        action="store_true",
        help="Don't resume from previous runs (re-run all modules)",
    )
    exec_group.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output",
    )

    # API keys
    api_group = parser.add_argument_group("API Keys")
    api_group.add_argument(
        "--shodan-key",
        help="Shodan API key (or set SHODAN_API_KEY env var)",
    )
    api_group.add_argument(
        "--github-token",
        help="GitHub token for git recon (or set GITHUB_TOKEN env var)",
    )

    # Other
    parser.add_argument(
        "-V", "--version",
        action="version",
        version=f"ReconTool v{__version__}",
    )

    return parser.parse_args()


def list_modules():
    """Print available modules and exit."""
    from recontool.modules import MODULE_REGISTRY, MODULE_DEPENDENCIES
    from recontool.config import DEFAULT_MODULES

    print("\nAvailable Modules:")
    print("=" * 60)

    for name, module_class in sorted(MODULE_REGISTRY.items()):
        enabled = "ENABLED" if DEFAULT_MODULES.get(name, False) else "disabled"
        deps = MODULE_DEPENDENCIES.get(name, [])
        deps_str = f" (requires: {', '.join(deps)})" if deps else ""

        print(f"\n{name}")
        print(f"  Status: {enabled}")
        print(f"  Description: {module_class.description}")
        print(f"  Tools: {', '.join(module_class.tools)}")
        if deps_str:
            print(f"  Dependencies: {', '.join(deps)}")

    print("\n" + "=" * 60)
    print("\nUse -m to enable specific modules: -m subdomain_enum,http_probe")
    print("Use --disable to disable modules: --disable xss_scan,sqli_scan")


def main():
    """Main entry point."""
    args = parse_args()

    # Handle --list-modules
    if args.list_modules:
        list_modules()
        return 0

    # Require either target or config
    if not args.target and not args.config:
        print("Error: Either --target or --config is required")
        print("Use --help for usage information")
        return 1

    try:
        # Load configuration
        if args.config:
            config = Config.from_yaml(args.config)
        else:
            # Build config from arguments
            modules_config = {}

            # Handle module selection
            if args.modules:
                # Disable all, then enable specified
                from recontool.config import DEFAULT_MODULES
                modules_config = {name: False for name in DEFAULT_MODULES}
                for module in args.modules.split(","):
                    module = module.strip()
                    if module:
                        modules_config[module] = True

            if args.disable:
                for module in args.disable.split(","):
                    module = module.strip()
                    if module:
                        modules_config[module] = False

            # Build scope
            scope_config = {}
            if args.in_scope:
                scope_config["in_scope"] = [s.strip() for s in args.in_scope.split(",")]
            if args.out_of_scope:
                scope_config["out_of_scope"] = [s.strip() for s in args.out_of_scope.split(",")]

            # Build API keys
            api_keys = {}
            if args.shodan_key:
                api_keys["shodan"] = args.shodan_key
            if args.github_token:
                api_keys["github"] = args.github_token

            config = Config.from_args(
                target=args.target,
                target_type=args.type,
                output_dir=args.output,
                modules=modules_config,
                scope=scope_config,
                parallel=not args.sequential,
                max_workers=args.workers,
                verbose=args.verbose,
                api_keys=api_keys,
            )

        # Override resume setting
        if args.no_resume:
            config.resume = False

        # Create and run the runner
        runner = ReconRunner(config)
        summary = runner.run()

        # Print summary
        print("\n" + "=" * 60)
        print("EXECUTION SUMMARY")
        print("=" * 60)
        print(f"Success: {summary['success']}")
        print(f"Duration: {summary['duration']}s")
        print(f"Modules: {summary['modules_succeeded']}/{summary['modules_executed']} succeeded")

        if summary['failed_modules']:
            print(f"Failed: {', '.join(summary['failed_modules'])}")

        print(f"\nContext saved to: {summary['context_path']}")
        print(f"Output directory: {summary['output_dir']}")

        # Print high-level stats
        print("\nKey Statistics:")
        for module_name, module_result in summary.get('results', {}).items():
            stats = module_result.get('stats', {})
            findings = module_result.get('findings_count', 0)
            if stats or findings:
                print(f"  {module_name}:")
                for key, value in list(stats.items())[:3]:
                    print(f"    - {key}: {value}")
                if findings:
                    print(f"    - findings: {findings}")

        print("\n" + "=" * 60)

        # Save summary to file
        summary_file = Path(summary['output_dir']) / "execution_summary.json"
        with open(summary_file, "w") as f:
            json.dump(summary, f, indent=2)

        return 0 if summary['success'] else 1

    except FileNotFoundError as e:
        print(f"Error: File not found - {e}")
        return 1
    except Exception as e:
        print(f"Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
