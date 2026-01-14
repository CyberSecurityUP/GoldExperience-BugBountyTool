"""
Recon Runner - Main Orchestrator

Coordinates the execution of all recon modules based on configuration.
Handles parallel execution, dependencies, and result aggregation.
"""

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from .config import Config
from .modules import MODULE_REGISTRY, MODULE_DEPENDENCIES, ModuleResult
from .context.builder import ContextBuilder
from .utils.logging import get_logger, setup_logging, log_banner
from .utils.scope import ScopeValidator

logger = get_logger("runner")


class ReconRunner:
    """
    Main orchestrator for reconnaissance operations.

    Coordinates module execution with:
    - Parallel execution for independent modules
    - Dependency resolution
    - Scope enforcement
    - Result aggregation
    - Context generation for LLM
    """

    def __init__(self, config: Config):
        """
        Initialize the runner.

        Args:
            config: Configuration object
        """
        self.config = config
        self.output_dir = config.output.base_dir
        self.scope = config.scope
        self.results: Dict[str, ModuleResult] = {}
        self.context_builder = ContextBuilder(self.output_dir)

        # Initialize logging
        log_dir = self.output_dir / "logs"
        setup_logging(log_dir, level="DEBUG" if config.verbose else "INFO")

        # Track execution state
        self._completed_modules: Set[str] = set()
        self._failed_modules: Set[str] = set()

    def run(self) -> Dict[str, Any]:
        """
        Run the full reconnaissance workflow.

        Returns:
            Dictionary with execution summary and context path
        """
        start_time = time.time()

        log_banner(logger, "STARTING RECONNAISSANCE")
        logger.info(f"\n{self.config.summary()}")

        # Validate configuration
        errors = self.config.validate()
        if errors:
            logger.error("Configuration errors:")
            for error in errors:
                logger.error(f"  - {error}")
            return {"success": False, "errors": errors}

        # Create directory structure
        self._create_directories()

        # Save configuration
        self.config.save()

        # Get targets
        targets = self.config.target.targets
        logger.info(f"Processing {len(targets)} target(s)")

        # Set context builder info
        self.context_builder.set_target_info(
            target_type=self.config.target.type,
            target_value=self.config.target.value,
            targets=targets,
        )
        self.context_builder.set_scope_info(
            in_scope=self.scope.in_scope,
            out_of_scope=self.scope.out_of_scope,
        )

        # Get enabled modules in execution order
        enabled_modules = self._get_execution_order()
        logger.info(f"Enabled modules: {', '.join(enabled_modules)}")

        # Execute modules
        if self.config.parallel:
            self._run_parallel(enabled_modules, targets)
        else:
            self._run_sequential(enabled_modules, targets)

        # Build and save context
        log_banner(logger, "GENERATING CONTEXT")
        for name, result in self.results.items():
            self.context_builder.add_module_result(result)

        context_path = self.context_builder.save()

        # Calculate summary
        duration = time.time() - start_time
        summary = self._build_summary(duration, context_path)

        log_banner(logger, "RECONNAISSANCE COMPLETE")
        logger.info(f"Duration: {duration:.2f}s")
        logger.info(f"Context saved to: {context_path}")

        return summary

    def run_module(
        self,
        module_name: str,
        targets: Optional[List[str]] = None,
    ) -> ModuleResult:
        """
        Run a single module.

        Args:
            module_name: Name of the module to run
            targets: Optional target override

        Returns:
            ModuleResult from the module
        """
        if module_name not in MODULE_REGISTRY:
            logger.error(f"Unknown module: {module_name}")
            return ModuleResult(
                module_name=module_name,
                success=False,
                duration=0.0,
                errors=[f"Unknown module: {module_name}"],
            )

        if targets is None:
            targets = self.config.target.targets

        # Check dependencies
        deps = MODULE_DEPENDENCIES.get(module_name, [])
        missing_deps = [d for d in deps if d not in self._completed_modules]
        if missing_deps:
            logger.warning(
                f"Module {module_name} has unmet dependencies: {missing_deps}"
            )

        # Get input from previous modules if available
        input_file = self._get_module_input(module_name)

        # Initialize and run module
        module_class = MODULE_REGISTRY[module_name]
        module = module_class(
            output_base=self.output_dir,
            scope=self.scope,
            timeout=self.config.modules.get_timeout(module_name),
            rate_limit=self.config.modules.get_rate_limit(module_name),
            tool_options=self.config.modules.tool_options.get(module_name, {}),
        )

        logger.info(f"Running module: {module_name}")
        start_time = time.time()

        try:
            result = module.run(
                targets=targets,
                resume=self.config.resume,
                input_file=input_file,
            )
            result.duration = time.time() - start_time

            if result.success:
                self._completed_modules.add(module_name)
            else:
                self._failed_modules.add(module_name)

            self.results[module_name] = result

            logger.info(
                f"Module {module_name} completed in {result.duration:.2f}s "
                f"(success={result.success})"
            )

            return result

        except Exception as e:
            logger.error(f"Error running module {module_name}: {e}")
            self._failed_modules.add(module_name)

            result = ModuleResult(
                module_name=module_name,
                success=False,
                duration=time.time() - start_time,
                errors=[str(e)],
            )
            self.results[module_name] = result
            return result

    def _create_directories(self) -> None:
        """Create the output directory structure."""
        self.config.output.ensure_dirs()
        logger.info(f"Output directory: {self.output_dir}")

    def _get_execution_order(self) -> List[str]:
        """
        Get modules in dependency-respecting order.

        Returns:
            List of module names in execution order
        """
        enabled = set(self.config.get_enabled_modules())
        ordered = []
        visited = set()

        def visit(module: str):
            if module in visited:
                return
            visited.add(module)

            # Visit dependencies first
            for dep in MODULE_DEPENDENCIES.get(module, []):
                if dep in enabled:
                    visit(dep)

            if module in enabled:
                ordered.append(module)

        for module in enabled:
            visit(module)

        return ordered

    def _run_sequential(
        self,
        modules: List[str],
        targets: List[str],
    ) -> None:
        """Run modules sequentially."""
        for module_name in modules:
            self.run_module(module_name, targets)

    def _run_parallel(
        self,
        modules: List[str],
        targets: List[str],
    ) -> None:
        """
        Run modules in parallel where dependencies allow.

        Modules are grouped by dependency level and executed in parallel
        within each level.
        """
        # Group modules by dependency level
        levels = self._group_by_dependency_level(modules)

        for level_idx, level_modules in enumerate(levels):
            logger.info(f"Executing level {level_idx + 1}: {level_modules}")

            with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
                futures = {}

                for module_name in level_modules:
                    future = executor.submit(self.run_module, module_name, targets)
                    futures[future] = module_name

                for future in as_completed(futures):
                    module_name = futures[future]
                    try:
                        result = future.result()
                        logger.debug(
                            f"Module {module_name} finished: success={result.success}"
                        )
                    except Exception as e:
                        logger.error(f"Module {module_name} failed: {e}")

    def _group_by_dependency_level(
        self,
        modules: List[str],
    ) -> List[List[str]]:
        """
        Group modules by dependency level for parallel execution.

        Level 0: No dependencies
        Level 1: Depends only on level 0
        Level N: Depends on level N-1 or lower
        """
        levels: List[List[str]] = []
        assigned = set()

        while len(assigned) < len(modules):
            current_level = []

            for module in modules:
                if module in assigned:
                    continue

                deps = MODULE_DEPENDENCIES.get(module, [])
                enabled_deps = [d for d in deps if d in modules]

                # Can run if all dependencies are assigned
                if all(d in assigned for d in enabled_deps):
                    current_level.append(module)

            if not current_level:
                # Circular dependency or error - add remaining
                remaining = [m for m in modules if m not in assigned]
                levels.append(remaining)
                break

            levels.append(current_level)
            assigned.update(current_level)

        return levels

    def _get_module_input(self, module_name: str) -> Optional[Path]:
        """
        Get input file for a module based on previous module outputs.

        This enables the pipeline flow between modules.
        """
        # Define input mappings with fallback options
        input_mappings = {
            # HTTP probing uses subdomain output
            "http_probe": [
                ("subdomain_enum", "all_subdomains"),
                ("subdomain_enum", "all_resolved"),
            ],
            # Crawling uses HTTP alive output
            "crawling": [
                ("http_probe", "alive"),
                ("subdomain_enum", "all_alive"),
            ],
            # URL collection uses subdomains
            "url_collection": [
                ("subdomain_enum", "all_subdomains"),
            ],
            # JS analysis uses crawling JS files or all URLs
            "js_analysis": [
                ("crawling", "js_files"),
                ("crawling", "all_urls"),
                ("url_collection", "js_files"),
            ],
            # Parameter discovery uses URLs with params from multiple sources
            "parameter_discovery": [
                ("crawling", "params_urls"),
                ("url_collection", "with_params"),
                ("crawling", "all_urls"),
            ],
            # Fuzzing uses alive hosts
            "fuzzing": [
                ("http_probe", "alive"),
            ],
            # Nuclei uses alive hosts
            "nuclei_scan": [
                ("http_probe", "alive"),
            ],
            # XSS uses params URLs
            "xss_scan": [
                ("parameter_discovery", "all_params"),
                ("crawling", "params_urls"),
                ("url_collection", "with_params"),
            ],
            # SQLi uses params URLs
            "sqli_scan": [
                ("parameter_discovery", "all_params"),
                ("crawling", "params_urls"),
                ("url_collection", "with_params"),
            ],
            # Screenshots uses alive hosts
            "screenshots": [
                ("http_probe", "alive"),
            ],
            # DNS uses subdomains
            "dns_enum": [
                ("subdomain_enum", "all_subdomains"),
            ],
            # Port scan uses resolved subdomains
            "port_scan": [
                ("subdomain_enum", "all_resolved"),
                ("subdomain_enum", "all_subdomains"),
            ],
            # Reverse DNS uses port scan IPs or DNS IPs
            "reverse_dns": [
                ("port_scan", "ips"),
                ("dns_enum", "ips"),
            ],
            # Subdomain takeover uses all subdomains
            "subdomain_takeover": [
                ("subdomain_enum", "all_subdomains"),
                ("subdomain_enum", "all_resolved"),
            ],
            # Cloud enum uses subdomains
            "cloud_enum": [
                ("subdomain_enum", "all_subdomains"),
            ],
            # Git recon uses alive hosts for finding git repos
            "git_recon": [
                ("http_probe", "alive"),
            ],
            # CORS check uses alive hosts
            "cors_check": [
                ("http_probe", "alive"),
            ],
            # Vuln patterns uses URLs with params
            "vuln_patterns": [
                ("parameter_discovery", "all_params"),
                ("crawling", "params_urls"),
                ("url_collection", "with_params"),
            ],
        }

        if module_name not in input_mappings:
            return None

        # Try each mapping in order until one works
        for source_module, output_key in input_mappings[module_name]:
            if source_module in self.results:
                result = self.results[source_module]
                if output_key in result.output_files:
                    input_file = result.output_files[output_key]
                    if input_file.exists() and input_file.stat().st_size > 0:
                        logger.debug(f"Module {module_name} using input from {source_module}/{output_key}")
                        return input_file

        return None

    def _build_summary(
        self,
        duration: float,
        context_path: Path,
    ) -> Dict[str, Any]:
        """Build execution summary."""
        return {
            "success": len(self._failed_modules) == 0,
            "duration": round(duration, 2),
            "modules_executed": len(self.results),
            "modules_succeeded": len(self._completed_modules),
            "modules_failed": len(self._failed_modules),
            "failed_modules": list(self._failed_modules),
            "context_path": str(context_path),
            "output_dir": str(self.output_dir),
            "results": {
                name: {
                    "success": r.success,
                    "duration": round(r.duration, 2),
                    "stats": r.stats,
                    "findings_count": len(r.findings),
                    "errors": r.errors[:3],  # First 3 errors
                }
                for name, r in self.results.items()
            },
        }
