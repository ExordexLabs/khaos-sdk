"""MCP server security testing engine.

Provides schema-aware fuzzing, response analysis, and risk assessment
for MCP (Model Context Protocol) servers without modifying server code.

Modules:
    client   - MCP client harness (wraps official mcp SDK)
    scanner  - Discovery & fingerprinting (khaos mcp scan)
    fuzzer   - Schema-aware input fuzzing from tool schemas
    analyzer - Response analysis (leakage, injection success)
    report   - MCP-specific Rich + JSON report formatting
"""

from .client import (
    MCPServerSpec,
    MCPTestClient,
    ToolInfo,
    ResourceInfo,
    ToolResult,
    parse_server_spec,
    spec_from_config,
)
from .scanner import (
    RiskFinding,
    ScanResult,
    scan_server,
)
from .fuzzer import (
    FuzzCase,
    generate_fuzz_cases,
    generate_fuzz_cases_for_tools,
)
from .analyzer import (
    AnalysisResult,
    Finding,
    analyze_tool_response,
)
from .report import (
    OWASP_MCP_TOP_10,
    TestResultCollector,
    print_scan_report,
    print_test_report,
    print_audit_config_report,
    scan_to_json,
    results_to_json,
)
from .mitl import (
    MITLConfig,
    MITLTestCase,
    MITLResult,
    generate_mitl_cases,
    run_mitl_suite,
)

__all__ = [
    # Client
    "MCPServerSpec",
    "MCPTestClient",
    "ToolInfo",
    "ResourceInfo",
    "ToolResult",
    "parse_server_spec",
    "spec_from_config",
    # Scanner
    "RiskFinding",
    "ScanResult",
    "scan_server",
    # Fuzzer
    "FuzzCase",
    "generate_fuzz_cases",
    "generate_fuzz_cases_for_tools",
    # Analyzer
    "AnalysisResult",
    "Finding",
    "analyze_tool_response",
    # Report
    "OWASP_MCP_TOP_10",
    "TestResultCollector",
    "print_scan_report",
    "print_test_report",
    "print_audit_config_report",
    "scan_to_json",
    "results_to_json",
    # MITL
    "MITLConfig",
    "MITLTestCase",
    "MITLResult",
    "generate_mitl_cases",
    "run_mitl_suite",
]
