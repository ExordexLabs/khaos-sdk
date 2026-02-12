# Changelog

All notable changes to the Khaos SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-02-12

### Added

#### Core CLI
- `khaos run` - Primary evaluation command with security testing ON by default
- `khaos compare` - A/B comparison of two agent runs across multiple dimensions
- `khaos gate` - CI/CD quality gates with configurable thresholds
- `khaos sync` - Cloud dashboard synchronization
- `khaos list-packs` - List available evaluation packs
- `khaos scenarios` - Scenario management subcommands

#### Evaluation Pack System
- **4 built-in packs**: `baseline`, `quickstart`, `full-eval`, `security`
- Three-phase evaluation: baseline → resilience → security
- Goal-based assertions with multiple criteria types (contains, regex, JSON validation)
- Fault coverage tracking and reporting
- Deterministic fault scheduling for reproducible tests

#### 20 Fault Types Across 5 Categories
- **HTTP**: `http_latency`, `http_error`, `http_timeout`, `http_connection_reset`
- **LLM**: `llm_rate_limit`, `llm_timeout`, `llm_malformed_response`, `llm_token_limit`
- **Tool**: `tool_failure`, `tool_latency`, `tool_invalid_response`, `tool_timeout`
- **RAG**: `rag_empty_results`, `rag_irrelevant_context`, `rag_partial_retrieval`, `rag_latency`
- **MCP**: `mcp_tool_latency`, `mcp_tool_failure`, `mcp_tool_corruption`, `mcp_server_unavailable`

#### Security Testing
- 6+ attack vectors: prompt injection, jailbreak, system prompt extraction, tool manipulation, data exfiltration, PII probing
- Automatic security score calculation
- Vulnerability categorization and reporting

#### Framework Support
- Zero-code LLM telemetry capture
- Automatic framework detection for: OpenAI, Anthropic, LangChain, CrewAI, AutoGen, LlamaIndex, Instructor
- Cost tracking with customizable pricing tables

#### Agent Discovery
- `khaos agents discover` - Scan repositories for agent entrypoints
- `khaos agents rules` - Configure include/exclude patterns
- Automatic metadata extraction

#### Cloud Integration
- Token-based authentication with project scoping
- Queue-based sync for offline operation
- Persistent job management

#### MCP Integration
- First-class MCP (Model Context Protocol) support
- MCP-specific fault injection
- stdio transport proxy

#### Custom Fault Plugins
- `FaultPlugin` base class for custom fault types
- `@register_fault` decorator for plugin registration
- Built-in examples: `custom_delay`, `data_corruption`, `rate_limit`, `partial_response`

### Developer Experience
- Rich CLI output with progress indicators
- JSON output mode for all commands
- Verbose mode for detailed diagnostics
- Deterministic runs with seed support

### Testing
- 84 unit tests
- 18 integration tests
- E2E test suite for dashboard integration
- CI/CD pipeline with GitHub Actions

### Documentation
- Framework compatibility guide
- Cloud sync walkthrough
- Evaluation packs documentation
- MCP integration guide
- Custom fault plugin examples

---

## [0.x.x] - Pre-release Development

Initial development phase including:
- Core chaos engine architecture
- Scenario YAML schema design
- Transport layer abstraction
- Metric evaluation protocols
- Dashboard integration prototypes
