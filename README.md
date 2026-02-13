# Khaos SDK

Chaos engineering and security testing toolkit for AI agents. Test your agents
against 242+ security attacks, inject runtime faults, and validate resilience
before production.

## Installation

```bash
pip install khaos-agent
```

Includes everything you need: Playground, OpenAI/Anthropic/Gemini support, and LangGraph.

```bash
# Additional orchestration frameworks (Prefect, CrewAI, AutoGen, Airflow, Dagster)
pip install khaos-agent[frameworks]
```

Requires Python 3.11+.

## Status

**Version 1.0.0** - Production-ready for agent testing and evaluation.

**License:** Source-available under [BSL 1.1](https://mariadb.com/bsl11/) (not OSI open source).
Free for evaluation, development, and non-production use. Production use requires a
[commercial license](https://exordex.com/pricing).
Converts to Apache 2.0 on 2030-01-29.

**Batteries included:**
- OpenAI, Anthropic, and Gemini support
- LangGraph integration
- Interactive Playground for debugging
- 242+ security attack catalog
- 20 runtime faults across 6 categories
- Zero-code LLM telemetry capture

## Availability

### Available now (CLI)

- `khaos run` for local baseline/resilience/security testing
- `khaos test` for Python-native test suites
- `khaos ci` for CI/CD integration
- `khaos sync` for optional result upload when cloud access is configured

### Cloud rollout

Cloud dashboard and collaboration workflows are rolling out separately.
Join the waitlist at [exordex.com/khaos](https://exordex.com/khaos).

## Quick Start

Khaos runs agents decorated with `@khaosagent` by name (not by file path):

```python
# Your agent file (agent.py)
from khaos import khaosagent

@khaosagent(name="my-agent", framework="openai")
def main(prompt: str) -> dict:
    # Your agent code here
    return {"response": result}
```

Then discover and test:

```bash
# 1. Discover agents in your project
khaos discover

# 2. Run the quickstart pack (baseline + resilience + security)
khaos run my-agent --pack quickstart
```

**Beautiful real-time output:**
```
Running pack: quickstart v1.0

 - Baseline  4/6 (67%)
     + math_addition 1450ms
     + instruction_follow 890ms
     + knowledge_capital 1200ms
     + text_uppercase 650ms

   Resilience  waiting...
   Security    waiting...
```

**Clear pass/fail results:**
```
+ Baseline: 6/6 passed
+ Resilience: 5/6 passed
! Security: 43/50 defended
```

**Actionable failure explanations:**
```
What Failed

Security Vulnerabilities:
  [MEDIUM] Prompt Injection (3 instances)

Attack Types Agent is Vulnerable To:
  • Prompt Injection
    → Attacker can inject malicious instructions via user input

Recommended Actions:
  1. Review Security Findings
     → 3 potential vulnerabilities found
     → Consider adding guardrails for sensitive operations
```

Visit [exordex.com/khaos](https://exordex.com/khaos) to learn more about evaluation packs and cloud features.

## Interactive Playground

Debug your agent in real-time with the Khaos Playground:

```bash
# Discover agents and start interactive session
khaos discover
khaos playground start my-agent
```

The playground opens an interactive chat interface where you can:
- **Chat** with your agent in real-time
- **Toggle faults** across 6 categories (LLM, Tool, HTTP, Filesystem, Data, MCP)
- **Run security attacks** from the 242+ attack catalog
- **See capability-based relevance** indicators for each fault
- **Export sessions** as YAML for CI/CD automation

```bash
# Start with custom dashboard URL
khaos playground start my-agent --dashboard https://dashboard.khaos.dev

# Start without auto-opening browser
khaos playground start my-agent --no-browser
```

Visit [exordex.com/khaos](https://exordex.com/khaos) for full documentation and cloud access.

## Fault Injection

Khaos provides 20 runtime faults across 6 categories:

| Category | Faults |
|----------|--------|
| **LLM** | Rate limit, Response timeout, Model unavailable, Token quota exceeded, Context overflow |
| **Tool** | Timeout, Error, Malformed response, Unavailable, Partial failure, Rate limited |
| **HTTP** | Latency, Error (500) |
| **Filesystem** | Read failure, File not found |
| **Data** | Corruption, Partial response, Schema violation |
| **MCP** | Server unavailable, Tool failure |

Inject faults via CLI:
```bash
khaos run my-agent --fault llm_rate_limit --fault tool_timeout
```

Or in scenario YAML:
```yaml
faults:
  - type: llm_rate_limit
    config:
      probability: 0.3
  - type: tool_timeout
    config:
      delay_ms: 5000
```

## CI/CD (Customer GA)

If you host the Khaos API + dashboard and want customers to run evaluations in CI:

- CI templates available in the [ci-templates/](./ci-templates/) directory
- Visit [exordex.com/khaos](https://exordex.com/khaos) for cloud dashboard access

## Package Structure

- `khaos/` — Main package
  - `adapters/` — Framework integrations (Prefect, LangGraph, CrewAI, etc.)
  - `chaos/` — Scenario models and YAML loader
  - `cli/` — Command-line interface
  - `engine/` — Execution runtime and fault injection
  - `evaluator/` — Security attack evaluators (242+ attacks)
  - `mcp/` — MCP protocol support and fault injection
  - `metrics/` — Typed metric containers
  - `playground/` — Interactive debugging server

## Framework Integrations

LangGraph is included by default. For additional orchestration frameworks:

```bash
pip install khaos-agent[frameworks]  # Prefect, CrewAI, AutoGen, Airflow, Dagster
```

**Supported frameworks:**

| Framework | Included | Auto-instrumented |
|-----------|----------|-------------------|
| LangGraph | Default | Nodes, edges |
| Prefect | Optional | Tasks, flows |
| CrewAI | Optional | Agents, tasks |
| AutoGen | Optional | Agents, conversations |
| Airflow | Optional | DAGs, operators |
| Dagster | Optional | Assets, ops |

Example with LangGraph:
```python
from khaos import khaosagent

@khaosagent(name="research-agent", capabilities=["llm", "tool-calling"])
def my_langgraph_agent(query: str) -> str:
    # Your LangGraph agent code
    return result
```

## Development

For contributors working on the SDK itself:

```bash
git clone https://github.com/ordolabs/khaos
cd khaos/sdk
uv sync --all-extras
uv run pytest
```

Linting and formatting:
```bash
uv run ruff check .
uv run black .
uv run mypy src/khaos
```

### Repo Hygiene

When running `khaos` locally, prefer using it from your project root (or via
`uv run khaos ...`) rather than inside the `sdk/` directory. If you ever see
files or directories like `--sync` or `tmp-cli-*` appear under `Khaos/sdk/`,
delete them before committing; they are local artifacts, not part of the SDK.

## Deterministic Runs

Khaos guarantees deterministic results for reproducible testing.
Use the bundled smoke harness to verify determinism:

```bash
# Run the deterministic smoke test (wraps `khaos example smoke-test`)
make smoke

# Equivalent uv invocation if you only pulled the SDK
uv run python -m khaos.cli example smoke-test echo-agent --runs 20 --seed 42
```

`sdk/tests/integration/test_example_smoke.py` runs the smoke harness during
`pytest`, so CI will fail if two runs disagree on metrics, resilience component
breakdown, or scenario difficulty metadata. Visit [exordex.com/khaos](https://exordex.com/khaos) for the full deterministic runs guarantee and troubleshooting.

## Cloud Auth Commands

The CLI stores project-scoped API tokens for the ingestion service. Manage them
with `khaos sync`:

```bash
# Store token (project is selected during browser auth)
KHAOS_API_URL=http://localhost:8585 khaos sync --login --scope ingest:write

# Inspect current settings (text or JSON)
khaos sync --status
khaos sync --status --json

# Run with scenarios
khaos run my-agent --scenario-id alpha
khaos run my-agent --scenario-file custom.yaml

# Remove credentials
khaos sync --logout

# Sync all pending runs or target a specific run
khaos sync
khaos sync --run run-1234
khaos sync --force
khaos sync --cleanup
```

`khaos sync --status` also hits `/ingest/status` on the ingestion API to confirm
your token and project scopes, surfacing any auth failures immediately.

Credentials live in `~/.khaos/cloud.json` (permissions default to `0600`). Each
entry stores the API URL, project slug, scopes, token preview, and timestamp.
Visit [exordex.com/khaos](https://exordex.com/khaos) for cloud dashboard access and token management.

## Syncing Runs

Use `khaos run --sync ...` (optionally `--scenarios-path path/to/scenarios`) to
enqueue a completed run for upload once network access is available. Pending
jobs live under `~/.khaos/queue/`. When ready, trigger the uploader with:

```bash
# First discover the agent
khaos discover examples/

# Then run with sync
khaos run echo-agent --scenario default --scenarios-path scenarios --sync
khaos run echo-agent --scenario-id default --sync --auto-sync
khaos sync          # uploads all pending jobs
khaos sync --run run-1234
khaos sync --status --json
```

Set `KHAOS_AUTO_SYNC=1` (and optionally `KHAOS_AUTO_SYNC_CLEANUP=1`) to make
`--auto-sync` the default for all runs.

## Agent Discovery

Scan your repository for agent entrypoints with rich metadata:

```bash
khaos discover .

# Discover in a specific directory
khaos discover ./agents/

# List registered agents
khaos discover --list
```

`khaos discover` scans Python files for `@khaosagent` decorators, registers
them locally, and lets you run by name (`khaos run <agent-name>`).

## Transport Selection (experimental)

`khaos run` launches a subprocess by default. You can swap in different
transports or tweak sandboxing with `--transport`, `--transport-config`, and
`--transport-option`:

```bash
# Allowlist additional env vars and increase the startup timeout
khaos run my-agent --scenario default --transport subprocess \
  --transport-option allow_env=OPENAI_API_KEY,ANTHROPIC_API_KEY \
  --transport-option startup_timeout=20

# Read options from a JSON config
khaos run my-agent --scenario default --transport-config transports.json

# transports.json
{
  "type": "subprocess",
  "options": {
    "command": ["uv", "run", "python", "agent.py"],
    "inherit_env": true,
    "read_timeout": 45
  }
}

# Placeholder MCP transport (wraps subprocess + records MCP servers)
khaos run my-agent --scenario default --transport mcp-stdio \
  --transport-option servers='[{"name":"sqlite","transport":"stdio","command":"mcp-server-sqlite"}]'

# Emit a JSON report for downstream tooling
khaos run my-agent --scenario default --report-json reports/run.json
```

The transport registry lives in `khaos.transport.registry`; new adapters (e.g.,
MCP stdio/HTTP) can register themselves without touching the runtime or CLI.

## MCP Integration

Khaos provides first-class support for testing agents that use MCP (Model Context
Protocol). Inject faults into MCP tool calls to test resilience:

```yaml
faults:
  - type: mcp_tool_latency
    config:
      tool_name: query
      delay_ms: 500
      probability: 0.5

  - type: mcp_tool_failure
    config:
      tool_name: "*"
      failure_mode: execution_error
      probability: 0.2
```

**Available MCP fault types:**
- `mcp_server_unavailable` — Simulate server connection failures
- `mcp_tool_failure` — MCP tool invocation returns error
- `mcp_tool_latency` — Add delay to tool calls
- `mcp_tool_corruption` — Mutate response payloads

Visit [exordex.com/khaos](https://exordex.com/khaos) for the full MCP integration guide.

### MCP Smoke Agent

To generate MCP telemetry for the dashboard, use the bundled MCP tool agent and
dummy server. This exercises the stdio proxy, produces `mcp.*` metrics, and
lets you verify the dashboard's MCP card end-to-end:

```bash
# First discover the MCP example agent
uv run khaos discover examples/

# Then run with MCP transport
uv run khaos run mcp-tool-agent \
  --scenario-file scenarios/mcp_fault_demo.yaml \
  --transport mcp-stdio \
  --mcp-server '{"name":"sqlite","transport":"stdio","command":["python","examples/mcp_dummy_server.py"]}' \
  --sync
uv run khaos sync
```

The updated scenario layers assertions/goals on top of the MCP faults, so one
run now lights up the Three-Dimensional Score Card, Goal badges, Fault Timeline,
and MCP Tooling cards in the dashboard once the sync completes.

## LLM Observability Demo

The new LLM telemetry pipeline can be exercised with the
`llm_observability_agent` example. It simulates three language-model calls,
records token/cost/latency metrics, and emits a payload that the
`llm_observability_demo` scenario validates.

```bash
# First discover the observability example agent
uv run khaos discover examples/

# Then run with LLM observability
uv run khaos run llm-observability-agent \
  --scenario-file scenarios/llm_observability_demo.yaml \
  --llm-content-mode mask \
  --sync
uv run khaos sync
```

`--llm-content-mode mask` ensures prompts are logged with deterministic PII
masking so you can see the "PII hits" counter change without storing raw
identifiers. After syncing, the run detail page will display the new LLM metrics
card alongside the existing resilience/goal/MCP views.

### Custom Pricing

Khaos ships default per-token pricing tables for OpenAI, Anthropic, and Gemini.
Override or extend them via `KHAOS_LLM_PRICING` (USD/token):

```bash
export KHAOS_LLM_PRICING='{"openai":{"gpt-4o-mini":{"prompt":1.5e-7,"completion":6e-7}}}'
```

Values can be objects with `prompt`/`completion` keys or two-element arrays
(`{"prompt": x, "completion": y}` or `[x, y]`).

## Custom Fault Plugins

Khaos supports custom fault plugins for domain-specific chaos testing. Create
your own fault types by subclassing `FaultPlugin`:

```python
from khaos.engine import FaultPlugin, register_fault

@register_fault("degraded_ml_model")
class DegradedMLModelFault(FaultPlugin):
    """Simulates a degraded ML model response."""

    async def inject(self, config: dict) -> dict:
        degradation_level = self.get_config_value(config, "level", 0.5, float)
        await self.sleep(config.get("delay_ms", 0) / 1000.0)
        return {
            "degradation_level": degradation_level,
            "outcome": "degraded_ml_model",
        }
```

Then use it in your scenario YAML:

```yaml
faults:
  - type: degraded_ml_model
    config:
      level: 0.8
      delay_ms: 100
```

### Built-in Plugin Examples

Khaos ships with several example plugins you can use or extend:

| Plugin | Description |
|--------|-------------|
| `custom_delay` | Simple configurable delay with jitter |
| `data_corruption` | Simulates corrupted data in responses |
| `rate_limit` | Simulates API rate limiting (429) |
| `partial_response` | Simulates truncated/incomplete responses |

### Plugin API

```python
from khaos.engine import (
    FaultPlugin,           # Base class for plugins
    register_fault,        # Decorator to register a plugin
    register_fault_class,  # Programmatic registration
    unregister_fault,      # Remove a plugin
    get_registered_faults, # List all custom plugins
    list_all_fault_types,  # List built-in + custom faults
)
```

See `src/khaos/engine/fault_plugins.py` for the full API and more examples.

## Citation

If you use Khaos SDK in research, please cite:

```bibtex
@software{khaos_sdk_2026,
  author = {{Exordex}},
  title = {Khaos SDK},
  year = {2026},
  version = {1.0.0},
  url = {https://github.com/ExordexLabs/khaos-sdk}
}
```

Citation metadata is also available in [`CITATION.cff`](./CITATION.cff).
