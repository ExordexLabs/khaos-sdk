# Release Scenario Pack v1 (Internal)

This folder contains the **versioned, frozen** scenarios used for the “first 5 minutes” release/demo flow.

Goals:

- **Highly usable:** one command runs the pack (`khaos suite run <agent> --release`).
- **Interpretable:** scenarios assert on **trace events** (what happened) in addition to final output.
- **Comparable:** scenario identifiers are versioned (`release.v1.*`) so future changes can be released as `v2`
  without silently shifting meaning.

Scenarios:

- `baseline.yaml` — minimal, fast sanity check (envelope + injection trace).
- `resilience.yaml` — confirms the agent still returns a response under injected timeout/error/latency.
- `tooling_http.yaml` — configures tool/HTTP faults for agents using requests/httpx (shim-based).
- `llm_resilience.yaml` — injects LLM turbulence (rate limit/timeout) when the LLM shim is active.
- `security_smoke.yaml` — runs the security lens using the default MVP corpus (attack limit is controlled by suite).
