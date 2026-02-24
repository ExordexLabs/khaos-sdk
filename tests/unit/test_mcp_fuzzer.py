"""Tests for khaos.evaluator.mcp.fuzzer — fuzz case generation."""

from __future__ import annotations

import pytest

from khaos.evaluator.mcp.client import ToolInfo
from khaos.evaluator.mcp.fuzzer import (
    CONTEXT_CANARY,
    FuzzCase,
    generate_fuzz_cases,
    generate_fuzz_cases_for_tools,
    _classify_param,
    _build_base_args,
)


# ---------------------------------------------------------------------------
# _classify_param
# ---------------------------------------------------------------------------


class TestClassifyParam:
    """Tests for parameter classification."""

    @pytest.mark.parametrize("name,expected", [
        ("path", "path"),
        ("file_path", "path"),
        ("directory", "path"),
        ("filename", "path"),
    ])
    def test_path_params(self, name: str, expected: str):
        assert _classify_param(name, {"type": "string"}) == expected

    @pytest.mark.parametrize("name,expected", [
        ("query", "query"),
        ("sql", "query"),
        ("filter", "query"),
    ])
    def test_query_params(self, name: str, expected: str):
        assert _classify_param(name, {"type": "string"}) == expected

    @pytest.mark.parametrize("name,expected", [
        ("command", "command"),
        ("cmd", "command"),
        ("script", "command"),
    ])
    def test_command_params(self, name: str, expected: str):
        assert _classify_param(name, {"type": "string"}) == expected

    @pytest.mark.parametrize("name,expected", [
        ("url", "url"),
        ("endpoint", "url"),
        ("callback", "url"),
    ])
    def test_url_params(self, name: str, expected: str):
        assert _classify_param(name, {"type": "string"}) == expected

    @pytest.mark.parametrize("name,expected", [
        ("role", "privilege"),
        ("scope", "privilege"),
        ("permission", "privilege"),
    ])
    def test_privilege_params(self, name: str, expected: str):
        assert _classify_param(name, {"type": "string"}) == expected

    def test_generic_param(self):
        assert _classify_param("name", {"type": "string"}) == "generic"

    def test_description_influences_classification(self):
        assert _classify_param("input", {"type": "string", "description": "File path to read"}) == "path"


# ---------------------------------------------------------------------------
# _build_base_args
# ---------------------------------------------------------------------------


class TestBuildBaseArgs:
    """Tests for base argument generation."""

    def test_skips_target_param(self):
        props = {
            "target": {"type": "string"},
            "other": {"type": "string"},
        }
        args = _build_base_args(props, "target")
        assert "target" not in args
        assert "other" in args

    def test_type_defaults(self):
        props = {
            "s": {"type": "string"},
            "i": {"type": "integer"},
            "n": {"type": "number"},
            "b": {"type": "boolean"},
            "a": {"type": "array"},
            "o": {"type": "object"},
        }
        args = _build_base_args(props, "__none__")
        assert args["s"] == "test"
        assert args["i"] == 1
        assert args["n"] == 1.0
        assert args["b"] is True
        assert args["a"] == []
        assert args["o"] == {}


# ---------------------------------------------------------------------------
# generate_fuzz_cases — OWASP coverage
# ---------------------------------------------------------------------------


class TestGenerateFuzzCases:
    """Tests for fuzz case generation across OWASP categories."""

    def _make_tool(self, name: str, params: dict) -> ToolInfo:
        return ToolInfo(name=name, description=f"Tool {name}", input_schema={
            "type": "object",
            "properties": params,
        })

    def test_path_tool_generates_mcp05(self):
        tool = self._make_tool("read", {"path": {"type": "string"}})
        cases = generate_fuzz_cases(tool)
        mcp05 = [c for c in cases if c.owasp_id == "MCP05"]
        assert len(mcp05) > 0
        # Should include path traversal cases
        path_cases = [c for c in mcp05 if c.attack_category == "path-traversal"]
        assert len(path_cases) > 0

    def test_query_tool_generates_sql_injection(self):
        tool = self._make_tool("search", {"query": {"type": "string"}})
        cases = generate_fuzz_cases(tool)
        sql = [c for c in cases if c.attack_category == "sql-injection"]
        assert len(sql) > 0

    def test_command_tool_generates_cmd_injection(self):
        tool = self._make_tool("run", {"command": {"type": "string"}})
        cases = generate_fuzz_cases(tool)
        cmd = [c for c in cases if c.attack_category == "command-injection"]
        assert len(cmd) > 0

    def test_url_tool_generates_ssrf(self):
        tool = self._make_tool("fetch", {"url": {"type": "string"}})
        cases = generate_fuzz_cases(tool)
        ssrf = [c for c in cases if c.attack_category == "ssrf"]
        assert len(ssrf) > 0

    def test_role_tool_generates_mcp02(self):
        tool = self._make_tool("set_role", {"role": {"type": "string"}})
        cases = generate_fuzz_cases(tool)
        priv = [c for c in cases if c.owasp_id == "MCP02"]
        assert len(priv) > 0
        assert all(c.attack_category == "privilege-escalation" for c in priv)

    def test_generates_mcp01_secret_scanning(self):
        tool = self._make_tool("read", {"path": {"type": "string"}})
        cases = generate_fuzz_cases(tool)
        mcp01 = [c for c in cases if c.owasp_id == "MCP01"]
        assert len(mcp01) == 1
        assert mcp01[0].attack_category == "secret-scanning"

    def test_generates_mcp03_tool_poisoning(self):
        tool = self._make_tool("read", {"path": {"type": "string"}})
        cases = generate_fuzz_cases(tool)
        mcp03 = [c for c in cases if c.owasp_id == "MCP03"]
        assert len(mcp03) == 1
        assert mcp03[0].attack_category == "tool-poisoning"

    def test_generates_mcp06_response_poisoning(self):
        tool = self._make_tool("read", {"path": {"type": "string"}})
        cases = generate_fuzz_cases(tool)
        mcp06 = [c for c in cases if c.owasp_id == "MCP06"]
        assert len(mcp06) == 1
        assert mcp06[0].attack_category == "response-poisoning"

    def test_generates_mcp10_context_injection(self):
        tool = self._make_tool("read", {"path": {"type": "string"}})
        cases = generate_fuzz_cases(tool)
        mcp10 = [c for c in cases if c.owasp_id == "MCP10"]
        assert len(mcp10) == 1
        assert mcp10[0].attack_category == "context-injection"
        # Verify canary is in arguments
        assert CONTEXT_CANARY in str(mcp10[0].arguments)

    def test_integer_param_gets_numeric_payloads(self):
        tool = self._make_tool("set", {"count": {"type": "integer"}})
        cases = generate_fuzz_cases(tool)
        numeric = [c for c in cases if c.attack_category.startswith("numeric-")]
        assert len(numeric) > 0

    def test_type_confusion_payloads_generated(self):
        tool = self._make_tool("set", {"value": {"type": "integer"}})
        cases = generate_fuzz_cases(tool)
        tc = [c for c in cases if "type-confusion" in c.attack_category]
        assert len(tc) > 0

    def test_no_properties_returns_empty(self):
        tool = ToolInfo("empty", "No params.", {"type": "object"})
        cases = generate_fuzz_cases(tool)
        assert cases == []


# ---------------------------------------------------------------------------
# generate_fuzz_cases_for_tools
# ---------------------------------------------------------------------------


class TestGenerateFuzzCasesForTools:
    """Tests for bulk fuzz case generation."""

    def test_multiple_tools(self):
        tools = [
            ToolInfo("read", "Read.", {"type": "object", "properties": {"path": {"type": "string"}}}),
            ToolInfo("query", "Query.", {"type": "object", "properties": {"sql": {"type": "string"}}}),
        ]
        cases = generate_fuzz_cases_for_tools(tools)
        tool_names = set(c.tool_name for c in cases)
        assert "read" in tool_names
        assert "query" in tool_names

    def test_empty_tools_list(self):
        assert generate_fuzz_cases_for_tools([]) == []
