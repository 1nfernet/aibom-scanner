"""Tests for tool capability classes and the combined-capability risk rule."""

import json

import pytest

from aibom_scanner.detectors.mcp_servers import scan_mcp_config, server_package
from aibom_scanner.detectors.tool_capabilities import (
    CAPABILITY_CLASSES,
    DATA_FILE,
    load_data,
    mcp_capabilities,
    scan_tool_imports,
)
from aibom_scanner.formatters.json_fmt import format_json
from aibom_scanner.formatters.sarif_fmt import format_sarif
from aibom_scanner.formatters.table_fmt import format_table
from aibom_scanner.risk_engine import TRIFECTA_TITLE, classify_risks, consolidate_risks
from aibom_scanner.scanner import scan_directory

UNTRUSTED = "from crewai_tools import BraveSearchTool\n"
SENSITIVE = "from langchain_community.agent_toolkits.sql.toolkit import SQLDatabaseToolkit\n"
ACTION = "from langchain_community.tools.ifttt import IFTTTWebhook\n"
CODE_EXEC = "from crewai_tools import CodeInterpreterTool\n"


def _risk(result):
    return [r for r in result.risks if r["title"] == TRIFECTA_TITLE]


def _scan(tmp_path, *imports):
    (tmp_path / "agent.py").write_text("".join(imports) + "x = 1\n")
    return scan_directory(tmp_path)


class TestData:
    def test_loader_finds_data(self):
        assert DATA_FILE.is_file()
        data = load_data()
        assert tuple(data["classes"]) == CAPABILITY_CLASSES
        assert data["_source"] and data["python_tools"] and data["mcp_packages"]

    def test_every_entry_uses_known_classes(self):
        data = load_data()
        for table in (data["python_tools"], data["mcp_packages"]):
            for key, classes in table.items():
                assert classes and set(classes) <= set(CAPABILITY_CLASSES), key

    def test_limits(self):
        assert len(load_data()["mcp_packages"]) <= 15


class TestImports:
    @pytest.mark.parametrize(
        "src,cls",
        [
            (UNTRUSTED, "untrusted_content_in"),
            (SENSITIVE, "sensitive_data_access"),
            (ACTION, "external_side_effect"),
            (CODE_EXEC, "code_execution"),
            ("from langchain_community.chat_models import ChatPremAI\n", "model_call"),
        ],
    )
    def test_each_class_from_an_import(self, src, cls):
        (t,) = scan_tool_imports("a.py", src)
        assert cls in t["classes"] and t["source"] == "import" and (t["file"], t["line"]) == ("a.py", 1)

    def test_alias_import(self):
        (t,) = scan_tool_imports("a.py", "from crewai_tools import CodeInterpreterTool as CI\nCI()\n")
        assert t["tool"] == "crewai_tools.CodeInterpreterTool"

    def test_module_alias_attribute_use(self):
        src = "import langchain_community.tools as lct\nt = lct.ShellTool()\n"
        (t,) = scan_tool_imports("a.py", src)
        assert t["tool"] == "langchain_community.tools.ShellTool"
        assert set(t["classes"]) == {"code_execution", "external_side_effect"}

    def test_reexported_path_matches_by_class_name(self):
        (t,) = scan_tool_imports("a.py", "from langchain_community.tools import SQLDatabaseToolkit\n")
        assert t["classes"] == ["sensitive_data_access"]

    def test_unknown_and_unparseable(self):
        assert scan_tool_imports("a.py", "from langchain_community.tools import NoSuchThing\n") == []
        assert scan_tool_imports("a.py", "from crewai_tools import (\n") == []


class TestModules:
    @pytest.mark.parametrize(
        "src,root",
        [
            ("import tavily\n", "tavily"),
            ("import playwright.sync_api\n", "playwright"),
            ("import selenium.webdriver as wd\n", "selenium"),
            ("from firecrawl import FirecrawlApp\n", "firecrawl"),
            ("from duckduckgo_search.exceptions import X\n", "duckduckgo_search"),
        ],
    )
    def test_each_import_form(self, src, root):
        (t,) = scan_tool_imports("a.py", src)
        assert (t["tool"], t["classes"], t["source"], t["line"]) == (root, ["untrusted_content_in"], "import", 1)

    def test_one_record_per_root_per_file(self):
        assert len(scan_tool_imports("a.py", "import tavily\nfrom tavily import TavilyClient\n")) == 1

    @pytest.mark.parametrize("src", ["import tavily_helpers\n", "from tavilyx import a\n", "import my_selenium\n"])
    def test_prefix_lookalike_does_not_match(self, src):
        assert scan_tool_imports("a.py", src) == []

    def test_exactly_the_agreed_modules(self):
        assert sorted(load_data()["python_modules"]) == sorted(
            "tavily duckduckgo_search ddgs firecrawl exa_py serpapi googlesearch newspaper trafilatura "
            "playwright selenium".split())

    def test_rule_fires_from_module_and_mcp_package_legs(self, tmp_path):
        (tmp_path / "scrape.py").write_text("from firecrawl import FirecrawlApp\n")
        (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {
            "db": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-sqlite@1"]},
            "git": {"command": "uvx", "args": ["mcp-server-git==0.6"]},
        }}))
        (risk,) = _risk(scan_directory(tmp_path))
        assert any(e.startswith("untrusted_content_in: firecrawl scrape.py:1") for e in risk["evidence"])


class TestMcpPackages:
    def _servers(self, cmd, args):
        return scan_mcp_config("mcp.json", json.dumps({"mcpServers": {"x": {"command": cmd, "args": args}}}))

    @pytest.mark.parametrize(
        "cmd,args,pkg",
        [
            ("npx", ["-y", "@modelcontextprotocol/server-github@1.2.3"], "@modelcontextprotocol/server-github"),
            ("npx", ["-y", "@modelcontextprotocol/server-github"], "@modelcontextprotocol/server-github"),
            ("npx", ["-y", "left-pad@1.0"], "left-pad"),
            ("uvx", ["mcp-server-git==0.6.2"], "mcp-server-git"),
            ("docker", ["run", "-i", "--rm", "ghcr.io/o/img:1.4"], "ghcr.io/o/img"),
            ("docker", ["run", "localhost:5000/img"], "localhost:5000/img"),
            ("node", ["server.js"], None),
        ],
    )
    def test_server_package(self, cmd, args, pkg):
        (s,) = self._servers(cmd, args)
        assert server_package(s) == pkg

    def test_lookup_with_and_without_version(self):
        for spec in ("@modelcontextprotocol/server-filesystem@1.0.0", "@modelcontextprotocol/server-filesystem"):
            (cap,) = mcp_capabilities(self._servers("npx", ["-y", spec, "/data"]))
            assert set(cap["classes"]) == {"sensitive_data_access", "external_side_effect"}
            assert cap["source"] == "mcp_server"

    def test_unknown_package_gets_no_classes_even_if_named_github(self):
        servers = scan_mcp_config(
            "mcp.json", json.dumps({"mcpServers": {"github": {"command": "npx", "args": ["-y", "some-other-pkg"]}}})
        )
        assert mcp_capabilities(servers) == []

    def test_full_scan_records_mcp_capabilities(self, tmp_path):
        (tmp_path / ".mcp.json").write_text(json.dumps(
            {"mcpServers": {"s": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-postgres@0.6"]}}}
        ))
        result = scan_directory(tmp_path)
        assert [t["classes"] for t in result.tool_capabilities] == [["sensitive_data_access"]]
        assert result.summary["capability_classes"] == ["sensitive_data_access"]


class TestRule:
    def test_fires_with_all_three_legs(self, tmp_path):
        (risk,) = _risk(_scan(tmp_path, UNTRUSTED, SENSITIVE, ACTION))
        assert risk["severity"] == "high"
        assert risk["category"] == "agentic_ai_governance" and risk["evidence_basis"] == "observed"
        assert risk["framework_refs"] == ["NIST-MANAGE-4.1", "ISO-42001-A.8.6", "EU-AI-ACT-ART-15"]
        assert risk["evidence"][0] == "scope: repository-wide; the tools below may belong to different agents"
        assert len(risk["evidence"]) == 4
        assert risk["evidence"][1].startswith("untrusted_content_in: BraveSearchTool agent.py:1")

    def test_fires_with_code_execution_as_action_leg(self, tmp_path):
        (risk,) = _risk(_scan(tmp_path, UNTRUSTED, SENSITIVE, CODE_EXEC))
        assert any(e.startswith("code_execution: CodeInterpreterTool") for e in risk["evidence"])

    @pytest.mark.parametrize(
        "imports",
        [(UNTRUSTED, SENSITIVE), (UNTRUSTED, ACTION), (SENSITIVE, ACTION), (UNTRUSTED,), ()],
        ids=["no-action", "no-sensitive", "no-untrusted", "one-leg", "none"],
    )
    def test_silent_when_a_leg_is_missing(self, tmp_path, imports):
        assert _risk(_scan(tmp_path, *imports)) == []

    def test_silent_on_provider_only_repo(self, tmp_repo, agentic_repo):
        assert _risk(scan_directory(tmp_repo)) == []
        assert _risk(scan_directory(agentic_repo)) == []
        assert not any(r["title"] == TRIFECTA_TITLE for r in classify_risks(["crewai", "autogen", "langgraph", "mcp"]))

    def test_mcp_server_legs_count(self, tmp_path):
        (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {
            "web": {"command": "uvx", "args": ["mcp-server-fetch"]},
            "db": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-sqlite@1"]},
            "git": {"command": "uvx", "args": ["mcp-server-git==0.6"]},
        }}))
        (risk,) = _risk(scan_directory(tmp_path))
        assert any(".mcp.json:" in e for e in risk["evidence"])

    def test_survives_consolidation(self):
        caps = [
            {"tool": "a.B", "classes": ["untrusted_content_in"], "source": "import", "file": "f.py", "line": 1},
            {"tool": "a.C", "classes": ["sensitive_data_access"], "source": "import", "file": "f.py", "line": 2},
            {"tool": "a.D", "classes": ["external_side_effect"], "source": "import", "file": "f.py", "line": 3},
        ]
        risks = consolidate_risks(classify_risks(["crewai", "autogen", "langgraph", "mcp"], tool_capabilities=caps))
        assert sum(r["title"] == TRIFECTA_TITLE for r in risks) == 1
        assert any(r["title"] == "AI agent tool use without access controls"
                   or "Agentic AI framework" in r["title"] for r in risks)

    def test_in_json_sarif_and_table(self, tmp_path):
        result = _scan(tmp_path, UNTRUSTED, SENSITIVE, ACTION)
        data = json.loads(format_json(result))
        assert any(r["title"] == TRIFECTA_TITLE for r in data["risks"])
        assert len(data["tool_capabilities"]) == 3
        assert data["summary"]["capability_classes"] == [
            "external_side_effect", "sensitive_data_access", "untrusted_content_in"]
        assert TRIFECTA_TITLE in format_sarif(result)
        assert "Tool Capabilities (3 classified tools)" in format_table(result)
