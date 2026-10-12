"""Tests for the per-server MCP inventory."""

import json

import pytest

from aibom_scanner.detectors.mcp_servers import (
    compute_pinned,
    redact_args,
    scan_mcp_config,
    scan_mcp_python,
    url_host,
)
from aibom_scanner.formatters.json_fmt import format_json
from aibom_scanner.formatters.sarif_fmt import format_sarif
from aibom_scanner.formatters.table_fmt import format_table
from aibom_scanner.risk_engine import classify_risks, consolidate_risks
from aibom_scanner.scanner import scan_directory

FAKE = "FAKE-NOT-A-KEY-123456"

CONFIG = {
    "mcpServers": {
        "files": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@1.2.3", "/data"]},
        "remote": {
            "url": f"https://user:{FAKE}@mcp.example.com/v1/mcp?token={FAKE}",
            "type": "sse",
            "headers": {"Authorization": f"Bearer {FAKE}"},
        },
    }
}


def _write_config(root, rel, data):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2))


class TestConfigFiles:
    @pytest.mark.parametrize(
        "rel", ["mcp.json", ".mcp.json", "mcp_config.json", "claude_desktop_config.json",
                ".cursor/mcp.json", ".vscode/mcp.json"],
    )
    def test_each_filename(self, tmp_path, rel):
        _write_config(tmp_path, rel, CONFIG)
        servers = scan_directory(tmp_path).mcp_servers
        assert {s["name"] for s in servers} == {"files", "remote"}
        assert all(s["source"] == "config" and s["file"] == rel for s in servers)

    def test_servers_key(self, tmp_path):
        _write_config(tmp_path, ".vscode/mcp.json", {"servers": {"a": {"command": "uvx", "args": ["tool==1.0"]}}})
        (server,) = scan_directory(tmp_path).mcp_servers
        assert (server["name"], server["transport"], server["pinned"]) == ("a", "stdio", True)

    def test_fields(self):
        files, remote = scan_mcp_config(".mcp.json", json.dumps(CONFIG))
        assert files["transport"] == "stdio" and files["command"] == "npx" and files["pinned"] is True
        assert remote["transport"] == "sse" and remote["url_host"] == "https://mcp.example.com"
        assert remote["header_keys"] == ["Authorization"] and remote["pinned"] is None
        assert files["line"] > 0

    def test_env_keys_only(self):
        cfg = {"mcpServers": {"s": {"command": "x", "env": {"API_TOKEN": FAKE, "OTHER": "v"}}}}
        (server,) = scan_mcp_config("mcp.json", json.dumps(cfg))
        assert server["env_keys"] == ["API_TOKEN", "OTHER"]

    def test_malformed_json_does_not_crash(self, tmp_path):
        (tmp_path / ".mcp.json").write_text('{"mcpServers": {"a": ')
        (tmp_path / "mcp.json").write_text("[1, 2]")
        (tmp_path / "mcp_config.json").write_text('{"mcpServers": {"a": "not a dict", "b": null}}')
        assert scan_directory(tmp_path).mcp_servers == []


class TestPythonConstructors:
    def test_mcp_stdio_server_parameters(self):
        src = (
            "from mcp import StdioServerParameters\n"
            f"fs = StdioServerParameters(command='npx', args=['-y', 'pkg@1.0.0'], env={{'API_TOKEN': '{FAKE}'}})\n"
        )
        (s,) = scan_mcp_python("app.py", src)
        assert (s["name"], s["transport"], s["framework"], s["line"]) == ("fs", "stdio", "mcp", 2)
        assert s["env_keys"] == ["API_TOKEN"] and s["pinned"] is True and s["source"] == "code"

    def test_langchain_multiserver_config_dict(self):
        src = (
            "from langchain_mcp_adapters.client import MultiServerMCPClient\n"
            "client = MultiServerMCPClient({\n"
            "  'math': {'command': 'python', 'args': ['math.py'], 'transport': 'stdio'},\n"
            "  'web': {'url': 'http://localhost:8000/mcp', 'transport': 'streamable_http'},\n"
            "})\n"
        )
        math, web = scan_mcp_python("a.py", src)
        assert (math["name"], math["transport"], math["framework"]) == ("math", "stdio", "langgraph")
        assert (web["name"], web["transport"], web["url_host"]) == ("web", "http", "http://localhost:8000")

    def test_langchain_connect_to_server(self):
        src = (
            "from langchain_mcp_adapters.client import MultiServerMCPClient\n"
            "async def main():\n"
            "    async with MultiServerMCPClient() as client:\n"
            "        await client.connect_to_server('weather', command='uvx', args=['wx'], transport='stdio')\n"
        )
        (s,) = scan_mcp_python("a.py", src)
        assert (s["name"], s["command"], s["pinned"]) == ("weather", "uvx", False)

    def test_openai_agents_family(self):
        src = (
            "from agents.mcp import MCPServerStdio, MCPServerSse, MCPServerStreamableHttp\n"
            "from agents import HostedMCPTool\n"
            "a = MCPServerStdio(name='fs', params={'command': 'npx', 'args': ['-y', 'x']})\n"
            "b = MCPServerSse(name='sse', params={'url': 'https://h.example/sse', 'headers': {'X-Key': 'v'}})\n"
            "c = MCPServerStreamableHttp(params={'url': 'https://h2.example/mcp'})\n"
            "d = HostedMCPTool(tool_config={'type': 'mcp', 'server_label': 'gitmcp', 'server_url': 'https://g.io/x'})\n"
        )
        a, b, c, d = scan_mcp_python("a.py", src)
        assert (a["transport"], a["command"], a["pinned"]) == ("stdio", "npx", False)
        assert (b["transport"], b["url_host"], b["header_keys"]) == ("sse", "https://h.example", ["X-Key"])
        assert (c["transport"], c["name"]) == ("http", "c")
        assert (d["transport"], d["name"], d["url_host"]) == ("hosted", "gitmcp", "https://g.io")
        assert {s["framework"] for s in (a, b, c, d)} == {"openai_agents"}

    def test_autogen_family(self):
        src = (
            "from autogen_ext.tools.mcp import StdioServerParams, SseServerParams, StreamableHttpServerParams\n"
            "p1 = StdioServerParams(command='uvx', args=['t==1.0'])\n"
            "p2 = SseServerParams(url='https://a.example/sse', headers={'Auth': 'x'})\n"
            "p3 = StreamableHttpServerParams(url='https://b.example/mcp')\n"
        )
        s1, s2, s3 = scan_mcp_python("a.py", src)
        assert [s["transport"] for s in (s1, s2, s3)] == ["stdio", "sse", "http"]
        assert s1["pinned"] is True and s2["header_keys"] == ["Auth"]
        assert {s["framework"] for s in (s1, s2, s3)} == {"autogen"}

    def test_crewai_stdio_and_adapter_dict(self):
        src = (
            "from crewai import Agent\n"
            "from crewai_tools import MCPServerAdapter\n"
            "from mcp import StdioServerParameters\n"
            "p = StdioServerParameters(command='python', args=['srv.py'])\n"
            "cfg = {'url': 'http://localhost:8001/sse', 'transport': 'sse'}\n"
            "with MCPServerAdapter(cfg) as tools:\n"
            "    pass\n"
        )
        stdio, adapter = scan_mcp_python("a.py", src)
        assert (stdio["framework"], stdio["transport"]) == ("crewai", "stdio")
        assert (adapter["framework"], adapter["transport"]) == ("crewai", "sse")
        assert adapter["url_host"] == "http://localhost:8001"

    def test_import_aliases(self):
        src = (
            "import mcp as m\n"
            "import agents.mcp as am\n"
            "from autogen_ext.tools.mcp import StdioServerParams as SP\n"
            "x = m.StdioServerParameters(command='a')\n"
            "y = am.MCPServerStdio(params={'command': 'b'})\n"
            "z = SP(command='c')\n"
        )
        assert [s["command"] for s in scan_mcp_python("a.py", src)] == ["a", "b", "c"]

    def test_unrelated_constructor_ignored(self):
        src = "class StdioServerParameters: pass\nx = StdioServerParameters(command='a')\n"
        assert scan_mcp_python("a.py", src) == []

    def test_unparseable_python_is_skipped(self, tmp_path):
        (tmp_path / "bad.py").write_text("from mcp import StdioServerParameters\nx = StdioServerParameters(command=\n")
        (tmp_path / "ok.py").write_text(
            "from mcp import StdioServerParameters\nx = StdioServerParameters(command='a')\n"
        )
        assert [s["file"] for s in scan_directory(tmp_path).mcp_servers] == ["ok.py"]


class TestRedaction:
    def test_redact_args_flag_forms(self):
        out = redact_args(["--token", FAKE, "--api-key=" + FAKE, "--port", "80", "-e", f"K={FAKE}", "--header", "A: b"])
        assert FAKE not in " ".join(out)
        assert out == ["--token", "<redacted>", "--api-key=<redacted>", "--port", "80", "-e", "K=<redacted>",
                       "--header", "<redacted>"]

    def test_redact_args_secret_shaped_value(self):
        shaped = "sk-" + "a" * 24
        assert redact_args([shaped, "https://u:p@h.example/p?q=1"]) == ["<redacted>", "https://h.example"]

    def test_url_host(self):
        assert url_host(f"https://u:{FAKE}@h.example:8443/a?t={FAKE}") == "https://h.example:8443"
        assert url_host("${MCP_URL}") is None and url_host(None) is None

    def test_full_scan_never_outputs_a_value(self, tmp_path):
        _write_config(tmp_path, ".mcp.json", {"mcpServers": {
            "remote": {"url": f"https://mcp.example.com/x?token={FAKE}", "headers": {"X-Api-Key": FAKE}},
            "local": {"command": "node", "args": ["srv.js", "--token", FAKE, f"--secret={FAKE}"],
                      "env": {"MY_SECRET": FAKE}},
        }})
        (tmp_path / "agent.py").write_text(
            "from mcp import StdioServerParameters\n"
            f"s = StdioServerParameters(command='node', args=['x.js', '--password', '{FAKE}'], "
            f"env={{'DB_PASS': '{FAKE}'}})\n"
            "from agents.mcp import MCPServerSse\n"
            f"t = MCPServerSse(params={{'url': 'https://h.example/sse?k={FAKE}', "
            f"'headers': {{'Authorization': '{FAKE}'}}}})\n"
        )
        result = scan_directory(tmp_path)
        assert len(result.mcp_servers) == 4
        for output in (format_json(result), format_sarif(result), format_table(result)):
            assert FAKE not in output
        data = json.loads(format_json(result))
        assert {k for s in data["mcp_servers"] for k in s["env_keys"]} == {"MY_SECRET", "DB_PASS"}
        assert {k for s in data["mcp_servers"] for k in s["header_keys"]} == {"X-Api-Key", "Authorization"}


class TestPinned:
    @pytest.mark.parametrize(
        "command,args,expected",
        [
            ("npx", ["-y", "pkg@1.2.3"], True),
            ("npx", ["-y", "@scope/pkg@1.2.3"], True),
            ("npx", ["-y", "pkg"], False),
            ("npx", ["-y", "@scope/pkg"], False),
            ("npx", ["pkg@latest"], False),
            ("uvx", ["pkg==1.2.3"], True),
            ("uvx", ["pkg"], False),
            ("uvx", ["--from", "pkg==2.0", "cmd"], True),
            ("pipx", ["run", "pkg==1.0"], True),
            ("pipx", ["run", "pkg"], False),
            ("pipx", ["install", "pkg"], None),
            ("docker", ["run", "-i", "--rm", "-e", "K", "ghcr.io/o/img:1.4"], True),
            ("docker", ["run", "-i", "ghcr.io/o/img:latest"], False),
            ("docker", ["run", "-i", "ghcr.io/o/img"], False),
            ("docker", ["run", "img@sha256:" + "a" * 64], True),
            ("docker", ["run", "-p", "5000:80", "localhost:5000/img"], False),
            ("node", ["server.js"], None),
            ("npx", ["-y", "<dynamic>"], None),
        ],
    )
    def test_pinned(self, command, args, expected):
        assert compute_pinned(command, args) is expected

    def test_url_transport_is_null(self):
        (s,) = scan_mcp_config("mcp.json", json.dumps({"mcpServers": {"r": {"url": "https://h.example/mcp"}}}))
        assert s["pinned"] is None


class TestRiskEvidence:
    def test_rule_carries_per_server_evidence(self, tmp_path):
        _write_config(tmp_path, ".mcp.json", CONFIG)
        (tmp_path / "srv.py").write_text("import mcp\nfrom mcp import StdioServerParameters\n"
                                         "s = StdioServerParameters(command='x')\n")
        result = scan_directory(tmp_path)
        risk = next(r for r in result.risks if r["title"] == "Agentic AI framework without human oversight controls")
        assert any("files (stdio) .mcp.json:" in e for e in risk["evidence"])
        assert any("s (stdio) srv.py:3" in e for e in risk["evidence"])
        assert risk["evidence_basis"] == "observed"

    def test_rule_unchanged_with_import_only(self):
        risks = consolidate_risks(classify_risks(["mcp"]))
        risk = next(r for r in risks if r["title"] == "Agentic AI framework without human oversight controls")
        assert "evidence" not in risk

    def test_standalone_rule_evidence(self):
        servers = [{"name": "a", "transport": "stdio", "file": "mcp.json", "line": 4}]
        risk = next(r for r in classify_risks(["mcp"], mcp_servers=servers)
                    if r["title"] == "MCP server exposes tools without governance controls")
        assert risk["evidence"] == ["a (stdio) mcp.json:4"]


class TestOutput:
    def test_json_has_servers_and_note(self, tmp_path):
        _write_config(tmp_path, "mcp.json", CONFIG)
        data = json.loads(format_json(scan_directory(tmp_path)))
        assert len(data["mcp_servers"]) == 2
        assert data["summary"]["total_mcp_servers"] == 2
        assert "C#, TypeScript or Go" in data["summary"]["mcp_servers_note"]

    def test_table_section_only_with_servers(self, tmp_path):
        assert "MCP Servers" not in format_table(scan_directory(tmp_path))
        _write_config(tmp_path, "mcp.json", CONFIG)
        assert "MCP Servers (2)" in format_table(scan_directory(tmp_path))

    def test_empty_repo(self, empty_repo):
        assert scan_directory(empty_repo).mcp_servers == []
