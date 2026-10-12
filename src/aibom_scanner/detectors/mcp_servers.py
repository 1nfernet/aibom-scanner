"""Per-server MCP inventory: which MCP servers a repo configures or starts, never their credentials.

Two sources:
  - config files (mcp.json, .mcp.json, mcp_config.json, claude_desktop_config.json), any language
  - Python code, via one AST visitor driven by the constructor table below

Hard rule: only key NAMES are stored for env and headers, URLs are reduced to scheme + host,
and credential-looking arguments are replaced with "<redacted>". No value from a server's
env, headers, or credential arguments ever reaches the output.

The list of MCP client constructor names was derived from splx-ai/agentic-radar (Apache-2.0).
See NOTICE.
"""

import ast
import json
import re
from urllib.parse import urlsplit

from aibom_scanner.detectors.secrets import HARDCODED_KEY_PATTERNS

MCP_CONFIG_FILENAMES = {"mcp.json", ".mcp.json", "mcp_config.json", "claude_desktop_config.json"}
MCP_CONFIG_KEYS = ("mcpServers", "servers")

MCP_SERVERS_NOTE = (
    "MCP servers are extracted from config files (any repo) and Python code only. "
    "Servers defined in C#, TypeScript or Go source are detected at import level, not listed per server."
)

# fully-qualified constructor -> (transport, framework). "framework" None = decide from file imports.
_CONSTRUCTORS: dict[str, tuple[str, str | None]] = {
    "mcp.StdioServerParameters": ("stdio", None),
    "mcp.client.stdio.StdioServerParameters": ("stdio", None),
    "agents.mcp.MCPServerStdio": ("stdio", "openai_agents"),
    "agents.mcp.server.MCPServerStdio": ("stdio", "openai_agents"),
    "agents.mcp.MCPServerSse": ("sse", "openai_agents"),
    "agents.mcp.server.MCPServerSse": ("sse", "openai_agents"),
    "agents.mcp.MCPServerStreamableHttp": ("http", "openai_agents"),
    "agents.mcp.server.MCPServerStreamableHttp": ("http", "openai_agents"),
    "agents.HostedMCPTool": ("hosted", "openai_agents"),
    "agents.tool.HostedMCPTool": ("hosted", "openai_agents"),
    "autogen_ext.tools.mcp.StdioServerParams": ("stdio", "autogen"),
    "autogen_ext.tools.mcp.SseServerParams": ("sse", "autogen"),
    "autogen_ext.tools.mcp.StreamableHttpServerParams": ("http", "autogen"),
}
_MULTI_CLIENT = "langchain_mcp_adapters.client.MultiServerMCPClient"
_CREWAI_ADAPTERS = {"crewai_tools.MCPServerAdapter", "crewai_tools.tools.mcp_tool.MCPServerAdapter"}
_QUICK_FILTER = ("StdioServer", "SseServer", "StreamableHttp", "MCPServer", "HostedMCPTool", "MultiServerMCPClient")

_TRANSPORT_NAMES = {
    "stdio": "stdio", "sse": "sse", "http": "http", "streamable_http": "http", "streamable-http": "http",
    "streamablehttp": "http", "streamable_http_server": "http", "hosted": "hosted",
}

_CREDENTIAL_FLAG = re.compile(
    r"^-{1,2}[\w-]*(token|api[-_]?key|key|password|passwd|secret|auth|bearer|credential|header)[\w-]*$", re.I
)
_ENV_FLAGS = {"-e", "--env"}
_REDACTED = "<redacted>"
_DYNAMIC = "<dynamic>"
_SECRET_PATTERNS = [re.compile(p) for p, _ in HARDCODED_KEY_PATTERNS]
_AUTH_VALUE = re.compile(r"^\s*(authorization\s*:|bearer\s+|basic\s+)", re.I)
_VERSION = re.compile(r"^v?\d[\w.+\-]*$")


def is_mcp_config_path(rel_path: str) -> bool:
    return rel_path.replace("\\", "/").split("/")[-1].lower() in MCP_CONFIG_FILENAMES


# --- redaction ---


def url_host(url: object) -> str | None:
    """Reduce a URL to scheme://host[:port]. Drops userinfo, path and query."""
    if not isinstance(url, str):
        return None
    try:
        parts = urlsplit(url.strip())
        host = parts.hostname
        port = parts.port
    except ValueError:
        return None
    if not parts.scheme or not host:
        return None
    return f"{parts.scheme}://{host}" + (f":{port}" if port else "")


def _redact_arg(arg: str) -> str:
    """Redact one standalone argument when it looks like a credential or a credentialed URL."""
    if _AUTH_VALUE.match(arg) or any(p.search(arg) for p in _SECRET_PATTERNS):
        return _REDACTED
    if re.match(r"^[a-z][a-z0-9+.-]*://", arg, re.I):
        return url_host(arg) or _REDACTED
    return arg


def redact_args(args: list) -> list[str]:
    """Return args with credential values removed: --token VALUE, --token=VALUE, -e KEY=VALUE, secret-shaped args."""
    out: list[str] = []
    redact_next = env_next = False
    for a in args:
        if not isinstance(a, str):
            out.append(_DYNAMIC)
            redact_next = env_next = False
            continue
        if redact_next:
            out.append(_REDACTED)
            redact_next = False
        elif env_next:
            out.append(a.split("=", 1)[0] + "=" + _REDACTED if "=" in a else a)
            env_next = False
        elif a.startswith("-") and "=" in a:
            flag, _ = a.split("=", 1)
            if _CREDENTIAL_FLAG.match(flag) or flag in _ENV_FLAGS:
                out.append(f"{flag}={_REDACTED}")
            else:
                out.append(_redact_arg(a))
        elif _CREDENTIAL_FLAG.match(a):
            out.append(a)
            redact_next = True
        elif a in _ENV_FLAGS:
            out.append(a)
            env_next = True
        else:
            out.append(_redact_arg(a))
    return out


def _env_names_from_args(args: list) -> list[str]:
    """Names set via docker-style `-e NAME=value` / `--env NAME`."""
    names = []
    for i, a in enumerate(args[:-1]):
        if a in _ENV_FLAGS and isinstance(args[i + 1], str):
            names.append(args[i + 1].split("=", 1)[0])
    return names


# --- pinned ---

_VALUE_FLAGS = {
    "docker": {"-e", "--env", "-v", "--volume", "-p", "--publish", "--name", "--network", "--net", "-w", "--workdir",
               "-u", "--user", "--env-file", "--mount", "--entrypoint", "-l", "--label", "--add-host", "--platform",
               "--pull", "--memory", "-m", "--cpus"},
    "uvx": {"--from", "--with", "--python", "-p", "--index-url", "--directory", "--with-requirements"},
    "pipx": {"--spec", "--python", "--pip-args", "--index-url"},
    "npx": {"-p", "--package", "-c", "--call", "--registry", "--cache", "--prefix"},
}


def _first_positional(args: list[str], value_flags: set[str]) -> str | None:
    skip = False
    for a in args:
        if skip:
            skip = False
        elif a in value_flags:
            skip = True
        elif not a.startswith("-"):
            return None if a == _DYNAMIC else a
    return None


def _flag_value(args: list[str], names: set[str]) -> str | None:
    for i, a in enumerate(args[:-1]):
        if a in names:
            return None if args[i + 1] == _DYNAMIC else args[i + 1]
    return None


def _versioned(spec: str, seps: tuple[str, ...]) -> bool:
    """True when spec is name<sep>version with a concrete version (not latest, not a range)."""
    for sep in seps:
        idx = spec.rfind(sep)
        if idx > 0 and _VERSION.match(spec[idx + len(sep):]):
            return True
    return False


def compute_pinned(command: str | None, args: list) -> bool | None:
    """True/False for npx, uvx, pipx run and docker run; None for everything else."""
    if not command or any(not isinstance(a, str) for a in args):
        return None
    cmd = command.replace("\\", "/").split("/")[-1].lower()
    cmd = re.sub(r"\.(cmd|exe)$", "", cmd)
    if cmd == "npx":
        spec = _flag_value(args, {"-p", "--package"}) or _first_positional(args, _VALUE_FLAGS["npx"])
        return _versioned(spec, ("@",)) if spec else None
    if cmd == "uvx":
        spec = _flag_value(args, {"--from"}) or _first_positional(args, _VALUE_FLAGS["uvx"])
        return _versioned(spec, ("==", "@")) if spec else None
    if cmd == "pipx" and args and args[0] == "run":
        spec = _flag_value(args, {"--spec"}) or _first_positional(args[1:], _VALUE_FLAGS["pipx"])
        return _versioned(spec, ("==",)) if spec else None
    if cmd == "docker" and "run" in args:
        image = _first_positional(args[args.index("run") + 1:], _VALUE_FLAGS["docker"])
        if not image:
            return None
        if "@sha256:" in image:
            return True
        tag = image.rsplit(":", 1)[1] if ":" in image.rsplit("/", 1)[-1] else ""
        return bool(tag) and tag != "latest"
    return None


# --- record building ---


def _record(
    *, name, transport, command, args, url, env_keys, header_keys, source, framework, file, line,
) -> dict:
    args = list(args or [])
    command = command if isinstance(command, str) else None
    if command is not None:
        command = _redact_arg(command)
    env = sorted({k for k in (env_keys or []) if isinstance(k, str)} | set(_env_names_from_args(args)))
    return {
        "name": name if isinstance(name, str) else None,
        "transport": transport,
        "command": command,
        "args": redact_args(args),
        "url_host": url_host(url),
        "env_keys": env,
        "header_keys": sorted({k for k in (header_keys or []) if isinstance(k, str)}),
        "source": source,
        "framework": framework,
        "file": file,
        "line": line,
        "pinned": compute_pinned(command, args) if command else None,
    }


def _transport_from_config(cfg: dict) -> str:
    declared = cfg.get("type", cfg.get("transport"))
    if isinstance(declared, str) and declared.lower() in _TRANSPORT_NAMES:
        return _TRANSPORT_NAMES[declared.lower()]
    if cfg.get("command"):
        return "stdio"
    url = cfg.get("url", cfg.get("serverUrl"))
    if isinstance(url, str) and urlsplit(url).path.rstrip("/").endswith("/sse"):
        return "sse"
    return "unknown"


# --- config files ---


def scan_mcp_config(rel_path: str, content: str) -> list[dict]:
    """Extract servers from an MCP client config file. Malformed JSON returns []."""
    try:
        data = json.loads(content)
    except ValueError:
        return []
    if not isinstance(data, dict):
        return []
    servers = []
    for key in MCP_CONFIG_KEYS:
        block = data.get(key)
        if not isinstance(block, dict):
            continue
        for name, cfg in block.items():
            if not isinstance(cfg, dict):
                continue
            args = cfg.get("args") if isinstance(cfg.get("args"), list) else []
            env, headers = cfg.get("env"), cfg.get("headers")
            m = re.search(r'"' + re.escape(name) + r'"\s*:', content)
            line = content.count("\n", 0, m.start()) + 1 if m else 0
            servers.append(_record(
                name=name,
                transport=_transport_from_config(cfg),
                command=cfg.get("command"),
                args=args,
                url=cfg.get("url", cfg.get("serverUrl")),
                env_keys=list(env) if isinstance(env, dict) else [],
                header_keys=list(headers) if isinstance(headers, dict) else [],
                source="config",
                framework="mcp_config",
                file=rel_path,
                line=line,
            ))
    return servers


# --- Python code ---


class _McpVisitor(ast.NodeVisitor):
    def __init__(self, rel_path: str):
        self.rel_path = rel_path
        self.servers: list[dict] = []
        self.imports: dict[str, str] = {}  # local name -> fully qualified
        self.star_modules: list[str] = []
        self.targets: dict[int, str] = {}  # id(Call) -> variable it is assigned to
        self.dict_vars: dict[str, ast.Dict] = {}
        self.client_vars: set[str] = set()
        self.uses_crewai = False

    # imports
    def visit_Import(self, node: ast.Import) -> None:
        for a in node.names:
            self.imports[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
            self.uses_crewai |= a.name.split(".")[0] == "crewai"

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.level or not node.module:
            return
        self.uses_crewai |= node.module.split(".")[0] == "crewai"
        for a in node.names:
            if a.name == "*":
                self.star_modules.append(node.module)
            else:
                self.imports[a.asname or a.name] = f"{node.module}.{a.name}"

    def _fq(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            if node.id in self.imports:
                return self.imports[node.id]
            for mod in self.star_modules:
                cand = f"{mod}.{node.id}"
                if cand in _CONSTRUCTORS or cand == _MULTI_CLIENT or cand in _CREWAI_ADAPTERS:
                    return cand
            return None
        if isinstance(node, ast.Attribute):
            base = self._fq(node.value)
            return f"{base}.{node.attr}" if base else None
        return None

    # targets
    def _note_target(self, value: ast.AST, target: ast.AST | None) -> None:
        if isinstance(value, ast.Await):
            value = value.value
        if isinstance(target, ast.Name):
            if isinstance(value, ast.Call):
                self.targets[id(value)] = target.id
            elif isinstance(value, ast.Dict):
                self.dict_vars[target.id] = value

    def visit_Assign(self, node: ast.Assign) -> None:
        if len(node.targets) == 1:
            self._note_target(node.value, node.targets[0])
            self._note_client(node.value, node.targets[0])
        self.generic_visit(node)

    def _visit_with(self, node) -> None:
        for item in node.items:
            if item.optional_vars is not None:
                self._note_target(item.context_expr, item.optional_vars)
                self._note_client(item.context_expr, item.optional_vars)
        self.generic_visit(node)

    visit_With = visit_AsyncWith = _visit_with

    def _note_client(self, value: ast.AST, target: ast.AST) -> None:
        if isinstance(value, ast.Await):
            value = value.value
        if isinstance(value, ast.Call) and isinstance(target, ast.Name) and self._fq(value.func) == _MULTI_CLIENT:
            self.client_vars.add(target.id)

    # calls
    def visit_Call(self, node: ast.Call) -> None:
        fq = self._fq(node.func)
        if fq in _CONSTRUCTORS:
            self._constructor(node, *_CONSTRUCTORS[fq])
        elif fq == _MULTI_CLIENT:
            self._multi_client(node)
        elif fq in _CREWAI_ADAPTERS:
            self._crewai_adapter(node)
        elif (
            isinstance(node.func, ast.Attribute) and node.func.attr == "connect_to_server"
            and isinstance(node.func.value, ast.Name) and node.func.value.id in self.client_vars
        ):
            name = node.args[0].value if node.args and isinstance(node.args[0], ast.Constant) else None
            self._add_from_fields(_fields(node), name, None, node.lineno, "langgraph")
        self.generic_visit(node)

    def _constructor(self, node: ast.Call, transport: str, framework: str | None) -> None:
        fields = _fields(node)
        for wrapper in ("params", "tool_config"):
            if wrapper in fields:
                inner = fields[wrapper]
                if isinstance(inner, ast.Name):
                    inner = self.dict_vars.get(inner.id)
                fields.update(_fields(inner))
        if "server_url" in fields:
            fields.setdefault("url", fields["server_url"])
        name = _const(fields.get("name")) or _const(fields.get("server_label")) or self.targets.get(id(node))
        fw = framework or ("crewai" if self.uses_crewai else "mcp")
        self._add_from_fields(fields, name, transport, node.lineno, fw)

    def _multi_client(self, node: ast.Call) -> None:
        conns = node.args[0] if node.args else _fields(node).get("connections")
        if isinstance(conns, ast.Name):
            conns = self.dict_vars.get(conns.id)
        if not isinstance(conns, ast.Dict):
            return
        for k, v in zip(conns.keys, conns.values):
            fields = _fields(v)
            if fields:
                self._add_from_fields(fields, _const(k), None, getattr(v, "lineno", node.lineno), "langgraph")

    def _crewai_adapter(self, node: ast.Call) -> None:
        arg = node.args[0] if node.args else _fields(node).get("serverparams")
        if isinstance(arg, ast.Name):
            arg = self.dict_vars.get(arg.id)
        if isinstance(arg, ast.Dict):
            self._add_from_fields(_fields(arg), self.targets.get(id(node)), None, node.lineno, "crewai")

    def _add_from_fields(self, fields: dict, name, transport: str | None, line: int, framework: str) -> None:
        args_node = fields.get("args")
        args = [_const(e) if _const(e) is not None else _DYNAMIC for e in args_node.elts] \
            if isinstance(args_node, (ast.List, ast.Tuple)) else []
        declared = _const(fields.get("transport")) or _const(fields.get("type"))
        if transport is None:
            transport = _TRANSPORT_NAMES.get(declared.lower(), "unknown") if declared else (
                "stdio" if "command" in fields else "unknown")
        self.servers.append(_record(
            name=name, transport=transport, command=_const(fields.get("command")), args=args,
            url=_const(fields.get("url")), env_keys=_dict_keys(fields.get("env")),
            header_keys=_dict_keys(fields.get("headers")), source="code", framework=framework,
            file=self.rel_path, line=line,
        ))


def _const(node: ast.AST | None) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _dict_keys(node: ast.AST | None) -> list[str]:
    if not isinstance(node, ast.Dict):
        return []
    return [k.value for k in node.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)]


def _fields(node: ast.AST | None) -> dict[str, ast.AST]:
    """Keyword arguments of a call, or the string keys of a dict literal, as name -> value node."""
    if isinstance(node, ast.Call):
        return {kw.arg: kw.value for kw in node.keywords if kw.arg}
    if isinstance(node, ast.Dict):
        return {k.value: v for k, v in zip(node.keys, node.values)
                if isinstance(k, ast.Constant) and isinstance(k.value, str)}
    return {}


def scan_mcp_python(rel_path: str, content: str) -> list[dict]:
    """Extract servers from Python source. A file that does not parse yields []."""
    if not any(token in content for token in _QUICK_FILTER):
        return []
    try:
        tree = ast.parse(content)
    except (SyntaxError, ValueError, RecursionError):
        return []
    visitor = _McpVisitor(rel_path)
    visitor.visit(tree)
    return visitor.servers


def scan_mcp_file(rel_path: str, content: str) -> list[dict]:
    """Dispatch on file type: MCP config files and .py files."""
    if is_mcp_config_path(rel_path):
        return scan_mcp_config(rel_path, content)
    if rel_path.endswith(".py"):
        return scan_mcp_python(rel_path, content)
    return []
