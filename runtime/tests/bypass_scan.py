"""Static bypass scanner (ADR-0009), an ALLOWLIST design.

Nothing here is a proof. Static analysis of a dynamic language cannot show that no bypass exists; it
raises the cost of the accidental and the lazy ones and forces every IO-capable or reflective
construct in ``src/axis_runtime`` to be named, located and justified in ONE place (this file). The
runtime audit-hook test (``test_audit_hook.py``) is the independent dynamic check.

Three layers, applied to every module except generated stubs (``_gen/``):

1. IMPORTS are allowlisted. A module may import only ``SAFE_IMPORTS`` (modules whose OWN API is
   believed free of process/network/file-write capability, see the caveat there) unless the FILE
   appears in ``IO_IMPORTS`` with that module and a reason. Anything unknown is a violation, so
   ``import urllib`` / ``smtplib`` / ``boto3`` / ``pickle`` / ``ctypes`` / ... need no denylist entry.
2. CONSTRUCTS are banned by AST (eval/exec, dynamic import, dynamic getattr, introspection, process /
   network / file-write primitives, ``open`` for writing). Files may be exempted per rule in
   ``EXEMPTIONS`` with a reason.
3. RESTRICTED_NAMES (the executor-only entry points) may only appear in the files listed for them.
"""

from __future__ import annotations

import ast
import importlib.util
import re
from dataclasses import dataclass
from pathlib import Path

GENERATED_PREFIX = "_gen/"

# ---------------------------------------------------------------------------------------------------
# (1) Import allowlists. Adding an entry is a security-review decision.
# ---------------------------------------------------------------------------------------------------

# Exact dotted module names whose *intended* API has no network, process, or file-write capability.
# CAVEAT: "safe" does NOT mean "pure compute". Several of these modules import and therefore re-export
# dangerous modules as attributes (``logging.os``, ``asyncio.subprocess``, ``typing.sys``,
# ``random._os``, ``contextlib.os`` ...). Importing the module is allowed; reaching such a member is
# not: rule "transitive-module" bans a second attribute segment naming a dangerous module, and
# rule "unlisted-member" confines the widest re-exporters (MEMBER_ALLOW) to the members src uses.
SAFE_IMPORTS: frozenset[str] = frozenset(
    {
        "__future__",  # compiler directives
        "abc",  # abstract base classes
        "asyncio",  # event loop / tasks; IO members banned by rule "net"/"process"
        "collections.abc",  # ABCs for typing
        "contextlib",  # context-manager helpers
        "contextvars",  # ExecutionToken-adjacent context state (guard.py)
        "copy",  # deepcopy
        "dataclasses",  # data classes
        "datetime",  # time values
        "decimal",  # money math
        "enum",  # enums
        "functools",  # lru_cache etc.
        "hashlib",  # hashing
        "hmac",  # MAC (sigv4)
        "inspect",  # isabstract / isawaitable; frame access banned by rule "introspection"
        "ipaddress",  # endpoint validation (pure parsing)
        "itertools",  # iteration helpers
        "json",  # (de)serialisation of strings
        "logging",  # logger; sinks that write files/sockets are banned by rule "logging-sink"
        "random",  # jitter
        "re",  # regular expressions
        "secrets",  # token generation
        "struct",  # AWS event-stream framing
        "time",  # clocks
        "typing",  # annotations
        "urllib.parse",  # URL parsing/quoting only (urllib.request etc. are NOT safe)
        "zlib",  # crc32 for event-stream framing
        "google.protobuf.json_format",  # protobuf <-> JSON, pure compute
        "google.protobuf.struct_pb2",  # protobuf Struct, pure compute
        "cryptography.fernet",  # symmetric encryption, pure compute
    }
)
# Internal package: always fine (its own files are scanned too).
SAFE_PREFIXES: tuple[str, ...] = ("axis_runtime",)

# file -> {module prefix: reason}. IO-capable modules are allowed in these files ONLY.
IO_IMPORTS: dict[str, dict[str, str]] = {
    "models/adapters/base.py": {
        "httpx": "HttpxTransport: the single place the ModelGateway speaks HTTP; reachable only via "
        "ModelGateway, which only runs inside ActionExecutor (ModelCall).",
        "socket": "default_resolver: getaddrinfo for the endpoint SSRF check (resolution only, "
        "never connects).",
    },
    "tools.py": {
        "httpx": "HttpMcpClient: MCP-over-HTTP backend; reachable only through McpCall performed "
        "by ActionExecutor.",
    },
    "gate.py": {
        "grpc": "GrpcGateClient: the gate's own transport to the Risk Kernel (not an action).",
    },
    "approvals.py": {
        "httpx": "HttpApprovalResolver: control-plane read of an approval decision from the "
        "approvals service (loopback dev bridge, NEEDS #62); not an agent action. It only fetches a "
        "record that the executor forwards to the Risk Kernel, which re-gates and verifies it.",
    },
    "memory.py": {
        "httpx": "HttpMemoryBackend / MemoryRagRetriever: client of the memory service (loopback dev "
        "surface, NEEDS). The write backend is reachable only through MemoryWrite performed by "
        "ActionExecutor; the retriever is read-only, ACL-filtered server side and re-checked by RagStage.",
    },
    "temporal.py": {
        "temporalio": "Temporal workflow/activity wiring: talks to the Temporal server, runs "
        "ActionExecutor inside the activity.",
    },
    "models/secrets.py": {
        "os": "FileSecretStore (dev-only encrypted secret file): atomic 0600 write; not reachable "
        "from any Action.",
        "pathlib": "FileSecretStore path handling.",
    },
    "tki/ipc.py": {
        "pathlib": "locates the frozen ipc-envelope-v1 schema (read only); patterns are not copied.",
    },
    "process.py": {
        "os": "reads AXIS_PROCESS_MODEL_PATH (environment read only).",
        "pathlib": "locates the frozen process-model.json (read only).",
    },
}

# ---------------------------------------------------------------------------------------------------
# (2) Banned constructs. rule id -> {file: reason} exemptions.
# ---------------------------------------------------------------------------------------------------
EXEMPTIONS: dict[str, dict[str, str]] = {
    "file-write": {
        "models/secrets.py": "FileSecretStore atomic write (os.open/fdopen/replace); dev-only store.",
    },
    "dns": {
        "models/adapters/base.py": "default_resolver uses loop.getaddrinfo (DNS lookup only).",
    },
    "introspection": {
        "actions.py": "all_action_types() walks Action.__subclasses__() (registry for the bypass test).",
    },
}

# Name references that are never acceptable in src.
BANNED_NAMES = frozenset(
    {
        "eval",
        "exec",
        "compile",
        "__import__",
        "globals",
        "locals",
        "vars",
        "breakpoint",
        "__builtins__",
    }
)
BANNED_DYNAMIC_ATTR_FUNCS = frozenset({"getattr", "setattr", "delattr"})
INTROSPECTION_ATTRS = frozenset(
    {
        "__mro__",
        "__bases__",
        "__base__",
        "__reduce__",
        "__reduce_ex__",
        "__loader__",
        "__spec__",
        "gi_code",
        "cr_code",
        "ag_code",
        "__dict__",
        "__globals__",
        "__builtins__",
        "__subclasses__",
        "__getattribute__",
        "__code__",
        "__closure__",
        "f_globals",
        "f_locals",
        "f_back",
        "f_builtins",
        "gi_frame",
        "cr_frame",
        "ag_frame",
        "currentframe",
        "_getframe",
        "getouterframes",
        "import_module",
    }
)
# Attribute names that are banned as ATTRIBUTES too (``builtins.exec``, ``x.eval``). ``compile`` is
# handled separately because ``re.compile`` is legitimate.
BANNED_ATTR_NAMES = BANNED_NAMES - {"compile"}
# Modules that "safe" modules re-export. A chain like ``logging.os.system`` / ``typing.sys.modules`` is
# flagged when any attribute is one of these, whatever the base is. ``signal`` is also a common method
# name (Temporal), so it is only flagged when the chain is rooted at an imported safe module.
DANGEROUS_MODULE_NAMES = frozenset(
    {
        "os",
        "sys",
        "subprocess",
        "socket",
        "threading",
        "io",
        "builtins",
        "_os",
        "_socket",
        "_io",
        "posix",
        "nt",
        "ctypes",
        "importlib",
        "pickle",
        "marshal",
        "shutil",
        "tempfile",
        "signal",
        "_thread",
        "multiprocessing",
        "concurrent",
    }
)
# The widest re-exporters may only expose the members src actually uses (first segment after module).
MEMBER_ALLOW: dict[str, frozenset[str]] = {
    "asyncio": frozenset(
        "CancelledError Event Lock Task create_task current_task get_running_loop sleep timeout "
        "wait_for gather Queue Semaphore Future shield wait TimeoutError iscoroutinefunction "
        "Condition as_completed ensure_future".split()
    ),
    "logging": frozenset(
        "getLogger Logger LoggerAdapter NullHandler DEBUG INFO WARNING ERROR CRITICAL".split()
    ),
    "inspect": frozenset(
        "isabstract isawaitable iscoroutinefunction isclass signature Signature Parameter".split()
    ),
    "contextlib": frozenset(
        "suppress contextmanager asynccontextmanager AbstractContextManager "
        "AbstractAsyncContextManager nullcontext closing aclosing AsyncExitStack ExitStack".split()
    ),
    "random": frozenset("Random SystemRandom random uniform randint choice shuffle".split()),
    "typing": frozenset(),  # denylist mode below: typing has hundreds of legitimate names
}
TYPING_DENIED_MEMBERS = frozenset({"types", "collections", "functools", "operator", "warnings"})
# Attributes carrying string attribute names that must not name introspection/dangerous members.
ATTR_NAME_FUNCS = frozenset(
    {"getattr", "setattr", "hasattr", "delattr", "attrgetter", "methodcaller"}
)
THREAD_ESCAPE_ATTRS = frozenset({"run_in_executor", "to_thread", "run_coroutine_threadsafe"})
# Fully qualified names (after alias resolution) and prefixes that are banned.
BANNED_QUALIFIED = frozenset(
    {
        "os.system",
        "os.kill",
        "os.killpg",
        "os.putenv",
        "os.unsetenv",
        "sys.modules",
        "sys.meta_path",
        "sys.path_hooks",
        "sys.settrace",
        "sys.setprofile",
        "sys.addaudithook",
    }
)
BANNED_QUALIFIED_PREFIXES = (
    "importlib.",
    "ctypes.",
    "pickle.",
    "_pickle.",
    "marshal.",
    "shelve.",
    "multiprocessing.",
    "subprocess.",
    "shutil.",
    "pty.",
)
OS_FILE_WRITE = frozenset(
    {
        "remove",
        "unlink",
        "rmdir",
        "removedirs",
        "rename",
        "renames",
        "replace",
        "truncate",
        "link",
        "symlink",
        "chmod",
        "chown",
        "mkdir",
        "makedirs",
        "open",
        "fdopen",
        "mkfifo",
        "utime",
    }
)
PATH_FILE_WRITE_ATTRS = frozenset(
    {
        "write_text",
        "write_bytes",
        "touch",
        "unlink",
        "rmdir",
        "rmtree",
        "mkdir",
        "symlink_to",
        "hardlink_to",
        "rename",
        "fdopen",
    }
)
PROCESS_ATTR = re.compile(
    r"^(exec[lv]p?e?|spawn[lv]p?e?|posix_spawnp?|fork(pty)?|popen|startfile|"
    r"create_subprocess_\w+|subprocess_(exec|shell))$"
)
NET_ATTRS = frozenset(
    {
        "open_connection",
        "open_unix_connection",
        "start_server",
        "start_unix_server",
        "create_connection",
        "create_server",
        "create_datagram_endpoint",
        "create_unix_connection",
        "create_unix_server",
        "sock_connect",
        "connect_read_pipe",
        "connect_write_pipe",
        "urlopen",
        "sock_sendall",
        "sock_recv",
        "sock_recv_into",
        "sock_recvfrom",
        "sock_recvfrom_into",
        "sock_sendto",
        "sock_accept",
        "sock_sendfile",
        "sendfile",
    }
)
# Name resolution (leaks a hostname, never connects): allowed only where the SSRF check lives.
DNS_ATTRS = frozenset({"getaddrinfo", "gethostbyname", "gethostbyname_ex"})
LOGGING_SINKS = frozenset(
    {
        "basicConfig",
        "fileConfig",
        "dictConfig",
        "FileIO",
        "FileHandler",
        "WatchedFileHandler",
        "RotatingFileHandler",
        "TimedRotatingFileHandler",
        "SocketHandler",
        "DatagramHandler",
        "SMTPHandler",
        "HTTPHandler",
        "SysLogHandler",
        "NTEventLogHandler",
    }
)

# ---------------------------------------------------------------------------------------------------
# (3) Executor-only names: name -> {file: reason}. Identifiers, attributes, definitions, imports AND
# exact string constants (so getattr(x, "perform") is caught) are checked.
# ---------------------------------------------------------------------------------------------------
RESTRICTED_NAMES: dict[str, dict[str, str]] = {
    "perform": {"executor.py": "the only caller of Action.perform", "actions.py": "defines it"},
    "_execute": {"actions.py": "defines and dispatches the guarded hook"},
    "need": {"actions.py": "Backends.need: backend lookup used only by Action._execute"},
    "bind_executor_token": {
        "executor.py": "binds the single token",
        "actions.py": "re-export",
        "guard.py": "defines it",
    },
    "ExecutionToken": {
        "executor.py": "issues the token",
        "actions.py": "re-export",
        "guard.py": "defines it",
    },
    "token_is_valid": {"guard.py": "defines it", "actions.py": "checks it in perform()"},
    "_bound_token": {"guard.py": "defines the bound token"},
    "_TOKEN": {"executor.py": "the single valid ExecutionToken instance"},
    "_executing": {"guard.py": "the context variable behind in_executor()"},
    "executing": {
        "guard.py": "defines the marker context manager",
        "actions.py": "Action.perform marks the execution window",
    },
    "in_executor": {
        "guard.py": "defines it",
        "actions.py": "re-export",
        "models/gateway.py": "the ModelGateway tripwire",
    },
    "call_tool": {
        "tools.py": "McpClient protocol and HttpMcpClient",
        "actions.py": "McpCall._execute, the only caller",
    },
    "call": {
        "tools.py": "ToolRegistry.call definition",
        "actions.py": "ToolCall._execute, the only caller",
    },
    "complete": {
        "models/gateway.py": "ModelGateway.complete (guarded)",
        "actions.py": "ModelCall._execute, the only caller",
    },
    "stream": {
        "models/gateway.py": "ModelGateway.stream and its transport call",
        "models/adapters/base.py": "Transport.stream definition/impl",
    },
    "_complete": {"models/gateway.py": "implementation behind the guard"},
    "_stream": {"models/gateway.py": "implementation behind the guard"},
    "unguarded_for_tests": {"models/gateway.py": "defines the test-only seam"},
    "UnguardedModelGateway": {
        "models/gateway.py": "defines the test-only seam",
        "models/__init__.py": "re-export",
    },
}
# Generic words: restricted only as attribute accesses / method definitions (``x.call(...)``), because
# ``call``/``stream`` are also ordinary local variable and parameter names in the adapters.
MEMBER_ONLY_NAMES = frozenset({"call", "complete", "stream", "need"})
# Constructing a ModelGateway is deployment wiring, not something agent-runtime code may do.
GATEWAY_CONSTRUCTION_FILES: dict[str, str] = {}  # nothing in src builds one; wiring lives outside


@dataclass(frozen=True)
class Finding:
    rule: str
    line: int
    detail: str

    def render(self, rel: str) -> str:
        return f"{rel}:{self.line}: [{self.rule}] {self.detail}"


# ---------------------------------------------------------------------------------------------------
# Implementation
# ---------------------------------------------------------------------------------------------------


def _is_module(dotted: str) -> bool:
    try:
        return importlib.util.find_spec(dotted) is not None
    except (ImportError, ValueError, AttributeError):
        return False


def _aliases(tree: ast.AST) -> dict[str, str]:
    """Local name -> fully qualified dotted name, from import statements."""
    out: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                out[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            for a in node.names:
                out[a.asname or a.name] = f"{node.module}.{a.name}"
    return out


def _qualified(node: ast.AST, aliases: dict[str, str]) -> str | None:
    """Resolve ``a.b.c`` through import aliases; None if the base is not a plain name."""
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if not isinstance(cur, ast.Name):
        return None
    parts.append(aliases.get(cur.id, cur.id))
    return ".".join(reversed(parts))


def imported_modules(tree: ast.AST) -> list[tuple[str, int]]:
    """(dotted module, line) for every import; ``from m import n`` yields ``m.n`` when it is a
    module and ``m`` otherwise, ``*`` imports yield ``m.*`` (never safe)."""
    found: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found += [(a.name, node.lineno) for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            for a in node.names:
                full = f"{node.module}.{a.name}"
                found.append(
                    (full if a.name != "*" and _is_module(full) else node.module, node.lineno)
                )
                if a.name == "*":
                    found.append((f"{node.module}.*", node.lineno))
    return found


def _import_safe(module: str) -> bool:
    return module in SAFE_IMPORTS or any(
        module == p or module.startswith(p + ".") for p in SAFE_PREFIXES
    )


def _io_allowed(rel: str, module: str) -> bool:
    return any(module == m or module.startswith(m + ".") for m in IO_IMPORTS.get(rel, {}))


def _open_mode_violation(call: ast.Call, *, attribute: bool) -> bool:
    """True if ``open``/``.open`` may open for writing (or the mode cannot be proven read-only)."""
    candidates: list[ast.expr] = [kw.value for kw in call.keywords if kw.arg in {"mode", "opener"}]
    if any(kw.arg == "opener" for kw in call.keywords):
        return True
    # builtin open(file, mode): mode is positional 1.  Path.open(mode): positional 0 (and some
    # look-alikes such as io.open(file, mode) use 1), so for attribute calls check both.
    positions = (0, 1) if attribute else (1,)
    candidates += [call.args[i] for i in positions if i < len(call.args)]
    for c in candidates:
        if not (isinstance(c, ast.Constant) and isinstance(c.value, str | int | type(None))):
            return True  # dynamic mode: cannot prove read-only
        if isinstance(c.value, str) and set(c.value) & set("wax+"):
            return True
    return False


def _root_module(q: str | None) -> str | None:
    return q.split(".")[0] if q else None


def _member_problem(q: str) -> str | None:
    """Why ``module.member`` (alias-resolved) may not be reached, or None."""
    parts = q.split(".")
    if len(parts) < 2 or parts[0] not in MEMBER_ALLOW:
        return None
    mod, member = parts[0], parts[1]
    if mod == "typing":
        return f"{q} (typing re-export)" if member in TYPING_DENIED_MEMBERS else None
    return None if member in MEMBER_ALLOW[mod] else f"{q} is not a listed {mod} member"


def _str_names(value: str) -> list[str]:
    return [seg for seg in value.split(".") if seg]


def _name_problem(name: str) -> str | None:
    """Rule id if a string used as an attribute name is introspective / dangerous."""
    if name in BANNED_ATTR_NAMES or name == "compile":
        return "dynamic-exec"
    if name in INTROSPECTION_ATTRS or name in DANGEROUS_MODULE_NAMES:
        return "introspection"
    return None


def _string_name_findings(node: ast.AST) -> list[tuple[str, str]]:
    """(rule, detail) for string constants used as attribute names or subscript keys."""
    found: list[tuple[str, str]] = []
    consts: list[ast.expr] = []
    if isinstance(node, ast.Call):
        fn = node.func
        fname = (
            fn.id if isinstance(fn, ast.Name) else fn.attr if isinstance(fn, ast.Attribute) else ""
        )
        if fname in ATTR_NAME_FUNCS:
            skip = 1 if fname in BANNED_DYNAMIC_ATTR_FUNCS | {"hasattr"} else 0
            consts = list(node.args[skip:])
    elif isinstance(node, ast.Subscript):
        consts = [node.slice]
    for c in consts:
        if isinstance(c, ast.Constant) and isinstance(c.value, str):
            for seg in _str_names(c.value):
                rule = _name_problem(seg)
                if rule:
                    found.append((rule, f"string attribute name {seg!r}"))
    return found


def raw_findings(rel: str, source: str) -> list[Finding]:
    """Every finding for one module BEFORE exemptions are applied."""
    tree = ast.parse(source)
    aliases = _aliases(tree)
    out: list[Finding] = []

    def add(rule: str, node: ast.AST, detail: str) -> None:
        out.append(Finding(rule, getattr(node, "lineno", 0), detail))

    for module, line in imported_modules(tree):
        if not _import_safe(module):
            out.append(Finding(f"import:{module}", line, f"imports {module}"))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            for a in node.names:
                q = f"{node.module}.{a.name}"
                if q in BANNED_QUALIFIED or q.startswith(BANNED_QUALIFIED_PREFIXES):
                    add("banned-qualified", node, f"imports {q}")
                if node.module == "os" and a.name in OS_FILE_WRITE:
                    add("file-write", node, f"imports os.{a.name}")
                if node.module.split(".")[0] in MEMBER_ALLOW:
                    if a.name in DANGEROUS_MODULE_NAMES:
                        add("transitive-module", node, f"imports {q}")
                    problem = _member_problem(q)
                    if problem:
                        add("unlisted-member", node, f"imports {problem}")
                if a.name in LOGGING_SINKS:
                    add("logging-sink", node, f"imports {q}")
                if a.name in BANNED_ATTR_NAMES:
                    add("dynamic-exec", node, f"imports {q}")
        if isinstance(node, ast.Name):
            if node.id in BANNED_NAMES:
                add("dynamic-exec", node, f"uses {node.id}")
            if node.id in INTROSPECTION_ATTRS:
                add("introspection", node, f"uses {node.id}")
        if isinstance(node, ast.Attribute):
            attr = node.attr
            q = _qualified(node, aliases)
            if attr in INTROSPECTION_ATTRS:
                add("introspection", node, f"uses .{attr}")
            if attr in BANNED_ATTR_NAMES or (attr == "compile" and q != "re.compile"):
                add("dynamic-exec", node, f"uses .{attr}")
            if attr in DANGEROUS_MODULE_NAMES and (
                attr != "signal" or _root_module(q) in MEMBER_ALLOW
            ):
                add("transitive-module", node, f"reaches .{attr} through an attribute chain")
            if q and (problem := _member_problem(q)):
                add("unlisted-member", node, f"uses {problem}")
            if attr in THREAD_ESCAPE_ATTRS:
                add("thread-escape", node, f"uses .{attr}")
            if q and (q in BANNED_QUALIFIED or q.startswith(BANNED_QUALIFIED_PREFIXES)):
                add("banned-qualified", node, f"uses {q}")
            if PROCESS_ATTR.match(attr):
                add("process", node, f"uses .{attr}")
            if attr in NET_ATTRS:
                add("net", node, f"uses .{attr}")
            if attr in DNS_ATTRS:
                add("dns", node, f"uses .{attr}")
            if attr in LOGGING_SINKS:
                add("logging-sink", node, f"uses .{attr}")
            if attr in PATH_FILE_WRITE_ATTRS:
                add("file-write", node, f"uses .{attr}")
            if q and q.startswith("os.") and q.split(".")[1] in OS_FILE_WRITE:
                add("file-write", node, f"uses {q}")
        for rule, detail in _string_name_findings(node):
            add(rule, node, detail)
        if isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Name) and fn.id in BANNED_DYNAMIC_ATTR_FUNCS:
                name_arg = node.args[1] if len(node.args) > 1 else None
                if not (isinstance(name_arg, ast.Constant) and isinstance(name_arg.value, str)):
                    add("dynamic-attr", node, f"{fn.id}() with a non-literal attribute name")
            if isinstance(fn, ast.Name) and fn.id == "open":
                if _open_mode_violation(node, attribute=False):
                    add("file-write", node, "open() for writing or with an unprovable mode")
            if isinstance(fn, ast.Name) and fn.id in LOGGING_SINKS:
                add("logging-sink", node, f"uses {fn.id}")
            if isinstance(fn, ast.Name) and PROCESS_ATTR.match(fn.id):
                add("process", node, f"uses {fn.id}")
            if isinstance(fn, ast.Name) and fn.id in NET_ATTRS:
                add("net", node, f"uses {fn.id}")
            if isinstance(fn, ast.Name) and fn.id in DNS_ATTRS:
                add("dns", node, f"uses {fn.id}")
            if isinstance(fn, ast.Attribute):
                if fn.attr == "open" and _open_mode_violation(node, attribute=True):
                    add("file-write", node, ".open() for writing or with an unprovable mode")
                if (
                    fn.attr == "replace"
                    and len(node.args) == 1
                    and not node.keywords
                    and (_qualified(fn.value, aliases) or "") not in {"dataclasses"}
                ):
                    add("file-write", node, "single-argument .replace() (Path.replace/os.replace)")
            name = fn.id if isinstance(fn, ast.Name) else ""
            if name == "ModelGateway" or (
                isinstance(fn, ast.Attribute) and fn.attr == "ModelGateway"
            ):
                add("gateway-construction", node, "constructs ModelGateway")
    out += _restricted_uses(tree)
    return out


def _restricted_uses(tree: ast.AST) -> list[Finding]:
    found: list[Finding] = []
    for node in ast.walk(tree):
        names: list[str] = []
        if isinstance(node, ast.Attribute):
            names.append(node.attr)
        elif isinstance(node, ast.Name):
            names.append(node.id)
        elif isinstance(node, ast.alias):
            names += [node.name.split(".")[-1], node.asname or ""]
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.append(node.name)
        elif isinstance(node, ast.arg):
            names.append(node.arg)
        elif isinstance(node, ast.keyword) and node.arg:
            names.append(node.arg)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            names.append(node.value)  # getattr(x, "perform"), vars(A)["perform"], ...
        is_member = isinstance(
            node, (ast.Attribute, ast.FunctionDef, ast.AsyncFunctionDef)
        )  # a method definition or attribute access (not a local variable that shares the name)
        for n in names:
            if n in MEMBER_ONLY_NAMES and not is_member:
                continue
            if n in RESTRICTED_NAMES:
                found.append(Finding(f"restricted:{n}", getattr(node, "lineno", 0), f"uses {n!r}"))
    return found


def scan_source(rel: str, source: str) -> list[str]:
    """Human-readable violations for one module (empty = clean). Generated stubs are skipped."""
    if rel.startswith(GENERATED_PREFIX):
        return []
    problems: list[str] = []
    for f in raw_findings(rel, source):
        if f.rule.startswith("import:"):
            if _io_allowed(rel, f.rule.removeprefix("import:")):
                continue
        elif f.rule.startswith("restricted:"):
            if rel in RESTRICTED_NAMES[f.rule.removeprefix("restricted:")]:
                continue
        elif f.rule == "gateway-construction":
            if rel in GATEWAY_CONSTRUCTION_FILES:
                continue
        elif rel in EXEMPTIONS.get(f.rule, {}):
            continue
        problems.append(f.render(rel))
    return problems


def package_modules(src: Path) -> list[tuple[str, str]]:
    return [(str(p.relative_to(src)), p.read_text()) for p in sorted(src.rglob("*.py"))]
