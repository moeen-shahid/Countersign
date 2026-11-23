"""A small MCP server over stdio, written by hand on the standard library.

MCP (Model Context Protocol) is how an agent host such as Claude Code talks to
a tool server: newline-delimited JSON-RPC 2.0 in UTF-8, one message per line,
requests on stdin and answers on stdout. Nothing but JSON-RPC ever goes to
stdout; everything for a person (start-up note, tracebacks) goes to the log
stream, which is stderr by default.

The server offers exactly the tools of the `ToolSurface` it is given and
nothing else: no resources, no prompts, no sampling. It answers `initialize`,
`ping`, `tools/list` and `tools/call`.

Protocol versions: 2025-11-25, 2025-06-18, 2025-03-26 and 2024-11-05. The
client's version is echoed when it is one of these; otherwise the newest is
offered and the client decides whether to go on. What differs by version:

* `structuredContent` in tool results and `title` on tools: 2025-06-18 on.
* tool `annotations` (read-only hint): 2025-03-26 on.
* JSON-RPC batches: 2025-03-26 only (added there, removed in 2025-06-18).

Errors follow the specification: a tool that does not exist and malformed
`tools/call` parameters are protocol errors (-32602); arguments that do not
fit a tool's schema come back as a normal result with `isError` true, so the
model can read the message and correct itself.

The 2026-07-28 revision of MCP drops the handshake: every request carries
its own version, and a new `server/discover` request replaces `initialize`.
This server does not speak that revision. A client that supports both probes
with `server/discover` first, gets "method not found" here, and falls back to
`initialize`, which is the fallback that revision describes for stdio. A
client that speaks only 2026-07-28 will not be able to use this server; its
requests are refused, never run without a handshake.

Requests are handled one at a time, in order. A tool that waits therefore
holds up later requests, including `ping`, until it returns.

`handle` is a pure function of one decoded message plus the session state, so
it can be tested without any streams. `serve` adds the line framing.

The command `countersign mcp --db PATH --inbox DIR` serves the agent's five
tools over an existing database. It opens the agent's side of the store only,
never creates a database, and writes one line per tool call to stderr.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import sys
import traceback
from datetime import datetime, timezone
from typing import Any, BinaryIO, Callable, TextIO

from . import __version__
from .store import StoreError, audit_head, open_agent
from .toolsurface import DictInbox, DirInbox, ToolResult, ToolSpec, ToolSurface, UnknownTool
from .toolsurface import build_surface

SUPPORTED_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
LATEST_VERSION = SUPPORTED_VERSIONS[0]
_WITH_STRUCTURED_CONTENT = frozenset({"2025-11-25", "2025-06-18"})
_WITH_ANNOTATIONS = frozenset({"2025-11-25", "2025-06-18", "2025-03-26"})
_WITH_BATCHES = frozenset({"2025-03-26"})

MAX_LINE_BYTES = 4 * 1024 * 1024  # one message; longer lines are refused unread

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

INSTRUCTIONS = (
    "Countersign is a payment guard in front of a simulated bank. Payments go through the "
    "pay tool; this server has no other way to move money. Every answer from pay (ALLOW, "
    "HOLD or BLOCK) is a final decision: do not send the same payment again with changed "
    "details. A HOLD waits for a person to countersign it. That approval happens outside "
    "this connection; this server has no tool for it."
)


class _RpcError(Exception):
    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def _is_id(value: Any) -> bool:
    """MCP request ids are strings or whole numbers, never null."""
    return isinstance(value, str) or (isinstance(value, int) and not isinstance(value, bool))


def _label(value: Any, limit: int = 60) -> str:
    """Text the peer chose, made safe to repeat in a message or a log line."""
    text = value if isinstance(value, str) else repr(value)
    cleaned = "".join(ch if ch.isascii() and ch.isprintable() else "?" for ch in text)
    return cleaned[:limit] + ("..." if len(cleaned) > limit else "")


def _no_constants(name: str) -> Any:
    raise ValueError(f"{name} is not JSON")


class McpServer:
    """One MCP session over one `ToolSurface`."""

    def __init__(
        self,
        surface: ToolSurface,
        *,
        name: str = "countersign",
        version: str = __version__,
        log: TextIO | None = None,
        instructions: str = INSTRUCTIONS,
    ) -> None:
        self._surface = surface
        self._name = name
        self._version = version
        self._log = log
        self._instructions = instructions
        self.protocol_version: str | None = None  # set by a successful initialize
        self.client_info: dict[str, Any] = {}
        self.ready = False  # the client has sent notifications/initialized

    # --- one message ------------------------------------------------------------

    def handle(self, message: Any) -> dict[str, Any] | list[dict[str, Any]] | None:
        """Answer one decoded message. None means there is nothing to send."""
        if isinstance(message, list):
            return self._handle_batch(message)
        return self._handle_one(message)

    def _handle_batch(self, batch: list[Any]) -> dict[str, Any] | list[dict[str, Any]] | None:
        if self.protocol_version not in _WITH_BATCHES:
            if self.protocol_version is None:
                why = "Batches are not accepted before initialize."
            else:
                why = f"Protocol version {self.protocol_version} has no batches."
            return _error(None, INVALID_REQUEST, f"Invalid Request. {why}")
        if not batch:
            return _error(None, INVALID_REQUEST, "Invalid Request. The batch is empty.")
        replies = [reply for reply in map(self._handle_one, batch) if reply is not None]
        return replies or None

    def _handle_one(self, message: Any) -> dict[str, Any] | None:
        if not isinstance(message, dict):
            return _error(None, INVALID_REQUEST, "Invalid Request. A message is a JSON object.")
        method = message.get("method")
        if not isinstance(method, str) and ("result" in message or "error" in message):
            return None  # an answer; this server never asks, so nothing is waiting for it
        if "id" not in message:
            if isinstance(method, str):
                self._notification(method)
                return None  # notifications are never answered, whatever they say
            return _error(None, INVALID_REQUEST, "Invalid Request. There is no method.")

        request_id = message["id"]
        if not _is_id(request_id):
            why = "The id must be text or a whole number."
            return _error(None, INVALID_REQUEST, f"Invalid Request. {why}")
        if message.get("jsonrpc") != "2.0":
            return _error(request_id, INVALID_REQUEST, 'Invalid Request. jsonrpc must be "2.0".')
        if not isinstance(method, str):
            return _error(request_id, INVALID_REQUEST, "Invalid Request. The method must be text.")
        params = message.get("params")
        if params is None:
            params = {}
        try:
            if not isinstance(params, dict):
                raise _RpcError(INVALID_PARAMS, "Invalid params. params must be an object.")
            result = self._request(method, params)
        except _RpcError as exc:
            return _error(request_id, exc.code, exc.message)
        except Exception:
            # The details stay on this side: the traceback goes to the log only.
            self._note(f"error while handling {_label(method)}:\n{traceback.format_exc()}")
            return _error(request_id, INTERNAL_ERROR, "Internal error.")
        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    def _notification(self, method: str) -> None:
        if method == "notifications/initialized" and self.protocol_version is not None:
            self.ready = True
        # Everything else (cancelled, progress, roots changed) needs no action here.

    def _request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        if method == "ping":
            return {}
        if method == "initialize":
            return self._initialize(params)
        if method not in ("tools/list", "tools/call"):
            hint = ""
            if self.protocol_version is None:
                # Likely a newer client finding out what this server speaks.
                hint = f". This server speaks MCP {LATEST_VERSION} and earlier; send initialize."
            raise _RpcError(METHOD_NOT_FOUND, f"Method not found: {_label(method)}{hint}")
        if self.protocol_version is None:
            raise _RpcError(INVALID_REQUEST, "Invalid Request. Send initialize first.")
        if method == "tools/list":
            return self._tools_list(params)
        return self._tools_call(params)

    # --- the methods ------------------------------------------------------------

    def _initialize(self, params: dict[str, Any]) -> dict[str, Any]:
        if self.protocol_version is not None:
            raise _RpcError(INVALID_REQUEST, "Invalid Request. Already initialized.")
        requested = params.get("protocolVersion")
        if not isinstance(requested, str):
            raise _RpcError(INVALID_PARAMS, "Invalid params. protocolVersion must be text.")
        agreed = requested if requested in SUPPORTED_VERSIONS else LATEST_VERSION
        client = params.get("clientInfo")
        self.client_info = client if isinstance(client, dict) else {}
        self.protocol_version = agreed
        who = " ".join(_label(self.client_info.get(key, "?")) for key in ("name", "version"))
        self._note(f"client {who}, protocol {agreed} (asked for {_label(requested)})")
        return {
            "protocolVersion": agreed,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": self._name, "version": self._version},
            "instructions": self._instructions,
        }

    def _tools_list(self, params: dict[str, Any]) -> dict[str, Any]:
        # Everything fits on one page, so no cursor was ever handed out.
        if params.get("cursor") not in (None, ""):
            raise _RpcError(INVALID_PARAMS, "Invalid params. Unknown cursor.")
        return {"tools": [self._describe(spec) for spec in self._surface.specs()]}

    def _describe(self, spec: ToolSpec) -> dict[str, Any]:
        version = self.protocol_version
        tool: dict[str, Any] = {"name": spec.name}
        if version in _WITH_STRUCTURED_CONTENT:
            tool["title"] = spec.title
        tool["description"] = spec.description
        tool["inputSchema"] = spec.input_schema
        if version in _WITH_ANNOTATIONS:
            tool["annotations"] = {"title": spec.title, "readOnlyHint": bool(spec.read_only)}
        return tool

    def _tools_call(self, params: dict[str, Any]) -> dict[str, Any]:
        name = params.get("name")
        arguments = params.get("arguments")
        if not isinstance(name, str):
            raise _RpcError(INVALID_PARAMS, "Invalid params. name must be the name of a tool.")
        if arguments is not None and not isinstance(arguments, dict):
            raise _RpcError(INVALID_PARAMS, "Invalid params. arguments must be an object.")
        try:
            result = self._surface.call(name, arguments)
        except UnknownTool:
            raise _RpcError(INVALID_PARAMS, f"Unknown tool: {_label(name)}") from None
        payload: dict[str, Any] = {
            "content": [{"type": "text", "text": result.text}],
            "isError": bool(result.is_error),
        }
        if self.protocol_version in _WITH_STRUCTURED_CONTENT:
            payload["structuredContent"] = result.data
        return payload

    # --- the stream -------------------------------------------------------------

    def serve(self, stdin: BinaryIO, stdout: BinaryIO) -> int:
        """Read messages from `stdin` until it closes; write answers to `stdout`.

        Both are binary streams. Each answer is one line, flushed at once.
        Returns 0 when the client closes the connection.
        """
        while True:
            line, too_long = _read_line(stdin)
            if line is None:
                return 0
            if too_long:
                self._note("refused a message longer than 4 MiB")
                reply: Any = _error(None, INVALID_REQUEST, "Invalid Request. Message over 4 MiB.")
            elif not line.strip():
                continue
            else:
                reply = self._handle_line(line)
            if reply is None:
                continue
            try:
                stdout.write(_encode(reply))
                stdout.flush()
            except BrokenPipeError:
                return 0  # the client stopped listening

    def _handle_line(self, line: bytes) -> Any:
        try:
            message = json.loads(line.decode("utf-8"), parse_constant=_no_constants)
        except (ValueError, RecursionError):  # includes text that is not UTF-8
            return _error(None, PARSE_ERROR, "Parse error. A message is one line of UTF-8 JSON.")
        reply = self.handle(message)
        try:
            _encode(reply)
        except (TypeError, ValueError, RecursionError):
            # A tool returned something that is not JSON. Say so without the data.
            self._note(f"an answer could not be written as JSON:\n{traceback.format_exc()}")
            request_id = message.get("id") if isinstance(message, dict) else None
            if not _is_id(request_id):
                request_id = None
            return _error(request_id, INTERNAL_ERROR, "Internal error.")
        return reply

    def _note(self, text: str) -> None:
        log = self._log if self._log is not None else sys.stderr
        try:
            log.write(f"countersign mcp: {text}\n")
            log.flush()
        except (OSError, ValueError):
            pass  # a log that cannot be written must not stop the session


def _encode(reply: Any) -> bytes:
    """One answer as one line. ASCII only, so it cannot contain a raw newline."""
    text = json.dumps(reply, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
    return text.encode("ascii") + b"\n"


def _read_line(stdin: BinaryIO) -> tuple[bytes | None, bool]:
    """The next line, or (None, False) at the end. An over-long line is skipped
    without being kept in memory and reported as (b"", True)."""
    line = stdin.readline(MAX_LINE_BYTES + 1)
    if not line:
        return None, False
    if line.endswith(b"\n") or len(line) <= MAX_LINE_BYTES:
        return line, False
    while True:
        rest = stdin.readline(64 * 1024)
        if not rest or rest.endswith(b"\n"):
            return b"", True


def serve_stdio(surface: ToolSurface, **options: Any) -> int:
    """Serve `surface` on this process's stdin and stdout until stdin closes.

    While serving, ordinary output (a stray `print`, a chatty child process)
    is sent to stderr, so only JSON-RPC reaches the client. Returns the exit
    code for the process: 0 when the client closes stdin, and also when it
    stops the server with an interrupt signal instead, as some clients do.
    `options` are passed to `McpServer` (name, version, instructions); the log
    is stderr unless one is given.
    """
    stdin = sys.stdin.buffer
    sys.stdout.flush()
    channel_fd = None
    try:
        channel_fd = os.dup(1)  # keep the real stdout for the protocol...
        os.dup2(2, 1)  # ...and point descriptor 1 at stderr for everyone else
    except OSError:
        if channel_fd is not None:
            os.close(channel_fd)
            channel_fd = None
    channel = sys.stdout.buffer if channel_fd is None else os.fdopen(channel_fd, "wb")
    try:
        with contextlib.redirect_stdout(sys.stderr):
            options.setdefault("log", sys.stderr)
            return McpServer(surface, **options).serve(stdin, channel)
    except KeyboardInterrupt:
        return 0
    finally:
        if channel_fd is not None:
            with contextlib.suppress(OSError):
                channel.flush()
                os.dup2(channel_fd, 1)
            with contextlib.suppress(OSError):
                channel.close()


# --- the command ------------------------------------------------------------------

DB_ENV = "COUNTERSIGN_DB"


def config_block(db: str, inbox: str | None = None) -> dict[str, Any]:
    """The entry an MCP client needs to start this server, with absolute paths."""
    args = ["-m", "countersign", "mcp", "--db", os.path.abspath(db)]
    if inbox:
        args += ["--inbox", os.path.abspath(inbox)]
    return {"mcpServers": {"countersign": {"command": sys.executable, "args": args}}}


class LoggedSurface:
    """A tool surface that writes one line per call to a log: the time, the
    tool, what came back (for pay: the outcome and the rule) and the audit
    head afterwards. Document names and other text an agent or a sender
    chose are not written."""

    def __init__(
        self,
        surface: ToolSurface,
        head: Callable[[], tuple[int, str]],
        log: TextIO,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._surface = surface
        self._head = head
        self._log = log
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def specs(self) -> list[ToolSpec]:
        return self._surface.specs()

    def call(self, name: str, arguments: dict[str, Any] | None = None) -> ToolResult:
        try:
            result = self._surface.call(name, arguments)
        except UnknownTool:
            self._line(_label(name, 40), "unknown tool")
            raise
        except Exception as exc:
            self._line(name, f"failed ({type(exc).__name__})")
            raise
        self._line(name, _summary(result))
        return result

    def _line(self, tool: str, what: str) -> None:
        try:
            seq, digest = self._head()
            head = f"{seq}:{digest[:12]}"
        except Exception:
            head = "unreadable"
        stamp = self._clock().isoformat(timespec="seconds")
        try:
            self._log.write(f"countersign mcp: {stamp} {tool} {what} head={head}\n")
            self._log.flush()
        except (OSError, ValueError):
            pass  # a log that cannot be written must not stop the session


def _summary(result: ToolResult) -> str:
    """A few fixed words about one result, for the log."""
    data = result.data
    if result.is_error:
        return f"error {_label(data.get('error', '?'), 30)}"
    if "outcome" in data:
        parts = [_label(data["outcome"], 10), _label(data.get("rule", "?"), 10)]
        if data.get("hold_id"):
            parts.append(f"hold={_label(data['hold_id'], 10)}")
        if data.get("transfer_id"):
            parts.append(f"transfer={_label(data['transfer_id'], 10)}")
        return " ".join(parts)
    if "status" in data:
        return f"status={_label(data['status'], 12)}"
    return "ok"


def _command(args: argparse.Namespace) -> int:
    db = args.db or os.environ.get(DB_ENV)
    if not db:
        print(f"countersign mcp: give the database with --db PATH or set {DB_ENV}.",
              file=sys.stderr)
        return 2
    if args.print_config:
        print(json.dumps(config_block(db, args.inbox), indent=2))
        return 0
    try:
        port = open_agent(db)
        inbox = DirInbox(args.inbox) if args.inbox else DictInbox({})
    except (StoreError, ValueError) as exc:
        print(f"countersign mcp: {exc}", file=sys.stderr)
        return 2
    surface = LoggedSurface(build_surface(port, inbox), lambda: audit_head(db), sys.stderr)
    return serve_stdio(surface)


def add_cli(subparsers: Any) -> None:
    """Register the `mcp` command (see cli.py for the convention)."""
    parser = subparsers.add_parser(
        "mcp",
        help="serve the agent's tools to an MCP client over stdio",
        description=(
            "Serve the agent's five tools (get_task, list_documents, read_document, pay, "
            "payment_status) over stdio, for an MCP client such as Claude Code. The "
            "database must exist already: create it with `countersign init` or "
            "`countersign quickstart`. One line per tool call goes to stderr."
        ),
    )
    parser.add_argument(
        "--db", metavar="PATH", help=f"the guard's database (or set {DB_ENV})"
    )
    parser.add_argument(
        "--inbox", metavar="DIR", help="a directory whose text files the agent may read"
    )
    parser.add_argument(
        "--print-config",
        action="store_true",
        help="print the JSON entry for an MCP client's configuration and exit",
    )
    parser.set_defaults(func=_command)
