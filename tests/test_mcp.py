"""The generic tool surface and the MCP server on top of it.

Run with: python3 -m unittest tests.test_mcp -v
"""

from __future__ import annotations

import ast
import contextlib
import inspect
import io
import json
import os
import signal
import subprocess
import sys
import tempfile
import textwrap
import threading
import unittest

from countersign import __version__, mcp, toolsurface
from countersign.mcp import MAX_LINE_BYTES, SUPPORTED_VERSIONS, McpServer
from countersign.toolsurface import (
    ToolResult,
    ToolSpec,
    ToolSurface,
    UnknownTool,
    check_schema,
    validate,
)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LATEST = "2025-11-25"

ECHO_SCHEMA = {
    "type": "object",
    "properties": {
        "text": {"type": "string", "maxLength": 20, "description": "What to say back."},
        "times": {"type": "integer", "minimum": 1, "maximum": 3},
    },
    "required": ["text"],
    "additionalProperties": False,
}
NO_ARGUMENTS = {"type": "object", "additionalProperties": False}


def make_surface(calls: list | None = None) -> ToolSurface:
    """A stand-in surface: one useful tool and three that misbehave."""
    calls = [] if calls is None else calls
    surface = ToolSurface()

    def echo(arguments):
        calls.append(arguments)
        return {"echo": arguments["text"] * arguments.get("times", 1)}

    def boom(arguments):
        raise RuntimeError("secret detail that must stay on the server")

    surface.register(ToolSpec("echo", "Echo", "Say the text back.", ECHO_SCHEMA, True), echo)
    surface.register(
        ToolSpec("fail", "Fail", "Always answers with an error result.", NO_ARGUMENTS),
        lambda arguments: ToolResult({"error": "not_today"}, is_error=True),
    )
    surface.register(ToolSpec("boom", "Boom", "Has a bug.", NO_ARGUMENTS), boom)
    surface.register(
        ToolSpec("not_json", "Not JSON", "Returns a value JSON cannot carry.", NO_ARGUMENTS),
        lambda arguments: {"x": float("nan")},
    )
    return surface


def request(method: str, params=None, request_id=1) -> dict:
    message = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        message["params"] = params
    return message


def call(name, arguments=None, request_id=1) -> dict:
    params = {"name": name}
    if arguments is not None:
        params["arguments"] = arguments
    return request("tools/call", params, request_id)


def make_server(version: str | None = LATEST, calls: list | None = None):
    """A server and its log. With a version, initialize has already happened."""
    log = io.StringIO()
    server = McpServer(make_surface(calls), log=log)
    if version is not None:
        reply = server.handle(request("initialize", {"protocolVersion": version}, 0))
        assert "result" in reply, reply
        assert server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    return server, log


def error_code(reply) -> int | None:
    return reply["error"]["code"] if isinstance(reply, dict) and "error" in reply else None


# --- the tool surface -----------------------------------------------------------


class ToolSurfaceTests(unittest.TestCase):
    def test_specs_keep_registration_order(self):
        self.assertEqual(
            [spec.name for spec in make_surface().specs()], ["echo", "fail", "boom", "not_json"]
        )

    def test_call_runs_the_handler_with_checked_arguments(self):
        calls = []
        surface = make_surface(calls)
        result = surface.call("echo", {"text": "hi", "times": 2})
        self.assertEqual(result, ToolResult({"echo": "hihi"}))
        self.assertFalse(result.is_error)
        self.assertEqual(calls, [{"text": "hi", "times": 2}])

    def test_dict_results_are_wrapped_and_results_pass_through(self):
        surface = make_surface()
        self.assertIsInstance(surface.call("echo", {"text": "a"}), ToolResult)
        self.assertEqual(surface.call("fail"), ToolResult({"error": "not_today"}, is_error=True))
        self.assertEqual(surface.call("fail", None).is_error, True)

    def test_unknown_tool(self):
        surface = make_surface()
        for name in ("approve", "Echo", "echo ", "", None, 5, ["echo"]):
            with self.subTest(name=name):
                with self.assertRaises(UnknownTool):
                    surface.call(name, {})

    def test_arguments_that_do_not_fit_give_an_error_result_naming_the_field(self):
        calls = []
        surface = make_surface(calls)
        cases = [
            ({}, "text: is required"),
            ({"text": 5}, "text: must be text"),
            ({"text": None}, "text: must be text"),
            ({"text": ["a"]}, "text: must be text"),
            ({"text": "x" * 21}, "text: must be at most 20 characters"),
            ({"text": "a", "times": "2"}, "times: must be a whole number"),
            ({"text": "a", "times": 2.0}, "times: must be a whole number"),
            ({"text": "a", "times": True}, "times: must be a whole number"),
            ({"text": "a", "times": 0}, "times: must be at least 1"),
            ({"text": "a", "times": 4}, "times: must be at most 3"),
            ({"text": "a", "extra": 1}, "extra: is not a field of this tool"),
            ({"text": "a", "bad\nname☃": 1}, "bad?name?: is not a field of this tool"),
            ("text", "arguments: must be an object"),
            (["text"], "arguments: must be an object"),
        ]
        for arguments, message in cases:
            with self.subTest(arguments=arguments):
                result = surface.call("echo", arguments)
                self.assertTrue(result.is_error)
                self.assertEqual(
                    result.data, {"error": "invalid_arguments", "message": message}
                )
        self.assertEqual(calls, [], "the handler never saw a bad call")

    def test_limits_are_inclusive(self):
        surface = make_surface()
        self.assertFalse(surface.call("echo", {"text": "x" * 20, "times": 3}).is_error)
        self.assertFalse(surface.call("echo", {"text": "", "times": 1}).is_error)

    def test_the_handler_gets_its_own_copy_of_the_arguments(self):
        surface = ToolSurface()
        surface.register(
            ToolSpec("keep", "Keep", "Changes its arguments.", {"type": "object"}),
            lambda arguments: arguments.update(seen=True) or {"ok": True},
        )
        mine = {"anything": "goes"}  # no additionalProperties: false, so extras pass
        self.assertEqual(surface.call("keep", mine).data, {"ok": True})
        self.assertEqual(mine, {"anything": "goes"})

    def test_a_handler_that_raises_or_returns_junk_is_left_to_the_caller(self):
        surface = make_surface()
        with self.assertRaises(RuntimeError):
            surface.call("boom", {})
        surface.register(ToolSpec("junk", "Junk", "Returns text.", NO_ARGUMENTS), lambda a: "text")
        with self.assertRaises(TypeError):
            surface.call("junk", {})

    def test_result_text_is_compact_sorted_ascii_json(self):
        result = ToolResult({"b": 1, "a": "café\n☃", "c": [True, None]})
        self.assertEqual(result.text, '{"a":"caf\\u00e9\\n\\u2603","b":1,"c":[true,null]}')
        self.assertTrue(result.text.isascii())
        self.assertEqual(json.loads(result.text), result.data)
        self.assertFalse(result.is_error)
        with self.assertRaises(ValueError):
            ToolResult({"x": float("inf")}).text

    def test_register_refuses_bad_names_duplicates_and_handlers(self):
        surface = make_surface()
        for name in ("", "has space", "a,b", "x" * 129, "café", None, "new\nline"):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    surface.register(ToolSpec(name, "T", "D", NO_ARGUMENTS), lambda a: {})
        with self.assertRaises(ValueError):
            surface.register(ToolSpec("echo", "T", "D", NO_ARGUMENTS), lambda a: {})
        with self.assertRaises(ValueError):
            surface.register(ToolSpec("fresh", "T", "D", NO_ARGUMENTS), "not callable")
        for name in ("a", "get_task", "admin.tools-list", "X" * 128):
            surface.register(ToolSpec(name, "T", "D", NO_ARGUMENTS), lambda a: {})

    def test_register_refuses_schemas_the_validator_cannot_enforce(self):
        bad = [
            None,
            {},
            {"type": "string"},
            {"type": "object", "properties": []},
            {"type": "object", "properties": {"a": {"type": "number"}}},
            {"type": "object", "properties": {"a": {"type": "array"}}},
            {"type": "object", "properties": {"a": {}}},
            {"type": "object", "properties": {"a": "string"}},
            {"type": "object", "properties": {"a": {"type": "string", "pattern": "^x"}}},
            {"type": "object", "properties": {"a": {"type": "string", "minimum": 1}}},
            {"type": "object", "properties": {"a": {"type": "integer", "maxLength": 1}}},
            {"type": "object", "properties": {"a": {"type": "string", "maxLength": "9"}}},
            {"type": "object", "properties": {"a": {"type": "integer", "minimum": 0.5}}},
            {"type": "object", "properties": {"a": {"type": "string"}}, "required": ["b"]},
            {"type": "object", "required": "a"},
            {"type": "object", "additionalProperties": {"type": "string"}},
            {"type": "object", "oneOf": []},
        ]
        for schema in bad:
            with self.subTest(schema=schema):
                with self.assertRaises(ValueError):
                    check_schema(schema)
                with self.assertRaises(ValueError):
                    ToolSurface().register(ToolSpec("t", "T", "D", schema), lambda a: {})
        check_schema(ECHO_SCHEMA)
        check_schema(NO_ARGUMENTS)
        check_schema({"type": "object"})

    def test_validate_returns_none_when_arguments_fit(self):
        self.assertIsNone(validate(ECHO_SCHEMA, {"text": "a"}))
        self.assertIsNone(validate(NO_ARGUMENTS, {}))
        self.assertEqual(validate(NO_ARGUMENTS, {"x": 1}), "x: is not a field of this tool")


class BoundaryTests(unittest.TestCase):
    """The agent-facing modules stay generic and free of the human side."""

    def package_imports(self, module) -> set[str]:
        found = set()
        for node in ast.walk(ast.parse(inspect.getsource(module))):
            if isinstance(node, ast.ImportFrom) and node.level:
                base = node.module or ""
                found.update(f"{base}.{alias.name}".lstrip(".") for alias in node.names)
            elif isinstance(node, ast.Import):
                found.update(a.name for a in node.names if a.name.startswith("countersign"))
        return found

    def test_toolsurface_imports_nothing_from_the_package(self):
        self.assertEqual(self.package_imports(toolsurface), set())

    def test_mcp_imports_only_the_surface_and_the_agent_side_of_the_store(self):
        self.assertEqual(
            self.package_imports(mcp),
            {"__version__", "toolsurface.ToolSpec", "toolsurface.ToolSurface",
             "toolsurface.UnknownTool", "toolsurface.ToolResult", "toolsurface.DictInbox",
             "toolsurface.DirInbox", "toolsurface.build_surface",
             "store.StoreError", "store.audit_head", "store.open_agent"},
        )

    def test_neither_mentions_the_human_side(self):
        for module in (toolsurface, mcp):
            source = inspect.getsource(module)
            for word in ("approve", "reject", "start_task", "Console"):
                with self.subTest(module=module.__name__, word=word):
                    self.assertNotIn(word, source)

    def test_the_mcp_command_is_registered(self):
        self.assertTrue(callable(mcp.add_cli))
        self.assertTrue(callable(mcp.serve_stdio))


# --- handle(): one message at a time --------------------------------------------


class LifecycleTests(unittest.TestCase):
    def test_initialize_answer(self):
        server, log = make_server(None)
        params = {
            "protocolVersion": LATEST,
            "capabilities": {"roots": {"listChanged": True}},
            "clientInfo": {"name": "test-client", "version": "9.9"},
        }
        reply = server.handle(request("initialize", params, "init-1"))
        self.assertEqual(reply["jsonrpc"], "2.0")
        self.assertEqual(reply["id"], "init-1")
        result = reply["result"]
        self.assertEqual(
            sorted(result), ["capabilities", "instructions", "protocolVersion", "serverInfo"]
        )
        self.assertEqual(result["protocolVersion"], LATEST)
        self.assertEqual(result["capabilities"], {"tools": {"listChanged": False}})
        self.assertEqual(result["serverInfo"], {"name": "countersign", "version": __version__})
        self.assertEqual(server.protocol_version, LATEST)
        self.assertEqual(server.client_info, {"name": "test-client", "version": "9.9"})
        self.assertIn("client test-client 9.9, protocol 2025-11-25", log.getvalue())

    def test_instructions_say_what_the_task_asks(self):
        server, _ = make_server(None)
        text = server.handle(request("initialize", {"protocolVersion": LATEST}))["result"][
            "instructions"
        ]
        self.assertIn("pay tool", text)
        self.assertIn("final decision", text)
        self.assertIn("approval happens outside this connection", text)
        self.assertIn("no tool for it", text)
        self.assertLess(len(text), 600)

    def test_name_version_and_instructions_can_be_set(self):
        server = McpServer(
            make_surface(), name="demo", version="1.2.3", log=io.StringIO(), instructions="Hi."
        )
        result = server.handle(request("initialize", {"protocolVersion": LATEST}))["result"]
        self.assertEqual(result["serverInfo"], {"name": "demo", "version": "1.2.3"})
        self.assertEqual(result["instructions"], "Hi.")

    def test_initialize_without_a_usable_version(self):
        for params in ({}, {"protocolVersion": None}, {"protocolVersion": 20251125}, None):
            with self.subTest(params=params):
                server, _ = make_server(None)
                self.assertEqual(error_code(server.handle(request("initialize", params))), -32602)
                self.assertIsNone(server.protocol_version)

    def test_a_second_initialize_is_refused_and_changes_nothing(self):
        server, _ = make_server(LATEST)
        reply = server.handle(request("initialize", {"protocolVersion": "2025-03-26"}, 5))
        self.assertEqual((reply["id"], error_code(reply)), (5, -32600))
        self.assertEqual(server.protocol_version, LATEST)

    def test_requests_before_initialize_are_refused(self):
        calls = []
        server, _ = make_server(None, calls)
        for message in (request("tools/list"), call("echo", {"text": "hi"})):
            with self.subTest(method=message["method"]):
                reply = server.handle(message)
                self.assertEqual((reply["id"], error_code(reply)), (1, -32600))
                self.assertIn("initialize first", reply["error"]["message"])
        for method in ("resources/list", "no/such/method", "server/discover"):
            with self.subTest(method=method):
                reply = server.handle(request(method))
                self.assertEqual((reply["id"], error_code(reply)), (1, -32601))
                self.assertIn("send initialize", reply["error"]["message"])
        self.assertEqual(calls, [])
        self.assertIsNone(server.protocol_version)

    def test_a_client_that_also_speaks_2026_07_28_falls_back_to_initialize(self):
        """Such a client probes with server/discover. Any error that is not one
        of that revision's own (such as -32022, unsupported version) tells it
        to use initialize."""
        calls = []
        server, _ = make_server(None, calls)
        modern = {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {},
        }
        probe = server.handle(request("server/discover", {"_meta": modern}, 0))
        self.assertEqual(error_code(probe), -32601)
        self.assertIn("2025-11-25 and earlier", probe["error"]["message"])
        self.assertNotIn("data", probe["error"])
        self.assertIsNone(server.protocol_version, "the probe changes nothing")
        # A request sent without the handshake, the 2026-07-28 way, is never run.
        params = {"name": "echo", "arguments": {"text": "hi"}, "_meta": modern}
        direct = server.handle(request("tools/call", params, 1))
        self.assertEqual(error_code(direct), -32600)
        self.assertEqual(calls, [])
        # The fallback then works as usual.
        reply = server.handle(request("initialize", {"protocolVersion": "2025-11-25"}, 2))
        self.assertEqual(reply["result"]["protocolVersion"], "2025-11-25")
        self.assertIn("result", server.handle(request("tools/call", params, 3)))
        self.assertEqual(error_code(server.handle(request("server/discover", {}, 4))), -32601)

    def test_ping_works_before_and_after_initialize(self):
        server, _ = make_server(None)
        self.assertEqual(
            server.handle(request("ping", request_id="123")),
            {"jsonrpc": "2.0", "id": "123", "result": {}},
        )
        server, _ = make_server(LATEST)
        self.assertEqual(server.handle(request("ping", {}, 7))["result"], {})

    def test_requests_are_served_once_initialize_is_answered(self):
        # A client that asks straight after initialize is served; only requests
        # before initialize are turned away.
        server, _ = make_server(None)
        server.handle(request("initialize", {"protocolVersion": LATEST}))
        self.assertFalse(server.ready)
        self.assertIn("result", server.handle(request("tools/list")))

    def test_initialized_notification(self):
        server, _ = make_server(None)
        note = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        self.assertIsNone(server.handle(note))
        self.assertFalse(server.ready, "it means nothing before initialize")
        server.handle(request("initialize", {"protocolVersion": LATEST}))
        self.assertIsNone(server.handle(note))
        self.assertTrue(server.ready)


class NegotiationTests(unittest.TestCase):
    def test_supported_versions_in_order_newest_first(self):
        self.assertEqual(
            SUPPORTED_VERSIONS, ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
        )

    def test_a_supported_version_is_echoed(self):
        for version in SUPPORTED_VERSIONS:
            with self.subTest(version=version):
                server, _ = make_server(None)
                reply = server.handle(request("initialize", {"protocolVersion": version}))
                self.assertEqual(reply["result"]["protocolVersion"], version)
                self.assertEqual(server.protocol_version, version)

    def test_anything_else_gets_our_newest(self):
        others = (
            "2026-07-28",  # newer than we speak
            "2026-12-31",
            "2024-10-07",  # older than we know
            "2025-11-26",
            "1.0.0",
            "",
            "latest",
            "2025-11-25 ",
            "DRAFT-2026-v1",
        )
        for version in others:
            with self.subTest(version=version):
                server, _ = make_server(None)
                reply = server.handle(request("initialize", {"protocolVersion": version}))
                self.assertEqual(reply["result"]["protocolVersion"], LATEST)
                self.assertEqual(server.protocol_version, LATEST)

    def test_what_each_version_gets(self):
        #            version       structured  title  annotations  batches
        matrix = [
            ("2025-11-25", True, True, True, False),
            ("2025-06-18", True, True, True, False),
            ("2025-03-26", False, False, True, True),
            ("2024-11-05", False, False, False, False),
        ]
        self.assertEqual([row[0] for row in matrix], list(SUPPORTED_VERSIONS))
        for version, structured, title, annotations, batches in matrix:
            with self.subTest(version=version):
                server, _ = make_server(version)
                tool = server.handle(request("tools/list"))["result"]["tools"][0]
                self.assertEqual("title" in tool, title)
                self.assertEqual("annotations" in tool, annotations)
                self.assertEqual(
                    {"name", "description", "inputSchema"} - set(tool), set(), "always there"
                )
                result = server.handle(call("echo", {"text": "hi"}))["result"]
                self.assertEqual("structuredContent" in result, structured)
                self.assertEqual(result["content"], [{"type": "text", "text": '{"echo":"hi"}'}])
                self.assertIs(result["isError"], False)
                reply = server.handle([request("ping", request_id=1)])
                self.assertEqual(isinstance(reply, list), batches)


class ToolsListTests(unittest.TestCase):
    def test_tools_are_listed_as_registered(self):
        server, _ = make_server(LATEST)
        reply = server.handle(request("tools/list", request_id=2))
        self.assertEqual(sorted(reply["result"]), ["tools"])  # one page: no nextCursor
        tools = reply["result"]["tools"]
        self.assertEqual([t["name"] for t in tools], ["echo", "fail", "boom", "not_json"])
        self.assertEqual(
            tools[0],
            {
                "name": "echo",
                "title": "Echo",
                "description": "Say the text back.",
                "inputSchema": ECHO_SCHEMA,
                "annotations": {"title": "Echo", "readOnlyHint": True},
            },
        )
        self.assertIs(tools[1]["annotations"]["readOnlyHint"], False)
        self.assertEqual(tools[1]["inputSchema"], {"type": "object", "additionalProperties": False})

    def test_no_cursor_or_an_empty_one_is_the_first_page(self):
        server, _ = make_server(LATEST)
        for params in (None, {}, {"cursor": None}, {"cursor": ""}, {"_meta": {"x": 1}}):
            with self.subTest(params=params):
                tools = server.handle(request("tools/list", params))["result"]["tools"]
                self.assertEqual(len(tools), 4)

    def test_any_other_cursor_is_refused(self):
        server, _ = make_server(LATEST)
        for cursor in ("abc", "0", " ", 5, 0, False, ["x"], {"page": 2}):
            with self.subTest(cursor=cursor):
                reply = server.handle(request("tools/list", {"cursor": cursor}))
                self.assertEqual(error_code(reply), -32602)


class ToolsCallTests(unittest.TestCase):
    def test_a_good_call(self):
        calls = []
        server, _ = make_server(LATEST, calls)
        reply = server.handle(call("echo", {"text": "café ", "times": 2}, "c-1"))
        self.assertEqual(
            reply,
            {
                "jsonrpc": "2.0",
                "id": "c-1",
                "result": {
                    "content": [{"type": "text", "text": '{"echo":"caf\\u00e9 caf\\u00e9 "}'}],
                    "isError": False,
                    "structuredContent": {"echo": "café café "},
                },
            },
        )
        self.assertEqual(calls, [{"text": "café ", "times": 2}])

    def test_arguments_may_be_left_out_for_a_tool_that_takes_none(self):
        server, _ = make_server(LATEST)
        for message in (call("fail"), request("tools/call", {"name": "fail", "arguments": None})):
            result = server.handle(message)["result"]
            self.assertIs(result["isError"], True)
            self.assertEqual(result["structuredContent"], {"error": "not_today"})

    def test_extra_request_fields_are_ignored(self):
        server, _ = make_server(LATEST)
        params = {"name": "echo", "arguments": {"text": "a"}, "_meta": {"progressToken": 1}}
        self.assertIn("result", server.handle(request("tools/call", params)))

    def test_arguments_that_do_not_fit_are_a_result_not_a_protocol_error(self):
        calls = []
        server, _ = make_server(LATEST, calls)
        for arguments in ({}, {"text": 5}, {"text": "a", "times": 9}, {"text": "a", "more": 1}):
            with self.subTest(arguments=arguments):
                reply = server.handle(call("echo", arguments))
                self.assertNotIn("error", reply)
                result = reply["result"]
                self.assertIs(result["isError"], True)
                data = json.loads(result["content"][0]["text"])
                self.assertEqual(data["error"], "invalid_arguments")
                self.assertRegex(data["message"], r"^(text|times|more): ")
                self.assertEqual(result["structuredContent"], data)
        self.assertEqual(calls, [])

    def test_unknown_tool_is_a_protocol_error(self):
        server, _ = make_server(LATEST)
        for name in ("approve", "reject", "start_task", "observe", "ECHO", ""):
            with self.subTest(name=name):
                reply = server.handle(call(name, {"hold_id": "H001"}, 9))
                self.assertEqual((reply["id"], error_code(reply)), (9, -32602))
                self.assertEqual(reply["error"]["message"], f"Unknown tool: {name}")
                self.assertNotIn("result", reply)

    def test_an_unknown_tool_name_is_cleaned_before_it_is_repeated(self):
        server, _ = make_server(LATEST)
        reply = server.handle(call("x\n☃" + "y" * 100))
        self.assertEqual(reply["error"]["message"], "Unknown tool: x??" + "y" * 57 + "...")

    def test_malformed_call_parameters_are_protocol_errors(self):
        calls = []
        server, _ = make_server(LATEST, calls)
        bad = [
            None,
            {},
            {"arguments": {"text": "a"}},
            {"name": None, "arguments": {"text": "a"}},
            {"name": 5},
            {"name": ["echo"]},
            {"name": "echo", "arguments": "text"},
            {"name": "echo", "arguments": ["a"]},
            {"name": "echo", "arguments": 5},
            ["echo", {"text": "a"}],
            "echo",
        ]
        for params in bad:
            with self.subTest(params=params):
                message = {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": params}
                reply = server.handle(message)
                self.assertEqual((reply["id"], error_code(reply)), (3, -32602))
        self.assertEqual(calls, [])

    def test_a_bug_in_a_handler_is_an_internal_error_with_the_details_in_the_log_only(self):
        server, log = make_server(LATEST)
        reply = server.handle(call("boom", {}, 4))
        self.assertEqual(reply["id"], 4)
        self.assertEqual(reply["error"], {"code": -32603, "message": "Internal error."})
        self.assertNotIn("secret", json.dumps(reply))
        logged = log.getvalue()
        self.assertIn("Traceback (most recent call last)", logged)
        self.assertIn("RuntimeError: secret detail that must stay on the server", logged)
        # The session goes on.
        self.assertIn("result", server.handle(call("echo", {"text": "still here"})))

    def test_a_result_that_is_not_json_is_an_internal_error(self):
        server, log = make_server(LATEST)
        reply = server.handle(call("not_json", {}, 4))
        self.assertEqual(error_code(reply), -32603)
        self.assertIn("Traceback", log.getvalue())

    def test_a_surface_that_breaks_while_listing_is_an_internal_error(self):
        class Broken(ToolSurface):
            def specs(self):
                raise KeyError("oops")

        log = io.StringIO()
        server = McpServer(Broken(), log=log)
        server.handle(request("initialize", {"protocolVersion": LATEST}))
        self.assertEqual(error_code(server.handle(request("tools/list"))), -32603)
        self.assertIn("KeyError", log.getvalue())


class JsonRpcTests(unittest.TestCase):
    def test_unknown_methods(self):
        server, _ = make_server(LATEST)
        methods = (
            "resources/list",
            "prompts/list",
            "logging/setLevel",
            "completion/complete",
            "tools/approve",
            "tools/",
            "TOOLS/LIST",
            "notifications/initialized",  # with an id it is a request, and not one we have
            "",
        )
        for method in methods:
            with self.subTest(method=method):
                reply = server.handle(request(method, {}, 8))
                self.assertEqual((reply["id"], error_code(reply)), (8, -32601))

    def test_invalid_requests(self):
        cases = [
            # message, id expected in the answer
            (5, None),
            ("text", None),
            (None, None),
            (True, None),
            ({}, None),
            ({"jsonrpc": "2.0"}, None),
            ({"jsonrpc": "2.0", "params": {}}, None),
            ({"jsonrpc": "2.0", "method": 5}, None),
            ({"jsonrpc": "2.0", "id": 1}, 1),
            ({"jsonrpc": "2.0", "id": 1, "method": None}, 1),
            ({"jsonrpc": "2.0", "id": 1, "method": 5}, 1),
            ({"jsonrpc": "2.0", "id": 1, "method": ["ping"]}, 1),
            ({"jsonrpc": "1.0", "id": 1, "method": "ping"}, 1),
            ({"id": 1, "method": "ping"}, 1),
            ({"jsonrpc": 2.0, "id": 1, "method": "ping"}, 1),
            ({"jsonrpc": "2.0", "id": None, "method": "ping"}, None),
            ({"jsonrpc": "2.0", "id": 1.5, "method": "ping"}, None),
            ({"jsonrpc": "2.0", "id": True, "method": "ping"}, None),
            ({"jsonrpc": "2.0", "id": [1], "method": "ping"}, None),
            ({"jsonrpc": "2.0", "id": {"a": 1}, "method": "ping"}, None),
        ]
        for version in (None, LATEST):
            for message, expected_id in cases:
                with self.subTest(initialized=version is not None, message=message):
                    server, _ = make_server(version)
                    reply = server.handle(message)
                    self.assertEqual(sorted(reply), ["error", "id", "jsonrpc"])
                    self.assertEqual(reply["jsonrpc"], "2.0")
                    self.assertEqual(reply["id"], expected_id)
                    self.assertEqual(reply["error"]["code"], -32600)
                    self.assertIsInstance(reply["error"]["message"], str)

    def test_params_must_be_an_object(self):
        server, _ = make_server(LATEST)
        for params in ([], [1, 2], "text", 5, True):
            for method in ("ping", "tools/list", "tools/call", "no/such/method"):
                with self.subTest(method=method, params=params):
                    message = {"jsonrpc": "2.0", "id": 6, "method": method, "params": params}
                    reply = server.handle(message)
                    self.assertEqual((reply["id"], error_code(reply)), (6, -32602))

    def test_ids_are_echoed_exactly(self):
        server, _ = make_server(LATEST)
        for request_id in (0, 1, -7, 2**53 + 1, "", "abc", "1", "café", "with\nnewline"):
            with self.subTest(request_id=request_id):
                reply = server.handle(request("ping", request_id=request_id))
                self.assertEqual(reply["id"], request_id)
                self.assertIs(type(reply["id"]), type(request_id))

    def test_notifications_are_never_answered(self):
        calls = []
        for version in (None, LATEST):
            server, log = make_server(version, calls)
            notifications = [
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                {"jsonrpc": "2.0", "method": "notifications/cancelled",
                 "params": {"requestId": 1}},
                {"jsonrpc": "2.0", "method": "notifications/progress", "params": {}},
                {"jsonrpc": "2.0", "method": "notifications/roots/list_changed"},
                {"jsonrpc": "2.0", "method": "no/such/notification"},
                {"jsonrpc": "2.0", "method": ""},
                # Requests sent without an id are notifications too: no answer, no effect.
                {"jsonrpc": "2.0", "method": "ping"},
                {"jsonrpc": "2.0", "method": "tools/list"},
                {"jsonrpc": "2.0", "method": "initialize", "params": {"protocolVersion": LATEST}},
                {"jsonrpc": "2.0", "method": "tools/call",
                 "params": {"name": "echo", "arguments": {"text": "hi"}}},
                {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "boom"}},
                # Malformed ones are dropped just as quietly.
                {"jsonrpc": "2.0", "method": "tools/call", "params": [1, 2]},
                {"jsonrpc": "1.0", "method": "ping"},
                {"method": "ping"},
            ]
            for message in notifications:
                with self.subTest(initialized=version is not None, message=message):
                    self.assertIsNone(server.handle(message))
            self.assertEqual(server.protocol_version, version)
            self.assertNotIn("Traceback", log.getvalue())
        self.assertEqual(calls, [], "a notification never runs a tool")

    def test_responses_to_requests_we_never_sent_are_ignored(self):
        for version in (None, LATEST):
            server, _ = make_server(version)
            responses = [
                {"jsonrpc": "2.0", "id": 1, "result": {}},
                {"jsonrpc": "2.0", "id": "x", "result": {"roots": []}},
                {"jsonrpc": "2.0", "id": 1, "error": {"code": -32601, "message": "no"}},
                {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "bad"}},
                {"jsonrpc": "2.0", "error": {"code": -32600, "message": "bad"}},
                {"jsonrpc": "2.0", "id": 1, "result": {}, "error": {}},
                {"id": 99, "result": None},
            ]
            for message in responses:
                with self.subTest(initialized=version is not None, message=message):
                    self.assertIsNone(server.handle(message))

    def test_handle_writes_nothing_to_stdout_or_stderr(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            server, _ = make_server(LATEST)
            server.handle(request("tools/list"))
            server.handle(call("echo", {"text": "hi"}))
            server.handle(call("boom"))
            server.handle("junk")
        self.assertEqual((out.getvalue(), err.getvalue()), ("", ""))

    def test_without_a_log_stream_notes_go_to_stderr_never_stdout(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            server = McpServer(make_surface())
            server.handle(request("initialize", {"protocolVersion": LATEST}))
            server.handle(call("boom"))
        self.assertEqual(out.getvalue(), "")
        self.assertIn("RuntimeError", err.getvalue())

    def test_a_log_that_cannot_be_written_does_not_stop_the_session(self):
        log = io.StringIO()
        log.close()
        server = McpServer(make_surface(), log=log)
        self.assertIn("result", server.handle(request("initialize", {"protocolVersion": LATEST})))
        self.assertEqual(error_code(server.handle(call("boom"))), -32603)


class BatchTests(unittest.TestCase):
    def batch(self):
        return [
            request("ping", request_id=1),
            {"jsonrpc": "2.0", "method": "notifications/progress"},
            call("echo", {"text": "hi"}, 2),
            5,
            request("no/such/method", request_id=3),
            {"jsonrpc": "2.0", "id": 4, "result": {}},
            call("approve", {}, 5),
        ]

    def test_batches_are_answered_in_2025_03_26(self):
        calls = []
        server, _ = make_server("2025-03-26", calls)
        replies = server.handle(self.batch())
        self.assertIsInstance(replies, list)
        self.assertEqual([r["id"] for r in replies], [1, 2, None, 3, 5])
        self.assertEqual(replies[0]["result"], {})
        self.assertEqual(replies[1]["result"]["content"][0]["text"], '{"echo":"hi"}')
        self.assertEqual([error_code(r) for r in replies[2:]], [-32600, -32601, -32602])
        self.assertEqual(len(calls), 1)

    def test_a_batch_of_notifications_gets_no_answer(self):
        server, _ = make_server("2025-03-26")
        notes = [{"jsonrpc": "2.0", "method": "notifications/progress"}] * 3
        self.assertIsNone(server.handle(notes))

    def test_an_empty_batch_is_one_invalid_request(self):
        server, _ = make_server("2025-03-26")
        reply = server.handle([])
        self.assertEqual((reply["id"], error_code(reply)), (None, -32600))

    def test_initialize_inside_a_batch_is_refused(self):
        server, _ = make_server("2025-03-26")
        replies = server.handle([request("initialize", {"protocolVersion": LATEST}, 1)])
        self.assertEqual([error_code(r) for r in replies], [-32600])
        self.assertEqual(server.protocol_version, "2025-03-26")

    def test_batches_are_refused_whole_in_every_other_version(self):
        for version in (None, "2025-11-25", "2025-06-18", "2024-11-05"):
            with self.subTest(version=version):
                calls = []
                server, _ = make_server(version, calls)
                reply = server.handle(self.batch())
                self.assertIsInstance(reply, dict)
                self.assertEqual((reply["id"], error_code(reply)), (None, -32600))
                self.assertEqual(calls, [], "nothing in the batch was run")
                self.assertEqual(error_code(server.handle([])), -32600)

    def test_a_batch_cannot_carry_the_first_initialize(self):
        server, _ = make_server(None)
        reply = server.handle([request("initialize", {"protocolVersion": "2025-03-26"})])
        self.assertEqual(error_code(reply), -32600)
        self.assertIsNone(server.protocol_version)


# --- serve(): the line framing --------------------------------------------------


def line(message) -> bytes:
    return json.dumps(message).encode("utf-8") + b"\n"


INIT = line(request("initialize", {"protocolVersion": LATEST}, 0))


def serve(data: bytes, version_line: bytes = INIT):
    """Run a whole session over in-memory streams. Returns (code, answers, log)."""
    log = io.StringIO()
    server = McpServer(make_surface(), log=log)
    out = io.BytesIO()
    code = server.serve(io.BytesIO(version_line + data), out)
    raw = out.getvalue()
    assert raw == b"" or raw.endswith(b"\n"), raw[-50:]
    answers = [json.loads(text) for text in raw.split(b"\n")[:-1]]
    return code, answers[1:] if version_line else answers, log.getvalue()


class ServeTests(unittest.TestCase):
    def test_a_session_from_start_to_end_of_input(self):
        log = io.StringIO()
        server = McpServer(make_surface(), log=log)
        stdin = io.BytesIO(
            INIT
            + line({"jsonrpc": "2.0", "method": "notifications/initialized"})
            + line(request("tools/list", request_id=1))
            + line(call("echo", {"text": "café\n☃"}, 2))
            + line(call("approve", {}, 3))
        )
        stdout = io.BytesIO()
        self.assertEqual(server.serve(stdin, stdout), 0)
        raw = stdout.getvalue()
        self.assertTrue(raw.isascii())
        lines = raw.split(b"\n")
        self.assertEqual(lines[-1], b"")
        answers = [json.loads(text) for text in lines[:-1]]
        self.assertEqual([a["id"] for a in answers], [0, 1, 2, 3])
        self.assertTrue(all(a["jsonrpc"] == "2.0" for a in answers))
        self.assertEqual(answers[2]["result"]["structuredContent"], {"echo": "café\n☃"})
        self.assertEqual(answers[3]["error"]["message"], "Unknown tool: approve")
        self.assertTrue(server.ready)

    def test_empty_input_ends_cleanly(self):
        self.assertEqual(serve(b"", b""), (0, [], ""))

    def test_each_answer_is_written_and_flushed_before_the_next_read(self):
        events = []

        class In(io.BytesIO):
            def readline(self, *args):
                data = super().readline(*args)
                events.append("read" if data else "eof")
                return data

        class Out(io.BytesIO):
            def write(self, data):
                events.append("write")
                return super().write(data)

            def flush(self):
                events.append("flush")

        server = McpServer(make_surface(), log=io.StringIO())
        server.serve(In(INIT + line(request("ping", request_id=1))), Out())
        self.assertEqual(events, ["read", "write", "flush", "read", "write", "flush", "eof"])

    def test_blank_lines_crlf_and_a_last_line_without_newline(self):
        data = (
            b"\n   \n\r\n"
            + line(request("ping", request_id=1)).rstrip(b"\n")
            + b"\r\n\n"
            + b"  "
            + line(request("ping", request_id=2))
            + line(request("ping", request_id=3)).rstrip(b"\n")
        )
        code, answers, _ = serve(data)
        self.assertEqual(code, 0)
        self.assertEqual([a["id"] for a in answers], [1, 2, 3])
        self.assertTrue(all(a["result"] == {} for a in answers))

    def test_parse_errors(self):
        junk = [
            b"{not json",
            b"hello",
            b'{"jsonrpc": "2.0", "id": 1, "method": "ping"',
            b'{"jsonrpc": "2.0", "id": 1, "method": "ping"} trailing',
            b'{"jsonrpc": "2.0", "id": NaN, "method": "ping"}',
            b'{"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {"x": Infinity}}',
            b'{"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {"x": -Infinity}}',
            b'\xff\xfe{"jsonrpc": "2.0", "id": 1, "method": "ping"}',
            b'{"jsonrpc": "2.0", "id": 1, "method": "p\xe9ng"}',  # Latin-1, not UTF-8
            b"\xef\xbb\xbf" + line(request("ping")).rstrip(b"\n"),  # byte order mark
            b"[" * 100000,
            b"\x00",
        ]
        for text in junk:
            with self.subTest(text=text[:40]):
                code, answers, _ = serve(text + b"\n" + line(request("ping", request_id=2)))
                self.assertEqual(code, 0)
                self.assertEqual(len(answers), 2)
                self.assertEqual(answers[0]["id"], None)
                self.assertEqual(answers[0]["error"]["code"], -32700)
                self.assertEqual(answers[1], {"jsonrpc": "2.0", "id": 2, "result": {}})

    def test_valid_json_that_is_not_a_request(self):
        for text in (b"5", b'"text"', b"null", b"true", b"{}"):
            with self.subTest(text=text):
                _, answers, _ = serve(text + b"\n")
                self.assertEqual([(a["id"], a["error"]["code"]) for a in answers], [(None, -32600)])

    def test_utf8_and_escaped_surrogates_come_back_as_ascii(self):
        message = request("ping", request_id="café ☃")
        raw = json.dumps(message, ensure_ascii=False).encode("utf-8") + b"\n"
        raw += b'{"jsonrpc": "2.0", "id": "lone \\ud83d", "method": "ping"}\n'
        log = io.StringIO()
        out = io.BytesIO()
        McpServer(make_surface(), log=log).serve(io.BytesIO(raw), out)
        self.assertTrue(out.getvalue().isascii())
        first, second = [json.loads(text) for text in out.getvalue().splitlines()]
        self.assertEqual(first["id"], "café ☃")
        self.assertEqual(second["id"], "lone \ud83d")

    def test_a_line_over_the_limit_is_refused_and_the_session_goes_on(self):
        ping = line(request("ping", request_id=1)).rstrip(b"\n")
        too_long = ping + b" " * (MAX_LINE_BYTES + 1 - len(ping)) + b"\n"
        self.assertEqual(len(too_long), MAX_LINE_BYTES + 2)  # one byte over, plus the newline
        junk = b"x" * (3 * MAX_LINE_BYTES) + b"\n"
        code, answers, log = serve(too_long + junk + line(request("ping", request_id=2)))
        self.assertEqual(code, 0)
        got = [(a["id"], error_code(a)) for a in answers]
        self.assertEqual(got, [(None, -32600), (None, -32600), (2, None)])
        self.assertIn("4 MiB", answers[0]["error"]["message"])
        self.assertEqual(log.count("refused a message longer than 4 MiB"), 2)

    def test_a_line_of_exactly_the_limit_is_accepted(self):
        ping = line(request("ping", request_id=1)).rstrip(b"\n")
        exact = ping + b" " * (MAX_LINE_BYTES - len(ping)) + b"\n"
        self.assertEqual(len(exact), MAX_LINE_BYTES + 1)  # the limit, plus the newline
        _, answers, _ = serve(exact + line(request("ping", request_id=2)))
        self.assertEqual([a["id"] for a in answers], [1, 2])
        _, answers, _ = serve(exact.rstrip(b"\n"))  # and as the last line, with no newline
        self.assertEqual([a["id"] for a in answers], [1])

    def test_an_over_long_line_cut_off_by_end_of_input(self):
        code, answers, _ = serve(b"x" * (MAX_LINE_BYTES + 10))
        self.assertEqual(code, 0)
        self.assertEqual([(a["id"], error_code(a)) for a in answers], [(None, -32600)])

    def test_the_limit_is_4_mib(self):
        self.assertEqual(MAX_LINE_BYTES, 4 * 1024 * 1024)

    def test_a_large_message_inside_the_limit_is_served(self):
        surface = ToolSurface()
        surface.register(
            ToolSpec("size", "Size", "Counts.", {
                "type": "object", "properties": {"text": {"type": "string"}},
                "required": ["text"], "additionalProperties": False,
            }),
            lambda arguments: {"length": len(arguments["text"])},
        )
        out = io.BytesIO()
        big = line(call("size", {"text": "y" * (3 * 1024 * 1024)}, 1))
        McpServer(surface, log=io.StringIO()).serve(io.BytesIO(INIT + big), out)
        answer = json.loads(out.getvalue().splitlines()[1])
        self.assertEqual(answer["result"]["structuredContent"], {"length": 3 * 1024 * 1024})

    def test_bugs_and_bad_results_do_not_end_the_session(self):
        data = (
            line(call("boom", {}, 1))
            + line(call("not_json", {}, 2))
            + line(call("echo", {"text": "ok"}, 3))
        )
        code, answers, log = serve(data)
        self.assertEqual(code, 0)
        got = [(a["id"], error_code(a)) for a in answers]
        self.assertEqual(got, [(1, -32603), (2, -32603), (3, None)])
        self.assertEqual(log.count("Traceback"), 2)

    def test_an_answer_that_cannot_be_encoded_becomes_an_internal_error(self):
        class Odd(ToolSurface):
            def call(self, name, arguments=None):
                class Result:
                    text = "fine"
                    is_error = False
                    data = {"when": object()}  # the text works, the data does not

                return Result()

        log = io.StringIO()
        out = io.BytesIO()
        McpServer(Odd(), log=log).serve(io.BytesIO(INIT + line(call("x", {}, 7))), out)
        answer = json.loads(out.getvalue().splitlines()[1])
        self.assertEqual((answer["id"], error_code(answer)), (7, -32603))
        self.assertIn("could not be written as JSON", log.getvalue())

    def test_batches_over_the_stream(self):
        batch = [request("ping", request_id=1), request("ping", request_id=2)]
        init = line(request("initialize", {"protocolVersion": "2025-03-26"}, 0))
        _, answers, _ = serve(line(batch), init)
        self.assertEqual(len(answers), 1, "one line for the whole batch")
        self.assertEqual([a["id"] for a in answers[0]], [1, 2])
        _, answers, _ = serve(line(batch))
        self.assertEqual([(a["id"], error_code(a)) for a in answers], [(None, -32600)])

    def test_a_client_that_stops_listening_ends_the_session(self):
        class Closed(io.BytesIO):
            def write(self, data):
                raise BrokenPipeError()

        server = McpServer(make_surface(), log=io.StringIO())
        self.assertEqual(server.serve(io.BytesIO(INIT + line(request("ping"))), Closed()), 0)


# --- end to end: a real process, real pipes -------------------------------------

DEMO_SERVER = '''
import subprocess
import sys

sys.path.insert(0, {repo!r})

from countersign.mcp import serve_stdio
from countersign.toolsurface import ToolSpec, ToolSurface


def add(arguments):
    # Output like this must never reach the client's side of the pipe.
    print("a stray print from inside a tool")
    sys.stdout.flush()
    subprocess.run([sys.executable, "-c", "print('output of a child process')"], check=True)
    return {{"sum": arguments["a"] + arguments["b"]}}


surface = ToolSurface()
surface.register(
    ToolSpec(
        name="add",
        title="Add",
        description="Add two whole numbers.",
        input_schema={{
            "type": "object",
            "properties": {{"a": {{"type": "integer"}}, "b": {{"type": "integer"}}}},
            "required": ["a", "b"],
            "additionalProperties": False,
        }},
        read_only=True,
    ),
    add,
)
sys.exit(serve_stdio(surface))
'''


class EndToEndTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.script = os.path.join(tmp.name, "demo_server.py")
        with open(self.script, "w", encoding="utf-8") as fp:
            fp.write(textwrap.dedent(DEMO_SERVER).format(repo=REPO))

    def start(self) -> subprocess.Popen:
        proc = subprocess.Popen(
            [sys.executable, self.script],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=os.path.dirname(self.script),
        )
        watchdog = threading.Timer(30, proc.kill)  # a hung server must not hang the suite
        watchdog.start()
        self.addCleanup(watchdog.cancel)
        self.addCleanup(lambda: [s.close() for s in (proc.stdin, proc.stdout, proc.stderr) if s])
        self.addCleanup(lambda: proc.poll() is None and proc.kill())
        return proc

    def ask(self, proc: subprocess.Popen, message: dict) -> dict:
        proc.stdin.write(line(message))
        proc.stdin.flush()
        answer = proc.stdout.readline()
        self.assertTrue(answer.endswith(b"\n"), f"no answer to {message}: {answer!r}")
        return json.loads(answer)

    def test_a_whole_session_over_pipes(self):
        proc = self.start()
        seen = []

        def ask(message):
            answer = self.ask(proc, message)
            seen.append(answer)
            return answer

        init = ask(request("initialize", {
            "protocolVersion": LATEST,
            "capabilities": {},
            "clientInfo": {"name": "pipe-test", "version": "1"},
        }, 1))
        self.assertEqual(init["result"]["protocolVersion"], LATEST)
        self.assertEqual(
            init["result"]["serverInfo"], {"name": "countersign", "version": __version__}
        )
        self.assertEqual(init["result"]["capabilities"], {"tools": {"listChanged": False}})

        proc.stdin.write(line({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        proc.stdin.flush()

        tools = ask(request("tools/list", {}, 2))["result"]["tools"]
        self.assertEqual([tool["name"] for tool in tools], ["add"])
        self.assertEqual(tools[0]["annotations"]["readOnlyHint"], True)

        result = ask(call("add", {"a": 19, "b": 23}, 3))["result"]
        self.assertEqual(result["content"], [{"type": "text", "text": '{"sum":42}'}])
        self.assertIs(result["isError"], False)
        self.assertEqual(result["structuredContent"], {"sum": 42})

        refused = ask(call("approve", {"hold_id": "H001"}, 4))
        self.assertEqual(refused["id"], 4)
        self.assertEqual(refused["error"], {"code": -32602, "message": "Unknown tool: approve"})

        proc.stdin.close()
        self.assertEqual(proc.wait(timeout=20), 0)
        rest = proc.stdout.read()
        self.assertEqual(rest, b"", "nothing after the last answer")
        self.assertEqual([a["id"] for a in seen], [1, 2, 3, 4], "one answer per request, no more")
        self.assertTrue(all(a["jsonrpc"] == "2.0" for a in seen))

        stderr = proc.stderr.read().decode("utf-8")
        # Ordinary output went to stderr instead of the protocol channel...
        self.assertIn("a stray print from inside a tool", stderr)
        self.assertIn("output of a child process", stderr)
        self.assertIn("client pipe-test 1, protocol 2025-11-25", stderr)
        self.assertNotIn("Traceback", stderr)

    @unittest.skipIf(sys.platform == "win32", "no interrupt signal to send")
    def test_an_interrupt_from_the_client_is_a_clean_stop(self):
        proc = self.start()
        self.assertEqual(self.ask(proc, request("ping", request_id=1))["result"], {})
        proc.send_signal(signal.SIGINT)  # the server is now waiting for the next line
        self.assertEqual(proc.wait(timeout=20), 0)
        self.assertEqual(proc.stdout.read(), b"")
        self.assertNotIn("Traceback", proc.stderr.read().decode("utf-8"))

    def test_closing_stdin_at_once_exits_0_with_nothing_on_stdout(self):
        proc = self.start()
        out, err = proc.communicate(b"", timeout=20)
        self.assertEqual(proc.returncode, 0, err)
        self.assertEqual(out, b"")

    def test_garbage_then_end_of_input(self):
        proc = self.start()
        out, err = proc.communicate(b"\xff\xfe garbage\n[]\n", timeout=20)
        self.assertEqual(proc.returncode, 0, err)
        self.assertTrue(out.endswith(b"\n"))
        answers = [json.loads(text) for text in out.splitlines()]
        self.assertEqual([error_code(a) for a in answers], [-32700, -32600])


if __name__ == "__main__":
    unittest.main()
