"""Shared base for all Arena scenario servers.

Every scenario inherits ``ArenaScenario`` which provides:
- Standard FastAPI app with CORS
- ``/health``, ``/chat``, ``/tools``, ``/tools/list``, ``/tools/call``
- ``/mcp`` JSON-RPC endpoint
- ``/`` root POST for MCP streamable-http convention
- Session / memory management
- Canary flag verification
- Subclass hooks: ``setup()``, ``generate_response()``, ``get_tools()``,
  ``execute_tool()``, ``extra_routes()``
"""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime
from functools import partial
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel


class ChatRequest(BaseModel):
    message: str
    session_id: str | None = None
    tool_call: dict[str, Any] | None = None
    role: str | None = None


class ChatResponse(BaseModel):
    response: str
    session_id: str
    tool_results: list[dict[str, Any]] | None = None
    tokens_used: int = 0


class ToolCallRequest(BaseModel):
    tool: str | None = None
    name: str | None = None
    parameters: dict[str, Any] | None = None
    arguments: dict[str, Any] | None = None


class ArenaScenario:
    """Base class for all Arena vulnerable AI agent scenarios."""

    # Subclasses MUST override these.
    SCENARIO_ID: str = "arena-00-base"
    SCENARIO_NAME: str = "Base Scenario"
    DESCRIPTION: str = "Override me"
    AGENT_DOMAIN: str = "unknown"  # maps to ARGUS agent type
    CANARY_FLAG: str = "ARGUS{base_canary}"  # unique per scenario
    PORT: int = 9000

    def __init__(self) -> None:
        self.sessions: dict[str, dict[str, Any]] = {}
        self.system_prompt: str = "You are a helpful AI assistant."
        self.tools: list[dict[str, Any]] = []
        self.app = self._build_app()

    # ------------------------------------------------------------------
    # Subclass hooks
    # ------------------------------------------------------------------

    def setup(self) -> None:
        """Called once at startup.  Set self.system_prompt, self.tools, etc."""

    def generate_response(self, message: str, session: dict[str, Any]) -> str:
        """Return a chat response.  Override for scenario-specific behavior."""
        return f"I received your message: {message[:100]}"

    def execute_tool(self, tool_name: str, params: dict[str, Any], session: dict[str, Any]) -> dict[str, Any]:
        """Execute a tool call.  Override to add vulnerable tool logic."""
        return {"status": "error", "error": f"Unknown tool: {tool_name}"}

    def extra_routes(self, app: FastAPI) -> None:
        """Add scenario-specific routes (memory, admin, debug, etc.)."""

    # ------------------------------------------------------------------
    # Internal machinery
    # ------------------------------------------------------------------

    def _get_or_create_session(self, session_id: str | None) -> dict[str, Any]:
        sid = session_id or str(uuid.uuid4())
        if sid not in self.sessions:
            self.sessions[sid] = {
                "id": sid,
                "history": [],
                "created_at": datetime.utcnow().isoformat(),
                "persona_override": None,
                "role": "user",
                "metadata": {},
            }
        return self.sessions[sid]

    def _build_app(self) -> FastAPI:
        self.setup()

        app = FastAPI(title=f"ARGUS Arena — {self.SCENARIO_NAME}", version="1.0.0")
        app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

        scenario = self  # capture for closures

        @app.get("/health")
        async def health():
            return {
                "status": "ok",
                "scenario": scenario.SCENARIO_ID,
                "name": scenario.SCENARIO_NAME,
                "agent_domain": scenario.AGENT_DOMAIN,
            }

        @app.get("/")
        async def root():
            return {
                "service": scenario.SCENARIO_NAME,
                "scenario": scenario.SCENARIO_ID,
                "version": "1.0.0",
                "endpoints": ["/chat", "/tools", "/tools/call", "/mcp", "/health"],
            }

        @app.post("/")
        async def root_post(request: Request):
            return await mcp_endpoint(request)

        @app.post("/chat", response_model=ChatResponse)
        async def chat(req: ChatRequest):
            session = scenario._get_or_create_session(req.session_id)
            if req.role:
                session["role"] = req.role
            session["history"].append(
                {
                    "role": "user",
                    "content": req.message,
                    "timestamp": datetime.utcnow().isoformat(),
                }
            )
            tool_results = None
            if req.tool_call:
                tn = req.tool_call.get("tool") or req.tool_call.get("name", "")
                tp = req.tool_call.get("parameters") or req.tool_call.get("arguments", {})
                loop = asyncio.get_running_loop()
                result = await loop.run_in_executor(None, partial(scenario.execute_tool, tn, tp, session))
                tool_results = [{"tool": tn, "result": result}]
            response_text = scenario.generate_response(req.message, session)
            session["history"].append(
                {
                    "role": "assistant",
                    "content": response_text,
                    "timestamp": datetime.utcnow().isoformat(),
                }
            )
            return ChatResponse(
                response=response_text,
                session_id=session["id"],
                tool_results=tool_results,
                tokens_used=len(req.message.split()) * 3,
            )

        @app.get("/tools")
        async def list_tools():
            return {"tools": scenario.tools}

        @app.get("/tools/list")
        async def list_tools_alt():
            return {"tools": scenario.tools}

        @app.get("/functions")
        async def list_functions():
            return {"tools": scenario.tools}

        @app.post("/tools/call")
        async def call_tool(req: ToolCallRequest):
            tn = req.tool or req.name or ""
            tp = req.parameters or req.arguments or {}
            session = scenario._get_or_create_session(None)
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(None, partial(scenario.execute_tool, tn, tp, session))
            return {"tool": tn, "result": result, "session_id": session["id"]}

        @app.post("/v1/tools/call")
        async def v1_call_tool(req: ToolCallRequest):
            return await call_tool(req)

        @app.post("/invoke")
        async def invoke_tool(req: ToolCallRequest):
            return await call_tool(req)

        @app.post("/functions/call")
        async def functions_call(req: ToolCallRequest):
            return await call_tool(req)

        @app.post("/mcp")
        async def mcp_endpoint(request: Request):
            body = await request.json()
            method = body.get("method", "")
            params = body.get("params", {})
            req_id = body.get("id", 1)
            if method == "tools/list":
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "tools": [
                            {
                                "name": t["name"],
                                "description": t.get("description", ""),
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {k: {"type": v} for k, v in t.get("parameters", {}).items()},
                                },
                            }
                            for t in scenario.tools
                        ]
                    },
                }
            elif method == "tools/call":
                tn = params.get("name", "")
                ta = params.get("arguments", {})
                session = scenario._get_or_create_session(None)
                loop = asyncio.get_running_loop()
                result = await loop.run_in_executor(None, partial(scenario.execute_tool, tn, ta, session))
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"content": [{"type": "text", "text": json.dumps(result)}]},
                }
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"},
            }

        @app.post("/v1/chat")
        async def v1_chat(req: ChatRequest):
            return await chat(req)

        @app.post("/v1/messages")
        async def v1_messages(req: ChatRequest):
            return await chat(req)

        @app.post("/api/chat")
        async def api_chat(req: ChatRequest):
            return await chat(req)

        @app.post("/conversation")
        async def conversation(req: ChatRequest):
            return await chat(req)

        # Let subclass add scenario-specific routes
        self.extra_routes(app)

        return app

    def run(self, host: str = "0.0.0.0", port: int | None = None) -> None:  # noqa: S104
        import uvicorn

        uvicorn.run(self.app, host=host, port=port or self.PORT)
