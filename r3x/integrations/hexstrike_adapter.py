"""
R3X HexStrike AI MCP Agents v6.0 Adapter
Connects to HexStrike AI MCP Server (https://github.com/0x4m4/hexstrike-ai v6.0).
Dynamically discovers MCP tools, reads schemas, and coordinates tool execution with safety controls.
"""
import asyncio
from typing import Any

import httpx

from r3x.core.config import settings
from r3x.core.exceptions import AdapterError, ToolExecutionError
from r3x.core.logger import logger


class HexStrikeAdapter:
    def __init__(self, endpoint: str | None = None):
        self.endpoint = endpoint or settings.hexstrike_endpoint
        self._discovered_tools: dict[str, dict[str, Any]] = {}
        self._is_connected: bool = False
        self._last_error: str | None = None

    def check_connection(self) -> tuple[bool, str]:
        """Verify connectivity to HexStrike MCP Server (Port 8888)."""
        try:
            r = httpx.get(f"{self.endpoint}/health", timeout=1.5)
            if r.status_code == 200:
                self._is_connected = True
                return True, f"HexStrike AI MCP v6.0 Active ({self.endpoint})"
            else:
                self._is_connected = False
                return False, f"HexStrike returned HTTP {r.status_code}"
        except Exception as e:
            self._is_connected = False
            self._last_error = str(e)
            return False, f"HexStrike Server unreachable at {self.endpoint}"

    async def discover_tools_async(self) -> dict[str, dict[str, Any]]:
        """
        Dynamically query HexStrike MCP Server for registered security tools and their schemas.
        Never assumes tool names without dynamic discovery.
        """
        self._discovered_tools.clear()
        endpoints_to_try = [
            f"{self.endpoint}/api/tools",
            f"{self.endpoint}/tools",
            f"{self.endpoint}/mcp/tools"
        ]

        async with httpx.AsyncClient(timeout=5.0) as client:
            for ep in endpoints_to_try:
                try:
                    resp = await client.get(ep)
                    if resp.status_code == 200:
                        data = resp.json()
                        tools_list = data if isinstance(data, list) else data.get("tools", [])
                        for t in tools_list:
                            name = t.get("name")
                            if name:
                                self._discovered_tools[name] = {
                                    "name": name,
                                    "description": t.get("description", "Security tool"),
                                    "schema": t.get("parameters") or t.get("inputSchema", {}),
                                    "is_available": True
                                }
                        logger.info(f"HexStrike MCP: Dynamically discovered {len(self._discovered_tools)} tools from {ep}")
                        self._is_connected = True
                        return self._discovered_tools
                except Exception as e:
                    logger.debug(f"HexStrike endpoint probe {ep} failed: {e}")
                    continue

        # If server is not responding, record that zero tools were discovered from server
        logger.debug(f"HexStrike MCP Server not responding at {self.endpoint}. Discovered 0 tools.")
        self._is_connected = False
        return {}

    def discover_tools(self) -> dict[str, dict[str, Any]]:
        """Synchronous wrapper for tool discovery."""
        try:
            return asyncio.run(self.discover_tools_async())
        except RuntimeError:
            loop = asyncio.get_event_loop()
            return loop.run_until_complete(self.discover_tools_async())

    async def execute_tool_async(self, tool_name: str, arguments: dict[str, Any], timeout: float = 30.0) -> dict[str, Any]:
        """
        Execute an authorized security action through HexStrike MCP protocol.
        """
        if not self._discovered_tools:
            await self.discover_tools_async()

        if tool_name not in self._discovered_tools and self._is_connected:
            raise ToolExecutionError(f"Tool '{tool_name}' was not discovered from HexStrike server.")

        url = f"{self.endpoint}/api/tools/execute"
        payload = {
            "tool": tool_name,
            "parameters": arguments
        }

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.post(url, json=payload)
                if resp.status_code != 200:
                    raise ToolExecutionError(f"HexStrike tool execution failed: HTTP {resp.status_code} - {resp.text}")
                return resp.json()
        except httpx.ConnectError:
            self._is_connected = False
            raise AdapterError(f"Lost connection to HexStrike MCP Server at {self.endpoint}")
        except Exception as e:
            raise ToolExecutionError(f"Error executing HexStrike tool '{tool_name}': {e}")

    def execute_tool(self, tool_name: str, arguments: dict[str, Any], timeout: float = 30.0) -> dict[str, Any]:
        """Synchronous wrapper for execute_tool_async."""
        try:
            return asyncio.run(self.execute_tool_async(tool_name, arguments, timeout))
        except RuntimeError:
            loop = asyncio.get_event_loop()
            return loop.run_until_complete(self.execute_tool_async(tool_name, arguments, timeout))

    def get_tool_list(self) -> list[dict[str, Any]]:
        """Return list of dynamically discovered tools and schemas."""
        if not self._discovered_tools and self._is_connected:
            self.discover_tools()
        return list(self._discovered_tools.values())

hexstrike_adapter = HexStrikeAdapter()
