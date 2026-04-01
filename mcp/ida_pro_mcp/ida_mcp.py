"""IDA Pro MCP Plugin Loader

This file serves as the entry point for IDA Pro's plugin system.
It loads the actual implementation from the ida_mcp package.

Features:
- Control channel for external discovery and control
- On-demand HTTP server startup
- Automatic registration of IDA instances
"""

import sys
import idaapi
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from . import ida_mcp


def unload_package(package_name: str):
    """Remove every module that belongs to the package from sys.modules."""
    to_remove = [
        mod_name
        for mod_name in sys.modules
        if mod_name == package_name or mod_name.startswith(package_name + ".")
    ]
    for mod_name in to_remove:
        del sys.modules[mod_name]


class MCP(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "MCP Plugin"
    help = "MCP"
    wanted_name = "MCP"
    wanted_hotkey = "Ctrl-Alt-M"

    # Configuration
    HOST = "127.0.0.1"
    PORT = 13337

    def init(self):
        hotkey = MCP.wanted_hotkey.replace("-", "+")
        if __import__("sys").platform == "darwin":
            hotkey = hotkey.replace("Alt", "Option")

        print(
            f"[MCP] Plugin loaded, use Edit -> Plugins -> MCP ({hotkey}) to start the server"
        )
        self.mcp = None
        self.control_channel = None

        # Start control channel for external discovery
        self._start_control_channel()

        return idaapi.PLUGIN_KEEP

    def _start_control_channel(self):
        """Start the control channel for external discovery and control"""
        try:
            if TYPE_CHECKING:
                from .ida_mcp.control_channel import create_control_channel
            else:
                # Fresh load
                unload_package("ida_mcp")
                from ida_mcp.control_channel import create_control_channel

            self.control_channel = create_control_channel(
                http_port=self.PORT,
                start_http_callback=self._start_http_server,
                stop_http_callback=self._stop_http_server,
                get_status_callback=self._get_status,
            )
            self.control_channel.start()
            print(f"[MCP] Control channel started on port {self.control_channel.control_port}")
        except Exception as e:
            print(f"[MCP] Failed to start control channel: {e}")

    def _start_http_server(self) -> bool:
        """Start the HTTP server (called from control channel)"""
        if self.mcp:
            return True  # Already running

        try:
            if TYPE_CHECKING:
                from .ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler, init_caches
            else:
                from ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler, init_caches

            try:
                import queue
                _cache_q = queue.Queue()

                def _do_init():
                    try:
                        init_caches()
                        _cache_q.put(None)
                    except Exception as ex:
                        _cache_q.put(ex)

                idaapi.execute_sync(_do_init, idaapi.MFF_WRITE)
                cache_res = _cache_q.get()
                if isinstance(cache_res, Exception):
                    raise cache_res
            except Exception as e:
                print(f"[MCP] Cache init failed: {e}")

            MCP_SERVER.serve(
                self.HOST, self.PORT, request_handler=IdaMcpHttpRequestHandler
            )
            print(f"[MCP] HTTP server started on port {self.PORT}")
            print(f"  Config: http://{self.HOST}:{self.PORT}/config.html")
            self.mcp = MCP_SERVER
            return True
        except OSError as e:
            if e.errno in (48, 98, 10048):  # Address already in use
                print(f"[MCP] Error: Port {self.PORT} is already in use")
            else:
                print(f"[MCP] Error starting HTTP server: {e}")
            return False
        except Exception as e:
            print(f"[MCP] Error starting HTTP server: {e}")
            return False

    def _stop_http_server(self) -> bool:
        """Stop the HTTP server (called from control channel)"""
        if self.mcp:
            try:
                self.mcp.stop()
                self.mcp = None
                print("[MCP] HTTP server stopped")
                return True
            except Exception as e:
                print(f"[MCP] Error stopping HTTP server: {e}")
                return False
        return True

    def _get_status(self) -> dict:
        """Get status information"""
        return {
            "http_server_running": self.mcp is not None,
            "control_port": self.control_channel.control_port if self.control_channel else None,
            "http_port": self.PORT,
        }

    def run(self, arg):
        """Manual start/stop of HTTP server (via menu or hotkey)"""
        if self.mcp:
            self._stop_http_server()
        else:
            self._start_http_server()

    def term(self):
        """Cleanup on plugin unload"""
        if self.mcp:
            self.mcp.stop()
        if self.control_channel:
            self.control_channel.stop()


def PLUGIN_ENTRY():
    return MCP()


# IDA plugin flags
PLUGIN_FLAGS = idaapi.PLUGIN_HIDE | idaapi.PLUGIN_FIX
