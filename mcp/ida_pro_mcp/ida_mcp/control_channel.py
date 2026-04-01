"""
IDA Pro Control Channel

This module provides a lightweight control channel for IDA Pro that allows
external tools (like Claude Code's MCP server) to:
1. Discover running IDA instances
2. Start the HTTP server on demand
3. Get instance status

Architecture:
- Each IDA instance registers itself in a shared directory (~/.ida-mcp/instances/)
- A control socket listens for commands on a unique port
- MCP server can discover instances and send commands
"""

import json
import os
import socket
import threading
import time
import uuid
from pathlib import Path
from typing import Callable, Optional, Dict, Any
from dataclasses import dataclass, asdict
from datetime import datetime

# Configuration
IDA_MCP_DIR = Path.home() / ".ida-mcp"
INSTANCES_DIR = IDA_MCP_DIR / "instances"
CONTROL_PORT_BASE = 13400  # Base port for control channels

# Ensure directories exist
IDA_MCP_DIR.mkdir(parents=True, exist_ok=True)
INSTANCES_DIR.mkdir(parents=True, exist_ok=True)


@dataclass
class IDAInstance:
    """Represents a running IDA instance"""
    instance_id: str
    control_port: int
    http_port: int
    pid: int
    database: str
    created_at: str
    http_server_running: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'IDAInstance':
        return cls(**data)


class ControlChannel:
    """
    Lightweight control channel for IDA Pro instances.

    Listens on a unique port and responds to commands:
    - PING: Health check
    - START_HTTP: Start the HTTP server
    - STOP_HTTP: Stop the HTTP server
    - STATUS: Get instance status
    - SHUTDOWN: Shutdown control channel
    """

    COMMANDS = ['PING', 'START_HTTP', 'STOP_HTTP', 'STATUS', 'SHUTDOWN']

    def __init__(
        self,
        http_port: int = 13337,
        start_http_callback: Optional[Callable[[], bool]] = None,
        stop_http_callback: Optional[Callable[[], bool]] = None,
        get_status_callback: Optional[Callable[[], Dict[str, Any]]] = None,
    ):
        self.instance_id = str(uuid.uuid4())[:8]
        self.http_port = http_port
        self.control_port = self._find_available_port()
        self.pid = os.getpid()

        # Callbacks
        self._start_http = start_http_callback
        self._stop_http = stop_http_callback
        self._get_status = get_status_callback

        # State
        self._running = False
        self._server_socket: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._instance_file: Optional[Path] = None

        # Try to get database name
        self.database = self._get_database_name()

    def _find_available_port(self) -> int:
        """Find an available port for the control channel"""
        for port in range(CONTROL_PORT_BASE, CONTROL_PORT_BASE + 100):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.bind(('127.0.0.1', port))
                    return port
            except OSError:
                continue
        raise RuntimeError("Could not find available port for control channel")

    def _get_database_name(self) -> str:
        """Get the name of the current IDA database"""
        try:
            import idaapi
            return os.path.basename(idaapi.get_input_file_path() or "unknown")
        except ImportError:
            return "standalone"

    def _register_instance(self):
        """Register this instance in the shared directory"""
        instance = IDAInstance(
            instance_id=self.instance_id,
            control_port=self.control_port,
            http_port=self.http_port,
            pid=self.pid,
            database=self.database,
            created_at=datetime.now().isoformat(),
            http_server_running=False,
        )

        self._instance_file = INSTANCES_DIR / f"{self.instance_id}.json"
        with open(self._instance_file, 'w') as f:
            json.dump(instance.to_dict(), f, indent=2)

    def _unregister_instance(self):
        """Unregister this instance"""
        if self._instance_file and self._instance_file.exists():
            try:
                self._instance_file.unlink()
            except Exception:
                pass

    def _update_instance(self, http_running: bool = False):
        """Update instance status"""
        if self._instance_file and self._instance_file.exists():
            try:
                with open(self._instance_file, 'r') as f:
                    data = json.load(f)
                data['http_server_running'] = http_running
                with open(self._instance_file, 'w') as f:
                    json.dump(data, f, indent=2)
            except Exception:
                pass

    def _handle_command(self, command: str) -> Dict[str, Any]:
        """Handle a control command"""
        command = command.strip().upper()

        if command == 'PING':
            return {'status': 'ok', 'message': 'pong'}

        elif command == 'START_HTTP':
            if self._start_http:
                try:
                    success = self._start_http()
                    self._update_instance(http_running=success)
                    return {'status': 'ok' if success else 'error', 'http_port': self.http_port}
                except Exception as e:
                    return {'status': 'error', 'message': str(e)}
            return {'status': 'error', 'message': 'No start_http callback'}

        elif command == 'STOP_HTTP':
            if self._stop_http:
                try:
                    success = self._stop_http()
                    self._update_instance(http_running=not success)
                    return {'status': 'ok' if success else 'error'}
                except Exception as e:
                    return {'status': 'error', 'message': str(e)}
            return {'status': 'error', 'message': 'No stop_http callback'}

        elif command == 'STATUS':
            status = {
                'instance_id': self.instance_id,
                'control_port': self.control_port,
                'http_port': self.http_port,
                'pid': self.pid,
                'database': self.database,
            }
            if self._get_status:
                status.update(self._get_status())
            return {'status': 'ok', 'data': status}

        elif command == 'SHUTDOWN':
            self._running = False
            return {'status': 'ok', 'message': 'shutting down'}

        else:
            return {'status': 'error', 'message': f'Unknown command: {command}'}

    def _handle_client(self, client_socket: socket.socket, addr):
        """Handle a client connection"""
        try:
            data = client_socket.recv(4096).decode('utf-8')
            if data:
                response = self._handle_command(data)
                client_socket.send(json.dumps(response).encode('utf-8'))
        except Exception as e:
            try:
                client_socket.send(json.dumps({'status': 'error', 'message': str(e)}).encode('utf-8'))
            except:
                pass
        finally:
            client_socket.close()

    def _server_loop(self):
        """Main server loop"""
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind(('127.0.0.1', self.control_port))
        self._server_socket.listen(5)
        self._server_socket.settimeout(1.0)  # Allow checking _running flag

        while self._running:
            try:
                client_socket, addr = self._server_socket.accept()
                threading.Thread(
                    target=self._handle_client,
                    args=(client_socket, addr),
                    daemon=True
                ).start()
            except socket.timeout:
                continue
            except Exception as e:
                if self._running:
                    print(f"[ControlChannel] Error: {e}")

    def start(self):
        """Start the control channel"""
        if self._running:
            return

        self._running = True
        self._register_instance()

        self._thread = threading.Thread(target=self._server_loop, daemon=True)
        self._thread.start()

        print(f"[ControlChannel] Started on port {self.control_port}")
        print(f"[ControlChannel] Instance ID: {self.instance_id}")
        print(f"[ControlChannel] Instance file: {self._instance_file}")

    def stop(self):
        """Stop the control channel"""
        self._running = False
        self._unregister_instance()

        if self._server_socket:
            try:
                self._server_socket.close()
            except:
                pass

        print(f"[ControlChannel] Stopped")


class IDADiscovery:
    """
    Utility class for discovering IDA instances.
    Used by the MCP server to find and control IDA instances.
    """

    @staticmethod
    def get_instances() -> list[IDAInstance]:
        """Get all registered IDA instances"""
        instances = []

        if not INSTANCES_DIR.exists():
            return instances

        for file in INSTANCES_DIR.glob("*.json"):
            try:
                with open(file, 'r') as f:
                    data = json.load(f)
                instance = IDAInstance.from_dict(data)

                # Check if process is still alive
                try:
                    os.kill(instance.pid, 0)
                    instances.append(instance)
                except OSError:
                    # Process is dead, clean up
                    file.unlink()
            except Exception as e:
                print(f"[IDADiscovery] Error reading {file}: {e}")

        # Sort by creation time
        instances.sort(key=lambda x: x.created_at)
        return instances

    @staticmethod
    def get_first_instance() -> Optional[IDAInstance]:
        """Get the first (oldest) IDA instance"""
        instances = IDADiscovery.get_instances()
        return instances[0] if instances else None

    @staticmethod
    def send_command(instance: IDAInstance, command: str) -> Dict[str, Any]:
        """Send a command to an IDA instance"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5.0)
                s.connect(('127.0.0.1', instance.control_port))
                s.send(command.encode('utf-8'))
                response = s.recv(4096).decode('utf-8')
                return json.loads(response)
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    @staticmethod
    def start_http_server(instance: IDAInstance) -> Dict[str, Any]:
        """Start the HTTP server on an IDA instance"""
        return IDADiscovery.send_command(instance, 'START_HTTP')

    @staticmethod
    def get_status(instance: IDAInstance) -> Dict[str, Any]:
        """Get the status of an IDA instance"""
        return IDADiscovery.send_command(instance, 'STATUS')


# Convenience function for IDA plugin
def create_control_channel(
    http_port: int = 13337,
    start_http_callback: Optional[Callable[[], bool]] = None,
    stop_http_callback: Optional[Callable[[], bool]] = None,
    get_status_callback: Optional[Callable[[], Dict[str, Any]]] = None,
) -> ControlChannel:
    """Create a control channel for the IDA plugin"""
    return ControlChannel(
        http_port=http_port,
        start_http_callback=start_http_callback,
        stop_http_callback=stop_http_callback,
        get_status_callback=get_status_callback,
    )
