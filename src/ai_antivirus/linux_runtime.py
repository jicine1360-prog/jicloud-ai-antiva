"""Read-only Linux monitoring for known local AI server processes."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass
import ipaddress
import os
from pathlib import Path
import socket
from threading import Event, Thread


DEFAULT_PROCESS_NAMES = (
    "ollama",
    "llama-server",
    "llama.cpp",
    "lmstudio",
    "text-generation-launcher",
    "vllm",
)


@dataclass(frozen=True)
class TcpConnection:
    inode: str
    host: str
    port: int


def _ipv4_address(value: str) -> str:
    return socket.inet_ntoa(bytes.fromhex(value)[::-1])


def _tcp_connections(lines: Iterator[str]) -> dict[str, TcpConnection]:
    connections: dict[str, TcpConnection] = {}
    for line in lines:
        fields = line.split()
        if len(fields) < 10 or fields[0] == "sl":
            continue
        if fields[3] != "01":  # TCP_ESTABLISHED
            continue
        try:
            address, port = fields[2].split(":")
            host = _ipv4_address(address)
            parsed_port = int(port, 16)
            if ipaddress.ip_address(host).is_loopback:
                continue
            connections[fields[9]] = TcpConnection(fields[9], host, parsed_port)
        except (OSError, ValueError):
            continue
    return connections


def _selected_processes(proc_root: Path, process_names: tuple[str, ...]) -> dict[int, str]:
    selected: dict[int, str] = {}
    names = tuple(name.lower() for name in process_names)
    try:
        entries = tuple(proc_root.iterdir())
    except OSError:
        return selected
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            name = (entry / "comm").read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if name.lower() in names:
            selected[int(entry.name)] = name
    return selected


def _process_socket_inodes(proc_root: Path, pid: int) -> set[str]:
    inodes: set[str] = set()
    try:
        descriptors = tuple((proc_root / str(pid) / "fd").iterdir())
    except OSError:
        return inodes
    for descriptor in descriptors:
        try:
            target = os.readlink(descriptor)
        except OSError:
            continue
        if target.startswith("socket:[") and target.endswith("]"):
            inodes.add(target[8:-1])
    return inodes


class LinuxRuntimeMonitor:
    """Emit process and external TCP connection events without altering traffic."""

    def __init__(
        self,
        on_event: Callable[[dict], None],
        interval_seconds: float = 5.0,
        process_names: tuple[str, ...] = DEFAULT_PROCESS_NAMES,
        proc_root: Path = Path("/proc"),
    ):
        if interval_seconds <= 0:
            raise ValueError("runtime interval must be greater than zero")
        self.on_event = on_event
        self.interval_seconds = interval_seconds
        self.process_names = process_names
        self.proc_root = proc_root
        self._known_pids: set[tuple[int, str]] = set()
        self._known_connections: set[tuple[int, str, str, int]] = set()
        self._stop = Event()
        self._thread: Thread | None = None
        self.polls = 0
        self.last_error: str | None = None

    def _emit(self, event: dict) -> None:
        try:
            self.on_event(event)
        except Exception as error:
            self.last_error = str(error)

    def poll_once(self) -> None:
        processes = _selected_processes(self.proc_root, self.process_names)
        current_pids = {(pid, name) for pid, name in processes.items()}
        for pid, name in current_pids - self._known_pids:
            self._emit({"event_type": "process_start", "pid": pid, "process_name": name})
        self._known_pids = current_pids

        try:
            with (self.proc_root / "net" / "tcp").open(encoding="utf-8") as stream:
                connections = _tcp_connections(iter(stream))
        except OSError:
            return

        current_connections: set[tuple[int, str, str, int]] = set()
        for pid, name in processes.items():
            for inode in _process_socket_inodes(self.proc_root, pid):
                connection = connections.get(inode)
                if connection is None:
                    continue
                item = (pid, inode, connection.host, connection.port)
                current_connections.add(item)
                if item not in self._known_connections:
                    self._emit(
                        {
                            "event_type": "network_egress",
                            "host": connection.host,
                            "port": connection.port,
                            "pid": pid,
                            "process_name": name,
                        }
                    )
        self._known_connections = current_connections
        self.polls += 1

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.poll_once()
            except Exception as error:
                self.last_error = str(error)
            self._stop.wait(self.interval_seconds)

    def start(self) -> None:
        if self._thread is not None:
            return
        self._stop.clear()
        self._thread = Thread(target=self._run, name="ai-antivirus-linux-runtime", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=self.interval_seconds + 1)
            if not self._thread.is_alive():
                self._thread = None
