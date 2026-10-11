from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from ai_antivirus.linux_runtime import _selected_processes, _tcp_connections


def test_tcp_connections_skips_loopback_and_reads_external_connection():
    lines = iter(
        [
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode",
            "   0: 0100007F:1F90 08080808:01BB 01 00000000:00000000 00:00000000 00000000 1000 0 12345 1",
            "   1: 0100007F:1F90 0100007F:01BB 01 00000000:00000000 00:00000000 00000000 1000 0 54321 1",
        ]
    )

    connections = _tcp_connections(lines)

    assert connections["12345"].host == "8.8.8.8"
    assert connections["12345"].port == 443
    assert "54321" not in connections


def test_selected_processes_filters_by_process_name(tmp_path):
    ollama = tmp_path / "100"
    ollama.mkdir()
    (ollama / "comm").write_text("ollama\n", encoding="utf-8")
    other = tmp_path / "200"
    other.mkdir()
    (other / "comm").write_text("python\n", encoding="utf-8")

    assert _selected_processes(tmp_path, ("ollama",)) == {100: "ollama"}


def test_runtime_monitor_keeps_running_when_event_callback_fails(tmp_path):
    from ai_antivirus.linux_runtime import LinuxRuntimeMonitor

    process = tmp_path / "100"
    process.mkdir()
    (process / "comm").write_text("ollama\n", encoding="utf-8")
    (tmp_path / "net").mkdir()
    (tmp_path / "net" / "tcp").write_text("sl local_address rem_address st\n", encoding="utf-8")
    monitor = LinuxRuntimeMonitor(lambda event: (_ for _ in ()).throw(RuntimeError("audit unavailable")), proc_root=tmp_path)

    monitor.poll_once()

    assert monitor.polls == 1
    assert monitor.last_error == "audit unavailable"
