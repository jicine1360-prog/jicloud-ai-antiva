from pathlib import Path
import os
import sys

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from ai_antivirus.linux_runtime import DEFAULT_PROCESS_NAMES, _selected_processes, _tcp_connections


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


def test_tcp_connections_parses_a_real_proc_net_tcp_line():
    # Copied from a live /proc/net/tcp ESTABLISHED entry: the field count and
    # the inode position (index 9) must stay correct.
    lines = iter(
        [
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref cnt",
            "  44: 0900A8C0:CD4C 12E9D17D:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 29921759 1 0000000000000000 20 4 32 10 -1",
        ]
    )

    connections = _tcp_connections(lines)

    assert connections["29921759"].host == "125.209.233.18"
    assert connections["29921759"].port == 443


def test_long_process_name_matches_the_truncated_comm(tmp_path):
    launcher = tmp_path / "300"
    launcher.mkdir()
    # The kernel truncates comm to 15 characters.
    (launcher / "comm").write_text("text-generation\n", encoding="utf-8")

    assert _selected_processes(tmp_path, DEFAULT_PROCESS_NAMES) == {300: "text-generation-launcher"}


def test_interpreter_hosted_runtime_matches_its_command_line(tmp_path):
    vllm = tmp_path / "400"
    vllm.mkdir()
    (vllm / "comm").write_text("python3\n", encoding="utf-8")
    (vllm / "cmdline").write_bytes(
        b"python3\0-m\0vllm.entrypoints.openai.api_server\0--model\0/srv/models/x\0"
    )

    assert _selected_processes(tmp_path, DEFAULT_PROCESS_NAMES) == {400: "vllm"}


def test_executable_path_matches_when_command_line_is_empty(tmp_path):
    served = tmp_path / "500"
    served.mkdir()
    (served / "comm").write_text("llama-server\n", encoding="utf-8")
    (served / "cmdline").write_bytes(b"")
    os.symlink("/usr/local/bin/llama-server", served / "exe")

    assert _selected_processes(tmp_path, DEFAULT_PROCESS_NAMES) == {500: "llama-server"}


def test_unreadable_process_entries_are_skipped(tmp_path):
    hidden = tmp_path / "600"
    hidden.mkdir()

    assert _selected_processes(tmp_path, DEFAULT_PROCESS_NAMES) == {}


def test_runtime_monitor_survives_a_missing_proc_net_tcp(tmp_path):
    from ai_antivirus.linux_runtime import LinuxRuntimeMonitor

    events = []
    monitor = LinuxRuntimeMonitor(events.append, proc_root=tmp_path)

    monitor.poll_once()

    assert monitor.polls == 1
    assert "net/tcp" in monitor.last_error
    assert events == []


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
