from contextlib import ExitStack
import os
from pathlib import Path
import socket
import struct
import subprocess
import time

import pytest

from selftests import Sh, privileged


NETLINK_SOCK_DIAG = 4
SOCK_DIAG_BY_FAMILY = 20
NLMSG_ERROR = 2
NLMSG_DONE = 3
TCP_ESTABLISHED = 1


class TcpDiagTarget:
    def __init__(self, sock, port):
        self.sock = sock
        sockid = (struct.pack("!HH", port, 0) + socket.inet_aton("127.0.0.1") + bytes(12)
                  + bytes(16) + struct.pack("=III", 0, 0xffffffff, 0xffffffff))
        request = struct.pack("=BBBBI", socket.AF_INET, socket.IPPROTO_TCP, 0, 0, 1 << TCP_ESTABLISHED) + sockid
        # NLM_F_REQUEST | NLM_F_ROOT | NLM_F_MATCH: dump sockets matching the request.
        self.packet = struct.pack("=IHHII", 16 + len(request), SOCK_DIAG_BY_FAMILY, 0x301, 1, 0) + request

    def dump(self):
        self.sock.sendto(self.packet, (0, 0))
        records = 0
        while True:
            data = self.sock.recv(65536)
            offset = 0
            while offset + 16 <= len(data):
                size, kind = struct.unpack_from("=IH", data, offset)
                if size < 16 or offset + size > len(data):
                    raise RuntimeError("malformed socket diagnostic reply")
                if kind == NLMSG_ERROR:
                    error, = struct.unpack_from("=i", data, offset + 16)
                    if error:
                        raise OSError(-error, "socket diagnostic request failed")
                if kind == NLMSG_DONE:
                    assert records > 0, "socket diagnostic request returned no connection"
                    return records
                records += kind == SOCK_DIAG_BY_FAMILY
                offset += (size + 3) & ~3


@pytest.fixture(scope="session")
def inet_diag_modules():
    # Modules stay loaded for the session; the intended test environment is a disposable VM.
    for module in ("inet_diag", "tcp_diag"):
        if not Path("/sys/module", module).exists():
            subprocess.run(privileged(["modprobe", module]), check=True, timeout=10)

    kallsyms = subprocess.check_output(privileged(["cat", "/proc/kallsyms"]), text=True, timeout=10)
    owners = set()
    for line in kallsyms.splitlines():
        fields = line.split()
        if fields[2] == "sk_diag_fill" and fields[1] in ("t", "T", "w", "W") and int(fields[0], 16):
            owners.add(fields[3] if len(fields) > 3 else "vmlinux")
    assert {"vmlinux", "[inet_diag]"} <= owners, "test requires sk_diag_fill in both vmlinux and inet_diag"


@pytest.fixture
def established_tcp_diag(inet_diag_modules):
    with ExitStack() as sockets:
        listener = sockets.enter_context(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        # Listening sockets bypass sk_diag_fill(); keep both ends established.
        sockets.enter_context(socket.create_connection(listener.getsockname(), timeout=2))
        accepted, _ = listener.accept()
        sockets.enter_context(accepted)

        diag = sockets.enter_context(socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_SOCK_DIAG))
        diag.bind((0, 0))
        diag.settimeout(2)
        target = TcpDiagTarget(diag, listener.getsockname()[1])
        target.dump()
        yield target


@pytest.mark.utrace
def test_inet_diag_selector(sh: Sh, established_tcp_diag: TcpDiagTarget) -> None:
    def workload():
        while True:
            established_tcp_diag.dump()
            time.sleep(0.01)

    worker = sh.fork(workload)
    process, artifacts = sh.wprof(
        """
            -d 1s --no-stacks -p $pid
            -U 'k:sk_diag_fill | name:bare |'
            -U 'k:vmlinux:sk_diag_fill | name:kernel |'
            -U 'k:inet_diag:sk_diag_fill | name:module |'
            -D "$data" -J "$json"
        """,
        pid=worker.pid,
    )
    assert process.wait(timeout=130) == 0, artifacts.stderr
    events = artifacts.json.select_dict(
        lambda event: event.task.pid == worker.pid,
        t="utrace_instant",
        key=lambda event: event.name,
    )
    module_count = len(events["module"])
    bare_count = len(events["bare"])
    assert module_count >= 20
    assert abs(bare_count - module_count) <= 1
    assert "kernel" not in events


@pytest.mark.utrace
def test_vfs_write_inline_and_outline(sh: Sh) -> None:
    def write_workload():
        fd = os.memfd_create("vfs-write-test")
        try:
            while True:
                os.lseek(fd, 0, os.SEEK_SET)
                assert os.write(fd, b"x") == 1
                time.sleep(0.01)
        finally:
            os.close(fd)

    def pwrite_workload():
        fd = os.memfd_create("vfs-pwrite-test")
        try:
            while True:
                assert os.pwrite(fd, b"x", 0) == 1
                time.sleep(0.01)
        finally:
            os.close(fd)

    writer = sh.fork(write_workload)
    pwriter = sh.fork(pwrite_workload)
    process, artifacts = sh.wprof(
        """
            -d 1s --no-stacks -p $write_pid -p $pwrite_pid
            -U 'k:vfs_write | name:entry |'
            -U 'k:vfs_write+0 | name:zero_offset |'
            -U 'kret:vfs_write | name:return_control |'
            -U 'tp:syscalls:sys_exit_write | name:write_syscall |'
            -U 'tp:syscalls:sys_exit_pwrite64 | name:pwrite_syscall |'
            -D "$data" -J "$json"
        """,
        write_pid=writer.pid,
        pwrite_pid=pwriter.pid,
    )
    assert process.wait(timeout=130) == 0, artifacts.stderr
    events = artifacts.json.select_dict(
        t="utrace_instant",
        key=lambda e: (e.task.pid, e.name),
    )
    write_count        = len(events[writer.pid, "write_syscall"])
    write_entry_count  = len(events[writer.pid, "entry"])
    write_zero_count   = len(events[writer.pid, "zero_offset"])
    pwrite_count       = len(events[pwriter.pid, "pwrite_syscall"])
    pwrite_entry_count = len(events[pwriter.pid, "entry"])
    pwrite_zero_count  = len(events[pwriter.pid, "zero_offset"])
    return_count       = len(events[pwriter.pid, "return_control"])

    # Both workloads must have run during capture.
    assert write_count >= 20
    assert pwrite_count >= 20
    # Entry probes cover inline write() and standalone pwrite() calls.
    # A syscall may straddle a capture boundary, so counts may differ by one.
    assert abs(write_entry_count - write_count) <= 1
    assert abs(pwrite_entry_count - pwrite_count) <= 1
    # Explicit +0 preserves both attachments.
    assert abs(write_zero_count - write_count) <= 1
    assert abs(pwrite_zero_count - pwrite_count) <= 1
    # Return probes cover only standalone calls.
    # Inline expansions have no standalone return site to probe.
    assert abs(return_count - pwrite_count) <= 1
    assert (writer.pid, "return_control") not in events

    prefix = "utrace: skipped "
    warnings = [line.partition(prefix)[2] for line in artifacts.stderr.splitlines() if prefix in line]
    # Only the return probe warns about the two inline sites it skips.
    assert warnings == ["2 attachments to inlined functions for probe 'kret:vfs_write | name:return_control |'"]
