from contextlib import ExitStack, contextmanager
from collections.abc import Iterator
from functools import cache
from multiprocessing.process import BaseProcess
import os
from pathlib import Path
import socket
import struct
import subprocess
import time

from selftests import Artifacts, Sh, assert_equal, assert_no_events, privileged, test


NETLINK_SOCK_DIAG = 4
SOCK_DIAG_BY_FAMILY = 20
NLMSG_ERROR = 2
NLMSG_DONE = 3
TCP_ESTABLISHED = 1


class SocketDiagTarget:
    def __init__(self, sock: socket.socket, request: bytes):
        self.sock = sock
        # NLM_F_REQUEST | NLM_F_ROOT | NLM_F_MATCH: dump sockets matching the request.
        self.packet = struct.pack("=IHHII", 16 + len(request), SOCK_DIAG_BY_FAMILY, 0x301, 1, 0) + request

    def dump(self) -> int:
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
                    assert records > 0, "socket diagnostic request returned no socket"
                    return records
                records += kind == SOCK_DIAG_BY_FAMILY
                offset += (size + 3) & ~3

    def run(self) -> None:
        while True:
            self.dump()
            time.sleep(0.01)


@cache
def inet_diag_modules():
    # Modules stay loaded for the session; the intended test environment is a disposable VM.
    for module in ("inet_diag", "tcp_diag"):
        if not Path("/sys/module", module).exists():
            subprocess.run(privileged(["modprobe", module]), check=True, timeout=10)


def sk_diag_fill_module() -> str:
    # TCP's sk_diag_fill lives in inet_diag on v6.16 and tcp_diag on v6.18.
    kallsyms = subprocess.check_output(privileged(["cat", "/proc/kallsyms"]), text=True, timeout=10)
    owners = set()
    for line in kallsyms.splitlines():
        fields = line.split()
        if fields[2] == "sk_diag_fill" and fields[1] in ("t", "T", "w", "W") and int(fields[0], 16):
            owners.add(fields[3] if len(fields) > 3 else "vmlinux")
    modules = owners & {"[inet_diag]", "[tcp_diag]"}
    assert "vmlinux" in owners and len(modules) == 1, f"unexpected sk_diag_fill owners: {owners}"
    return modules.pop()[1:-1]


@contextmanager
def established_tcp_diag() -> Iterator[SocketDiagTarget]:
    inet_diag_modules()
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
        port = listener.getsockname()[1]
        sockid = (struct.pack("!HH", port, 0) + socket.inet_aton("127.0.0.1") + bytes(12)
                  + bytes(16) + struct.pack("=III", 0, 0xffffffff, 0xffffffff))
        request = struct.pack("=BBBBI", socket.AF_INET, socket.IPPROTO_TCP, 0, 0, 1 << TCP_ESTABLISHED) + sockid
        target = SocketDiagTarget(diag, request)
        target.dump()
        yield target


@contextmanager
def netlink_diag() -> Iterator[SocketDiagTarget]:
    with ExitStack() as sockets:
        target = sockets.enter_context(socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 2))  # NETLINK_USERSOCK
        target.bind((0, 0))
        diag = sockets.enter_context(socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_SOCK_DIAG))
        diag.bind((0, 0))
        diag.settimeout(2)
        request = struct.pack("=BBHIIII", socket.AF_NETLINK, 2, 0, 0, 0, 0xffffffff, 0xffffffff)
        query = SocketDiagTarget(diag, request)
        query.dump()
        yield query


@cache
def udp_diag_modules() -> None:
    inet_diag_modules()
    if not Path("/sys/module/udp_diag").exists():
        subprocess.run(privileged(["modprobe", "udp_diag"]), check=True, timeout=10)


@contextmanager
def udp_diag() -> Iterator[SocketDiagTarget]:
    udp_diag_modules()
    with ExitStack() as sockets:
        target = sockets.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        target.bind(("127.0.0.1", 0))
        diag = sockets.enter_context(socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_SOCK_DIAG))
        diag.bind((0, 0))
        diag.settimeout(2)
        request = struct.pack("=BBBBI", socket.AF_INET, socket.IPPROTO_UDP, 0, 0, 0xffffffff) + bytes(48)
        query = SocketDiagTarget(diag, request)
        query.dump()
        yield query


def write_workers(sh: Sh) -> tuple[BaseProcess, BaseProcess]:
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

    return sh.fork(write_workload), sh.fork(pwrite_workload)


def skipped_inline_warnings(artifacts: Artifacts) -> list[str]:
    prefix = "utrace: skipped "
    return [line.partition(prefix)[2] for line in artifacts.stderr.splitlines() if prefix in line]


# Exercise module filtering when kallsyms contains the same function name in
# vmlinux and a TCP diagnostic module. TCP diagnostics call the module's sk_diag_fill;
# netlink diagnostics call the kernel's. An unqualified probe must cover both.
@test
def test_inet_diag_selector(sh: Sh) -> None:
    tcp_diag = sh.enter_context(established_tcp_diag())
    netlink_target = sh.enter_context(netlink_diag())
    tcp_worker = sh.fork(tcp_diag.run)
    netlink_worker = sh.fork(netlink_target.run)
    process, artifacts = sh.wprof(
        """
            -d 1s --no-stacks -p $tcp_pid -p $netlink_pid
            -U 'k:sk_diag_fill | name:bare |'
            -U 'k:vmlinux:sk_diag_fill | name:kernel |'
            -U 'k:$module:sk_diag_fill | name:module |'
            -D "$data" -J "$json"
        """,
        tcp_pid=tcp_worker.pid,
        netlink_pid=netlink_worker.pid,
        module=sk_diag_fill_module(),
    )
    # All three selectors must resolve and attach successfully.
    assert process.wait(timeout=130) == 0, artifacts.stderr
    events = artifacts.json.select_dict(
        t="utrace_instant",
        key=lambda e: (e.task.pid, e.name),
    )
    module_count       = len(events[tcp_worker.pid, "module"])
    tcp_bare_count     = len(events[tcp_worker.pid, "bare"])
    kernel_count       = len(events[netlink_worker.pid, "kernel"])
    netlink_bare_count = len(events[netlink_worker.pid, "bare"])

    # Both workloads must reach their respective sk_diag_fill implementations.
    assert module_count >= 20, f"{module_count=}"
    assert kernel_count >= 20, f"{kernel_count=}"
    # Omitting the module covers both owners, without duplicate attachments.
    # Separate probes can start or stop on opposite sides of one invocation.
    assert abs(tcp_bare_count - module_count) <= 1, f"{tcp_bare_count=}, {module_count=}"
    assert abs(netlink_bare_count - kernel_count) <= 1, f"{netlink_bare_count=}, {kernel_count=}"
    # Explicit selectors must not leak into the other owner's implementation.
    assert_no_events(events, (tcp_worker.pid, "kernel"))
    assert_no_events(events, (netlink_worker.pid, "module"))


# Exercise the union of DWARF and kallsyms targets, including explicit +0.
# In this kernel, write() reaches an inline vfs_write expansion and pwrite()
# calls its standalone body. Syscall exit events provide independent counts;
# return probes can cover only the standalone body.
@test(requires=["vfs-write-inlined"])
def test_vfs_write_inline_and_outline(sh: Sh) -> None:
    writer, pwriter = write_workers(sh)
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
    # Entry, return and syscall probes must all attach.
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
    assert write_count >= 20, f"{write_count=}"
    assert pwrite_count >= 20, f"{pwrite_count=}"
    # Entry probes cover inline write() and standalone pwrite() calls.
    # A syscall may straddle a capture boundary, so counts may differ by one.
    assert abs(write_entry_count - write_count) <= 1, f"{write_entry_count=}, {write_count=}"
    assert abs(pwrite_entry_count - pwrite_count) <= 1, f"{pwrite_entry_count=}, {pwrite_count=}"
    # Explicit +0 preserves both attachments.
    assert abs(write_zero_count - write_count) <= 1, f"{write_zero_count=}, {write_count=}"
    assert abs(pwrite_zero_count - pwrite_count) <= 1, f"{pwrite_zero_count=}, {pwrite_count=}"
    # Return probes cover only standalone calls.
    # Inline expansions have no standalone return site to probe.
    assert abs(return_count - pwrite_count) <= 1, f"{return_count=}, {pwrite_count=}"
    assert_no_events(events, (writer.pid, "return_control"))

    warnings = skipped_inline_warnings(artifacts)
    # Only the return probe warns about the two inline sites it skips.
    assert_equal(warnings, ["2 attachments to inlined functions for probe 'kret:vfs_write | name:return_control |'"])


# Preserve native span behavior without an entry probe requesting DWARF indexing.
# pwrite() calls the standalone vfs_write, producing paired entry/exit events
# with a byte count and result. The inline write() path has no span to attach to.
@test(requires=["vfs-write-inlined"])
def test_vfs_write_span(sh: Sh) -> None:
    writer, pwriter = write_workers(sh)
    process, artifacts = sh.wprof(
        """
            -d 1s --no-stacks -p $write_pid -p $pwrite_pid
            -U 'kspan:vfs_write (arg:2/name(count), arg:ret/name(result)) | name:subject |'
            -U 'tp:syscalls:sys_exit_write | name:write_syscall |'
            -U 'tp:syscalls:sys_exit_pwrite64 | name:pwrite_syscall |'
            -D "$data" -J "$json"
        """,
        write_pid=writer.pid,
        pwrite_pid=pwriter.pid,
    )
    # Both span legs and the syscall controls must attach successfully.
    assert process.wait(timeout=130) == 0, artifacts.stderr
    events = artifacts.json.select_dict(
        lambda e: e.t in ("utrace_instant", "utrace_entry", "utrace_exit"),
        key=lambda e: (e.task.pid, e.t, e.name),
    )
    phases = artifacts.json.select(lambda e: e.task.pid == pwriter.pid, name="subject")
    entries = events[pwriter.pid, "utrace_entry", "subject"]
    exits = events[pwriter.pid, "utrace_exit", "subject"]
    write_count  = len(events[writer.pid, "utrace_instant", "write_syscall"])
    pwrite_count = len(events[pwriter.pid, "utrace_instant", "pwrite_syscall"])
    entry_count  = len(entries)
    exit_count   = len(exits)

    # Both workloads must have run during capture.
    assert write_count >= 20, f"{write_count=}"
    assert pwrite_count >= 20, f"{pwrite_count=}"
    # Each standalone call produces two span phases; allow one boundary event.
    assert abs(entry_count - pwrite_count) <= 1, f"{entry_count=}, {pwrite_count=}"
    assert abs(exit_count - pwrite_count) <= 1, f"{exit_count=}, {pwrite_count=}"
    # Entry arguments and return values must survive span capture.
    assert all(e.args.count == 1 for e in entries)
    assert all(e.args.result == 1 for e in exits)
    # Sequential calls must alternate entry and exit, including partial boundary spans.
    assert all(a.t != b.t for a, b in zip(phases, phases[1:]))
    # The inline path must not generate either leg of a native span.
    assert_no_events(events, (writer.pid, "utrace_entry", "subject"))
    assert_no_events(events, (writer.pid, "utrace_exit", "subject"))
    # No entry probe requests DWARF records, so there are no known inline skips to report.
    assert_equal(skipped_inline_warnings(artifacts), [])


# Exercise span filtering after another spec populates the DWARF function index.
# The entry probe finds inline and standalone vfs_write bodies; both span legs
# must exclude inline bodies while retaining argument capture for pwrite().
@test(requires=["vfs-write-inlined"])
def test_vfs_write_span_with_entry_probe(sh: Sh) -> None:
    writer, pwriter = write_workers(sh)
    process, artifacts = sh.wprof(
        """
            -d 1s --no-stacks -p $write_pid -p $pwrite_pid
            -U 'k:vfs_write | name:index_seed |'
            -U 'kspan:vfs_write (arg:2/name(count), arg:ret/name(result)) | name:subject |'
            -U 'tp:syscalls:sys_exit_write | name:write_syscall |'
            -U 'tp:syscalls:sys_exit_pwrite64 | name:pwrite_syscall |'
            -D "$data" -J "$json"
        """,
        write_pid=writer.pid,
        pwrite_pid=pwriter.pid,
    )
    # The entry probe, both span legs and syscall controls must all attach.
    assert process.wait(timeout=130) == 0, artifacts.stderr
    events = artifacts.json.select_dict(
        lambda e: e.t in ("utrace_instant", "utrace_entry", "utrace_exit"),
        key=lambda e: (e.task.pid, e.t, e.name),
    )
    phases = artifacts.json.select(lambda e: e.task.pid == pwriter.pid, name="subject")
    entries = events[pwriter.pid, "utrace_entry", "subject"]
    exits = events[pwriter.pid, "utrace_exit", "subject"]
    write_count       = len(events[writer.pid, "utrace_instant", "write_syscall"])
    pwrite_count      = len(events[pwriter.pid, "utrace_instant", "pwrite_syscall"])
    write_seed_count  = len(events[writer.pid, "utrace_instant", "index_seed"])
    pwrite_seed_count = len(events[pwriter.pid, "utrace_instant", "index_seed"])
    entry_count       = len(entries)
    exit_count        = len(exits)

    # Both workloads must have run during capture.
    assert write_count >= 20, f"{write_count=}"
    assert pwrite_count >= 20, f"{pwrite_count=}"
    # The seed probe proves that both inline and standalone addresses were found.
    assert abs(write_seed_count - write_count) <= 1, f"{write_seed_count=}, {write_count=}"
    assert abs(pwrite_seed_count - pwrite_count) <= 1, f"{pwrite_seed_count=}, {pwrite_count=}"
    # Only standalone calls produce spans; allow one event at capture boundaries.
    assert abs(entry_count - pwrite_count) <= 1, f"{entry_count=}, {pwrite_count=}"
    assert abs(exit_count - pwrite_count) <= 1, f"{exit_count=}, {pwrite_count=}"
    assert_no_events(events, (writer.pid, "utrace_entry", "subject"))
    assert_no_events(events, (writer.pid, "utrace_exit", "subject"))
    # Resolving through DWARF must preserve the captured arguments and phase order.
    assert all(e.args.count == 1 for e in entries)
    assert all(e.args.result == 1 for e in exits)
    assert all(a.t != b.t for a, b in zip(phases, phases[1:]))
    warning = ("2 attachments to inlined functions for probe "
               "'kspan:vfs_write (arg:2:u64/name(count), arg:ret:s64/name(result)) | name:subject |'")
    # Each span leg resolves targets separately and reports its two excluded inline sites.
    assert_equal(skipped_inline_warnings(artifacts), [warning, warning])


# Preserve return-probe behavior when no entry probe requests DWARF indexing.
# Only the standalone vfs_write called by pwrite() has a return site; its return
# value must still be captured after switching from name to address attachment.
@test(requires=["vfs-write-inlined"])
def test_vfs_write_retprobe(sh: Sh) -> None:
    writer, pwriter = write_workers(sh)
    process, artifacts = sh.wprof(
        """
            -d 1s --no-stacks -p $write_pid -p $pwrite_pid
            -U 'kret:vfs_write (arg:ret/name(result)) | name:subject |'
            -U 'tp:syscalls:sys_exit_write | name:write_syscall |'
            -U 'tp:syscalls:sys_exit_pwrite64 | name:pwrite_syscall |'
            -D "$data" -J "$json"
        """,
        write_pid=writer.pid,
        pwrite_pid=pwriter.pid,
    )
    # The return probe and syscall controls must attach successfully.
    assert process.wait(timeout=130) == 0, artifacts.stderr
    events = artifacts.json.select_dict(t="utrace_instant", key=lambda e: (e.task.pid, e.name))
    returns = events[pwriter.pid, "subject"]
    write_count  = len(events[writer.pid, "write_syscall"])
    pwrite_count = len(events[pwriter.pid, "pwrite_syscall"])
    return_count = len(returns)

    # Both workloads must have run during capture.
    assert write_count >= 20, f"{write_count=}"
    assert pwrite_count >= 20, f"{pwrite_count=}"
    # Each standalone call returns one byte; allow one event at capture boundaries.
    assert abs(return_count - pwrite_count) <= 1, f"{return_count=}, {pwrite_count=}"
    assert all(e.args.result == 1 for e in returns)
    # An inline expansion has no standalone return site.
    assert_no_events(events, (writer.pid, "subject"))
    # Without indexed inline records, the return probe has no inline skips to report.
    assert_equal(skipped_inline_warnings(artifacts), [])


# Exercise return-probe filtering with inline records present in the DWARF index.
# The entry probe indexes both forms of vfs_write; the return probe must exclude
# inline sites and report the omission once, while pwrite() still yields results.
@test(requires=["vfs-write-inlined"])
def test_vfs_write_retprobe_with_entry_probe(sh: Sh) -> None:
    writer, pwriter = write_workers(sh)
    process, artifacts = sh.wprof(
        """
            -d 1s --no-stacks -p $write_pid -p $pwrite_pid
            -U 'k:vfs_write | name:index_seed |'
            -U 'kret:vfs_write (arg:ret/name(result)) | name:subject |'
            -U 'tp:syscalls:sys_exit_write | name:write_syscall |'
            -U 'tp:syscalls:sys_exit_pwrite64 | name:pwrite_syscall |'
            -D "$data" -J "$json"
        """,
        write_pid=writer.pid,
        pwrite_pid=pwriter.pid,
    )
    # Entry, return and syscall probes must all attach successfully.
    assert process.wait(timeout=130) == 0, artifacts.stderr
    events = artifacts.json.select_dict(t="utrace_instant", key=lambda e: (e.task.pid, e.name))
    returns = events[pwriter.pid, "subject"]
    write_count       = len(events[writer.pid, "write_syscall"])
    pwrite_count      = len(events[pwriter.pid, "pwrite_syscall"])
    write_seed_count  = len(events[writer.pid, "index_seed"])
    pwrite_seed_count = len(events[pwriter.pid, "index_seed"])
    return_count      = len(returns)

    # Both workloads must have run during capture.
    assert write_count >= 20, f"{write_count=}"
    assert pwrite_count >= 20, f"{pwrite_count=}"
    # The seed probe verifies that both forms are present in the indexed targets.
    assert abs(write_seed_count - write_count) <= 1, f"{write_seed_count=}, {write_count=}"
    assert abs(pwrite_seed_count - pwrite_count) <= 1, f"{pwrite_seed_count=}, {pwrite_count=}"
    # Return filtering must retain standalone calls and their results, with boundary tolerance.
    assert abs(return_count - pwrite_count) <= 1, f"{return_count=}, {pwrite_count=}"
    assert all(e.args.result == 1 for e in returns)
    assert_no_events(events, (writer.pid, "subject"))
    # Report one summary for the two inline sites excluded from return attachment.
    assert_equal(skipped_inline_warnings(artifacts), [
        "2 attachments to inlined functions for probe 'kret:vfs_write (arg:ret:s64/name(result)) | name:subject |'"
    ])


# Exercise declaration-file filtering before attachment. A full relative path
# and a basename must select the same DWARF records as the unfiltered name:
# on v6.16 this includes inline vfs_write for write() and the standalone body for pwrite().
@test
def test_vfs_write_file_selectors(sh: Sh) -> None:
    writer, pwriter = write_workers(sh)
    process, artifacts = sh.wprof(
        """
            -d 1s --no-stacks -p $write_pid -p $pwrite_pid
            -U 'k:vfs_write | name:unfiltered |'
            -U 'k:vfs_write@fs/read_write.c | name:full_path |'
            -U 'k:vfs_write@read_write.c | name:basename |'
            -U 'tp:syscalls:sys_exit_write | name:write_syscall |'
            -U 'tp:syscalls:sys_exit_pwrite64 | name:pwrite_syscall |'
            -D "$data" -J "$json"
        """,
        write_pid=writer.pid,
        pwrite_pid=pwriter.pid,
    )
    # Both file selectors must resolve through DWARF; kallsyms cannot supply file names.
    assert process.wait(timeout=130) == 0, artifacts.stderr
    events = artifacts.json.select_dict(t="utrace_instant", key=lambda e: (e.task.pid, e.name))
    write_count           = len(events[writer.pid, "write_syscall"])
    pwrite_count          = len(events[pwriter.pid, "pwrite_syscall"])
    write_unfiltered      = len(events[writer.pid, "unfiltered"])
    pwrite_unfiltered     = len(events[pwriter.pid, "unfiltered"])
    write_full_path       = len(events[writer.pid, "full_path"])
    pwrite_full_path      = len(events[pwriter.pid, "full_path"])
    write_basename        = len(events[writer.pid, "basename"])
    pwrite_basename       = len(events[pwriter.pid, "basename"])

    # Both workloads must have run during capture.
    assert write_count >= 20, f"{write_count=}"
    assert pwrite_count >= 20, f"{pwrite_count=}"
    # Unfiltered probes cover both forms; allow one event at capture boundaries.
    assert abs(write_unfiltered - write_count) <= 1, f"{write_unfiltered=}, {write_count=}"
    assert abs(pwrite_unfiltered - pwrite_count) <= 1, f"{pwrite_unfiltered=}, {pwrite_count=}"
    # The complete declaration path must retain both inline and standalone bodies.
    assert abs(write_full_path - write_count) <= 1, f"{write_full_path=}, {write_count=}"
    assert abs(pwrite_full_path - pwrite_count) <= 1, f"{pwrite_full_path=}, {pwrite_count=}"
    # Matching only the final path component must retain those same bodies.
    assert abs(write_basename - write_count) <= 1, f"{write_basename=}, {write_count=}"
    assert abs(pwrite_basename - pwrite_count) <= 1, f"{pwrite_basename=}, {pwrite_count=}"
    # Entry probes do not exclude inline sites, so no skip summary is expected.
    assert_equal(skipped_inline_warnings(artifacts), [])


# A correct basename under the wrong directory must not match fs/read_write.c.
# Resolution happens before capture; a file selector must also prevent kallsyms
# fallback from silently attaching to the otherwise valid vfs_write symbol.
@test
def test_vfs_write_wrong_directory(sh: Sh) -> None:
    process, artifacts = sh.wprof("""
        -d 1s --no-stacks -U 'k:vfs_write@net/read_write.c' -D "$data" -J "$json"
    """)
    # Reject the unresolved selector cleanly, rather than crashing or capturing.
    assert process.wait(timeout=130) > 0, artifacts.stderr
    # The error must come from target resolution for this exact probe.
    assert "utrace: failed to resolve kernel probe 'k:vfs_write@net/read_write.c': -ESRCH" in artifacts.stderr


# A suffix must start at a path-component boundary. ead_write.c is a string
# suffix of read_write.c, but not a declaration-file selector for that file.
@test
def test_vfs_write_partial_basename(sh: Sh) -> None:
    process, artifacts = sh.wprof("""
        -d 1s --no-stacks -U 'k:vfs_write@ead_write.c' -D "$data" -J "$json"
    """)
    # Reject a suffix beginning in the middle of a basename.
    assert process.wait(timeout=130) > 0, artifacts.stderr
    # Do not hide the file mismatch by falling back to the bare kallsyms name.
    assert "utrace: failed to resolve kernel probe 'k:vfs_write@ead_write.c': -ESRCH" in artifacts.stderr


# Check the same component-boundary rule for a suffix containing a slash:
# s/read_write.c must not match fs/read_write.c just because it ends the path.
@test
def test_vfs_write_partial_directory(sh: Sh) -> None:
    process, artifacts = sh.wprof("""
        -d 1s --no-stacks -U 'k:vfs_write@s/read_write.c' -D "$data" -J "$json"
    """)
    # A slash inside the selector does not excuse a partial first component.
    assert process.wait(timeout=130) > 0, artifacts.stderr
    # Resolution must fail for the file-qualified probe itself.
    assert "utrace: failed to resolve kernel probe 'k:vfs_write@s/read_write.c': -ESRCH" in artifacts.stderr


# Exercise named-module and any-module lookup for a module-only function.
# Repeated UDP socket diagnostic dumps call udp_diag_dump in udp_diag; the
# bare and qualified probes must observe the same invocations.
@test
def test_udp_diag_module_selector(sh: Sh) -> None:
    diag = sh.enter_context(udp_diag())
    worker = sh.fork(diag.run)
    process, artifacts = sh.wprof(
        """
            -d 1s --no-stacks -p $pid
            -U 'k:udp_diag:udp_diag_dump | name:qualified |'
            -U 'k:udp_diag_dump | name:bare |'
            -D "$data" -J "$json"
        """,
        pid=worker.pid,
    )
    # Both explicit-module and unqualified lookup must find the module symbol.
    assert process.wait(timeout=130) == 0, artifacts.stderr
    events = artifacts.json.select_dict(
        lambda e: e.task.pid == worker.pid, t="utrace_instant", key=lambda e: e.name,
    )
    qualified_count = len(events["qualified"])
    bare_count      = len(events["bare"])

    # The workload must reach the module's diagnostic dump handler.
    assert qualified_count >= 20, f"{qualified_count=}"
    # Any-module lookup must cover the same handler, with one boundary event allowed.
    assert abs(bare_count - qualified_count) <= 1, f"{bare_count=}, {qualified_count=}"


# Explicit module selection must restrict lookup even when another loaded
# module owns a symbol with the requested name. tcp_diag exists, but the
# udp_diag_dump symbol belongs to udp_diag, so resolution must fail.
@test
def test_udp_diag_wrong_module(sh: Sh) -> None:
    udp_diag_modules()
    process, artifacts = sh.wprof("""
        -d 1s --no-stacks -U 'k:tcp_diag:udp_diag_dump' -D "$data" -J "$json"
    """)
    # A loaded but incorrect module must not act like an unspecified module.
    assert process.wait(timeout=130) > 0, artifacts.stderr
    # Verify the specific resolution error rather than an unrelated startup failure.
    assert "utrace: failed to resolve kernel probe 'k:tcp_diag:udp_diag_dump': -ESRCH" in artifacts.stderr


# Exercise nonzero-offset filtering and the legacy address-attachment failure
# path. On this x86-64 kernel the large offset is outside kernel text. Inline
# sites must be excluded before the remaining standalone target fails to attach.
@test(requires=["vfs-write-inlined"])
def test_vfs_write_invalid_offset(sh: Sh) -> None:
    process, artifacts = sh.wprof("""
        -d 1s --no-stacks -U 'k:vfs_write+0x7fffffff' -D "$data" -J "$json"
    """)
    # A failed attachment must produce a normal error exit, not a crash.
    assert process.wait(timeout=130) > 0, artifacts.stderr
    # The function was resolved; failure must occur when attaching its adjusted address.
    assert "utrace: failed to attach kprobe to 'vfs_write' at 0x" in artifacts.stderr
    # A nonzero offset must skip the two inline bodies and summarize the omission once.
    assert_equal(skipped_inline_warnings(artifacts), [
        "2 attachments to inlined functions for probe 'k:vfs_write+0x7fffffff'"
    ])
