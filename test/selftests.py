#!/usr/bin/env python3
"""Kernel test harness using only the Python standard library."""
from collections import defaultdict
from collections.abc import Callable, Hashable
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, chdir, contextmanager
from dataclasses import asdict, dataclass, field
from fnmatch import fnmatchcase
from functools import cached_property
from multiprocessing.process import BaseProcess
from pathlib import Path
from string import Template
from tempfile import NamedTemporaryFile, TemporaryDirectory, mkdtemp
from types import SimpleNamespace
from typing import Any, IO, TypeVar
import argparse
import asyncio
import importlib.util
import inspect
import json
import logging
import multiprocessing
import os
import re
import shlex
import subprocess
import sys
import time
import traceback


K = TypeVar("K", bound=Hashable)


def verbose() -> bool:
    return logging.getLogger().isEnabledFor(logging.INFO)


def privileged(command):
    return command if os.geteuid() == 0 else ["sudo", "-n", *command]


def kill(process, *, as_root: bool = True):
    if isinstance(process, subprocess.Popen):
        if process.poll() is not None:
            return
        # Processes have their own process group. The profiler may run through
        # sudo, while VNG and its children belong to the host user.
        command = ["kill", "-TERM", "--", f"-{process.pid}"]
        subprocess.run(privileged(command) if as_root else command,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            command = ["kill", "-KILL", "--", f"-{process.pid}"]
            subprocess.run(privileged(command) if as_root else command,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
            process.wait(timeout=5)
    else:
        exitcode = process.exitcode
        if process.is_alive():
            process.terminate()
            process.join(timeout=5)
        if process.is_alive():
            process.kill()
        process.join()
        process.close()
        if exitcode not in (None, 0):
            raise AssertionError(f"forked function exited {exitcode}")


class JsonTrace:
    def __init__(self, path: Path) -> None:
        self.path = path
        decoder = json.JSONDecoder(object_hook=lambda fields: SimpleNamespace(**fields))
        with path.open() as stream:
            self.header: SimpleNamespace = decoder.decode(next(stream))
            self.stacks: dict[int, SimpleNamespace] = {}
            for _ in range(self.header.stack_cnt):
                stack = decoder.decode(next(stream))
                self.stacks[stack.id] = stack
            self.events: list[SimpleNamespace] = [decoder.decode(line) for line in stream]

    def select(self, predicate: Callable[[SimpleNamespace], bool] | None = None,
               **filters: object) -> list[SimpleNamespace]:
        """Return event objects matching field equalities and an optional predicate."""
        return [event for event in self.events
                if all(getattr(event, field, None) == value for field, value in filters.items())
                and (predicate is None or predicate(event))]

    def select_dict(self, predicate: Callable[[SimpleNamespace], bool] | None = None, *,
                    key: Callable[[SimpleNamespace], K], **filters: object) -> defaultdict[K, list[SimpleNamespace]]:
        """Group selected events by key(event); missing keys create empty lists."""
        groups: defaultdict[K, list[SimpleNamespace]] = defaultdict(list)
        for event in self.select(predicate, **filters):
            groups[key(event)].append(event)
        return groups


@dataclass
class Artifacts:
    directory: Path

    @property
    def stdout(self) -> str:
        return (self.directory / "stdout.log").read_text()

    @property
    def stderr(self) -> str:
        return (self.directory / "stderr.log").read_text()

    @cached_property
    def json(self) -> JsonTrace:
        return JsonTrace(self.directory / "trace.json")


class Sh(ExitStack):
    def __init__(self, directory: Path, binary: Path):
        super().__init__()
        self.directory = directory
        self.binary = binary
        self.count = 0

    def tempfile(self, **kwargs):
        kwargs.setdefault("dir", "/tmp")
        return self.enter_context(NamedTemporaryFile(**kwargs))

    def tempdir(self, **kwargs) -> Path:
        kwargs.setdefault("dir", "/tmp")
        return Path(self.enter_context(TemporaryDirectory(**kwargs)))

    def fork(self, function: Callable[..., object], *args: Any, **kwargs: Any) -> BaseProcess:
        # Fork preserves local functions and inherited sockets.
        process = multiprocessing.get_context("fork").Process(target=function, args=args, kwargs=kwargs)
        process.start()
        self.callback(kill, process)
        return process

    def shell(self, command: str, **kwargs: Any) -> subprocess.Popen[Any]:
        logging.info("Command: %s", command)
        process = subprocess.Popen(command, shell=True, start_new_session=True, **kwargs)
        self.callback(kill, process)
        return process

    def wprof(self, parameters: str, **substitutions: object) -> tuple[subprocess.Popen[bytes], Artifacts]:
        self.count += 1
        directory = self.directory / f"capture-{self.count}"
        directory.mkdir()
        # Put wprof's raw output in /tmp. Can't use `directory`
        # because wprof memory maps the output file, while VM
        # runners mount the `directory` via 9p protocol and mmap
        # is not available.
        recording = self.enter_context(NamedTemporaryFile(
            dir="/tmp",
            prefix=f"wprof-{self.directory.name}-{self.count}-",
            suffix=".data",
        ))
        json_path = directory / "trace.json"
        # Touch json file before wprof creates it, such that user
        # running the tests owns it, not the root.
        json_path.touch()
        values = {**substitutions, "data": recording.name, "json": json_path}
        # Substitute after tokenization so spaces and shell metacharacters
        # in values stay inside one argument.
        args = [Template(arg).substitute(values) for arg in shlex.split(parameters)]
        command = "exec " + shlex.join(privileged([str(self.binary), *args]))
        logging.info("Capture directory: %s", directory)
        with (directory / "stdout.log").open("w") as stdout, (directory / "stderr.log").open("w") as stderr:
            process = self.shell(command, stdout=stdout, stderr=stderr)
        return process, Artifacts(directory)


def match_test_name(name: str, pattern: str) -> bool:
    stem, _, function = name.partition("/")
    stem_pattern, separator, function_pattern = pattern.partition("/")
    return fnmatchcase(stem, stem_pattern) and (
        not separator or fnmatchcase(function, function_pattern)
    )


@contextmanager
def capture_output(directory: Path):
    # Capture OS descriptors as well as Python prints, including inherited child output.
    with ExitStack() as cleanup:
        sys.stdout.flush()
        sys.stderr.flush()
        for fd, name in ((1, "stdout.log"), (2, "stderr.log")):
            stream = cleanup.enter_context((directory / name).open("w"))
            saved = os.dup(fd)
            cleanup.callback(os.close, saved)
            cleanup.callback(os.dup2, saved, fd)
            os.dup2(stream.fileno(), fd)
        try:
            yield
        finally:
            sys.stdout.flush()
            sys.stderr.flush()


def load_case_modules():
    for path in sorted((Path(__file__).resolve().parent / "cases").glob("*.py")):
        if path.name.startswith("_"):
            continue
        name = f"_wprof_case_{path.stem}"
        if name not in sys.modules:
            spec = importlib.util.spec_from_file_location(name, path)
            module = importlib.util.module_from_spec(spec)
            sys.modules[name] = module
            spec.loader.exec_module(module)


@dataclass
class TestResult:
    name: str
    artifacts: str
    outcome: str = "passed"
    duration: float = 0.0
    complete: bool = False
    details: list[str] = field(default_factory=list)


@dataclass
class ReportData:
    collected: list[str] = field(default_factory=list)
    results: list[TestResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    exitstatus: int | None = None


def read_report(path: Path) -> ReportData:
    data = json.loads(path.read_text())
    data["results"] = [TestResult(**result) for result in data["results"]]
    return ReportData(**data)


# Save progress as we go; exitstatus stays null until the session finishes.
class RunReport:
    def __init__(self, path: Path | None):
        self.path = path
        self.data = ReportData()
        self.start = time.monotonic()
        self.boot_uptime = None

    def write(self):
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(asdict(self.data), indent=2) + "\n")

    def begin(self, name: str, directory: Path) -> TestResult:
        if self.boot_uptime is None:
            self.boot_uptime = time.clock_gettime(time.CLOCK_BOOTTIME)
        self.test_start = time.monotonic()
        record = TestResult(name=name, artifacts=str(directory))
        self.data.results.append(record)
        # Leave an incomplete record if the process or VM dies during this test.
        self.write()
        return record

    def end(self, record: TestResult) -> None:
        record.duration = time.monotonic() - self.test_start
        record.complete = True
        self.write()
        label, outcome = record.name + ":", record.outcome
        timing = f" {record.duration:7.2f}s" if verbose() else ""
        print(f"{label:<{79 - len(outcome)}} {outcome}{timing}", flush=True)
        if outcome == "failed":
            for message in record.details:
                print(message, flush=True)
        if outcome == "failed" or verbose():
            for name in ("stdout.log", "stderr.log"):
                path = Path(record.artifacts) / name
                if path.exists() and path.stat().st_size:
                    print(f"Captured {name} ({path}):\n{path.read_text()}", flush=True)

    def finish(self, status):
        self.data.exitstatus = status
        self.write()
        if verbose():
            boot = f"{self.boot_uptime:.2f}s" if self.boot_uptime is not None else "n/a"
            print(f"{len(self.data.results)} tests, done in {time.monotonic() - self.start:.2f}s (boot {boot})")
        return status


def runner_main(args: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="selftests.py --runner", fromfile_prefix_chars="@")
    parser.add_argument("tests", nargs="*")
    parser.add_argument("--report-json", type=Path)
    parser.add_argument("--basetemp", type=Path)
    parser.add_argument("--wprof", type=Path, default=Path(__file__).resolve().parent.parent / "src/wprof")
    parser.add_argument("-v", "--verbose", action="count", default=0)
    options = parser.parse_args(args)
    logging.basicConfig(level=logging.INFO if options.verbose else logging.WARNING, format="%(message)s")
    report = RunReport(options.report_json.resolve() if options.report_json else None)
    try:
        load_case_modules()
        selected = options.tests or list(TESTS)
        for name in selected:
            if name not in TESTS:
                raise ValueError(f"Unknown test: {name}")
    except Exception:
        message = traceback.format_exc()
        print(message, file=sys.stderr)
        report.data.errors.append(message)
        return report.finish(1)
    report.data.collected = selected
    report.write()
    if not selected:
        return report.finish(5)
    binary = options.wprof.resolve()
    base = options.basetemp.resolve() if options.basetemp else Path(mkdtemp(prefix="wprof-runner-"))
    base.mkdir(parents=True, exist_ok=True)
    try:
        run_selected(selected, binary, base, report)
    except Exception:
        message = traceback.format_exc()
        print(message, file=sys.stderr)
        report.data.errors.append(message)
    failed = report.data.errors or any(r.outcome == "failed" for r in report.data.results)
    return report.finish(int(bool(failed)))


TESTS: dict[str, Callable[[Sh], None]] = {}


def test(function: Callable[[Sh], None]):
    TESTS[test_name(function)] = function
    return function


class SkipTest(Exception):
    pass


def test_name(function: Callable[[Sh], None]) -> str:
    path = Path(inspect.getfile(function))
    return f"{path.stem}/{function.__name__}"


def run_selected(tests, binary, base, report):
    for name in tests:
        directory = Path(mkdtemp(prefix=name.replace("/", "-") + "-", dir=base))
        record = report.begin(name, directory)
        try:
            with capture_output(directory), chdir(directory), Sh(directory, binary) as sh:
                TESTS[name](sh)
        except SkipTest as err:
            record.outcome = "skipped"
            record.details.append(str(err))
        except Exception:
            # A cleanup failure also fails the test; chained tracebacks retain the body failure.
            record.outcome = "failed"
            record.details.append(traceback.format_exc())
        report.end(record)


def hugetlb_available() -> bool:
    info = dict(line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines())
    return int(info.get("HugePages_Total", "0")) > 0


def start_vm(options: argparse.Namespace, vm_id: int, shared_dir: Path,
             guest_command: list[str], *, hugetlb: bool) -> subprocess.Popen[str]:
    shared_dir = shared_dir.resolve()
    shared_dir.mkdir(parents=True, exist_ok=True)
    # Convert RAM amount from <float> Gb to <int> Mb.
    memory = f"{int(options.vm_memory * 1024)}M"
    # VNG sets up matching installed modules. The read-only host root also
    # exposes /boot and /usr/lib/modules, including vmlinux DWARF.
    command = [
        "vng",
        "--run", str(Path(options.kernel).resolve()),
        "--user", "root",
        "--name", f"wprof-vm{vm_id}",
        "--cpus", str(options.vm_cpus),
        "--memory", memory,
        "--disable-microvm",
        "--cwd", str(Path.cwd()),
        "--rwdir", str(shared_dir),
    ]
    # Use the same machine with and without hugepage backing.
    qemu_opts = ["-machine", "q35"]
    # Empyrical data shows that on (some?) hosts with huge pages pool
    # VM boot is much faster (4x times) if `hugetlb=on` option is
    # passed to QEMU.
    if hugetlb:
        # Unfortunately, VNG does not provide an option to pass
        # `hugetlb` to QEMU.
        # However, a `--numa` parameter suppresses VNG's automatic
        # memory configuration and allows to configure memory device
        # "manually". Use it here as a workaround: create a machine
        # with a single NUMA node.
        command.extend(["--numa", "0,memdev=mem"])
        qemu_opts.extend(["-object", f"memory-backend-memfd,id=mem,size={memory},share=on,hugetlb=on"])
    command.append("--qemu-opts=" + shlex.join(qemu_opts))
    if options.ssh:
        command.extend(["--ssh", str(options.ssh), "--ssh-tcp"])
    # Make sure python environment is always mounted.
    command.extend(["--rodir", f"{sys.prefix}={sys.prefix}"])
    command.extend(["--exec", shlex.join(guest_command)])

    logging.info("VM %d: %s", vm_id, shlex.join(command))
    return subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        start_new_session=True,
    )


async def log_monitor(stream: IO[str], log: IO[str], prefix: str) -> None:
    while line := await asyncio.to_thread(stream.readline):
        log.write(line)
        if line.strip():
            print(prefix + line.rstrip("\n"), flush=True)


async def wait_vm(process: subprocess.Popen[str], deadline: float, log: IO[str]) -> None:
    def wait_and_kill() -> None:
        try:
            timeout = None if deadline == 0 else max(0, deadline - time.monotonic())
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            logging.error("VM killed after a timeout, see %s", log.name)
            kill(process, as_root=False)
            # timeout(1) status
            process.returncode = 124

    await asyncio.to_thread(wait_and_kill)


_hugetlb_warning_shown = False


def maybe_show_hugetlb_warning(log_path: Path) -> None:
    global _hugetlb_warning_shown
    if _hugetlb_warning_shown:
        return
    with log_path.open() as log:
        if any(re.search(r"qemu.*Cannot allocate memory", line) for line in log):
            logging.error(
                "QEMU could not allocate memory with hugetlb enabled; try --no-hugetlb (see %s)",
                log_path)
            _hugetlb_warning_shown = True


def read_vm_report(path: Path, expected: list[str]) -> ReportData:
    try:
        report = read_report(path)
        results = report.results
        names = [result.name for result in results]
        completed = {result.name for result in results if result.complete is True}
        if not isinstance(report.errors, list) or any(not isinstance(e, str) for e in report.errors):
            raise ValueError("invalid errors list")
        if any(result.outcome not in ("passed", "failed", "skipped") for result in results):
            raise ValueError("invalid test outcome")
        if len(names) != len(set(names)) or set(names) - set(expected):
            raise ValueError("duplicate or unexpected test names")
        missing = set(expected) - completed
        if missing:
            report.errors.append("unfinished tests: " + ", ".join(sorted(missing)))
        if report.exitstatus is None:
            report.errors.append("runner did not finish its session")
        return report
    except (OSError, ValueError, KeyError, TypeError) as err:
        return ReportData(errors=[f"{path}: {err}"], exitstatus=1)


def collect_tests(options: argparse.Namespace) -> list[str]:
    collected = []
    load_case_modules()
    for name in TESTS:
        if match_test_name(name, options.test_pattern):
            collected.append(name)
            logging.info("%s", name)
    return collected


def run_tests_on_host(options: argparse.Namespace, shared_dir: Path,
                      collected: list[str]) -> ReportData:
    report_path = shared_dir / "report-host.json"
    runner_args = [*collected, "--wprof", str(options.wprof.resolve()), *(["-v"] * options.verbose),
                   "--report-json", str(report_path)]
    status = runner_main(runner_args)
    try:
        report = read_report(report_path)
    except (OSError, ValueError, KeyError, TypeError) as err:
        report = ReportData(errors=[f"Cannot read runner report: {err}"],
                            exitstatus=status if status != 0 else 1)
    return report


def prepare_ssh_guest(shared_dir: Path, guest_command: list[str], ssh: int) -> list[str]:
    script = shared_dir / "run-selftests.sh"
    script.write_text(
        "#!/bin/sh\n"
        "set -e\n"
        f"cd {shlex.quote(str(Path.cwd()))}\n"
        f"exec {shlex.join(guest_command)}\n"
    )

    # Copy into guest-local /tmp so the script can be edited during the session.
    setup = shared_dir / "ssh-setup.sh"
    setup.write_text(
        "set -e\n"
        f"cp {shlex.quote(str(script))} /tmp/run-selftests.sh\n"
        "chmod +x /tmp/run-selftests.sh\n"
        "echo 'VM started, to connect:'\n"
        f"echo '  vng --ssh-client {ssh} --ssh-tcp'\n"
        f"echo '  ssh -F ~/.cache/virtme-ng/.ssh/virtme-ng-ssh.conf -p {ssh} virtme-ng'\n"
        "echo 'To execute the tests, run /tmp/run-selftests.sh inside the guest.'\n"
        "echo 'Press Ctrl-C in the launcher terminal to stop the VM.'\n"
        "exec sleep infinity\n"
    )
    return ["/bin/sh", str(setup)]


# File system mapping host -> guest:
# - / -> /, read-only.
# - /tmp/wprof-run -> /tmp/wprof-run: read/write:
#   - vm-N.args: runner arguments.
#   - report-vmN.json: per-VM results, with test names and outcomes.
#   - report.json: combined results and infrastructure errors.
#   - vm-N.log: VNG and guest console output.
#   - vm-N-tests/some_test/capture-M/trace.json
#   - vm-N-tests/some_test/capture-M/stdout.log
#   - vm-N-tests/some_test/capture-M/stderr.log
# - _ -> /tmp, guest /tmp is private (to allow mmap'ing files within it).
#
# Test names go in an argument file (vm-N.args):
#
#   --report-json
#   /tmp/wprof-run/report-vm0.json
#   utrace/test_vfs_write_span
#   utrace/test_vfs_write_retprobe
#
# Example VM launch command:
#
#   vng --run /boot/vmlinuz-... --user root --name wprof-vm0 \
#       --cpus 2 --memory 4G --rwdir /tmp/wprof-run \
#       --disable-microvm --qemu-opts='-machine q35' \
#       --rodir /tmp/wprof-venv=/tmp/wprof-venv \
#       --exec '/tmp/wprof-venv/bin/python -B -u \
#       /work/wprof/test/selftests.py --runner @/tmp/wprof-run/vm-0.args'
def run_tests_in_vm(options: argparse.Namespace, shared_dir: Path,
                    collected: list[str]) -> ReportData:
    vm_count = min(options.vms, len(collected))
    batches = [collected[i::vm_count] for i in range(vm_count)]
    hugetlb = not options.no_hugetlb and hugetlb_available()
    logging.info("Running %d tests in %d VMs; artifacts: %s",
                 len(collected), vm_count, shared_dir)

    async def run_vms() -> list[int]:
        with ExitStack() as cleanup:
            # One blocking read and wait per VM, plus room for timeout cleanup.
            # Register the pool first so cleanup stops the VMs before joining threads.
            pool = cleanup.enter_context(ThreadPoolExecutor(max_workers=2 * vm_count + 1))
            asyncio.get_running_loop().set_default_executor(pool)
            vm_processes = []
            async with asyncio.TaskGroup() as group:
                for vm_id, tests in enumerate(batches):
                    # Do not mistake a previous run's report for this VM's results.
                    (shared_dir / f"report-vm{vm_id}.json").unlink(missing_ok=True)
                    runner_args = [
                        "--wprof", str(options.wprof.resolve()),
                        *(["-v"] * options.verbose),
                        # Keep each VM's artifacts separate from the argument files and reports.
                        "--basetemp", str(shared_dir / f"vm-{vm_id}-tests"),
                        "--report-json", str(shared_dir / f"report-vm{vm_id}.json"),
                        *tests,
                    ]
                    args_file = shared_dir / f"vm-{vm_id}.args"
                    # The runner's @file syntax takes one argument per line, without shell quoting.
                    args_file.write_text("\n".join(runner_args) + "\n")
                    guest_command = [
                        sys.executable, "-B", "-u",
                        str(Path(__file__).resolve()), "--runner", f"@{args_file}",
                    ]
                    if options.ssh:
                        guest_command = prepare_ssh_guest(shared_dir, guest_command, options.ssh)
                    log = cleanup.enter_context((shared_dir / f"vm-{vm_id}.log").open("w", buffering=1))
                    deadline = 0 if options.ssh else time.monotonic() + options.vm_timeout
                    process = start_vm(options, vm_id, shared_dir, guest_command, hugetlb=hugetlb)
                    vm_processes.append(process)
                    assert process.stdout is not None
                    stream = cleanup.enter_context(process.stdout)
                    # Kill before closing stdout: a cancelled monitor may still have a blocked reader thread.
                    cleanup.callback(kill, process, as_root=False)
                    group.create_task(log_monitor(stream, log, f"vm{vm_id}: "))
                    group.create_task(wait_vm(process, deadline, log))
            return [process.returncode for process in vm_processes]

    statuses = asyncio.run(run_vms())

    results: list[TestResult] = []
    errors: list[str] = []
    for vm_id, (tests, status) in enumerate(zip(batches, statuses)):
        log_path = shared_dir / f"vm-{vm_id}.log"
        report_path = shared_dir / f"report-vm{vm_id}.json"
        if options.ssh and not report_path.exists():
            # An SSH session may end without running the tests.
            report = ReportData(exitstatus=0)
        else:
            report = read_vm_report(report_path, tests)
        if hugetlb and status != 0:
            maybe_show_hugetlb_warning(log_path)
        if (status != 0 or report.exitstatus != 0) and not report.errors and not any(
            result.outcome == "failed" for result in report.results
        ):
            report.errors.append(f"VM exited unsuccessfully; see {log_path}")
        results.extend(report.results)
        errors.extend(f"VM {vm_id}: {error}" for error in report.errors)
    status = int(any(status != 0 for status in statuses) or bool(errors) or
                 any(result.outcome == "failed" for result in results))
    return ReportData(collected=collected, results=results, errors=errors, exitstatus=status)


def launcher_main(args: list[str]) -> int:
    start = time.monotonic()
    parser = argparse.ArgumentParser(
        prog="selftests.py", allow_abbrev=False,
        description="Run selected tests in virtme-ng guests or on the host.",
    )
    parser.add_argument("-t", dest="test_pattern", default="*", metavar="GLOB",
                        help="match FILE or FILE/FUNCTION globs, without the file extension (default: all)")
    parser.add_argument("--wprof", type=Path, default=Path(__file__).resolve().parent.parent / "src/wprof",
                        help="wprof binary to test (default: src/wprof)")
    parser.add_argument("--no-vm", action="store_true", help="run tests on the host instead of starting VMs")
    parser.add_argument("--ssh", nargs="?", type=int, const=2222, metavar="N",
                        help="prepare one VM for manual testing over SSH (default: 2222); disable VM timeout")
    parser.add_argument("--vms", type=int, default=1, help="maximum parallel VMs (default: 1)")
    parser.add_argument("--kernel", default=f"/boot/vmlinuz-{os.uname().release}", help="guest kernel image")
    parser.add_argument("--vm-cpus", type=int, default=2, help="CPUs per VM (default: 2)")
    parser.add_argument("--vm-memory", type=float, default=4.0, help="memory per VM in GiB (default: 4)")
    parser.add_argument("--no-hugetlb", action="store_true", help="disable hugepage backing for guest RAM")
    parser.add_argument("--vm-timeout", type=float, default=300, help="seconds per VM, including boot (default: 300)")
    parser.add_argument("--report-json", type=Path, help="write results as JSON (default: <output directory>/report.json)")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="show commands and verbose test output")
    options = parser.parse_args(args)
    if options.ssh is not None:
        if not 1 <= options.ssh <= 65535:
            parser.error("--ssh must be a TCP port between 1 and 65535")
        if options.no_vm:
            parser.error("--ssh cannot be combined with --no-vm")
        options.vms = 1
    if not options.no_vm and (options.vms < 1 or options.vm_cpus < 1 or
                              options.vm_memory <= 0 or options.vm_timeout <= 0):
        parser.error("--vms, --vm-cpus, --vm-memory and --vm-timeout must be positive")
    logging.basicConfig(level=logging.INFO if options.verbose > 0 else logging.WARNING, format="%(message)s")

    shared_dir = Path(mkdtemp(prefix="wprof-selftests-", dir="/tmp")).resolve()
    destination = options.report_json.resolve() if options.report_json else shared_dir / "report.json"
    try:
        collected = collect_tests(options)
    except Exception:
        logging.exception("Cannot collect tests")
        report = ReportData(errors=["Test collection failed"], exitstatus=1)
    else:
        if not collected:
            logging.error("No tests match %r", options.test_pattern)
            report = ReportData(exitstatus=5)
        elif options.no_vm:
            report = run_tests_on_host(options, shared_dir, collected)
        else:
            report = run_tests_in_vm(options, shared_dir, collected)

    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(asdict(report), indent=2) + "\n")
    counts = {outcome: sum(r.complete and r.outcome == outcome for r in report.results)
              for outcome in ("passed", "failed", "skipped")}
    elapsed = time.monotonic() - start
    print(f"{counts['passed']} passed, {counts['failed']} failed, {counts['skipped']} skipped, "
          f"{len(report.errors)} infrastructure errors, elapsed time: {elapsed:.2f}s.")
    print(f"Report: {destination}")
    for error in report.errors:
        logging.error("%s", error)
    return int(report.exitstatus)


if __name__ == "__main__":
    # Case modules must import the same registry/classes as this script.
    sys.modules["selftests"] = sys.modules[__name__]
    try:
        args = sys.argv[1:]
        if args and args[0] == "--runner":
            status = runner_main(args[1:])
        else:
            status = launcher_main(args)
    except KeyboardInterrupt:
        # Cleanup has unwound; suppress the traceback and use the conventional Ctrl-C status.
        status = 130
    raise SystemExit(status)
