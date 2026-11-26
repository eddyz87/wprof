#!/usr/bin/env python3
"""Kernel test harness using only the Python standard library."""
from collections import defaultdict
from collections.abc import Callable, Hashable, Mapping, Sequence
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
import difflib
import gzip
import importlib.util
import inspect
import json
import logging
import multiprocessing
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
import traceback

TEST_DIR = Path(__file__).resolve().parent
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


def open_artifact(path: Path) -> IO[str]:
    if path.suffix == ".gz":
        return gzip.open(path, "rt")
    if path.exists():
        return path.open()
    return gzip.open(path.with_name(path.name + ".gz"), "rt")


def compress_artifacts(directory: Path) -> None:
    # Writers have finished; remove originals only after compression succeeds.
    for path in directory.rglob("*"):
        if path.is_file() and path.suffix in (".json", ".log"):
            compressed = path.with_name(path.name + ".gz")
            with path.open("rb") as source, gzip.open(compressed, "wb", compresslevel=1) as target:
                shutil.copyfileobj(source, target)
            path.unlink()


class JsonTrace:
    def __init__(self, path: Path) -> None:
        self.path = path
        decoder = json.JSONDecoder(object_hook=lambda fields: SimpleNamespace(**fields))
        with open_artifact(path) as stream:
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
        with open_artifact(self.directory / "wprof-stdout.log") as stream:
            return stream.read()

    @property
    def stderr(self) -> str:
        with open_artifact(self.directory / "wprof-stderr.log") as stream:
            return stream.read()

    @cached_property
    def json(self) -> JsonTrace:
        return JsonTrace(self.directory / "trace.json")


def assert_no_events(events: Mapping[K, list[SimpleNamespace]], key: K) -> None:
    found = events.get(key, [])
    if found:
        raise AssertionError(
            f"{key!r} unexpectedly present: {len(found)} event(s), "
            f"first: {found[0]!r}"
        )


def assert_equal(actual: object, expected: object) -> None:
    if actual == expected:
        return
    message = f"actual: {actual!r}\nexpected: {expected!r}"
    if isinstance(actual, list) and isinstance(expected, list):
        diff = "\n".join(difflib.unified_diff(expected, actual, fromfile="expected", tofile="actual", lineterm=""))
        if diff:
            message += f"\n{diff}"
    raise AssertionError(message)


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
        # Put wprof's raw output in /tmp. Can't use `self.directory`
        # because wprof memory maps the output file, while VM
        # runners mount the test directory via 9p protocol and mmap
        # is not available.
        recording = self.enter_context(NamedTemporaryFile(
            dir="/tmp",
            prefix=f"wprof-{self.directory.name}-{self.count}-",
            suffix=".data",
        ))
        json_path = self.directory / "trace.json"
        # Touch json file before wprof creates it, such that user
        # running the tests owns it, not the root.
        json_path.touch()
        values = {**substitutions, "data": recording.name, "json": json_path}
        # Substitute after tokenization so spaces and shell metacharacters
        # in values stay inside one argument.
        args = [Template(arg).substitute(values) for arg in shlex.split(parameters)]
        command = "exec " + shlex.join(privileged([str(self.binary), *args]))
        stdout_path = self.directory / "wprof-stdout.log"
        stderr_path = self.directory / "wprof-stderr.log"
        with stdout_path.open("w") as stdout, stderr_path.open("w") as stderr:
            process = self.shell(command, stdout=stdout, stderr=stderr)
        return process, Artifacts(self.directory)


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
        for fd, name in ((1, "test-stdout.log"), (2, "test-stderr.log")):
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
    for path in sorted((TEST_DIR / "cases").glob("*.py")):
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
    artifacts: str | None  # Relative to this report's artifact root. None after cleanup.
    outcome: str = "passed"
    complete: bool = False
    details: list[str] = field(default_factory=list)
    kernel_tag: str | None = None


@dataclass
class ReportData:
    results: list[TestResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    complete: bool = False

    def failed(self) -> bool:
        return bool(self.errors) or any(r.outcome == "failed" for r in self.results)


def read_report(path: Path) -> ReportData:
    data = json.loads(path.read_text())
    data["results"] = [TestResult(**result) for result in data["results"]]
    return ReportData(**data)


# Save progress as we go so an interrupted run leaves a partial report.
class RunReport:
    def __init__(self, path: Path | None, artifact_root: Path, *, kernel_tag: str | None = None,
                 keep_artifacts: bool = False):
        self.path = path
        self.artifact_root = artifact_root
        self.keep_artifacts = keep_artifacts
        self.kernel_tag = kernel_tag
        self.data = ReportData()
        self.start = time.monotonic()
        self.boot_uptime = None

    def write(self):
        if self.path:
            write_report(self.path, self.data)

    def begin(self, name: str, directory: Path) -> TestResult:
        if self.boot_uptime is None:
            self.boot_uptime = time.clock_gettime(time.CLOCK_BOOTTIME)
        self.test_start = time.monotonic()
        record = TestResult(name=name, artifacts=str(directory.relative_to(self.artifact_root)),
                            kernel_tag=self.kernel_tag)
        self.data.results.append(record)
        # Leave an incomplete record if the process or VM dies during this test.
        self.write()
        return record

    def end(self, record: TestResult) -> None:
        record.complete = True
        label, outcome = record.name + ":", record.outcome
        timing = f" {time.monotonic() - self.test_start:7.2f}s" if verbose() else ""
        print(f"{label:<{79 - len(outcome)}} {outcome}{timing}", flush=True)
        if outcome == "failed":
            for message in record.details:
                print(message, flush=True)
        if record.artifacts is not None:
            directory = self.artifact_root / record.artifacts
            if outcome == "passed" and not self.keep_artifacts:
                shutil.rmtree(directory)
                record.artifacts = None
            else:
                if outcome == "failed" or verbose():
                    for name in ("test-stdout.log", "test-stderr.log"):
                        path = directory / name
                        if path.exists() and path.stat().st_size:
                            print(f"Captured {name} ({path}.gz):\n{path.read_text()}", flush=True)
                compress_artifacts(directory)
        self.write()

    def finish(self) -> int:
        self.data.complete = True
        self.write()
        if verbose():
            boot = f"{self.boot_uptime:.2f}s" if self.boot_uptime is not None else "n/a"
            print(f"{len(self.data.results)} tests, done in {time.monotonic() - self.start:.2f}s (boot {boot})")
        return int(self.data.failed())


def runner_main(args: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="selftests.py --runner", fromfile_prefix_chars="@")
    parser.add_argument("tests", nargs="+")
    parser.add_argument("--report-json", type=Path)
    parser.add_argument("--kernel", default="host-no-vm", help="kernel label for reporting (default: %(default)s)")
    parser.add_argument("--artifact-root", type=Path, metavar="DIR",
                        help="directory for test artifacts (default: a new temporary directory)")
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument("--wprof", type=Path, default=TEST_DIR.parent / "src/wprof")
    parser.add_argument("-v", "--verbose", action="count", default=0)
    options = parser.parse_args(args)
    logging.basicConfig(level=logging.INFO if options.verbose else logging.WARNING, format="%(message)s")
    artifact_root = options.artifact_root.resolve() if options.artifact_root else Path(mkdtemp(prefix="wprof-runner-"))
    report = RunReport(options.report_json.resolve() if options.report_json else None, artifact_root,
                       kernel_tag=options.kernel, keep_artifacts=options.keep_artifacts)
    try:
        load_case_modules()
        for name in options.tests:
            if name not in TESTS:
                raise ValueError(f"Unknown test: {name}")
    except Exception:
        message = traceback.format_exc()
        print(message, file=sys.stderr)
        report.data.errors.append(message)
        return report.finish()
    report.write()
    binary = options.wprof.resolve()
    artifact_root.mkdir(parents=True, exist_ok=True)
    try:
        for name in options.tests:
            run_test(name, binary, report)
    except Exception:
        message = traceback.format_exc()
        print(message, file=sys.stderr)
        report.data.errors.append(message)
    return report.finish()


@dataclass
class TestCase:
    run: Callable[[Sh], None]
    requires: frozenset[str]


TESTS: dict[str, TestCase] = {}


def test(function=None, *, requires: Sequence[str] = ()):
    def register(fn: Callable[[Sh], None]):
        TESTS[test_name(fn)] = TestCase(fn, frozenset(requires))
        return fn
    return register if function is None else register(function)


def test_name(function: Callable[[Sh], None]) -> str:
    path = Path(inspect.getfile(function))
    return f"{path.stem}/{function.__name__}"


def run_test(name, binary, report):
    directory = report.artifact_root / name.replace("/", "-")
    directory.mkdir()
    record = report.begin(name, directory)
    try:
        with capture_output(directory), chdir(directory), Sh(directory, binary) as sh:
            try:
                TESTS[name].run(sh)
            except Exception:
                traceback.print_exc()
                raise
    except Exception:
        # A cleanup failure also fails the test; chained tracebacks retain the body failure.
        record.outcome = "failed"
        record.details.append(traceback.format_exc())
    report.end(record)


def hugetlb_available() -> bool:
    info = dict(line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines())
    return int(info.get("HugePages_Total", "0")) > 0


def start_vm(options: argparse.Namespace, vm_id: int, shared_dir: Path,
             guest_command: list[str], *, kernel: Path, hugetlb: bool) -> subprocess.Popen[str]:
    shared_dir = shared_dir.resolve()
    shared_dir.mkdir(parents=True, exist_ok=True)
    # Convert RAM amount from <float> Gb to <int> Mb.
    memory = f"{int(options.vm_memory * 1024)}M"
    # vng passes the image path through a shell when invoking virtme-run.
    command = [
        "vng",
        "--run", shlex.quote(str(kernel.resolve())),
        "--user", "root",
        "--name", f"wprof-vm{vm_id}",
        "--cpus", str(options.vm_cpus),
        "--memory", memory,
        "--disable-microvm",
        "--cwd", str(Path.cwd()),
        "--rwdir", f"{shared_dir}={shared_dir}",
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
    with open_artifact(log_path) as log:
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
        if report.complete is not True:
            report.errors.append("runner did not finish its session")
        return report
    except (OSError, ValueError, KeyError, TypeError) as err:
        return ReportData(errors=[f"{path}: {err}"])


def collect_tests(pattern: str) -> list[str]:
    load_case_modules()
    return [name for name in TESTS if match_test_name(name, pattern)]


def write_report(final_report: Path, report: ReportData) -> None:
    final_report.parent.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(dir=final_report.parent) as staging:
        new = Path(staging) / "report.json"
        new.write_text(json.dumps(asdict(report), indent=2) + "\n")
        new.replace(final_report)


def run_tests_on_host(options: argparse.Namespace, shared_dir: Path,
                      tests: list[str], final_report: Path) -> ReportData:
    runner_args = [*tests, "--wprof", str(options.wprof.resolve()), *(["-v"] * options.verbose),
                   "--artifact-root", str(shared_dir),
                   "--report-json", str(final_report),
                   *(["--keep-artifacts"] if options.keep_artifacts else [])]
    runner_main(runner_args)
    try:
        report = read_report(final_report)
    except (OSError, ValueError, KeyError, TypeError) as err:
        report = ReportData(errors=[f"Cannot read runner report: {err}"], complete=True)
        write_report(final_report, report)
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
# - /tmp/wprof-selftests-current -> /tmp/wprof-selftests-current: read/write:
#   - vm-N.args: runner arguments, removed after the VMs exit.
#   - report-vmN.json: per-VM results, with test names and outcomes, removed after merging.
#   - report.json: combined results and infrastructure errors.
#   - vm-N.log.gz: VNG and guest console output.
#   - some_test/trace.json.gz
#   - some_test/wprof-stdout.log.gz
#   - some_test/wprof-stderr.log.gz
#   - some_test/test-stdout.log.gz
#   - some_test/test-stderr.log.gz
# - _ -> /tmp, guest /tmp is private (to allow mmap'ing files within it).
#
# Test names go in an argument file (vm-N.args):
#
#   --artifact-root
#   /tmp/wprof-selftests-current
#   --report-json
#   /tmp/wprof-selftests-current/report-vm0.json
#   utrace/test_vfs_write_span
#   utrace/test_vfs_write_retprobe
#
# Example VM launch command:
#
#   vng --run /boot/vmlinuz-... --user root --name wprof-vm0 \
#       --cpus 2 --memory 4G --rwdir /tmp/wprof-selftests-current \
#       --disable-microvm --qemu-opts='-machine q35' \
#       --exec '/usr/bin/python3.11 -B -u \
#       /work/wprof/test/selftests.py --runner @/tmp/wprof-selftests-current/vm-0.args'
def run_tests_in_vm(options: argparse.Namespace, shared_dir: Path,
                    tests: list[str], *, kernel: Path, tag: str | None) -> ReportData:
    kernel_label = f"@{tag}" if tag else options.kernel or "host-vm"
    vm_count = min(options.vms, len(tests))
    batches = [tests[i::vm_count] for i in range(vm_count)]
    hugetlb = not options.no_hugetlb and hugetlb_available()
    logging.info("Running %d tests in %d VMs; artifacts: %s",
                 len(tests), vm_count, shared_dir)

    async def run_vms() -> list[int]:
        with ExitStack() as cleanup:
            # One blocking read and wait per VM, plus room for timeout cleanup.
            # Register the pool first so cleanup stops the VMs before joining threads.
            pool = cleanup.enter_context(ThreadPoolExecutor(max_workers=2 * vm_count + 1))
            asyncio.get_running_loop().set_default_executor(pool)
            vm_processes = []
            async with asyncio.TaskGroup() as group:
                for vm_id, batch in enumerate(batches):
                    # Do not mistake a previous run's report for this VM's results.
                    (shared_dir / f"report-vm{vm_id}.json").unlink(missing_ok=True)
                    runner_args = [
                        "--wprof", str(options.wprof.resolve()),
                        # Keep @RECIPE inside the option so argparse won't read it as an argument file.
                        f"--kernel={kernel_label}",
                        *(["-v"] * options.verbose),
                        *(["--keep-artifacts"] if options.keep_artifacts else []),
                        "--artifact-root", str(shared_dir),
                        "--report-json", str(shared_dir / f"report-vm{vm_id}.json"),
                        *batch,
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
                    log = cleanup.enter_context(gzip.open(
                        shared_dir / f"vm-{vm_id}.log.gz", "wt", compresslevel=1))
                    deadline = 0 if options.ssh else time.monotonic() + options.vm_timeout
                    process = start_vm(options, vm_id, shared_dir, guest_command, kernel=kernel, hugetlb=hugetlb)
                    vm_processes.append(process)
                    assert process.stdout is not None
                    stream = cleanup.enter_context(process.stdout)
                    # Kill before closing stdout: a cancelled monitor may still have a blocked reader thread.
                    cleanup.callback(kill, process, as_root=False)
                    group.create_task(log_monitor(stream, log, f"vm{vm_id}: "))
                    group.create_task(wait_vm(process, deadline, log))
            return [process.returncode for process in vm_processes]

    statuses = asyncio.run(run_vms())

    for vm_id in range(vm_count):
        (shared_dir / f"vm-{vm_id}.args").unlink(missing_ok=True)

    results: list[TestResult] = []
    errors: list[str] = []
    for vm_id, (batch, status) in enumerate(zip(batches, statuses)):
        log_path = shared_dir / f"vm-{vm_id}.log.gz"
        report_path = shared_dir / f"report-vm{vm_id}.json"
        if options.ssh and not report_path.exists():
            # An SSH session may end without running the tests.
            report = ReportData()
        else:
            report = read_vm_report(report_path, batch)
        if hugetlb and status != 0:
            maybe_show_hugetlb_warning(log_path)
        if status != 0 and not report.failed():
            report.errors.append(f"VM exited unsuccessfully; see {log_path}")
        for result in report.results:
            if tag and result.artifacts is not None:
                result.artifacts = f"{tag}/{result.artifacts}"
            results.append(result)
        errors.extend(f"VM {vm_id}: {error}" for error in report.errors)
    report = ReportData(results=results, errors=errors, complete=True)
    for vm_id in range(vm_count):
        (shared_dir / f"report-vm{vm_id}.json").unlink(missing_ok=True)
    return report


def prepare_run_directory(base: Path) -> Path:
    base = base.resolve()
    base.mkdir(parents=True, exist_ok=True)
    current = base / "wprof-selftests-current"
    previous = base / "wprof-selftests-previous"
    if current.exists():
        if previous.exists():
            shutil.rmtree(previous)
        current.rename(previous)
    current.mkdir()
    return current


def read_bundle_features(bundle: Path) -> set[str]:
    marker = bundle / "build-inputs"
    if not marker.is_file():
        raise ValueError(f"missing {marker}")
    release = (bundle / "release").read_text().strip()
    modules = bundle / "lib/modules" / release
    for path in (bundle / ".config", bundle / "bzImage", modules / f"vmlinux-{release}", modules / "modules.dep"):
        if not path.is_file():
            raise ValueError(f"missing {path}")
    return set((bundle / "features").read_text().split())


def select_tests(matched: list[str], tag: str | None, pattern: str, features: set[str]) -> list[str]:
    selected = [name for name in matched if TESTS[name].requires <= features]
    label = f"{tag}: " if tag else ""
    if not selected:
        missing = sorted({feature for name in matched for feature in TESTS[name].requires - features})
        print(f"{label}no eligible tests for {pattern!r}; missing kernel features: {', '.join(missing)}")
        return selected

    print(f"{label}selected tests: {len(selected)}", flush=True)
    for name in selected:
        logging.info("%s%s", label, name)
    return selected


def print_summary(report: ReportData, tag: str | None) -> None:
    label = f"{tag}: " if tag else ""
    counts = {outcome: sum(r.complete and r.outcome == outcome for r in report.results)
              for outcome in ("passed", "failed", "skipped")}
    print(f"{label}{counts['passed']} passed, {counts['failed']} failed, {counts['skipped']} skipped, "
          f"{len(report.errors)} infrastructure errors")
    for error in report.errors:
        logging.error("%s%s", label, error)


def launcher_main(args: list[str]) -> int:
    start = time.monotonic()
    parser = argparse.ArgumentParser(
        prog="selftests.py", allow_abbrev=False,
        description="Run selected tests in virtme-ng guests or on the host.",
    )
    parser.add_argument("-t", dest="test_pattern", default="*", metavar="GLOB",
                        help="match FILE or FILE/FUNCTION globs, without the file extension (default: all)")
    parser.add_argument("--wprof", type=Path, default=TEST_DIR.parent / "src/wprof",
                        help="wprof binary to test (default: src/wprof)")
    cache_home = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    parser.add_argument("--cache-dir", type=Path, metavar="DIR", default=cache_home / "wprof-selftests",
                        help="cache containing the kernel bundles built by Make (default: %(default)s)")
    parser.add_argument("--basetemp", type=Path, default=Path("/tmp"),
                        help="parent of wprof-selftests-current and wprof-selftests-previous (default: /tmp)")
    parser.add_argument("--keep-artifacts", action="store_true", help="keep artifacts for passing tests too")
    parser.add_argument("--ssh", nargs="?", type=int, const=2222, metavar="N",
                        help="prepare one VM for manual testing over SSH (default: 2222); disable VM timeout")
    parser.add_argument("--vms", type=int, default=1, help="maximum parallel VMs (default: 1)")
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--no-vm", action="store_true", help="run tests on the host instead of starting VMs")
    selection.add_argument("--kernel", metavar="IMAGE|DIR|@RECIPE",
                           help="boot an image, build tree or managed bundle (default: host's installed image)")
    selection.add_argument("--all-kernels", action="store_true", help="run eligible tests on each configured kernel")
    parser.add_argument("--kernel-features", nargs="*", metavar="GLOB",
                        help="override available kernel features with space-separated names or globs")
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
        if options.all_kernels:
            parser.error("--ssh requires a single target")
        options.vms = 1
    if not options.no_vm and (options.vms < 1 or options.vm_cpus < 1 or
                              options.vm_memory <= 0 or options.vm_timeout <= 0):
        parser.error("--vms, --vm-cpus, --vm-memory and --vm-timeout must be positive")
    logging.basicConfig(level=logging.INFO if options.verbose > 0 else logging.WARNING, format="%(message)s")

    options.cache_dir = options.cache_dir.resolve()
    bundle_tag = options.kernel[1:] if options.kernel and options.kernel.startswith("@") else None
    if options.all_kernels or bundle_tag is not None:
        try:
            tags = subprocess.check_output(["make", "-s", "--no-print-directory", "-C", TEST_DIR, "list-kernel-tags"],
                                           text=True).splitlines()
        except (OSError, subprocess.CalledProcessError) as err:
            parser.error(f"cannot list kernel recipes: {err}")
        if bundle_tag is not None and bundle_tag not in tags:
            parser.error(f"unknown kernel recipe {bundle_tag!r}; choose from {', '.join(tags)}")

    shared_dir = prepare_run_directory(options.basetemp)
    final_report = options.report_json.resolve() if options.report_json else shared_dir / "report.json"
    try:
        matched = collect_tests(options.test_pattern)
    except Exception as err:
        logging.exception("Cannot collect tests")
        failure = ReportData(errors=[f"Test collection failed: {err}"], complete=True)
        write_report(final_report, failure)
        return 1

    def run_for_tag(tag: str | None) -> ReportData:
        features: set[str] = set()
        if tag:
            bundle = options.cache_dir / "bundles" / tag
            kernel = bundle / "bzImage"
            try:
                features = read_bundle_features(bundle)
            except (OSError, ValueError) as err:
                make = ["make", "-C", str(TEST_DIR), f"CACHE_DIR={options.cache_dir}"]
                clean = shlex.join([*make, f"clean-kernel-{tag}"])
                build = shlex.join([*make, f"kernel-{tag}"])
                message = (f"Incomplete kernel bundle: {err}.\n"
                           f"Run {clean} &&\n"
                           f"    {build}")
                return ReportData(errors=[message], complete=True)
        else:
            kernel = Path(options.kernel or f"/boot/vmlinuz-{os.uname().release}")
        if options.kernel_features is not None:
            features = {feature for name in matched for feature in TESTS[name].requires
                        if any(fnmatchcase(feature, pattern) for pattern in options.kernel_features)}
        selected = select_tests(matched, tag, options.test_pattern, features)
        if not selected:
            return ReportData(complete=True)
        directory = shared_dir / tag if tag else shared_dir
        try:
            directory.mkdir(exist_ok=True)
            if options.no_vm:
                return run_tests_on_host(options, directory, selected, final_report)
            else:
                return run_tests_in_vm(options, directory, selected, kernel=kernel, tag=tag)
        except Exception as err:
            logging.exception("%sfailed to run tests", f"{tag}: " if tag else "")
            return ReportData(errors=[str(err)], complete=True)

    if not matched:
        print(f"no tests match {options.test_pattern!r}")
        report = ReportData(complete=True)
        write_report(final_report, report)
        print_summary(report, bundle_tag)
    elif options.all_kernels:
        reports = {}
        combined = ReportData()
        for tag in tags:
            write_report(final_report, combined)
            report = run_for_tag(tag)
            reports[tag] = report
            combined.results.extend(report.results)
            combined.errors.extend(f"{tag}: {error}" for error in report.errors)
        combined.complete = True
        write_report(final_report, combined)
        for tag, report in reports.items():
            print_summary(report, tag)
            for result in report.results:
                if result.outcome == "failed":
                    print(f"  {tag} {result.name}")
        report = combined
    else:
        report = run_for_tag(bundle_tag)
        write_report(final_report, report)
        print_summary(report, bundle_tag)
    print(f"Report: {final_report} (elapsed time: {time.monotonic() - start:.2f}s)")
    return int(report.failed())


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
