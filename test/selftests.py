#!/usr/bin/env python3
"""Kernel test harness and pytest driver."""
from collections import defaultdict
from contextlib import ExitStack
from concurrent.futures import ThreadPoolExecutor
from collections.abc import Callable, Hashable, Iterator
from dataclasses import dataclass
from functools import cached_property
import argparse
import asyncio
import json
import logging
import multiprocessing
from multiprocessing.process import BaseProcess
import os
from pathlib import Path
import re
import shlex
from string import Template
import subprocess
import sys
from tempfile import NamedTemporaryFile, mkdtemp
import time
from types import SimpleNamespace
from typing import Any, IO, TypeVar

import pytest


K = TypeVar("K", bound=Hashable)


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


@dataclass
class Sh:
    fork: Callable[..., BaseProcess]
    shell: Callable[..., subprocess.Popen[Any]]
    wprof: Callable[..., tuple[subprocess.Popen[bytes], Artifacts]]


def absolute_nodeid(item: pytest.Item) -> str:
    # Make the file path absolute while preserving the selector,
    # including any parametrized test ID.
    _, separator, selector = item.nodeid.partition("::")
    return f"{item.path}{separator}{selector}"


# Save completed tests as we go; exitstatus stays null until the session finishes.
class JsonReport:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.collected: list[str] = []
        self.results: dict[str, dict[str, Any]] = {}
        self.errors: list[str] = []
        self.exitstatus: int | None = None

    def write(self) -> None:
        report = dict(collected=self.collected, results=list(self.results.values()),
                      errors=self.errors, exitstatus=self.exitstatus)
        self.path.write_text(json.dumps(report, indent=2) + "\n")

    def pytest_collection_finish(self, session: pytest.Session) -> None:
        self.collected = list(dict.fromkeys(absolute_nodeid(item) for item in session.items))
        self.write()

    def pytest_collectreport(self, report: pytest.CollectReport) -> None:
        if report.failed:
            self.errors.append(report.longreprtext)

    @pytest.hookimpl(wrapper=True, tryfirst=True)
    def pytest_runtest_makereport(self, item, call):
        report = yield
        nodeid = absolute_nodeid(item)
        result = self.results.setdefault(nodeid, dict(
            test=nodeid, outcome="passed", duration=0.0, complete=False, details=[],
        ))
        # Keep pytest's durations and combine setup, call, and teardown into
        # one result. A passing teardown must not hide an earlier failure.
        result["duration"] += report.duration
        if report.failed:
            result["outcome"] = "failed"
        elif report.skipped and result["outcome"] == "passed":
            result["outcome"] = "skipped"
        if report.failed or report.skipped:
            result["details"].append(dict(phase=report.when, message=report.longreprtext))
        if report.when == "teardown":
            result["complete"] = True
            self.write()
        return report

    def pytest_sessionfinish(self, session: pytest.Session, exitstatus: int) -> None:
        self.exitstatus = int(exitstatus)
        self.write()

    def pytest_internalerror(self, excrepr) -> None:
        self.errors.append(str(excrepr))


class ProgressReport:
    def __init__(self) -> None:
        # Pytest reports each phase separately; retain failures and skips until teardown.
        self.outcomes: dict[str, str] = {}

    @pytest.hookimpl(wrapper=True)
    def pytest_report_teststatus(self, report, config):
        # Keep pytest's categories and summary labels, but suppress progress characters.
        category, _, word = yield
        return category, "", word

    @pytest.hookimpl(trylast=True)
    def pytest_runtest_logreport(self, report: pytest.TestReport) -> None:
        # A passing teardown must not hide an earlier failure.
        if report.failed:
            self.outcomes[report.nodeid] = "failed"
        elif report.skipped:
            self.outcomes.setdefault(report.nodeid, "skipped")

        if report.when == "teardown":
            label = f"{report.nodeid}:"
            outcome = self.outcomes.pop(report.nodeid, "passed")
            print(f"{label:<{79 - len(outcome)}} {outcome}", flush=True)


def pytest_addoption(parser):
    parser.addoption("--wprof", default=str(Path(__file__).resolve().parent.parent / "src/wprof"),
                     help="wprof binary to test (default: src/wprof)")
    parser.addoption("--report-json", type=Path, help="write test collection and results as JSON")


@pytest.hookimpl(tryfirst=True)
def pytest_configure(config):
    config.pluginmanager.register(ProgressReport(), "wprof-progress")
    if config.option.report_json:
        config.pluginmanager.register(JsonReport(config.option.report_json.resolve()), "wprof-json-report")
    if (config.option.verbose > 0 and config.option.log_cli_level is None and
        config.getini("log_cli_level") in (None, "")):
        config.option.log_cli_level = "INFO"
    config.addinivalue_line("python_files", "*.py")
    config.addinivalue_line("markers", "utrace: kernel utrace tests")


@pytest.hookimpl(wrapper=True)
def pytest_cmdline_main(config):
    result = yield
    if config.option.help:
        print("\nwprof selftests:\n"
              "  Use -v (or --log-cli-level=INFO) to show commands and capture\n"
              "  directories while tests run.\n"
              "  An explicit log level takes precedence.")
    return result


@pytest.fixture(scope="session")
def wprof_binary(pytestconfig, tmp_path_factory):
    binary = Path(pytestconfig.getoption("--wprof")).resolve()
    directory = tmp_path_factory.mktemp("wprof-schema")
    schema = subprocess.check_output([str(binary), "--json-schema"], text=True, timeout=10)
    (directory / "json-schema.md").write_text(schema)
    return binary


@pytest.fixture
def sh(tmp_path: Path, wprof_binary: Path) -> Iterator[Sh]:
    with ExitStack() as cleanup:
        count = 0

        def fork(function: Callable[..., object], *args: Any, **kwargs: Any) -> BaseProcess:
            # Fork preserves local functions and sockets inherited from fixtures.
            process = multiprocessing.get_context("fork").Process(target=function, args=args, kwargs=kwargs)
            process.start()
            cleanup.callback(kill, process)
            return process

        def shell(command: str, **kwargs: Any) -> subprocess.Popen[Any]:
            logging.info("Command: %s", command)
            process = subprocess.Popen(command, shell=True, start_new_session=True, **kwargs)
            cleanup.callback(kill, process)
            return process

        def wprof(parameters: str, **substitutions: object) -> tuple[subprocess.Popen[bytes], Artifacts]:
            nonlocal count
            count += 1
            directory = tmp_path / f"capture-{count}"
            directory.mkdir()
            # Put wprof's raw output in /tmp. Can't use `directory`
            # because wprof memory maps the output file, while VM
            # runners mount the `directory` via 9p protocol and mmap
            # is not available.
            recording = cleanup.enter_context(NamedTemporaryFile(
                dir="/tmp",
                prefix=f"wprof-{tmp_path.name}-{count}-",
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
            command = "exec " + shlex.join(privileged([str(wprof_binary), *args]))
            logging.info("Capture directory: %s", directory)
            with (directory / "stdout.log").open("w") as stdout, (directory / "stderr.log").open("w") as stderr:
                process = shell(command, stdout=stdout, stderr=stderr)
            return process, Artifacts(directory)

        yield Sh(fork=fork, shell=shell, wprof=wprof)


def runner_main(args: list[str]) -> int:
    # -o overrides a pytest configuration option. testpaths supplies the default
    # discovery directory; explicit file paths or node IDs take precedence.
    # Disable XML and cache output, including when options come from an @file.
    return int(pytest.main(
        ["-o", f"testpaths={Path(__file__).resolve().parent / 'cases'}", *args,
         # Our reporter handles progress; retain pytest's failure diagnostics.
         "-o", "verbosity_test_cases=-1", "-o", "console_output_style=classic",
         "-p", "no:junitxml", "-p", "no:cacheprovider"],
        plugins=[sys.modules[__name__]],
    ))


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
        print(prefix + line.rstrip("\n"), flush=True)


async def wait_vm(process: subprocess.Popen[str], deadline: float, log: IO[str]) -> None:
    def wait_and_kill() -> None:
        try:
            process.wait(timeout=max(0, deadline - time.monotonic()))
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


def read_vm_report(path: Path, expected: list[str]) -> dict[str, Any]:
    try:
        report = json.loads(path.read_text())
        results = report["results"]
        ids = [result["test"] for result in results]
        completed = {result["test"] for result in results if result["complete"] is True}
        if not isinstance(report["errors"], list) or any(not isinstance(e, str) for e in report["errors"]):
            raise ValueError("invalid errors list")
        if any(result["outcome"] not in ("passed", "failed", "skipped") for result in results):
            raise ValueError("invalid test outcome")
        if len(ids) != len(set(ids)) or set(ids) - set(expected):
            raise ValueError("duplicate or unexpected test IDs")
        missing = set(expected) - completed
        if missing:
            report["errors"].append("unfinished tests: " + ", ".join(sorted(missing)))
        if report["exitstatus"] is None:
            report["errors"].append("runner did not finish its session")
        return report
    except (OSError, ValueError, KeyError, TypeError) as err:
        return dict(results=[], errors=[f"{path}: {err}"], exitstatus=1)


def collect_tests(options: argparse.Namespace, collection_path: Path) -> tuple[int, dict[str, Any]]:
    collection_path.unlink(missing_ok=True)
    # Apply selectors during collection only. Each guest receives its assigned
    # node IDs as positional arguments, without the original paths or filters.
    command = [sys.executable, "-B", "-u", str(Path(__file__).resolve()), "runner",
               *options.tests, "--collect-only", "--report-json", str(collection_path),
               *(["-v"] * options.verbose)]
    if options.keyword:
        command.extend(["-k", options.keyword])
    if options.markexpr:
        command.extend(["-m", options.markexpr])
    status = subprocess.call(command)
    if status not in (0, pytest.ExitCode.NO_TESTS_COLLECTED):
        return status, {}
    try:
        collection = json.loads(collection_path.read_text())
        collection["collected"] = list(dict.fromkeys(collection["collected"]))
    except (OSError, ValueError, KeyError, TypeError) as err:
        logging.error("Cannot read collected tests from %s: %s", collection_path, err)
        return 1, {}
    return 0, collection


def run_tests_on_host(options: argparse.Namespace, shared_dir: Path) -> dict[str, Any]:
    report_path = shared_dir / "report-host.json"
    runner_args = [*options.tests, "--wprof", str(options.wprof.resolve()), *(["-v"] * options.verbose),
                   "--report-json", str(report_path)]
    if options.keyword:
        runner_args.extend(["-k", options.keyword])
    if options.markexpr:
        runner_args.extend(["-m", options.markexpr])
    status = runner_main(runner_args)
    try:
        report = json.loads(report_path.read_text())
    except (OSError, ValueError) as err:
        report = dict(collected=[], results=[], errors=[f"Cannot read runner report: {err}"],
                      exitstatus=status if status != 0 else 1)
    return report


# File system mapping host -> guest:
# - / -> /, read-only.
# - /tmp/wprof-run -> /tmp/wprof-run: read/write:
#   - vm-N.args: pytest arguments.
#   - collection.json: selected test IDs from the runner.
#   - report-vmN.json: per-VM results, with exact test IDs and outcomes.
#   - report.json: combined results and infrastructure errors.
#   - vm-N.log: VNG and guest console output.
#   - vm-N-tests/some_test/capture-M/trace.json
#   - vm-N-tests/some_test/capture-M/stdout.log
#   - vm-N-tests/some_test/capture-M/stderr.log
# - _ -> /tmp, guest /tmp is private (to allow mmap'ing files within it).
#
# Test IDs go in an argument file (vm-N.args):
#
#   --report-json
#   /tmp/wprof-run/report-vm0.json
#   /work/wprof/test/cases/utrace.py::test_vfs_write_span
#   /work/wprof/test/cases/utrace.py::test_vfs_write_retprobe
#
# Example VM launch command:
#
#   vng --run /boot/vmlinuz-... --user root --name wprof-vm0 \
#       --cpus 2 --memory 4G --rwdir /tmp/wprof-run \
#       --disable-microvm --qemu-opts='-machine q35' \
#       --rodir /tmp/wprof-venv=/tmp/wprof-venv \
#       --exec '/tmp/wprof-venv/bin/python -B -u /work/wprof/test/selftests.py runner @/tmp/wprof-run/vm-0.args'
def run_tests_in_vm(options: argparse.Namespace, shared_dir: Path) -> dict[str, Any]:
    status, collection = collect_tests(options, shared_dir / "collection.json")
    if status != 0:
        return dict(collected=[],
                    results=[],
                    errors=[f"Test collection failed (exit status {status})"],
                    exitstatus=status)

    node_ids = collection["collected"]
    vm_count = min(options.vms, len(node_ids))
    if vm_count == 0:
        logging.error("No tests matched the selection")
        return dict(collected=[], results=[], errors=[], exitstatus=5)
    batches = [node_ids[i::vm_count] for i in range(vm_count)]
    hugetlb = not options.no_hugetlb and hugetlb_available()
    logging.info("Running %d tests in %d VMs; artifacts: %s",
                 len(node_ids), vm_count, shared_dir)

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
                        # Pytest clears its base directory. Keep each VM's directory separate
                        # from the argument files, reports, and other VMs' artifacts.
                        "--basetemp", str(shared_dir / f"vm-{vm_id}-tests"),
                        "--report-json", str(shared_dir / f"report-vm{vm_id}.json"),
                        *tests,
                    ]
                    args_file = shared_dir / f"vm-{vm_id}.args"
                    # Pytest's @file syntax takes one argument per line, without shell quoting.
                    args_file.write_text("\n".join(runner_args) + "\n")
                    guest_command = [
                        sys.executable, "-B", "-u",
                        str(Path(__file__).resolve()), "runner", f"@{args_file}",
                    ]
                    log = cleanup.enter_context((shared_dir / f"vm-{vm_id}.log").open("w", buffering=1))
                    deadline = time.monotonic() + options.vm_timeout
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

    results: list[dict[str, Any]] = []
    errors: list[str] = []
    for vm_id, (tests, status) in enumerate(zip(batches, statuses)):
        log_path = shared_dir / f"vm-{vm_id}.log"
        report = read_vm_report(shared_dir / f"report-vm{vm_id}.json", tests)
        if hugetlb and status != 0:
            maybe_show_hugetlb_warning(log_path)
        if (status != 0 or report["exitstatus"] != 0) and not report["errors"] and not any(
            result["outcome"] == "failed" for result in report["results"]
        ):
            report["errors"].append(f"VM exited unsuccessfully; see {log_path}")
        results.extend(report["results"])
        errors.extend(f"VM {vm_id}: {error}" for error in report["errors"])
    status = int(any(status != 0 for status in statuses) or bool(errors) or
                 any(result["outcome"] == "failed" for result in results))
    return dict(collected=node_ids, results=results, errors=errors, exitstatus=status)


def launcher_main(args: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="selftests.py launcher", allow_abbrev=False,
        description="Run selected tests in virtme-ng guests or on the host.",
    )
    parser.add_argument("tests", nargs="*", help="test paths or node IDs (default: test/cases)")
    parser.add_argument("-k", dest="keyword", metavar="EXPR", help="pytest test-name selection expression")
    parser.add_argument("-m", dest="markexpr", metavar="EXPR", help="pytest marker selection expression")
    parser.add_argument("--wprof", type=Path, default=Path(__file__).resolve().parent.parent / "src/wprof",
                        help="wprof binary to test (default: src/wprof)")
    parser.add_argument("--no-vm", action="store_true", help="run tests on the host instead of starting VMs")
    parser.add_argument("--vms", type=int, default=1, help="maximum parallel VMs (default: 1)")
    parser.add_argument("--kernel", default=f"/boot/vmlinuz-{os.uname().release}", help="guest kernel image")
    parser.add_argument("--vm-cpus", type=int, default=2, help="CPUs per VM (default: 2)")
    parser.add_argument("--vm-memory", type=float, default=4.0, help="memory per VM in GiB (default: 4)")
    parser.add_argument("--no-hugetlb", action="store_true", help="disable hugepage backing for guest RAM")
    parser.add_argument("--vm-timeout", type=float, default=300, help="seconds per VM, including boot (default: 300)")
    parser.add_argument("--report-json", type=Path, help="write results as JSON (default: <output directory>/report.json)")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="show commands and verbose test output")
    options = parser.parse_intermixed_args(args)
    if not options.no_vm and (options.vms < 1 or options.vm_cpus < 1 or
                              options.vm_memory <= 0 or options.vm_timeout <= 0):
        parser.error("--vms, --vm-cpus, --vm-memory and --vm-timeout must be positive")
    logging.basicConfig(level=logging.INFO if options.verbose > 0 else logging.WARNING, format="%(message)s")

    shared_dir = Path(mkdtemp(prefix="wprof-selftests-", dir="/tmp")).resolve()
    destination = options.report_json.resolve() if options.report_json else shared_dir / "report.json"
    if options.no_vm:
        report = run_tests_on_host(options, shared_dir)
    else:
        report = run_tests_in_vm(options, shared_dir)

    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, indent=2) + "\n")
    counts = {outcome: sum(r["complete"] and r["outcome"] == outcome for r in report["results"])
              for outcome in ("passed", "failed", "skipped")}
    print(f"{counts['passed']} passed, {counts['failed']} failed, {counts['skipped']} skipped; "
          f"{len(report['errors'])} infrastructure errors. Report: {destination}")
    for error in report["errors"]:
        logging.error("%s", error)
    return int(report["exitstatus"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="wprof test runner and VM launcher")
    parser.add_argument("command", choices=("runner", "launcher"))
    parser.add_argument("args", nargs=argparse.REMAINDER)
    arguments = parser.parse_args()
    entry = runner_main if arguments.command == "runner" else launcher_main
    raise SystemExit(entry(arguments.args))
