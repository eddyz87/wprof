#!/usr/bin/env python3
"""Kernel test harness and pytest driver."""
from collections import defaultdict
from contextlib import ExitStack
from collections.abc import Callable, Hashable, Iterator
from dataclasses import dataclass
from functools import cached_property
import json
import logging
import multiprocessing
from multiprocessing.process import BaseProcess
import os
from pathlib import Path
import shlex
from string import Template
import subprocess
import sys
from types import SimpleNamespace
from typing import Any, TypeVar

import pytest


K = TypeVar("K", bound=Hashable)


def privileged(command):
    return command if os.geteuid() == 0 else ["sudo", "-n", *command]


def kill(process):
    if isinstance(process, subprocess.Popen):
        if process.poll() is not None:
            return
        # Shell commands have their own process group. The profiler may run
        # through sudo, so signal the group with the same privilege.
        subprocess.run(privileged(["kill", "-TERM", "--", f"-{process.pid}"]),
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            subprocess.run(privileged(["kill", "-KILL", "--", f"-{process.pid}"]),
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


def pytest_addoption(parser):
    parser.addoption("--wprof", default=str(Path(__file__).resolve().parent.parent / "src/wprof"),
                     help="wprof binary to test (default: src/wprof)")


@pytest.hookimpl(tryfirst=True)
def pytest_configure(config):
    if config.option.verbose > 0 and config.option.log_cli_level is None and config.getini("log_cli_level") in (None, ""):
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
              "  -v also retains pytest's verbose reporting; an explicit log level takes precedence.")
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
            values = {**substitutions, "data": directory / "trace.data", "json": directory / "trace.json"}
            # Substitute after tokenization so spaces and shell metacharacters
            # in values stay inside one argument. Wprof's {env:...} survives.
            args = [Template(arg).substitute(values) for arg in shlex.split(parameters)]
            command = "exec " + shlex.join(privileged([str(wprof_binary), *args]))
            logging.info("Capture directory: %s", directory)
            with (directory / "stdout.log").open("w") as stdout, (directory / "stderr.log").open("w") as stderr:
                process = shell(command, stdout=stdout, stderr=stderr)
            return process, Artifacts(directory)

        yield Sh(fork=fork, shell=shell, wprof=wprof)


if __name__ == "__main__":
    raise SystemExit(pytest.main(
        [str(Path(__file__).resolve().parent / "cases"), *sys.argv[1:]],
        plugins=[sys.modules[__name__]],
    ))
