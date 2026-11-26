# Wprof selftests

## Overview

Test harness consists of the following components:
- [`test/selftests.py`](selftests.py) - the launcher script.

Tests are ordinary Python functions grouped into modules under `test/cases/*.py`.
These functions are supposed to:
- Spawn child processes to execute the `wprof`
- Spawn child processes with workloads triggering various kernel and
  user-space events.
- Inspect captured `wprof` output and assert if it matches the
  test expectations.

## Quick start

The host environment must provide:
- Python 3.11+
- Compiled wprof ([details](../README.md#building-wprof)).

Save the following under `test/cases/example.py`:

```python
import time

from selftests import Sh, test

@test
def test_background_write(sh: Sh) -> None:
    def write_loop():
        # Spam write system calls every 10 ms.
        with open("/dev/null", "wb", buffering=0) as sink:
            while True:
                sink.write(b"x")
                time.sleep(0.01)

    # Run the workload in a child process.
    writer = sh.fork(write_loop)
    # Start a wprof process to record the writer's write syscall exits.
    process, artifacts = sh.wprof(
        """-d 1s --no-stacks -p $pid
           -U 'tp:syscalls:sys_exit_write | name:write_syscall |'
           -D $data -J $json""",
        pid=writer.pid,
    )
    # wait for wprof to exit (for about one second (`-d 1s`))
    assert process.wait(timeout=130) == 0, artifacts.stderr
    # artifacts.json holds the parsed trace from -J $json, check its contents.
    writes = artifacts.json.select(t="utrace_instant", name="write_syscall")
    assert any(event.task.pid == writer.pid for event in writes), "no write from the worker"
```

Run the test case using the following command:

```sh
python3 -B test/selftests.py -t example/test_background_write
```

## Command-line parameters

Invoke the launcher as `python3 -B test/selftests.py [options]`.

### Test filtering

| Option                         | Effect and default                                                         |
|--------------------------------|----------------------------------------------------------------------------|
| `-t GLOB`                      | Match the `test/cases/*.py` base file name without `.py`. Defaults to `*`. |
| `-t GLOB/GLOB`                 | First glob matches the file name, second glob matches the function.        |

### Filesystem configuration

| Option               | Effect and default                                                                         |
|----------------------|--------------------------------------------------------------------------------------------|
| `--report-json PATH` | Final JSON report. Defaults to `<basetemp>/wprof-selftests-current/report.json`.           |

Each invocation creates a fresh `<basetemp>/wprof-selftests-current`
If a current directory already exists, the launcher first renames it
to `<basetemp>/wprof-selftests-previous`. Test artifacts include
`std{out,err}` and `wprof` captures. Here is an example of the
directory layout:

```
wprof-selftests-current/
    report.json
```

By default artifacts are retained only for failing test cases.

### Other options

| Option             | Effect and default                                                                           |
|--------------------|----------------------------------------------------------------------------------------------|
| `-v`, `--verbose`  | Show selected names, commands, timings and verbose test output.                              |
| `-h`, `--help`     | Print the launcher usage.                                                                    |
| `--keep-artifacts` | Retain per-test artifacts for both failing and passing cases.                                |
| `--wprof PATH`     | Profiler binary, default `src/wprof` in the checkout.                                        |
