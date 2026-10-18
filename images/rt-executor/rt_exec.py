"""Run /in/script.py with hard limits; leave results in /out. Exit code is always 0 when the
wrapper itself worked: the script outcome is in /out/_result.json.

Environment: RT_TIMEOUT_S (wall clock), RT_CPU_S (cpu seconds), RT_MEM_MB (address space),
RT_FSIZE_MB (largest file), RT_NPROC.
"""
import json
import os
import resource
import subprocess
import sys
import time


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def main() -> int:
    timeout = _int("RT_TIMEOUT_S", 60)
    cpu = _int("RT_CPU_S", timeout)
    mem = _int("RT_MEM_MB", 512) * 1024 * 1024
    fsize = _int("RT_FSIZE_MB", 100) * 1024 * 1024
    nproc = _int("RT_NPROC", 64)
    script = os.environ.get("RT_SCRIPT", "/in/script.py")

    def limits() -> None:
        resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
        resource.setrlimit(resource.RLIMIT_AS, (mem, mem))
        resource.setrlimit(resource.RLIMIT_FSIZE, (fsize, fsize))
        resource.setrlimit(resource.RLIMIT_NPROC, (nproc, nproc))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        os.setsid()

    t0 = time.monotonic()
    timed_out = False
    try:
        with open("/out/_stdout.txt", "wb") as so, open("/out/_stderr.txt", "wb") as se:
            p = subprocess.Popen([sys.executable, script], cwd="/out", stdout=so, stderr=se,
                                 preexec_fn=limits, env={**os.environ, "RT_OUT": "/out",
                                                         "RT_IN": "/in"})
            try:
                code = p.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(p.pid, 9)
                code = p.wait()
    except OSError as e:
        code = 127
        with open("/out/_stderr.txt", "a") as se:
            se.write(f"executor error: {e}\n")
    res = {"exit_code": code, "timed_out": timed_out,
           "duration_s": round(time.monotonic() - t0, 3)}
    with open("/out/_result.json", "w") as f:
        json.dump(res, f)
    return 0


if __name__ == "__main__":
    sys.exit(main())
