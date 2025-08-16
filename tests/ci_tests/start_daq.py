#! /usr/bin/env python3
import sys, os, subprocess, time, shlex

import control_util as util

USAGE = """start_daq.py --run_dir DIR --max_file_size_mb N [--bindhost IFACE] --module_id M1 [--module_id M2 ...]
"""

def _parse_args(argv):
    run_dir = None
    max_file_size_mb = -1
    module_ids = []
    bindhost = "0.0.0.0"
    obs = "TEST"
    i = 1
    while i < len(argv):
        a = argv[i]
        if a == "--run_dir":
            i += 1; run_dir = argv[i]
        elif a == "--max_file_size_mb":
            i += 1; max_file_size_mb = int(argv[i])
        elif a == "--module_id":
            i += 1; module_ids.append(int(argv[i]))
        elif a == "--bindhost":
            i += 1; bindhost = argv[i]
        elif a == "--obs":
            i += 1; obs = argv[i]
        else:
            raise SystemExit(f"Unknown arg {a}\n{USAGE}")
        i += 1
    if not run_dir or not module_ids:
        raise SystemExit(f"Missing required args\n{USAGE}")
    return run_dir, max_file_size_mb, bindhost, obs, module_ids

def _write_module_config(run_dir, run_name, module_ids):
    cfg_dir = os.path.join(run_dir, run_name)
    os.makedirs(cfg_dir, exist_ok=True)
    cfg_path = os.path.join(cfg_dir, "module.config")
    with open(cfg_path, "w") as f:
        f.write("".join(f"{m}\n" for m in module_ids))
    return cfg_path

def _write_run_script(run_dir, run_name, bindhost, max_file_size_mb, obs):
    # Hashpipe runs with cwd = run_dir (parent), RUNDIR is run_name
    script_path = os.path.join(run_dir, "run_hashpipe.sh")
    cfg_rel = f"{run_name}/module.config"
    lines = [
        "#!/usr/bin/env bash",
        "set -e",
        # Ensure we run in the run_dir’s parent (already the case if caller sets cwd)
        f'exec hashpipe -p hashpipe.so -I 0 '
        f'-o BINDHOST={bindhost} '
        f'-o RUNDIR={run_name} '
        f'-o CONFIG={cfg_rel} '
        f'-o MAXFILESIZE={max_file_size_mb} '
        f'-o GROUPPHFRAMES=0 '
        f'-o OBS={obs} '
        f'net_thread compute_thread output_thread'
    ]
    with open(script_path, "w") as f:
        f.write("\n".join(lines) + "\n")
    os.chmod(script_path, 0o755)
    return script_path

def _find_hashpipe_pid(expected_tokens, retries=30, delay=0.5):
    # expected_tokens: substrings to match in cmdline, including hashpipe name and args
    import psutil
    for _ in range(retries):
        for p in psutil.process_iter(attrs=["pid", "name", "cmdline"]):
            try:
                if p.info["name"] != util.hashpipe_name:
                    continue
                cmd = " ".join(p.info.get("cmdline") or [])
                if all(tok in cmd for tok in expected_tokens):
                    return p.info["pid"]
            except Exception:
                continue
        time.sleep(delay)
    return None

def main():
    run_dir, max_file_size_mb, bindhost, obs, module_ids = _parse_args(sys.argv)
    # The tests set cwd to run_dir’s parent (/tmp/ci_run_dir). We ensure directories exist.
    os.makedirs(run_dir, exist_ok=True)

    run_name = "obs_ci_run"  # In CI we use fixed run name
    # Ensure module directories exist like production
    for mid in module_ids:
        os.makedirs(os.path.join(run_dir, f"module_{mid}", run_name), exist_ok=True)

    cfg_path = _write_module_config(run_dir, run_name, module_ids)
    script_path = _write_run_script(run_dir, run_name, bindhost, max_file_size_mb, obs)

    # Launch the wrapper script detached from stdio
    proc = subprocess.Popen(
        ["bash", os.path.basename(script_path)],
        cwd=run_dir,
        start_new_session=True,
        close_fds=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # Build expected tokens to identify the hashpipe process reliably
    expected = [
        "-p", "hashpipe.so",
        "-o", f"BINDHOST={bindhost}",
        "-o", f"RUNDIR={run_name}",
        "-o", f"CONFIG={run_name}/module.config",
    ]
    pid = _find_hashpipe_pid(expected_tokens=expected, retries=40, delay=0.5)
    if not pid:
        raise Exception("hashpipe did not appear in process list with expected cmdline; it may have crashed early")

    with open(util.daq_hashpipe_pid_filename, "w") as f:
        f.write(str(pid))

if __name__ == "__main__":
    main()