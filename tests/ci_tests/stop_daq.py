import os, signal, sys, time
sys.path.append('/app/')
import control_util as util
import psutil

GRACE_SECONDS = 5.0

def _send_sigint_to_pid(pid: int):
    try:
        p = psutil.Process(pid)
        if p.name() == util.hashpipe_name:
            os.kill(pid, signal.SIGINT)
            return True
    except Exception:
        pass
    return False

def _any_hashpipe_pids():
    pids = []
    for p in psutil.process_iter(attrs=["pid","name"]):
        try:
            if p.info["name"] == util.hashpipe_name:
                pids.append(p.info["pid"])
        except Exception:
            continue
    return pids

def _wait_for_exit(pids, timeout_s):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        alive = []
        for pid in pids:
            try:
                os.kill(pid, 0)
                alive.append(pid)
            except Exception:
                pass
        if not alive:
            return True
        time.sleep(0.1)
    return False

def main():
    # 1) Try SIGINT to the recorded PID if present
    recorded_pid = None
    try:
        with open(util.daq_hashpipe_pid_filename, 'r') as f:
            recorded_pid = int(f.read().strip())
    except Exception:
        recorded_pid = None

    sent = False
    target_pids = []
    if recorded_pid and _send_sigint_to_pid(recorded_pid):
        sent = True
        target_pids = [recorded_pid]
    else:
        # 2) No valid recorded PID: send SIGINT to all hashpipe processes
        hp_pids = _any_hashpipe_pids()
        for pid in hp_pids:
            try:
                os.kill(pid, signal.SIGINT)
                sent = True
            except Exception:
                pass
        target_pids = hp_pids

    # 3) Wait briefly for graceful exit; if still alive, SIGKILL them
    if target_pids:
        if not _wait_for_exit(target_pids, GRACE_SECONDS):
            # escalate
            for pid in target_pids:
                try:
                    os.kill(pid, signal.SIGKILL)
                except Exception:
                    pass
            # Wait one more short interval to ensure death
            _wait_for_exit(target_pids, 1.0)

    # 4) As a final safety, if any hashpipe remains, kill them (covers races)
    residual = _any_hashpipe_pids()
    if residual:
        for pid in residual:
            try:
                os.kill(pid, signal.SIGKILL)
            except Exception:
                pass

    # 5) Cleanup pid file and auxiliary daemons
    try:
        if os.path.exists(util.daq_hashpipe_pid_filename):
            os.unlink(util.daq_hashpipe_pid_filename)
    except Exception:
        pass

    # HK recorder shouldn’t run in CI; ensure it’s not left behind
    try:
        util.kill_hk_recorder()
    except Exception:
        pass

    try:
        os.unlink(util.daq_run_name_filename)
    except Exception:
        pass

    print('stop_daq.py: OK')

if __name__ == '__main__':
    main()