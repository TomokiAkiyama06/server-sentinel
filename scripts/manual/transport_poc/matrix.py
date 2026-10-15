"""Deterministic impairment matrix and its orchestrator.

``role=both`` (loopback) runs receiver, proxy and sender on this host and
drives every scheduled action. For a real two-host run, start
``--role main`` on the Main Server and ``--role agent`` on the capture host
within a few seconds of each other: each side executes only its own actions,
relative to its own start, and every metric compares timestamps of one host
only (or Agent capture-clock values carried in the envelope).

Times are seconds; ``fast`` values are the CI/loopback smoke durations.
"""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

from . import materials, records

POC = Path(__file__).resolve().parent / "poc15.py"
RECEIVER_PORTS = {"a_framed": 47200, "b_chunked": 47201, "b_segment": 47201}
PROXY_PORTS = {"a_framed": 47210, "b_chunked": 47211, "b_segment": 47212}


def _scenario(name, full, fast, **options):
    return name, {"full": full, "fast": fast, **options}


# Each timing set: duration, proxy schedule [[offset, action, duration, rate_fraction]],
# orchestrator actions [[offset, action, duration]].
SCENARIOS = dict((
    _scenario("normal", {"duration": 300}, {"duration": 8}),
    # 2- and 3-source topologies (1 is ``normal``, 4 is ``capacity_4``): every
    # 1-4 source count must be exercised before G2/G3/G6 can pass.
    _scenario("sources_2", {"duration": 120}, {"duration": 8}, sources=2),
    _scenario("sources_3", {"duration": 120}, {"duration": 8}, sources=3),
    _scenario("outage_1s",
              {"duration": 110, "proxy": [[20, "blackhole", 1], [50, "blackhole", 1],
                                          [80, "blackhole", 1]]},
              {"duration": 10, "proxy": [[3, "blackhole", 0.5], [6, "blackhole", 0.5]]},
              silent=True),
    _scenario("outage_5s",
              {"duration": 140, "proxy": [[20, "blackhole", 5], [60, "blackhole", 5],
                                          [100, "blackhole", 5]]},
              {"duration": 10, "proxy": [[3, "blackhole", 3]]}, silent=True),
    _scenario("outage_120s", {"duration": 200, "proxy": [[20, "blackhole", 120]]},
              {"duration": 14, "proxy": [[3, "blackhole", 6]]}, silent=True),
    _scenario("rst", {"duration": 110, "proxy": [[20, "reset"], [50, "reset"], [80, "reset"]]},
              {"duration": 10, "proxy": [[3, "reset"], [6, "reset"]]}),
    _scenario("bandwidth_cap", {"duration": 230, "proxy": [[20, "rate_cap", 180, 0.5]]},
              {"duration": 10, "proxy": [[3, "rate_cap", 4, 0.5]]}),
    # Every Main stop must be detected by the Agent (G5), so each stop is at
    # least the Agent loss timeout + 2.5 s (fast: 1.5 s timeout, 1 s segment
    # cadence for b_segment); a 2 s fast stop could end before b_segment's
    # first reply timeout and leave no loss to detect (#237).
    _scenario("slow_stop_10s", {"duration": 80, "actions": [[20, "sigstop", 10]]},
              {"duration": 10, "actions": [[3, "sigstop", 4]]}, silent=True),
    _scenario("slow_stop_60s", {"duration": 140, "actions": [[20, "sigstop", 60]]},
              {"duration": 12, "actions": [[3, "sigstop", 5]]}, silent=True),
    # The fast queue is small so seconds of half-rate drain reach backpressure.
    _scenario("slow_drain", {"duration": 90}, {"duration": 8, "queue": 30}, drain_fraction=0.5),
    _scenario("main_restart", {"duration": 90, "actions": [[30, "restart_receiver", 0]]},
              {"duration": 10, "actions": [[4, "restart_receiver", 0]]}, silent=True),
    _scenario("capture_restart", {"duration": 90, "actions": [[30, "restart_sender", 0]]},
              {"duration": 10, "actions": [[4, "restart_sender", 0]]}),
    _scenario("capacity_4", {"duration": 120}, {"duration": 8}, sources=4),
    _scenario("fifth_refused", {"duration": 60}, {"duration": 6}, sources=5),
    _scenario("auth_unpaired", {"duration": 30}, {"duration": 5}, node="unpaired", negative=True),
    _scenario("auth_other_ca", {"duration": 30}, {"duration": 5}, node="other_ca", negative=True),
    _scenario("auth_revoked", {"duration": 30}, {"duration": 5}, node="revoked", negative=True),
    _scenario("auth_revoked_live", {"duration": 45, "actions": [[20, "revoke", 0]]},
              {"duration": 7, "actions": [[3, "revoke", 0]]}, node="revoked_live"),
    _scenario("route_probe", {"duration": 10}, {"duration": 4}, route_probe=True),
    _scenario("soak", {"duration": 1800}, {"duration": 20}, optional=True),
))
DEFAULT_ORDER = [name for name, spec in SCENARIOS.items() if not spec.get("optional")]
MAIN_ACTIONS = {"sigstop", "restart_receiver", "revoke"}
AGENT_ACTIONS = {"restart_sender"}


def timing(name, fast):
    spec = SCENARIOS[name]
    return spec["fast" if fast else "full"]


def _wait_stopped(pid, timeout=1.0, stat_root="/proc"):
    """True once ``/proc/<pid>/stat`` shows the process stopped (state ``T``)."""
    deadline = time.monotonic() + timeout
    path = Path(stat_root) / str(int(pid)) / "stat"
    while True:
        try:
            # The state follows the parenthesised command name.
            state = path.read_text(encoding="ascii", errors="replace").rpartition(")")[2].split()
        except OSError:
            return False
        if state and state[0] == "T":
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.001)


def nominal_bitrate(n_sources, fps, frame_bytes):
    return n_sources * fps * frame_bytes


class Child:
    def __init__(self, name, argv, *, wait_ready, stderr_path=None):
        self.name = name
        environment = {**os.environ, "CUDA_VISIBLE_DEVICES": "", "PYTHONDONTWRITEBYTECODE": "1"}
        # stderr (tracebacks only; no measurement) goes to the private state
        # directory, never to the numeric measurement output.
        stderr = subprocess.DEVNULL
        if stderr_path is not None:
            stderr = open(os.open(stderr_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND
                                  | os.O_NOFOLLOW, 0o600), "ab")
        self.process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=stderr,
                                        stdin=subprocess.DEVNULL, env=environment, text=True)
        if stderr is not subprocess.DEVNULL:
            stderr.close()
        if wait_ready:
            line = self.process.stdout.readline().strip()
            if line != "ready":
                self.stop(5)
                raise RuntimeError(f"{name} did not become ready")

    def stop(self, timeout, *, sig=signal.SIGTERM):
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGCONT)
            self.process.send_signal(sig)
        try:
            return self.process.wait(timeout)
        except subprocess.TimeoutExpired:
            self.process.kill()
            return self.process.wait(5)
        finally:
            self.process.stdout.close()


class Orchestrator:
    def __init__(self, args, run_id):
        self.args = args
        self.run_id = run_id
        out = materials.private_directory(args.out, exist_ok=True)
        state = materials.private_directory(args.state, exist_ok=True)
        self.out_root = materials.private_directory(out / run_id, exist_ok=True)
        self.state_root = materials.private_directory(state / run_id, exist_ok=True)
        self.python = sys.executable

    def _argv(self, *parts):
        return [self.python, str(POC), *[str(part) for part in parts]]

    def receiver_argv(self, candidate, port, out_dir, state_dir, drain_rate, queue=240):
        argv = self._argv("receiver", "--candidate", candidate, "--bind", self.args.bind,
                          "--port", port, "--materials", self.args.materials,
                          "--state", state_dir, "--out", out_dir / "receiver.jsonl",
                          "--run-id", self.run_id, "--drain-rate", drain_rate,
                          "--max-queue", queue)
        return argv + (["--fast"] if self.args.fast else [])

    def sender_argv(self, candidate, port, out_dir, state_dir, node, n_sources, seconds,
                    route_probe):
        argv = self._argv("sender", "--candidate", candidate, "--host", self.args.proxy_host,
                          "--port", port, "--node-dir", Path(self.args.node_root) / node,
                          "--epoch-file", state_dir / "epoch", "--sources", n_sources,
                          "--seconds", f"{seconds:.3f}", "--out", out_dir / "sender.jsonl",
                          "--run-id", self.run_id, "--source-kind", self.args.source_kind,
                          "--fps", self.args.fps, "--frame-bytes", self.args.frame_bytes)
        if self.args.holder_socket:
            argv += ["--holder-socket", self.args.holder_socket]
        if self.args.real_inputs:
            argv.append("--real-inputs")
        if route_probe:
            argv.append("--route-probe")
        return argv + (["--fast"] if self.args.fast else [])

    def run_one(self, name, candidate):
        spec = SCENARIOS[name]
        plan = timing(name, self.args.fast)
        role = self.args.role
        n_sources = spec.get("sources", self.args.sources)
        node = spec.get("node", "good")
        out_dir = materials.private_directory(self.out_root / f"{name}-{candidate}", exist_ok=True)
        state_dir = materials.private_directory(self.state_root / f"{name}-{candidate}",
                                                exist_ok=True)
        offset = self.args.port_offset
        receiver_port = RECEIVER_PORTS[candidate] + offset
        proxy_port = PROXY_PORTS[candidate] + offset
        upstream_port = self.args.upstream_port or receiver_port
        rate = nominal_bitrate(n_sources, self.args.fps, self.args.frame_bytes)
        schedule = [[item[0], item[1], item[2] if len(item) > 2 else 0,
                     int(rate * item[3]) if len(item) > 3 else 0]
                    for item in plan.get("proxy", [])]
        drain_rate = (spec["drain_fraction"] * n_sources * self.args.fps
                      if "drain_fraction" in spec else 0)
        duration = plan["duration"]
        writer = records.JsonlWriter(out_dir / f"orchestrator-{role}.jsonl", run_id=self.run_id,
                                     role="orchestrator")
        writer.write("start", scenario=name, candidate=candidate, n_sources=n_sources,
                     inputs="real" if self.args.real_inputs else "synthetic",
                     fast=bool(self.args.fast), side=role, duration_ns=int(duration * 1e9),
                     fps=self.args.fps,
                     node=node if node in records.TOKENS else "other")
        if role == "both" and name == "auth_revoked_live":
            materials.replace_loopback_node(self.args.materials, "revoked_live")
        children = {}
        started = time.monotonic()
        try:
            if role in ("both", "main"):
                writer.write("spawn", process="receiver", side=role)
                children["receiver"] = Child("receiver", self.receiver_argv(
                    candidate, receiver_port, out_dir, state_dir, drain_rate,
                    plan.get("queue", 240)), wait_ready=True,
                    stderr_path=state_dir / "receiver.stderr")
            if role in ("both", "agent"):
                writer.write("spawn", process="proxy", side=role)
                children["proxy"] = Child("proxy", self._argv(
                    "proxy", "--listen", f"127.0.0.1:{proxy_port}",
                    "--upstream", f"{self.args.upstream_host}:{upstream_port}",
                    "--schedule", json.dumps(schedule), "--seconds", duration + 10,
                    "--out", out_dir / "proxy.jsonl", "--run-id", self.run_id), wait_ready=True,
                    stderr_path=state_dir / "proxy.stderr")
                writer.write("spawn", process="sender", side=role)
                children["sender"] = Child("sender", self.sender_argv(
                    candidate, proxy_port, out_dir, state_dir, node, n_sources, duration,
                    spec.get("route_probe", False)), wait_ready=False,
                    stderr_path=state_dir / "sender.stderr")
            started = time.monotonic()
            if role == "main":
                # Operator cue for a two-host run: start the capture side now.
                print("ready", name, candidate, flush=True)
            actions = sorted(plan.get("actions", []))
            for at, action, length in actions:
                if (role == "main" and action not in MAIN_ACTIONS) or (
                        role == "agent" and action not in AGENT_ACTIONS):
                    continue
                self._sleep_until(started + at)
                self._act(action, length, children, writer, candidate, receiver_port, out_dir,
                          state_dir, drain_rate, proxy_port, node, n_sources,
                          duration - at, spec)
            if "sender" in children:
                self._sleep_until(started + duration)
                children["sender"].process.wait(timeout=duration + 30)
            else:
                self._sleep_until(started + duration + self.args.main_grace)
        finally:
            for key in ("sender", "proxy", "receiver"):
                if key in children:
                    code = children[key].stop(15)
                    writer.write("exit", process=key if key in records.TOKENS else "other",
                                 code=code, side=role)
        # Written only when every child stopped: a run without ``end`` crashed.
        writer.write("end", scenario=name, candidate=candidate, side=role,
                     wall_ns=int((time.monotonic() - started) * 1e9))
        writer.close()
        return out_dir

    @staticmethod
    def _sleep_until(at):
        while True:
            remaining = at - time.monotonic()
            if remaining <= 0:
                return
            time.sleep(min(0.2, remaining))

    def _act(self, action, length, children, writer, candidate, receiver_port, out_dir,
             state_dir, drain_rate, proxy_port, node, n_sources, remaining, spec):
        writer.write("action", action=action, duration_ns=int(length * 1e9))
        if action == "sigstop":
            receiver = children["receiver"].process
            started = time.monotonic()
            receiver.send_signal(signal.SIGSTOP)
            if _wait_stopped(receiver.pid):
                # Main clock time by which the receiver was seen frozen: a
                # reply it handed to the kernel before this is no survival
                # evidence for G4/G5 (#237). Not written if unconfirmed.
                writer.write("action", action="stopped", duration_ns=0)
            time.sleep(max(0.0, length - (time.monotonic() - started)))
            receiver.send_signal(signal.SIGCONT)
            writer.write("action", action="sigcont", duration_ns=0)
        elif action == "restart_receiver":
            # Abrupt stop (SIGUSR1): the receiver discards its unpersisted
            # queue like a crash, then the new process resumes from the
            # durable watermark.
            code = children["receiver"].stop(15, sig=signal.SIGUSR1)
            writer.write("exit", process="receiver", code=code, side=self.args.role)
            writer.write("spawn", process="receiver", side=self.args.role)
            children["receiver"] = Child("receiver", self.receiver_argv(
                candidate, receiver_port, out_dir, state_dir, drain_rate), wait_ready=True,
                    stderr_path=state_dir / "receiver.stderr")
            writer.write("action", action="ready", duration_ns=0)
        elif action == "restart_sender":
            code = children["sender"].stop(15)
            writer.write("exit", process="sender", code=code, side=self.args.role)
            writer.write("spawn", process="sender", side=self.args.role)
            children["sender"] = Child("sender", self.sender_argv(
                candidate, proxy_port, out_dir, state_dir, node, n_sources, remaining,
                spec.get("route_probe", False)), wait_ready=False,
                stderr_path=state_dir / "sender.stderr")
        elif action == "revoke":
            materials.revoke(self.args.materials, node)

    def run(self, scenarios, candidates):
        for candidate in candidates:
            for name in scenarios:
                self.run_one(name, candidate)
        return self.out_root
