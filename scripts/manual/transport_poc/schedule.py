"""Time-scheduled two-host launcher for the scenario matrix (MANUAL TEST ONLY).

A two-host run used to need an operator hand-off per scenario ("start Main,
wait for ``ready``, start the capture side within 10 s"), and one launch done
twice under one run id fails that run's integrity. ``poc15.py schedule``
removes the hand-off without changing what a single run does: both hosts run
the same command with their own ``--role`` and the same ``--start``,
``--candidates``, ``--scenarios`` and ``--real-camera``; each side computes the
identical timetable from those arguments alone (no communication, no SSH) and
launches, per slot, exactly the README's single-scenario ``matrix --role``
command (one scenario, one candidate) in its ``ss-poc15-*`` scope.

Timetable: slot 0 starts at ``--start``; slot i+1 starts ``duration +
SLOT_MARGIN_S`` after slot i, where ``duration`` is the scenario's full
timing. The run id of a slot is its UTC start (``rYYYYMMDDtHHMMSS``), so both
hosts agree on it. Launch times compare the two hosts' wall clocks (both must
be NTP synchronised); measurements still compare one host's clock only.

Margin (90 s): the Main orchestrator needs up to ``duration`` + receiver
start-up + ``--main-grace`` 20 s + a receiver stop of at most 15 s (about
``duration`` + 37 s). Every launch is bounded by ``timeout -k 30`` with a limit
of ``duration`` + ``RUN_LIMIT_EXTRA_S`` (55 s) from its slot start, so even a
run that hangs and needs SIGKILL is gone ``duration`` + 85 s after the slot
start: before the next slot's receiver binds the same port and before the
next Agent connects. 60 s could not give both the normal run its headroom and
that hard bound.

Fail-closed rules: slots never overlap (each slot waits for its own
processes); a slot whose start already passed by more than
``START_TOLERANCE_S`` (a previous launch overran) stops the whole schedule
with a non-zero exit, and the other host then simply fails to connect, which
the records show. A schedule longer than the README's 3 h/day budget is
refused (split the candidates across days). ``auth_revoked_live`` needs a
fresh ``revoked_live`` bundle per candidate and stays a manual run. SIGINT /
SIGTERM stop the current slot's processes and start no further slot. The
scheduler never uses sudo, ``tc``, the firewall, Tailscale or SSH.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import threading
import time

from . import materials, matrix, records

POC = Path(__file__).resolve().parent / "poc15.py"
SLOT_MARGIN_S = 90
RUN_LIMIT_EXTRA_S = 55       # timeout limit = duration + this, from the slot start
KILL_AFTER_S = 30            # ``timeout -k``
AGENT_OFFSET_S = 5           # Agent launch after the slot start (Main is ``ready`` by then)
HOLDER_EXTRA_S = 45          # holder ``--seconds`` = duration + this (outlives the Agent)
HOLDER_STOP_S = 15           # SIGTERM -> SIGKILL wait for the holder after the Agent exits
START_TOLERANCE_S = 5        # a slot this late was missed: the schedule stops
MAX_AHEAD_S = 24 * 3600
DAILY_BUDGET_S = 3 * 3600    # README: at most 3 h of runs per day
MANUAL_ONLY = {
    "auth_revoked_live": "auth_revoked_live needs a fresh revoked_live bundle per candidate "
                         "(node-key + issue); run it manually with matrix --role, not in a "
                         "schedule",
}
DEFAULT_SCENARIOS = [name for name in matrix.DEFAULT_ORDER if name not in MANUAL_ONLY]
_START = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
EXIT_MISSED = 3
EXIT_STOPPED = 130


@dataclass(frozen=True)
class Slot:
    index: int
    start: int          # UTC epoch seconds
    scenario: str
    candidate: str
    duration: int       # full scenario duration, seconds
    real: bool          # holder / real camera on the capture host, --real-inputs on both

    @property
    def run_id(self):
        return run_id_for(self.start)

    @property
    def end(self):
        """Start of the next slot."""
        return self.start + self.duration + SLOT_MARGIN_S


def run_id_for(start):
    run_id = "r" + datetime.fromtimestamp(start, timezone.utc).strftime("%Y%m%dt%H%M%S")
    if not records.RUN_ID_PATTERN.fullmatch(run_id):
        raise SystemExit("slot start does not give a valid run id")
    return run_id


def parse_start(text):
    """``YYYY-MM-DDTHH:MM:SSZ`` (UTC, whole seconds) -> epoch seconds."""
    if not _START.fullmatch(text or ""):
        raise SystemExit("--start must be a UTC time like 2026-10-21T01:00:00Z")
    try:
        moment = datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        raise SystemExit("--start must be a UTC time like 2026-10-21T01:00:00Z") from None
    return int(moment.timestamp())


def scenario_names(text):
    names = DEFAULT_SCENARIOS if text == "default" else text.split(",")
    for name in names:
        if name in MANUAL_ONLY:
            raise SystemExit(MANUAL_ONLY[name])
        if name not in matrix.SCENARIOS:
            raise SystemExit("unknown scenario")
    if len(set(names)) != len(names):
        raise SystemExit("a scenario is listed twice")
    return list(names)


def candidate_names(text):
    names = text.split(",")
    for name in names:
        if name not in matrix.RECEIVER_PORTS:
            raise SystemExit("schedule candidates: a_framed, b_chunked, b_segment")
    if len(set(names)) != len(names):
        raise SystemExit("a candidate is listed twice")
    return names


def uses_real_camera(name, real_camera):
    """Real camera only for 1-source scenarios that stream media.

    The holder supplies only the connected cameras (currently one), so the
    2- to 5-source scenarios stay synthetic (``gst``); negative-auth runs and
    ``route_probe`` carry no measured media, so they never open the camera.
    """
    spec = matrix.SCENARIOS[name]
    return bool(real_camera and spec.get("sources", 1) == 1 and not spec.get("negative")
                and not spec.get("route_probe"))


def timetable(start, candidates, scenarios, real_camera):
    """Deterministic slots from the shared arguments only (identical on both hosts)."""
    slots = []
    at = start
    for candidate in candidates:
        for name in scenarios:
            duration = int(matrix.timing(name, False)["duration"])
            slot = Slot(len(slots), at, name, candidate, duration,
                        uses_real_camera(name, real_camera))
            slots.append(slot)
            at = slot.end
    return slots


def validate(slots, now):
    if not slots:
        raise SystemExit("empty schedule")
    first = slots[0].start
    if first < now:
        raise SystemExit("--start is in the past")
    if first > now + MAX_AHEAD_S:
        raise SystemExit("--start is more than 24 h ahead")
    total = slots[-1].end - first
    if total > DAILY_BUDGET_S:
        raise SystemExit(f"schedule takes {format_span(total)}, over the 3 h/day budget: "
                         "split the candidates across days (e.g. --candidates "
                         "a_framed,b_chunked today, b_segment on another day)")


def format_span(seconds):
    return f"{seconds // 3600}h{seconds % 3600 // 60:02d}m{seconds % 60:02d}s"


def render(slots, role):
    lines = [f"schedule role={role} slots={len(slots)} margin={SLOT_MARGIN_S}s "
             f"total={format_span(slots[-1].end - slots[0].start)}"]
    for slot in slots:
        at = datetime.fromtimestamp(slot.start, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        lines.append(f"{slot.index:3d} {at} {slot.run_id} {slot.scenario} {slot.candidate} "
                     f"{slot.duration}s {'real' if slot.real else 'synthetic'}")
    end = datetime.fromtimestamp(slots[-1].end, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines.append(f"ends {end}")
    return "\n".join(lines)


def _timeout(limit, unit, quota, memory, *, nice=False):
    # ``--collect``: a scope that ended failed (e.g. a MemoryMax OOM kill) is
    # unloaded instead of kept, so the next slot can create the same fixed
    # unit name. The fixed names still refuse a second scope while the
    # previous one is active (no overlap).
    argv = ["timeout", "-k", str(KILL_AFTER_S), f"{int(limit)}s", "systemd-run", "--user",
            "--scope", "--collect", f"--unit={unit}", "-p", f"CPUQuota={quota}", "-p", f"MemoryMax={memory}"]
    return argv + (["nice", "-n", "10", "ionice", "-c", "3"] if nice else [])


def main_command(slot, args, python=sys.executable):
    argv = _timeout(slot.duration + RUN_LIMIT_EXTRA_S, "ss-poc15-main", "200%", "1G", nice=True)
    argv += [python, str(POC), "matrix", "--role", "main", "--bind", args.bind,
             "--materials", args.materials, "--state", args.state, "--out", args.out,
             "--candidates", slot.candidate, "--scenarios", slot.scenario,
             "--run-id", slot.run_id]
    return argv + (["--real-inputs"] if slot.real else [])


def holder_socket(args):
    return str(Path(args.holder_socket_dir) / "frames.sock")


def holder_command(slot, args, python=sys.executable):
    argv = _timeout(slot.duration + RUN_LIMIT_EXTRA_S, "ss-poc15-holder", "100%", "512M")
    argv += [python, str(POC), "holder", "--state-dir", args.holder_state_dir,
             "--socket-dir", args.holder_socket_dir, "--sources", "1",
             "--profile", "1280x720@30", "--approve",
             "--seconds", str(slot.duration + HOLDER_EXTRA_S),
             "--out", str(Path(args.out) / f"holder-{slot.run_id}.jsonl"),
             "--run-id", slot.run_id]
    return argv + (["--dev-checkout-helper"] if args.dev_checkout_helper else [])


def agent_command(slot, args, python=sys.executable):
    # The limit counts from the Agent's own launch, AGENT_OFFSET_S after the slot.
    argv = _timeout(slot.duration + RUN_LIMIT_EXTRA_S - AGENT_OFFSET_S, "ss-poc15-agent",
                    "100%", "512M")
    argv += [python, str(POC), "matrix", "--role", "agent", "--upstream-host",
             args.upstream_host, "--node-root", args.node_root, "--materials", args.node_root,
             "--state", args.state, "--out", args.out]
    if slot.real:
        argv += ["--source-kind", "holder", "--holder-socket", holder_socket(args),
                 "--real-inputs"]
    else:
        argv += ["--source-kind", "gst"]
    return argv + ["--candidates", slot.candidate, "--scenarios", slot.scenario,
                   "--run-id", slot.run_id]


def preflight(slots, args):
    """Paths outside the repository; no slot may reuse an existing run's records."""
    names = ["state", "out"] + (["materials"] if args.role == "main" else ["node_root"])
    if args.role == "agent" and any(slot.real for slot in slots):
        names += ["holder_state_dir", "holder_socket_dir"]
    for name in names:
        if not getattr(args, name, None):
            raise SystemExit(f"--{name.replace('_', '-')} is required for this schedule")
        setattr(args, name, str(materials.require_outside_repository(getattr(args, name))))
    if args.role == "main" and not args.bind:
        raise SystemExit("--bind is required for --role main")
    if args.role == "agent" and not args.upstream_host:
        raise SystemExit("--upstream-host is required for --role agent")
    out = materials.private_directory(args.out, exist_ok=True)
    for slot in slots:
        if (out / slot.run_id).exists() or (out / f"holder-{slot.run_id}.jsonl").exists():
            # Records append: a rerun under one run id fails that run's integrity.
            raise SystemExit("records for a slot's run id already exist: choose a new --start")


class Scheduler:
    """Run the slots of one role in order; clock, sleep and spawn are injectable."""

    def __init__(self, slots, args, *, clock=time.time, sleep=time.sleep, spawn=None,
                 output=None, python=sys.executable):
        self.slots = slots
        self.args = args
        self.clock = clock
        self.sleep = sleep
        self.spawn = spawn or self._popen
        self.output = output or sys.stdout
        self.python = python
        self.stop = threading.Event()

    @staticmethod
    def _popen(argv):
        environment = {**os.environ, "CUDA_VISIBLE_DEVICES": "", "PYTHONDONTWRITEBYTECODE": "1"}
        return subprocess.Popen(argv, stdin=subprocess.DEVNULL, env=environment)

    def request_stop(self, *_):
        self.stop.set()

    def _say(self, text):
        print(text, file=self.output, flush=True)

    def _sleep_until(self, at):
        """False if a stop was requested before ``at``."""
        while not self.stop.is_set():
            remaining = at - self.clock()
            if remaining <= 0:
                return True
            self.sleep(min(0.5, remaining))
        return False

    def _await(self, process):
        """Exit code; on a stop request the process is terminated first."""
        while process.poll() is None:
            if self.stop.is_set():
                return self._terminate(process, KILL_AFTER_S + 15)
            self.sleep(0.2)
        return process.poll()

    def _terminate(self, process, grace):
        if process.poll() is None:
            process.send_signal(signal.SIGTERM)
            deadline = self.clock() + grace
            while process.poll() is None and self.clock() < deadline:
                self.sleep(0.2)
            if process.poll() is None:
                process.kill()
                process.wait()
        return process.poll()

    def _missed(self, slot):
        return self.clock() > slot.start + START_TOLERANCE_S

    def run(self):
        failures = 0
        for slot in self.slots:
            if not self._sleep_until(slot.start):
                break
            if self._missed(slot):
                self._say(f"slot {slot.index} {slot.run_id} missed its start by more than "
                          f"{START_TOLERANCE_S}s (a previous launch overran): schedule stopped, "
                          "no further slot is started")
                return EXIT_MISSED
            if self.args.role == "main":
                code = self._await(self.spawn(main_command(slot, self.args, self.python)))
                detail = f"exit={code}"
            else:
                code, detail = self._run_agent(slot)
            failures += code != 0
            self._say(f"slot {slot.index} {slot.run_id} {slot.scenario} {slot.candidate} "
                      f"{'real' if slot.real else 'synthetic'} {detail}")
            if self.stop.is_set():
                break
        if self.stop.is_set():
            self._say("schedule stopped by signal: no further slot is started")
            return EXIT_STOPPED
        return 1 if failures else 0

    def _run_agent(self, slot):
        holder = None
        if slot.real:
            holder = self.spawn(holder_command(slot, self.args, self.python))
        try:
            if not self._sleep_until(slot.start + AGENT_OFFSET_S):
                return 1, "stopped before the agent launch"
            if holder is not None and (holder.poll() is not None
                                       or not os.path.exists(holder_socket(self.args))):
                # The sender does not retry the holder socket: launching it now
                # could only produce a failed run.
                return 1, f"holder not ready (holder={holder.poll()}): agent not started"
            code = self._await(self.spawn(agent_command(slot, self.args, self.python)))
            detail = f"exit={code}"
        finally:
            if holder is not None:
                holder_code = self._terminate(holder, HOLDER_STOP_S)
        if holder is not None:
            detail += f" holder={holder_code}"
            # The holder exits 0 on SIGTERM; anything else breaks the run's linkage.
            code = code or holder_code
        return code, detail


def run(args, *, clock=None, output=None):
    clock = clock or time.time
    slots = timetable(parse_start(args.start), candidate_names(args.candidates),
                      scenario_names(args.scenarios), args.real_camera)
    validate(slots, clock())
    output = output or sys.stdout
    print(render(slots, args.role), file=output, flush=True)
    if args.print:
        return 0
    preflight(slots, args)
    scheduler = Scheduler(slots, args, clock=clock, output=output)
    previous = {sig: signal.signal(sig, scheduler.request_stop)
                for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        return scheduler.run()
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
