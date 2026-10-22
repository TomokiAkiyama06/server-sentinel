"""Synthetic tests for the Issue #15 PoC two-host scheduler (scripts/manual/transport_poc).

The scheduler only launches the README's single-scenario ``matrix --role``
commands at deterministic UTC times. These tests drive it with an injected
clock and fake processes: nothing is launched (no ``timeout``, no
``systemd-run``, no camera, no network). They do not verify any real
two-host run.
"""
import argparse
import contextlib
import io
import os
from pathlib import Path
import signal
import sys
import tempfile
import unittest
from unittest import mock

HARNESS = Path(__file__).resolve().parents[2] / "scripts" / "manual"
_SAVED_PATH = list(sys.path)
sys.path.insert(0, str(HARNESS))
try:
    from transport_poc import holder, matrix, poc15, records, schedule  # noqa: E402
finally:
    # ``poc15`` puts the harness, agent and server trees on ``sys.path`` when
    # imported; none is needed here, and a path left behind reaches every
    # later test module in the process (Issue #284).
    sys.path[:] = _SAVED_PATH

START = 1_792_544_400  # 2026-10-21T01:00:00Z
NOW = START - 600


class Clock:
    def __init__(self, now):
        self.now = float(now)

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += max(seconds, 0.001)


class FakeProcess:
    """Exits by itself ``runtime`` seconds after spawn, or on a signal."""

    def __init__(self, clock, argv, runtime, code=0):
        self.clock = clock
        self.argv = argv
        self.spawned = clock.now
        self.exit_at = clock.now + runtime
        self.code = code
        self.signals = []

    def poll(self):
        return self.code if self.clock.now >= self.exit_at else None

    def send_signal(self, sig):
        self.signals.append(sig)
        self.exit_at = min(self.exit_at, self.clock.now)

    def kill(self):
        self.signals.append(signal.SIGKILL)
        self.exit_at = self.clock.now

    def wait(self, timeout=None):
        return self.code


def _args(role, directory, **overrides):
    values = dict(role=role, start="2026-10-21T01:00:00Z", candidates="a_framed",
                  scenarios="default", real_camera=False, print=False,
                  materials=str(Path(directory) / "materials"),
                  node_root=str(Path(directory) / "nodes"), state=str(Path(directory) / "state"),
                  out=str(Path(directory) / "out"), bind="192.0.2.10",
                  upstream_host="192.0.2.10",
                  holder_state_dir=str(Path(directory) / "holder-state"),
                  holder_socket_dir=str(Path(directory) / "holder-sock"),
                  dev_checkout_helper=False)
    values.update(overrides)
    return argparse.Namespace(**values)


class TimetableTests(unittest.TestCase):
    def test_start_parses_strict_utc(self):
        self.assertEqual(START, schedule.parse_start("2026-10-21T01:00:00Z"))
        for text in ("2026-10-21T01:00:00", "2026-10-21 01:00:00Z", "2026-10-21T01:00:00+09:00",
                     "2026-10-21T01:00Z", "2026-13-21T01:00:00Z", ""):
            with self.subTest(text=text), self.assertRaises(SystemExit):
                schedule.parse_start(text)

    def test_both_roles_compute_the_same_slots_and_run_ids(self):
        with tempfile.TemporaryDirectory() as directory:
            built = {}
            for role in ("main", "agent"):
                args = _args(role, directory, candidates="a_framed,b_chunked",
                             real_camera=True)
                built[role] = schedule.timetable(
                    schedule.parse_start(args.start), schedule.candidate_names(args.candidates),
                    schedule.scenario_names(args.scenarios), args.real_camera)
            self.assertEqual(built["main"], built["agent"])
            slots = built["main"]
            self.assertEqual(2 * len(schedule.DEFAULT_SCENARIOS), len(slots))
            self.assertEqual(len(slots), len({slot.run_id for slot in slots}))
            for slot in slots:
                self.assertRegex(slot.run_id, records.RUN_ID_PATTERN)
                self.assertEqual(slot.run_id, schedule.run_id_for(slot.start))
            self.assertEqual("r20261021t010000", slots[0].run_id)
            # matrix order: candidate outer, scenario inner
            self.assertEqual(["a_framed"] * 19 + ["b_chunked"] * 19,
                             [slot.candidate for slot in slots])

    def test_margin_and_duration_math(self):
        slots = schedule.timetable(START, ["a_framed", "b_chunked"],
                                   schedule.DEFAULT_SCENARIOS, False)
        for before, after in zip(slots, slots[1:]):
            self.assertEqual(before.duration + schedule.SLOT_MARGIN_S, after.start - before.start)
            self.assertEqual(matrix.timing(before.scenario, False)["duration"], before.duration)
        durations = sum(matrix.timing(name, False)["duration"]
                        for name in schedule.DEFAULT_SCENARIOS)
        self.assertEqual(2 * (durations + 19 * schedule.SLOT_MARGIN_S),
                         slots[-1].end - slots[0].start)
        # Main needs duration + start-up + --main-grace + one receiver stop (15 s);
        # the timeout limit covers that, and limit + kill-after ends before the
        # next slot so a hung run never meets the next slot's processes.
        grace = poc15.build_parser().parse_args(
            ["matrix", "--materials", "m", "--state", "s", "--out", "o"]).main_grace
        self.assertGreaterEqual(schedule.RUN_LIMIT_EXTRA_S, grace + 15 + 10)
        self.assertLess(schedule.RUN_LIMIT_EXTRA_S + schedule.KILL_AFTER_S,
                        schedule.SLOT_MARGIN_S)
        self.assertGreater(schedule.HOLDER_EXTRA_S, schedule.AGENT_OFFSET_S + 15)
        self.assertLess(schedule.HOLDER_EXTRA_S, schedule.RUN_LIMIT_EXTRA_S)

    def test_past_far_and_over_budget_starts_are_refused(self):
        slots = schedule.timetable(START, ["a_framed"], ["normal"], False)
        schedule.validate(slots, START)  # exactly now is accepted
        with self.assertRaisesRegex(SystemExit, "past"):
            schedule.validate(slots, START + 1)
        with self.assertRaisesRegex(SystemExit, "24 h"):
            schedule.validate(slots, START - schedule.MAX_AHEAD_S - 1)
        schedule.validate(slots, START - schedule.MAX_AHEAD_S)
        three = schedule.timetable(START, ["a_framed", "b_chunked", "b_segment"],
                                   schedule.DEFAULT_SCENARIOS, False)
        with self.assertRaisesRegex(SystemExit, "3 h/day budget"):
            schedule.validate(three, NOW)
        schedule.validate(three[:38], NOW)  # two candidates fit
        # exactly at the budget passes; one second more does not
        soak = schedule.timetable(START, ["a_framed"], ["soak"], False)
        self.assertLessEqual(soak[0].end - soak[0].start, schedule.DAILY_BUDGET_S)
        with mock.patch.object(schedule, "DAILY_BUDGET_S", soak[0].end - soak[0].start):
            schedule.validate(soak, NOW)
        with mock.patch.object(schedule, "DAILY_BUDGET_S", soak[0].end - soak[0].start - 1):
            with self.assertRaises(SystemExit):
                schedule.validate(soak, NOW)
        with self.assertRaises(SystemExit):
            schedule.validate([], NOW)

    def test_auth_revoked_live_stays_manual(self):
        self.assertNotIn("auth_revoked_live", schedule.DEFAULT_SCENARIOS)
        self.assertNotIn("soak", schedule.DEFAULT_SCENARIOS)
        self.assertEqual([name for name in matrix.DEFAULT_ORDER if name != "auth_revoked_live"],
                         schedule.scenario_names("default"))
        for text in ("auth_revoked_live", "normal,auth_revoked_live"):
            with self.subTest(text=text), self.assertRaisesRegex(SystemExit, "manually"):
                schedule.scenario_names(text)
        for text in ("normal,nope", "normal,normal", "all"):
            with self.subTest(text=text), self.assertRaises(SystemExit):
                schedule.scenario_names(text)
        self.assertEqual(["soak"], schedule.scenario_names("soak"))
        for text in ("a_framed,a_framed", "srt"):
            with self.subTest(text=text), self.assertRaises(SystemExit):
                schedule.candidate_names(text)


class CommandTests(unittest.TestCase):
    def test_input_plan_is_real_only_for_one_source_media_scenarios(self):
        real = {name for name in schedule.DEFAULT_SCENARIOS
                if schedule.uses_real_camera(name, True)}
        self.assertEqual({"normal", "outage_1s", "outage_8s", "outage_120s", "rst",
                          "bandwidth_cap", "slow_stop_10s", "slow_stop_60s", "slow_drain",
                          "main_restart", "capture_restart"}, real)
        self.assertTrue(schedule.uses_real_camera("soak", True))
        self.assertFalse(any(schedule.uses_real_camera(name, False)
                             for name in matrix.SCENARIOS))

    def test_both_sides_agree_on_inputs_and_run(self):
        with tempfile.TemporaryDirectory() as directory:
            for real_camera in (False, True):
                slots = schedule.timetable(START, ["b_segment"], schedule.DEFAULT_SCENARIOS,
                                           real_camera)
                main_args = _args("main", directory)
                agent_args = _args("agent", directory, dev_checkout_helper=True)
                for slot in slots:
                    with self.subTest(slot=slot.scenario, real_camera=real_camera):
                        main = schedule.main_command(slot, main_args, "py")
                        agent = schedule.agent_command(slot, agent_args, "py")
                        for argv in (main, agent):
                            for flag, value in (("--run-id", slot.run_id),
                                                ("--candidates", "b_segment"),
                                                ("--scenarios", slot.scenario)):
                                self.assertEqual(value, argv[argv.index(flag) + 1])
                        self.assertEqual(slot.real, "--real-inputs" in main)
                        self.assertEqual(slot.real, "--real-inputs" in agent)
                        kind = agent[agent.index("--source-kind") + 1]
                        self.assertEqual("holder" if slot.real else "gst", kind)
                        self.assertEqual(slot.real, "--holder-socket" in agent)
                        # the README's Main command: scope, limits, nice/ionice, timeout
                        self.assertEqual(["timeout", "-k", "30",
                                          f"{slot.duration + schedule.RUN_LIMIT_EXTRA_S}s",
                                          "systemd-run", "--user", "--scope", "--collect",
                                          "--unit=ss-poc15-main", "-p", "CPUQuota=200%",
                                          "-p", "MemoryMax=1G", "nice", "-n", "10", "ionice",
                                          "-c", "3", "py"], main[:main.index("py") + 1])
                        self.assertIn("--unit=ss-poc15-agent", agent)
                        self.assertEqual(["main"], main[main.index("--role") + 1:][:1])
                        self.assertEqual(["agent"], agent[agent.index("--role") + 1:][:1])
            holder = schedule.holder_command(slots[0], agent_args, "py")
            self.assertIn("--unit=ss-poc15-holder", holder)
            # failed scopes are unloaded so the next slot can reuse the name
            for argv in (holder, schedule.agent_command(slots[0], agent_args, "py")):
                self.assertIn("--collect", argv[:argv.index("py")])
            self.assertIn("--dev-checkout-helper", holder)
            self.assertEqual(str(Path(directory) / "out" / f"holder-{slots[0].run_id}.jsonl"),
                             holder[holder.index("--out") + 1])
            self.assertEqual(str(slots[0].duration + schedule.HOLDER_EXTRA_S),
                             holder[holder.index("--seconds") + 1])
            self.assertNotIn("--dev-checkout-helper", schedule.holder_command(
                slots[0], _args("agent", directory), "py"))

    def test_launch_environment_hides_the_gpu(self):
        with mock.patch.object(schedule.subprocess, "Popen") as popen:
            schedule.Scheduler._popen(["x"])
        self.assertEqual("", popen.call_args.kwargs["env"]["CUDA_VISIBLE_DEVICES"])

    def test_preflight_refuses_reused_run_ids_and_missing_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            slots = schedule.timetable(START, ["a_framed"], ["normal", "rst"], True)
            args = _args("main", directory)
            schedule.preflight(slots, args)
            self.assertEqual(0o700, os.stat(args.out).st_mode & 0o777)
            os.mkdir(Path(args.out) / slots[1].run_id)
            with self.assertRaisesRegex(SystemExit, "already exist"):
                schedule.preflight(slots, _args("main", directory))
            os.rmdir(Path(args.out) / slots[1].run_id)
            (Path(args.out) / f"holder-{slots[0].run_id}.jsonl").touch()
            with self.assertRaisesRegex(SystemExit, "already exist"):
                schedule.preflight(slots, _args("agent", directory))
            for role, name in (("main", "bind"), ("agent", "upstream_host"),
                               ("agent", "holder_socket_dir"), ("main", "materials")):
                with self.subTest(missing=name), self.assertRaises(SystemExit):
                    schedule.preflight(slots, _args(role, directory, **{name: None}))
        with self.assertRaises(Exception):
            schedule.preflight(slots, _args("main", HARNESS / "transport_poc"))


class SchedulerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.clock = Clock(NOW)
        self.spawned = []
        self.output = io.StringIO()

    def _scheduler(self, slots, args, runtime):
        def spawn(argv):
            kind = "holder" if "--unit=ss-poc15-holder" in argv else argv[argv.index("--role") + 1]
            process = FakeProcess(self.clock, argv, runtime(kind, len(self.spawned)))
            self.spawned.append((kind, process))
            return process
        return schedule.Scheduler(slots, args, clock=self.clock, sleep=self.clock.sleep,
                                  spawn=spawn, output=self.output, python="py")

    def test_main_slots_start_on_time_and_report_one_line_each(self):
        slots = schedule.timetable(START, ["a_framed"], ["normal", "rst"], False)
        scheduler = self._scheduler(slots, _args("main", self.directory.name),
                                    lambda kind, n: slots[n].duration + 30)
        self.assertEqual(0, scheduler.run())
        self.assertEqual([slot.start for slot in slots],
                         [round(process.spawned) for _, process in self.spawned])
        lines = self.output.getvalue().splitlines()
        self.assertEqual([f"slot 0 {slots[0].run_id} normal a_framed synthetic exit=0",
                          f"slot 1 {slots[1].run_id} rst a_framed synthetic exit=0"], lines)

    def test_a_failed_slot_does_not_shift_the_timetable(self):
        slots = schedule.timetable(START, ["a_framed"], ["rst", "normal"], False)
        scheduler = self._scheduler(slots, _args("main", self.directory.name), lambda k, n: 5)
        original = scheduler.spawn

        def failing(argv):
            process = original(argv)
            process.code = 2 if len(self.spawned) == 1 else 0
            return process
        scheduler.spawn = failing
        self.assertEqual(1, scheduler.run())
        self.assertEqual(slots[1].start, round(self.spawned[1][1].spawned))
        self.assertIn("exit=2", self.output.getvalue())

    def test_missed_slot_stops_the_whole_schedule(self):
        slots = schedule.timetable(START, ["a_framed"], ["rst", "normal", "outage_8s"], False)
        overrun = slots[0].duration + schedule.SLOT_MARGIN_S + schedule.START_TOLERANCE_S + 1
        scheduler = self._scheduler(slots, _args("main", self.directory.name),
                                    lambda kind, n: overrun)
        self.assertEqual(schedule.EXIT_MISSED, scheduler.run())
        self.assertEqual(1, len(self.spawned))
        self.assertIn("missed its start", self.output.getvalue())
        # within the tolerance the slot still runs
        self.spawned.clear()
        self.clock.now = NOW
        late = slots[0].duration + schedule.SLOT_MARGIN_S + schedule.START_TOLERANCE_S - 1
        scheduler = self._scheduler(slots[:2], _args("main", self.directory.name),
                                    lambda kind, n: late if n == 0 else 5)
        self.assertEqual(0, scheduler.run())
        self.assertEqual(2, len(self.spawned))

    def test_signal_stops_the_running_slot_and_starts_no_more(self):
        slots = schedule.timetable(START, ["a_framed"], ["normal", "rst"], False)
        scheduler = self._scheduler(slots, _args("main", self.directory.name),
                                    lambda kind, n: 10_000)
        sleep = self.clock.sleep

        def sleep_then_signal(seconds):
            sleep(seconds)
            if self.spawned and self.clock.now > START + 30:
                scheduler.request_stop(signal.SIGTERM, None)
        scheduler.sleep = sleep_then_signal
        self.assertEqual(schedule.EXIT_STOPPED, scheduler.run())
        self.assertEqual(1, len(self.spawned))
        self.assertEqual([signal.SIGTERM], self.spawned[0][1].signals)
        self.assertIn("stopped by signal", self.output.getvalue())
        # a stop before the first slot launches nothing
        self.spawned.clear()
        scheduler = self._scheduler(slots, _args("main", self.directory.name), lambda k, n: 1)
        scheduler.request_stop()
        self.assertEqual(schedule.EXIT_STOPPED, scheduler.run())
        self.assertEqual([], self.spawned)

    def test_hung_process_is_killed_after_the_grace(self):
        slots = schedule.timetable(START, ["a_framed"], ["rst"], False)
        scheduler = self._scheduler(slots, _args("main", self.directory.name),
                                    lambda kind, n: 10_000)
        process = FakeProcess(self.clock, [], 10_000)
        process.send_signal = lambda sig: process.signals.append(sig)  # ignores SIGTERM
        self.assertEqual(0, scheduler._terminate(process, 15))
        self.assertEqual([signal.SIGTERM, signal.SIGKILL], process.signals)

    def test_real_agent_slot_runs_holder_then_agent_then_stops_holder(self):
        args = _args("agent", self.directory.name)
        os.mkdir(args.holder_socket_dir, 0o700)
        slots = schedule.timetable(START, ["a_framed"], ["normal", "sources_2"], True)

        def runtime(kind, n):
            if kind == "holder":
                os.mkdir(schedule.holder_socket_dir(slots[0], args), 0o700)
                Path(schedule.holder_socket(slots[0], args)).touch()
                return 10_000  # runs until the scheduler stops it
            return 300 + 10
        scheduler = self._scheduler(slots, args, runtime)
        self.assertEqual(0, scheduler.run())
        kinds = [kind for kind, _ in self.spawned]
        self.assertEqual(["holder", "agent", "agent"], kinds)
        holder_process, agent_process = self.spawned[0][1], self.spawned[1][1]
        self.assertEqual(START, round(holder_process.spawned))
        self.assertEqual(START + schedule.AGENT_OFFSET_S, round(agent_process.spawned))
        self.assertEqual([signal.SIGTERM], holder_process.signals)
        self.assertGreaterEqual(holder_process.exit_at, agent_process.exit_at)
        # the synthetic multi-source slot uses no holder
        self.assertEqual(slots[1].start + schedule.AGENT_OFFSET_S,
                         round(self.spawned[2][1].spawned))
        self.assertIn("gst", self.spawned[2][1].argv)
        lines = self.output.getvalue().splitlines()
        self.assertEqual(f"slot 0 {slots[0].run_id} normal a_framed real exit=0 holder=0",
                         lines[0])

    def test_each_real_slot_gets_its_own_holder_socket(self):
        """PR #303 review: a killed holder leaves its socket; a shared path
        would make every later holder fail to bind."""
        with tempfile.TemporaryDirectory() as directory:
            args = _args("agent", directory)
            slots = schedule.timetable(START, ["a_framed"], ["normal", "rst"], True)
            sockets = []
            for slot in slots:
                holder = schedule.holder_command(slot, args, "py")
                agent = schedule.agent_command(slot, args, "py")
                socket_dir = holder[holder.index("--socket-dir") + 1]
                self.assertEqual(str(Path(args.holder_socket_dir) / slot.run_id), socket_dir)
                self.assertEqual(str(Path(socket_dir) / "frames.sock"),
                                 agent[agent.index("--holder-socket") + 1])
                sockets.append(socket_dir)
            self.assertEqual(len(slots), len(set(sockets)))
            schedule.preflight(slots, args)
            self.assertEqual(0o700, os.stat(args.holder_socket_dir).st_mode & 0o777)

    def test_holder_not_ready_skips_the_agent(self):
        args = _args("agent", self.directory.name)
        slots = schedule.timetable(START, ["a_framed"], ["normal"], True)
        for exits in (False, True):
            self.spawned.clear()
            self.output = io.StringIO()
            self.clock.now = NOW
            scheduler = self._scheduler(slots, args,
                                        lambda kind, n: 1 if exits else 10_000)
            with self.subTest(holder_exits=exits):
                self.assertEqual(1, scheduler.run())
                self.assertEqual(["holder"], [kind for kind, _ in self.spawned])
                self.assertIn("holder not ready", self.output.getvalue())

    def test_holder_failure_fails_the_slot(self):
        args = _args("agent", self.directory.name)
        slots = schedule.timetable(START, ["a_framed"], ["rst"], True)
        os.makedirs(schedule.holder_socket_dir(slots[0], args), 0o700)
        Path(schedule.holder_socket(slots[0], args)).touch()
        scheduler = self._scheduler(slots, args, lambda kind, n: 10_000 if n == 0 else 20)
        original = scheduler.spawn

        def spawn(argv):
            process = original(argv)
            if "--unit=ss-poc15-holder" in argv:
                process.code = 1
            return process
        scheduler.spawn = spawn
        self.assertEqual(1, scheduler.run())
        self.assertIn("exit=0 holder=1", self.output.getvalue())


class HolderTrustPreflightTests(unittest.TestCase):
    """2026-10-20 real-host run: every holder refused a group-writable sandbox
    helper and all 24 real slots failed one by one. The schedule must refuse
    before slot 0 instead. The trust check itself is mocked: no camera, no
    GStreamer, no process."""

    REFUSAL = "PipelineError: sandbox helper is writable by others"

    def _run(self, args, problem):
        with mock.patch.object(holder, "launch_trust_problem",
                               return_value=problem) as check, \
                mock.patch.object(schedule.Scheduler, "run", return_value=0) as started, \
                mock.patch.object(schedule.subprocess, "Popen") as popen:
            try:
                code = schedule.run(args, clock=lambda: NOW, output=io.StringIO())
            except SystemExit as refusal:
                code = refusal
        popen.assert_not_called()
        return code, check, started

    def test_failed_trust_check_refuses_before_any_slot(self):
        for dev in (False, True):
            with self.subTest(dev_checkout_helper=dev), tempfile.TemporaryDirectory() as directory:
                args = _args("agent", directory, real_camera=True, scenarios="normal,sources_2",
                             dev_checkout_helper=dev)
                code, check, started = self._run(args, self.REFUSAL)
                self.assertIsInstance(code, SystemExit)
                self.assertIn("holder launch trust check failed", str(code))
                self.assertIn("writable by others", str(code))
                self.assertIn("no slot is started", str(code))
                started.assert_not_called()
                check.assert_called_once_with(holder.DEFAULT_GST, dev_checkout_helper=dev)

    def test_passing_trust_check_starts_the_schedule(self):
        with tempfile.TemporaryDirectory() as directory:
            args = _args("agent", directory, real_camera=True, scenarios="normal")
            code, check, started = self._run(args, None)
        self.assertEqual(0, code)
        check.assert_called_once()
        started.assert_called_once()

    def test_not_run_for_main_or_synthetic_only_schedules(self):
        for role, overrides in (("main", dict(real_camera=True, scenarios="normal")),
                                ("agent", dict(real_camera=False, scenarios="normal")),
                                ("agent", dict(real_camera=True,
                                               scenarios="sources_2,auth_unpaired"))):
            with self.subTest(role=role, **overrides), \
                    tempfile.TemporaryDirectory() as directory:
                code, check, started = self._run(_args(role, directory, **overrides),
                                                 self.REFUSAL)
                self.assertEqual(0, code)
                check.assert_not_called()
                started.assert_called_once()


class CliTests(unittest.TestCase):
    def test_print_shows_the_timetable_and_launches_nothing(self):
        output = io.StringIO()
        with mock.patch.object(schedule.time, "time", return_value=NOW), \
                mock.patch.object(schedule.subprocess, "Popen") as popen, \
                contextlib.redirect_stdout(output):
            code = poc15.main(["schedule", "--role", "agent", "--start", "2026-10-21T01:00:00Z",
                               "--candidates", "a_framed,b_chunked", "--real-camera",
                               "--print"])
        self.assertEqual(0, code)
        popen.assert_not_called()
        lines = output.getvalue().splitlines()
        self.assertTrue(lines[0].startswith("schedule role=agent slots=38 margin=90s"))
        self.assertIn("r20261021t010000 normal a_framed 300s real", lines[1])
        self.assertIn("sources_2 a_framed 120s synthetic", lines[2])
        self.assertEqual(40, len(lines))

    def test_cli_refusals(self):
        base = ["schedule", "--role", "main", "--candidates", "a_framed", "--print"]
        with mock.patch.object(schedule.time, "time", return_value=NOW), \
                contextlib.redirect_stdout(io.StringIO()):
            for extra, message in ((["--start", "2026-10-20T01:00:00Z"], "past"),
                                   (["--start", "2026-10-21T01:00:00Z", "--scenarios",
                                     "auth_revoked_live"], "manually"),
                                   (["--start", "2026-10-21T01:00:00Z", "--candidates",
                                     "a_framed,b_chunked,b_segment"], "budget")):
                with self.subTest(message=message):
                    with self.assertRaisesRegex(SystemExit, message):
                        poc15.main(base + extra)


if __name__ == "__main__":
    unittest.main()
