"""Issue #15 transport PoC harness entry point (MANUAL TEST ONLY).

Not part of the product: nothing under ``server/`` or ``agent/`` imports it.
Run from a checkout; ``SERVER_DIR``/``AGENT_DIR`` default to this checkout.
Every path given here (materials, state, out, holder state) must be OUTSIDE
the repository. See README.md (Japanese runbook) for the full procedure.

Subcommands:
  materials init|node-key|issue|revoke   disposable CA / ledger / node bundles
  receiver   Main-side mTLS listener + continuity + bounded ingest (hash, discard)
  sender     capture-side sender (builtin | gst | holder media source)
  proxy      loopback impairment proxy (blackhole / reset / rate cap)
  holder     capture-host camera holder (product UvcCapture, video only)
  matrix     run the scenario matrix (role both|main|agent)
  summarize  evaluate G1-G6 and secondary metrics from JSONL
  srt-check  report whether the system ffmpeg provides srt (no network)
"""
import argparse
import os
from pathlib import Path
import sys

_HERE = Path(__file__).resolve()
_REPOSITORY = _HERE.parents[3]
sys.path.insert(0, str(_HERE.parents[1]))  # scripts/manual -> package ``transport_poc``
sys.path.insert(0, os.environ.get("AGENT_DIR", str(_REPOSITORY / "agent")))
sys.path.insert(0, os.environ.get("SERVER_DIR", str(_REPOSITORY / "server")))

from transport_poc import materials, records  # noqa: E402


def _profile(text):
    size, _, fps = text.partition("@")
    width, _, height = size.partition("x")
    return int(width), int(height), int(fps)


def build_parser():
    parser = argparse.ArgumentParser(prog="poc15", description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)

    m = commands.add_parser("materials")
    m.add_argument("action", choices=("init", "node-key", "issue", "revoke"))
    m.add_argument("--root", required=True, help="private directory outside the repository")
    m.add_argument("--csr", help="issue: CSR created by node-key on the capture host")
    m.add_argument("--label", default="good")
    m.add_argument("--negatives-only", action="store_true",
                   help="init: only negative bundles (real runs issue good/revoked_live "
                        "from a capture-host CSR)")

    r = commands.add_parser("receiver")
    r.add_argument("--candidate", required=True,
                   choices=("a_framed", "b_chunked", "b_segment", "srt_ffmpeg"))
    r.add_argument("--bind", required=True, help="explicit IP literal; never a wildcard")
    r.add_argument("--port", type=int, required=True)
    r.add_argument("--materials", required=True)
    r.add_argument("--state", required=True)
    r.add_argument("--out", required=True)
    r.add_argument("--run-id", required=True)
    r.add_argument("--drain-rate", type=float, default=0.0,
                   help="units/s consumed by the durable stand-in; 0 = unthrottled")
    r.add_argument("--max-queue", type=int, default=240,
                   help="AgentIngestQueue maximum_queued_messages")
    r.add_argument("--fast", action="store_true")
    r.add_argument("--no-ss", action="store_true", help="skip ss -tmi sampling")
    r.add_argument("--srt-passphrase-file")
    r.add_argument("--srt-node", default="good")

    s = commands.add_parser("sender")
    s.add_argument("--candidate", required=True,
                   choices=("a_framed", "b_chunked", "b_segment", "srt_ffmpeg"))
    s.add_argument("--host", required=True)
    s.add_argument("--port", type=int, required=True)
    s.add_argument("--node-dir", required=True)
    s.add_argument("--epoch-file", required=True)
    s.add_argument("--sources", type=int, default=1)
    s.add_argument("--seconds", type=float, required=True)
    s.add_argument("--out", required=True)
    s.add_argument("--run-id", required=True)
    s.add_argument("--source-kind", choices=("builtin", "gst", "holder"), default="builtin")
    s.add_argument("--fps", type=int, default=30)
    s.add_argument("--frame-bytes", type=int, default=125000)
    s.add_argument("--profile", type=_profile, default=(1280, 720, 30))
    s.add_argument("--holder-socket")
    s.add_argument("--real-inputs", action="store_true",
                   help="declare that the holder frames come from real cameras")
    s.add_argument("--route-probe", action="store_true")
    s.add_argument("--fast", action="store_true")
    s.add_argument("--srt-passphrase-file")

    p = commands.add_parser("proxy")
    p.add_argument("--listen", required=True)
    p.add_argument("--upstream", required=True)
    p.add_argument("--schedule", default="[]")
    p.add_argument("--seconds", type=float, required=True)
    p.add_argument("--buffer-bytes", type=int, default=65536)
    p.add_argument("--out", required=True)
    p.add_argument("--run-id", required=True)

    h = commands.add_parser("holder")
    h.add_argument("--state-dir", required=True)
    h.add_argument("--socket-dir", required=True)
    h.add_argument("--sources", type=int, default=1)
    h.add_argument("--profile", type=_profile, default=(1280, 720, 30))
    h.add_argument("--gst", default="/usr/bin/gst-launch-1.0")
    h.add_argument("--approve", action="store_true")
    h.add_argument("--dev-checkout-helper", action="store_true")
    h.add_argument("--seconds", type=float, required=True)
    h.add_argument("--out", required=True)
    h.add_argument("--run-id", required=True)

    x = commands.add_parser("matrix")
    x.add_argument("--role", choices=("both", "main", "agent"), default="both")
    x.add_argument("--materials", required=True)
    x.add_argument("--node-root", help="node bundles (default: MATERIALS/nodes)")
    x.add_argument("--state", required=True)
    x.add_argument("--out", required=True)
    x.add_argument("--run-id")
    x.add_argument("--candidates", default="a_framed,b_chunked,b_segment")
    x.add_argument("--scenarios", default="default",
                   help="comma list, 'default' (all but soak) or 'all'")
    x.add_argument("--sources", type=int, default=1)
    x.add_argument("--fps", type=int, default=30)
    x.add_argument("--frame-bytes", type=int, default=None)
    x.add_argument("--source-kind", choices=("builtin", "gst", "holder"), default="builtin")
    x.add_argument("--holder-socket")
    x.add_argument("--real-inputs", action="store_true")
    x.add_argument("--bind", default="127.0.0.1", help="receiver bind (main/both)")
    x.add_argument("--upstream-host", default="127.0.0.1", help="Main LAN IP (agent role)")
    x.add_argument("--upstream-port", type=int, default=0)
    x.add_argument("--proxy-host", default="127.0.0.1")
    x.add_argument("--port-offset", type=int, default=0)
    x.add_argument("--main-grace", type=float, default=20.0)
    x.add_argument("--fast", action="store_true")
    x.add_argument("--summarize", action="store_true")

    y = commands.add_parser("summarize")
    y.add_argument("runs", nargs="+")
    y.add_argument("--json")
    y.add_argument("--rss-limit-mib", type=int, default=512)
    y.add_argument("--holder", action="append", default=[],
                   help="holder JSONL; its CPU is added to real-camera Agent CPU")
    y.add_argument("--two-host", action="store_true",
                   help="inputs come from two hosts: Main-clock windows are not compared")

    c = commands.add_parser("srt-check")
    c.add_argument("--ffmpeg", default="ffmpeg")
    return parser


def _materials(args):
    if args.action == "init":
        materials.init(args.root, negatives_only=args.negatives_only)
    elif args.action == "node-key":
        materials.node_key(args.root)
    elif args.action == "issue":
        if not args.csr:
            raise SystemExit("--csr is required")
        materials.issue(args.root, args.csr, args.label)
    else:
        materials.revoke(args.root, args.label)
    return 0


def _receiver(args):
    from transport_poc import receiver
    config = receiver.ReceiverConfig(candidate=args.candidate, bind_host=args.bind,
                                     port=args.port, fast=args.fast, drain_rate=args.drain_rate,
                                     maximum_queued_messages=args.max_queue,
                                     ss_sampling=not args.no_ss)
    materials.require_outside_repository(args.out)
    if args.candidate == "srt_ffmpeg":
        from transport_poc import srt_adapter
        ffmpeg = srt_adapter.require_srt()
        passphrase = srt_adapter.read_passphrase(args.srt_passphrase_file)
        writer = records.JsonlWriter(args.out, run_id=args.run_id, role="receiver")
        state = materials.private_directory(args.state, exist_ok=True)
        instance = receiver.Receiver(config, args.materials, state, writer)
        node = materials.load_deployment(args.materials)["nodes"][args.srt_node]
        url = srt_adapter.srt_url(args.bind, args.port, mode="listener", passphrase=passphrase)
        srt_adapter.run_receiver(instance, node, ffmpeg, url)
        writer.close()
        return 0
    return receiver.run(config, args.materials, args.state, args.out, args.run_id)


def _sender(args):
    from transport_poc import sender
    materials.require_outside_repository(args.out)
    frame_bytes = 16000 if args.fast and args.frame_bytes == 125000 else args.frame_bytes
    config = sender.SenderConfig(
        candidate=args.candidate, host=args.host, port=args.port, n_sources=args.sources,
        source_kind=args.source_kind, fps=args.fps, frame_bytes=frame_bytes,
        width=args.profile[0], height=args.profile[1], fast=args.fast,
        holder_socket=args.holder_socket, real_inputs=args.real_inputs,
        route_probe=args.route_probe)
    if args.candidate == "srt_ffmpeg":
        from transport_poc import srt_adapter
        ffmpeg = srt_adapter.require_srt()
        passphrase = srt_adapter.read_passphrase(args.srt_passphrase_file)
        writer = records.JsonlWriter(args.out, run_id=args.run_id, role="sender")
        instance = sender.Sender(config, args.node_dir, sender.next_epoch(args.epoch_file), writer)
        url = srt_adapter.srt_url(args.host, args.port, mode="caller", passphrase=passphrase)
        srt_adapter.run_sender(instance, ffmpeg, url, args.seconds)
        writer.close()
        return 0
    return sender.run(config, args.node_dir, args.epoch_file, args.out, args.run_id,
                      args.seconds)


def _proxy(args):
    from transport_poc import proxy
    materials.require_outside_repository(args.out)
    listen = proxy.parse_endpoint(args.listen, loopback_only=True)
    upstream = proxy.parse_endpoint(args.upstream)
    return proxy.run(listen, upstream, proxy.parse_schedule(args.schedule), args.seconds,
                     args.out, args.run_id, buffer_bytes=args.buffer_bytes)


def _holder(args):
    from transport_poc import holder
    materials.require_outside_repository(args.out)
    writer = records.JsonlWriter(args.out, run_id=args.run_id, role="holder")
    try:
        return holder.run(args, writer)
    finally:
        writer.close()


def _matrix(args):
    from transport_poc import matrix, summarize
    for name in ("materials", "state", "out"):
        setattr(args, name, str(materials.require_outside_repository(getattr(args, name))))
    args.node_root = args.node_root or str(Path(args.materials) / "nodes")
    if args.frame_bytes is None:
        args.frame_bytes = 16000 if args.fast else 125000
    names = (matrix.DEFAULT_ORDER if args.scenarios == "default"
             else list(matrix.SCENARIOS) if args.scenarios == "all"
             else args.scenarios.split(","))
    for name in names:
        if name not in matrix.SCENARIOS:
            raise SystemExit("unknown scenario")
    candidates = args.candidates.split(",")
    for candidate in candidates:
        if candidate not in matrix.RECEIVER_PORTS:
            raise SystemExit("matrix candidates: a_framed, b_chunked, b_segment")
    run_id = args.run_id or records.new_run_id()
    out = matrix.Orchestrator(args, run_id).run(names, candidates)
    print(run_id)
    if args.summarize:
        report = summarize.summarize([out])
        summarize.write(report, out / "summary.json")
        print(summarize.render(report))
    return 0


def _summarize(args):
    from transport_poc import summarize
    report = summarize.summarize(args.runs, rss_limit=args.rss_limit_mib * 1024 * 1024,
                                 single_host=not args.two_host, holder_files=args.holder)
    if args.json:
        materials.require_outside_repository(args.json)
        summarize.write(report, args.json)
    print(summarize.render(report))
    return 0


def _srt_check(args):
    from transport_poc import srt_adapter
    print("srt_available" if srt_adapter.srt_available(args.ffmpeg) else "unavailable")
    return 0


def main(argv=None):
    args = build_parser().parse_args(argv)
    handler = {"materials": _materials, "receiver": _receiver, "sender": _sender,
               "proxy": _proxy, "holder": _holder, "matrix": _matrix,
               "summarize": _summarize, "srt-check": _srt_check}[args.command]
    return handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
