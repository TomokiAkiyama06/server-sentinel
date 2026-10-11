"""Optional SRT candidate through the operator-installed system ``ffmpeg``.

No package is added: the adapter runs only when ``ffmpeg -protocols`` lists
``srt`` for both input and output, and refuses otherwise (recorded as
``unavailable``). Nothing in this module has been run against a real ffmpeg
in this repository; treat every SRT number as unverified until measured.

Known, by-design limitations recorded as gate failures rather than hidden:

* SRT encryption is a pre-shared passphrase (AES), not the ADR-0006 mutual
  certificate identity, so G1 is ``fail`` for this candidate. ffmpeg only
  accepts the passphrase inside the URL argument, so it is visible in the
  process list of the host: use a disposable per-run passphrase on hosts
  without other users, and never a real secret.
* The ADR-0007 envelope rides in a JPEG COM segment (``wire.embed_envelope``);
  SRT carries no application acknowledgement back, so the sender cannot retry
  a refused unit and loss detection is the receiver's only.
* The local TCP impairment proxy cannot impair UDP: SRT impairment runs are
  ``unmeasured``.
"""
import os
from pathlib import Path
import shutil
import subprocess
import threading
import time

from . import wire

SRT_PORT = 47203


class SrtUnavailable(RuntimeError):
    pass


def srt_available(executable="ffmpeg", *, run=subprocess.run):
    """True only if ffmpeg lists ``srt`` among both input and output protocols."""
    path = shutil.which(executable)
    if path is None:
        return False
    try:
        output = run([path, "-hide_banner", "-protocols"], capture_output=True, text=True,
                     timeout=10, check=False).stdout
    except (OSError, subprocess.SubprocessError):
        return False
    section, found = None, set()
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.rstrip(":") in ("Input", "Output"):
            section = stripped.rstrip(":")
        elif stripped == "srt" and section:
            found.add(section)
    return found == {"Input", "Output"}


def require_srt(executable="ffmpeg", **kwargs):
    if not srt_available(executable, **kwargs):
        raise SrtUnavailable("system ffmpeg does not provide the srt protocol")
    return shutil.which(executable)


def read_passphrase(path):
    """A disposable 10..79 character passphrase from a private (0600) file."""
    info = os.stat(path)
    if info.st_mode & 0o077 or info.st_uid != os.geteuid():
        raise SrtUnavailable("passphrase file must be private to this user")
    value = Path(path).read_text(encoding="ascii").strip()
    if not 10 <= len(value) <= 79 or not value.isalnum():
        raise SrtUnavailable("passphrase must be 10-79 alphanumeric characters")
    return value


def srt_url(host, port, *, mode, passphrase, latency_ms=120):
    return (f"srt://{host}:{int(port)}?mode={mode}&pbkeylen=32&passphrase={passphrase}"
            f"&latency={int(latency_ms) * 1000}")


def sender_argv(ffmpeg, url):
    return [ffmpeg, "-hide_banner", "-loglevel", "error", "-f", "mjpeg", "-i", "pipe:0",
            "-c", "copy", "-an", "-f", "mpegts", url]


def receiver_argv(ffmpeg, url):
    return [ffmpeg, "-hide_banner", "-loglevel", "error", "-i", url, "-c", "copy", "-an",
            "-f", "mjpeg", "pipe:1"]


def run_sender(sender, ffmpeg, url, seconds):
    """Feed every source's frames (envelope embedded) into one ffmpeg SRT caller."""
    process = subprocess.Popen(sender_argv(ffmpeg, url), stdin=subprocess.PIPE,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    sender.start_sources()
    deadline = time.monotonic() + seconds
    try:
        while time.monotonic() < deadline and not sender.stop.is_set():
            sent = False
            for state, unit in sender._next_units(stop_and_wait=False, limit=8):
                frame = wire.embed_envelope(unit.payload, state.index, sender.epoch,
                                            unit.sequence, unit.capture_ns)
                process.stdin.write(frame)
                state.sent += 1
                sender.payload_bytes += len(unit.payload)
                sent = True
            if not sent:
                time.sleep(0.005)
            if process.poll() is not None:
                break
    finally:
        sender.stop.set()
        try:
            process.stdin.close()
        except OSError:
            pass
        process.terminate()
        sender._finish()


def run_receiver(receiver, node_id, ffmpeg, url):
    """Parse ffmpeg's MJPEG output and feed the product continuity tracker.

    There is no TLS identity on this path: the configured node is admitted
    by configuration alone, which is exactly the SRT authentication gap.
    """
    from media_capture_agent.uvc_pipeline import MjpegFrameParser
    receiver.authorizer.admit(node_id)
    grant = receiver.tracker.open_session(node_id)
    ids = wire.source_ids(node_id)
    process = subprocess.Popen(receiver_argv(ffmpeg, url), stdout=subprocess.PIPE,
                               stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def loop():
        parser = MjpegFrameParser(8 * 1024 * 1024)
        heartbeat = threading.Event()

        def beat():
            while not heartbeat.wait(1.0):
                receiver.tracker.heartbeat(grant)
        threading.Thread(target=beat, daemon=True).start()
        try:
            while not receiver.stop.is_set():
                data = process.stdout.read1(65536)
                if not data:
                    break
                with receiver._lock:
                    receiver.bytes_in += len(data)
                for frame in parser.feed(data):
                    try:
                        (index, epoch, sequence, capture_ns), payload = wire.extract_envelope(frame)
                    except wire.ProtocolError:
                        continue
                    if index < len(ids):
                        receiver._media(grant, ids[index], epoch, sequence, capture_ns, payload)
        finally:
            heartbeat.set()
            process.terminate()
    receiver.serve_with(loop)
