"""Deviceless OpenH264 encoder child for the Agent ring (Issue #16 PR B).

Owner decision 2026-11-26 (``docs/decisions/2026-11-26-agent-ring-h264.md``):
the Agent re-encodes each camera's MJPG frames to H.264 with OpenH264 and the
ring stores those segments. The encoder is a second child process per source,
separate from the capture child that holds the camera:

    fdsrc fd=0 ! image/jpeg caps ! jpegparse ! jpegdec ! videoconvert
      ! video/x-raw,format=I420 ! openh264enc (bitrate, max-bitrate, gop-size,
        rate-control=bitrate, enable-frame-skip=false)
      ! video/x-h264,stream-format=byte-stream,alignment=au,
        profile=constrained-baseline ! fdsink fd=1

The Agent writes the JPEG frames it has already framed and paced
(``frame_pacer``) to the child's stdin and reads an Annex B stream from its
stdout (``h264_annexb``). Frame skipping is disabled, so every picture written
yields exactly one access unit and a segment's sample count stays fixed.

The child follows the capture child's rules (``uvc_pipeline``): an
operator-installed ``gst-launch-1.0`` and plugin files that must be
root-controlled (checked at construction and again at every start), no plugin
directory scan, no registry, a minimal environment, stderr discarded, its own
process group, and the ``uvc_sandbox`` Landlock helper in ``--no-device``
mode, so the encoder can open no device node and no file outside the
read-only system paths (and no TCP socket where Landlock supports it). It
holds no camera: an encoder fault cannot take the live preview down, and the
camera child does not gain decoder or encoder plugins. Only the five plugin
files below can load; no audio, network, display or file sink element exists
in the argv.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import select
import subprocess
import sys
import time

from . import uvc_sandbox
from .uvc_pipeline import (GSTREAMER_ENVIRONMENT, SANDBOX_HELPER, SANDBOX_HELPER_ARGS,
                           MjpegProfile, PipelineError, SubprocessPipeline,
                           default_plugin_dirs, minimal_environment,
                           require_trusted_executable, require_trusted_file)


# coreelements: fdsrc/fdsink; jpegformat: jpegparse; jpeg: jpegdec;
# videoconvertscale: videoconvert; openh264: openh264enc.
ENCODER_PLUGINS = ("libgstcoreelements.so", "libgstjpegformat.so", "libgstjpeg.so",
                   "libgstvideoconvertscale.so", "libgstopenh264.so")
MAX_BITRATE = 100_000_000
MAX_GOP_FRAMES = 1000
# Threads OpenH264 may use for one source; bounds the encoder's CPU share.
ENCODER_THREADS = 2


@dataclass(frozen=True)
class EncoderProfile:
    """The camera's MJPEG input and the H.264 rate/GOP for one source."""

    capture: MjpegProfile
    target_bitrate: int
    max_bitrate: int
    gop_frames: int

    def __post_init__(self):
        if not isinstance(self.capture, MjpegProfile):
            raise ValueError("an explicit MJPEG capture profile is required")
        for value in (self.target_bitrate, self.max_bitrate):
            if type(value) is not int or not 1 <= value <= MAX_BITRATE:
                raise ValueError("invalid encoder bitrate")
        if self.target_bitrate > self.max_bitrate:
            raise ValueError("encoder target bitrate exceeds its maximum")
        if type(self.gop_frames) is not int or not 1 <= self.gop_frames <= MAX_GOP_FRAMES:
            raise ValueError("invalid encoder GOP size")


def encoder_argv(executable, profile, *, plugins=()):
    """The fixed encoder pipeline; nothing else can be expressed."""
    if not isinstance(profile, EncoderProfile):
        raise PipelineError("explicit encoder profile is required")
    if any(not isinstance(plugin, str) or "," in plugin for plugin in plugins):
        raise PipelineError("invalid pipeline plugin")
    preload = [f"--gst-plugin-load={','.join(plugins)}"] if plugins else []
    return [str(executable), "-q", *preload,
            "fdsrc", "fd=0",
            "!", profile.capture.caps(),
            "!", "jpegparse",
            "!", "jpegdec",
            "!", "videoconvert",
            "!", "video/x-raw,format=I420",
            "!", "openh264enc", f"bitrate={profile.target_bitrate}",
            f"max-bitrate={profile.max_bitrate}", f"gop-size={profile.gop_frames}",
            "rate-control=bitrate", "enable-frame-skip=false", "usage-type=camera",
            f"multi-thread={ENCODER_THREADS}",
            "!", "video/x-h264,stream-format=byte-stream,alignment=au,profile=constrained-baseline",
            "!", "fdsink", "fd=1", "sync=false"]


def no_device_sandbox_argv(python, helper, read_paths, command, helper_args=()):
    """Run ``command`` under ``uvc_sandbox --no-device``: no device is openable."""
    python, helper, helper_args = Path(python), Path(helper), tuple(helper_args)
    if (not python.is_absolute() or not helper.is_absolute()
            or helper_args not in ((), (uvc_sandbox.ARCHIVE_ENTRY,))):
        raise PipelineError("video pipeline sandbox is unavailable")
    reads = []
    for path in read_paths:
        reads += ["--read", str(path)]
    return [str(python), "-I", "-S", "-B", str(helper), *helper_args,
            uvc_sandbox.NO_DEVICE, *reads, "--", *command]


class EncoderProcess(SubprocessPipeline):
    """The encoder child: JPEG frames in on stdin, Annex B out on stdout.

    ``write`` never blocks past its timeout: a stalled or exited child is a
    ``PipelineError`` (fixed text), so the recorder thread can restart it at
    the next segment boundary instead of hanging.
    """

    def __init__(self, process, *, proc_root="/proc"):
        super().__init__(process, proc_root=proc_root)
        self._stdin = process.stdin
        os.set_blocking(self._stdin.fileno(), False)

    def write(self, data, timeout):
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("frame must be bytes")
        view = memoryview(data)
        deadline = time.monotonic() + timeout
        try:
            descriptor = self._stdin.fileno()
            while view:
                # Checked before every attempt, so a child that keeps draining
                # slowly cannot stretch one frame past the timeout either
                # (PR #432 review).
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise PipelineError("video encoder stalled")
                try:
                    view = view[os.write(descriptor, view):]
                except BlockingIOError:
                    select.select([], [descriptor], [], remaining)
        except PipelineError:
            raise
        except (OSError, ValueError):
            raise PipelineError("video encoder stopped") from None

    def close_input(self):
        """End of input: the encoder flushes its last access unit and exits."""
        try:
            self._stdin.close()
        except OSError:
            pass

    def close(self):
        self.close_input()
        super().close()


class EncoderLauncher:
    """Operator-installed GStreamer with OpenH264; not bundled, never downloaded.

    Construction refuses (``PipelineError``) when Landlock is unavailable or a
    required plugin is missing or not root-controlled, so a host without the
    encoder packages fails its check instead of recording nothing silently.
    """

    def __init__(self, executable, *, plugin_dirs=None, trust=require_trusted_executable,
                 trust_file=require_trusted_file, sandbox_abi=uvc_sandbox.abi_version,
                 python=sys.executable, helper=SANDBOX_HELPER,
                 helper_args=SANDBOX_HELPER_ARGS, popen=subprocess.Popen):
        self._trust, self._trust_file = trust, trust_file
        self.executable = trust(executable)
        if sandbox_abi() < 1:
            raise PipelineError("video pipeline sandbox is unavailable")
        self.plugins = self._find_plugins(default_plugin_dirs() if plugin_dirs is None
                                          else plugin_dirs)
        if not python:
            raise PipelineError("video pipeline sandbox is unavailable")
        self.python, self.helper, self.helper_args = python, helper, tuple(helper_args)
        self._trusted_sandbox()
        self.environment = minimal_environment(GSTREAMER_ENVIRONMENT)
        self.popen = popen

    def _find_plugins(self, plugin_dirs):
        for directory in plugin_dirs:
            candidates = [Path(directory) / name for name in ENCODER_PLUGINS]
            if all(candidate.exists() for candidate in candidates):
                return tuple(self._trust_file(candidate) for candidate in candidates)
        raise PipelineError("required GStreamer encoder plugins are unavailable")

    def _trusted_sandbox(self):
        return self._trust(self.python), self._trust_file(self.helper)

    def argv(self, profile):
        # Re-check at every start: a package change must not be trusted blindly.
        python, helper = self._trusted_sandbox()
        executable = self._trust(self.executable)
        plugins = tuple(self._trust_file(plugin) for plugin in self.plugins)
        command = encoder_argv(executable, profile, plugins=[str(plugin) for plugin in plugins])
        read_paths = (*uvc_sandbox.DEFAULT_READ_PATHS, str(executable),
                      *(str(plugin) for plugin in plugins))
        return no_device_sandbox_argv(python, helper, read_paths, command, self.helper_args)

    def launch(self, profile):
        argv = self.argv(profile)
        if any(not isinstance(item, str) or "\0" in item for item in argv):
            raise PipelineError("invalid pipeline command")
        try:
            process = self.popen(
                argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, close_fds=True, start_new_session=True,
                env=self.environment, cwd="/", bufsize=0,
            )
        except (OSError, ValueError, subprocess.SubprocessError):
            raise PipelineError("video encoder could not start") from None
        return EncoderProcess(process)
