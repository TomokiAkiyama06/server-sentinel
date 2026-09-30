"""Independent media profiles and bounded, transport-neutral scheduling."""

from .model import (
    CaptureProfile, CompressedPacket, InferenceProfile, QueueLimits,
    RecordingProfile, SourceProfiles, VideoFormat, ViewerProfile,
)
from .admission import (
    AdmissionDecision, AdmissionLease, SourceProfileAdmissions, SourceProfileCapabilities,
)
from .pipeline import AdapterUnavailable, PacketAdapter, PipelineStatus, SourcePipeline
from .planner import EncodeMode, EncodePlan, plan_encoding
from .sampling import InferenceSampler, SampleDecision
from .options import CaptureOption, RoomOverviewCriteria, room_overview_violations
from .adapters import (
    AccelerationPolicy, AdapterCandidate, AdapterKind, AdapterSelection, AdapterSelector,
    AdapterStartFailed, SelectedAdapter,
)

__all__ = [
    "AccelerationPolicy", "AdapterCandidate", "AdapterKind", "AdapterSelection",
    "AdapterSelector", "AdapterStartFailed", "CaptureOption", "RoomOverviewCriteria",
    "room_overview_violations",
    "AdapterUnavailable", "AdmissionDecision", "AdmissionLease", "CaptureProfile",
    "CompressedPacket", "EncodeMode",
    "EncodePlan", "InferenceProfile", "InferenceSampler", "PacketAdapter",
    "PipelineStatus", "QueueLimits", "RecordingProfile", "SampleDecision", "SourcePipeline",
    "SourceProfileAdmissions", "SourceProfileCapabilities", "SourceProfiles", "VideoFormat",
    "SelectedAdapter", "ViewerProfile", "plan_encoding",
]
