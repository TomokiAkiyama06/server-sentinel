# Local UVC Adapter

Owns Main Server UVC/V4L2 discovery, capability negotiation, video-only capture integration, stable physical identity, and hotplug/reconnect reporting through the Camera Source abstraction.

Do not rely on `/dev/videoN` alone. Ambiguous identical non-serial cameras require `manual_intervention_required` and explicit owner re-approval; never bind an arbitrary substitute or capture audio.
