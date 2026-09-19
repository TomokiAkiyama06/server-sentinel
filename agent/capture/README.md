# Agent Capture

Owns local UVC/V4L2 discovery, profile negotiation, video capture, and hotplug/reconnect for sources attached to the capture node.

Use stable physical evidence; `/dev/videoN` alone is insufficient. Ambiguous identical non-serial cameras enter `manual_intervention_required` until owner re-approval. Report camera loss without terminating the agent; do not capture audio or fix source roles to front/rear.
