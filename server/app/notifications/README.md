# Owner Notifications

Owns configured local/UI/Slack alerts and daily summaries. Hardware baseline changes/missing devices, unexpected recording storage, and recording self-test failures notify the owner immediately, alongside critical movement/tamper conditions.

Slack is optional and goes directly from the deployment to its configured endpoint; faults remain visible in dashboard/audit when Slack is disabled. Do not use a developer relay, include secrets/raw hardware identifiers, or upload monitoring media as telemetry.
