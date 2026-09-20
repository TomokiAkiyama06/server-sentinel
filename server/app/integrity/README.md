# Main Server Hardware Integrity

Owns deployment-local, owner-approved CPU, RAM, NVMe/M.2, HDD/recording-device, and GPU baselines; compares available identifiers at startup and at least daily.

Report `OK`, `CHANGED`, `MISSING`, `NEW_DEVICE`, and `UNVERIFIABLE` honestly. Changed/missing components require immediate owner notification; deliberate changes require audited owner approval. Never rewrite a baseline silently, invent unavailable identity guarantees, publish raw serials/UUIDs, or run the whole stack as root for probing.

Recording-path self-tests belong in `../media/health/`; capture-node health belongs in the agent boundary.
