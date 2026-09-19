# Integration Tests

Owns boundary checks for API permissions, trusted-proxy isolation, pairing/revocation, ingest validation, media/storage coordination, migrations, and service health using temporary storage and mocked/virtual devices/transports.

Cover absent/substituted media mounts, safety reserves, separate node/camera failure, and incident preservation. Do not touch deployment disks/services, use real secrets/media, or require public services for ordinary CI.
