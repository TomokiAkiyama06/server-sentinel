# Diagnostic export

This package prepares a deployment-local support bundle only after the injected
authorization boundary approves the exact Owner action. It exposes no network,
upload, share, or scheduled-export primitive. The human route remains unmounted
until the application authorization work is complete.

Every diagnostic producer must label scalar fields. Credentials, pairing
secrets, private keys, sensitive headers, Owner biometric data, and embedded raw
media are always excluded. Hardware serials/UUIDs receive a keyed per-bundle
digest; the ephemeral key is never exported. Raw monitoring media uses a separate resolver which cannot enumerate
media and is called only for IDs individually selected in the authorized action.

The manifest reports included categories, counts, exclusion reasons and the
identifier transformation. It contains no excluded value, media ID, path,
deployment hostname, or other private deployment value.
