"""Main Server monitoring runtime wiring for Issues #21 and #23.

`config` is standard-library only so the standalone installer can validate a
deployment's monitoring section; `runtime` holds the lifespan worker and is
imported explicitly by the application.
"""
