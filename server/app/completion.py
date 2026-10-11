"""Cancellation-deferring completion of one step (lifespan and background tasks).

Lives outside ``app.main`` so that modules ``app.main`` imports (the human
route foundation) can use it without an import cycle. ``app.main`` re-exports
it under the same name.
"""

import asyncio


async def run_to_completion(awaitable):
    """Finish a cleanup step even when the awaiting task is cancelled.

    Cancelling an ASGI lifespan (shutdown timeout, embedder cancellation)
    must not abandon a stop thread or skip the cleanup after it, so the step
    runs as its own task and every cancellation of the caller is deferred
    until it finishes. The caller's cancellation is re-raised afterwards.
    """
    task = asyncio.ensure_future(awaitable)
    cancelled = False
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            # Recorded even when the step finished in the same loop turn as
            # the caller's cancellation, so that cancellation is never lost.
            # If the step itself was cancelled, re-raising is its result too.
            cancelled = True
        except BaseException:
            # The step failed. Before any cancellation this is its result;
            # after one, the recorded cancellation still wins below.
            if not cancelled:
                raise
    if cancelled:
        if not task.cancelled():
            task.exception()  # Retrieved; the caller's cancellation wins.
        raise asyncio.CancelledError
    return task.result()
