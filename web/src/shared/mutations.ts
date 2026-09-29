export type MutationOutcome = 'done' | 'failed' | 'aborted';

/** One in-flight mutation per subject; a replaced session aborts what remains.
 *
 * Repeated activation of the same subject is refused rather than queued, so a
 * repeated click cannot issue a second conflicting write. An aborted mutation
 * reports `aborted` and must not be treated as a failure or a fresh result.
 */
export class MutationQueue {
  private readonly inflight = new Map<string, AbortController>();

  get pending(): readonly string[] {
    return [...this.inflight.keys()];
  }

  has(id: string): boolean {
    return this.inflight.has(id);
  }

  start(id: string, run: (signal: AbortSignal) => Promise<void>,
        settle: (outcome: MutationOutcome) => void): boolean {
    if (this.inflight.has(id)) return false;
    const controller = new AbortController();
    this.inflight.set(id, controller);
    const finish = (outcome: MutationOutcome) => {
      if (this.inflight.get(id) === controller) this.inflight.delete(id);
      settle(controller.signal.aborted ? 'aborted' : outcome);
    };
    void (async () => {
      try {
        await run(controller.signal);
        finish('done');
      } catch {
        finish('failed');
      }
    })();
    return true;
  }

  abortAll(): void {
    for (const controller of this.inflight.values()) controller.abort();
    this.inflight.clear();
  }
}
