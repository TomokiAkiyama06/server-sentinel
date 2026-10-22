/**
 * The client side of the Owner step-up contract (Issue #10 phase 2 S3/S6,
 * Owner decisions D3 and S4-1, AUTH-008).
 *
 * The server alone decides freshness: an Owner change made with a stale user
 * verification is refused with the fixed `403 step_up_required` and commits
 * nothing. Only then does this helper ask the Owner (an explicit click, never
 * a silent retry), run the step-up ceremony and retry the original change
 * exactly once. A declined, failed or cancelled step-up, or a second
 * `step_up_required`, leaves the change unperformed; no loop exists.
 */
import { ApiError } from '../api';

export type OwnerOutcome<T> =
  | { state: 'done'; value: T }
  /** The server refused before committing (step-up declined, failed, or
   *  still required after one): the change was not made. */
  | { state: 'not_performed' }
  /** Any other failure: the change may or may not have been made. */
  | { state: 'unknown' }
  /** The screen went away; neither a result nor an error. */
  | { state: 'aborted' };

export interface StepUpHooks {
  /** Ask the Owner to confirm with their passkey; `false` declines. */
  confirm(): Promise<boolean>;
  /** The ceremony (`DashboardServices.stepUp`); absent ⇒ nothing can refresh. */
  stepUp?: ((signal: AbortSignal) => Promise<void>) | undefined;
  /** Called after the Owner confirmed, while the ceremony runs. */
  onCeremony?: () => void;
  /** Called right before the one retry is sent. Until then the change was
   *  refused before any commit, so abandoning it means "not performed". */
  onRetry?: () => void;
}

const stale = (error: unknown) => error instanceof ApiError && error.code === 'step_up_required';

export async function runOwnerChange<T>(run: (signal: AbortSignal) => Promise<T>, hooks: StepUpHooks,
  signal: AbortSignal): Promise<OwnerOutcome<T>> {
  try {
    return { state: 'done', value: await run(signal) };
  } catch (error) {
    if (signal.aborted) return { state: 'aborted' };
    if (!stale(error)) return { state: 'unknown' };
  }
  const confirmed = await hooks.confirm();
  if (signal.aborted) return { state: 'aborted' };
  if (!confirmed || !hooks.stepUp) return { state: 'not_performed' };
  hooks.onCeremony?.();
  try {
    await hooks.stepUp(signal);
  } catch {
    return signal.aborted ? { state: 'aborted' } : { state: 'not_performed' };
  }
  if (signal.aborted) return { state: 'aborted' };
  hooks.onRetry?.();
  try {
    return { state: 'done', value: await run(signal) };
  } catch (error) {
    if (signal.aborted) return { state: 'aborted' };
    // Still stale right after a step-up: refused again before any commit.
    return stale(error) ? { state: 'not_performed' } : { state: 'unknown' };
  }
}
