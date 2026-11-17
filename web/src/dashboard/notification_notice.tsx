/**
 * The Owner's notification destination notice (Issue #301 follow-up).
 *
 * The server answers `GET /api/monitoring/notifications` (`OWNER_READ`) with
 * one fixed word: no notification destination (Slack) is configured, so no
 * Owner notification (camera offline, capture node, hardware, recording
 * health, human access, ...) leaves the Main Server (`not_configured`), or
 * Slack is configured and a delivery since this Main Server start did not
 * reach it (`delivery_failed`). The App loads it only for an Owner session;
 * the server repeats that check and refuses everyone else.
 *
 * It is sampled like the camera offline notice (`startOfflineNoticeSampling`,
 * every 60 s, without an idle touch on the server) and shown above it on
 * every screen. It never shows the webhook URL, an error, a count, a time or
 * which notification.
 */
import type { NotificationCause } from '../domain';
import type { Catalog } from '../i18n';
import type { SampledNotice } from './offline_notice';

export type NotificationNoticeState = SampledNotice<NotificationCause>;

export function NotificationNotice({ t, notice }: { t: Catalog; notice: NotificationNoticeState }) {
  if (notice.state === 'ready' && notice.cause !== null) {
    const failed = notice.cause === 'delivery_failed';
    return <section className="notice-inline notice-offline" role="alert" data-notification-notice="true"
      data-notification-cause={notice.cause}>
      <strong>{failed ? t.notificationsDeliveryFailedTitle : t.notificationsNotConfiguredTitle}</strong>
      <p>{failed ? t.notificationsDeliveryFailed : t.notificationsNotConfigured}</p>
      <p>{failed ? t.notificationsDeliveryFailedHint : t.notificationsNotConfiguredHint}</p>
    </section>;
  }
  // A check that could not be made is said so, never shown as "nothing to report".
  if (notice.state === 'failed') return <p role="status" className="muted">{t.notificationsNoticeUnavailable}</p>;
  return null;
}
