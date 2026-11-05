/** Test-only bundle entry: one bundle, so `ApiError` is the same class in the
 *  provider and the test. Never part of dist. */
export { ApiError } from '../src/api';
export { createDashboardServices, parseCameraOfflineNotice, CAMERA_OFFLINE_NOTICE_PATH } from '../src/shared/services';
export {
  CameraOfflineNotice, CAMERA_OFFLINE_NOTICE_REFRESH_MS, startOfflineNoticeSampling,
} from '../src/dashboard/offline_notice';
export { App } from '../src/App';
