/** Test-only bundle entry: one bundle, so `ApiError` is the same class in the
 *  provider, the step-up helper and the test. Never part of dist. */
export { ApiError } from '../src/api';
export { calibrationReasons } from '../src/domain';
export { createDashboardServices, parseCalibrationResult, parseSceneCalibration } from '../src/shared/services';
export { CalibrationCard, CalibrationScreen, refusalText } from '../src/calibration/screen';
