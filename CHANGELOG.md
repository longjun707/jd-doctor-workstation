# Changelog

## 2025-11-26

Browser extension (v4.2.5)
- JD8888 only: trigger skip after auto-reply "在的，请稍等" when message is pre-prescription (before Rx).
- Added page → content bridge using `window.postMessage('SKIP_PATIENT_REQUEST')`; content.js forwards to background.
- background.js: added `skipPatient` handler to POST to `http://154.44.25.188:8787/api/device/skip_patient`.
- manifest.json: added host_permissions for `http://154.44.25.188:8787/*`.
- Rebuilt dist assets.

APP HOOK (VersionChecker 3.8.6)
- Added `skip_patient` handling: JS `skipDiagIds` (5 min TTL) and Java `PrescriptionFetcher.addSkipDiagId()` integration.
- Fixed Frida static call argument type by constructing `java.lang.String` for `addSkipDiagId`.

Server-side (TCP.js) [ops note]
- `handleSkipPatient` now accepts `doctorName` and queries `fa_jdhealth` for phone; pushes to matching device; logging added. Service restarted.

Notes
- Feature restricted to JD8888 channel.
- Auto-reply content: "在的，请稍等".
