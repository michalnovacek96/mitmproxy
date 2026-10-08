# Changelog

All notable changes to this project are documented here.
Versions follow [Semantic Versioning](https://semver.org): `MAJOR.MINOR.PATCH`.

## [1.0.1] - 2026-10-08

- mitmweb opens only the tracking hits UI on start, not its own page (the installer sets `web_open_browser: false`; mitmweb stays available on http://127.0.0.1:8081)
- The installer adds the addon to an existing `scripts:` list in `config.yaml` automatically

## [1.0.0] - 2026-10-08

First public release.

- Tracking hits UI on http://127.0.0.1:8082: live list of analytics hits, one row per event, filters per tool, regex search, hit detail with all parameters
- Detection of 25+ tools by domain (GA4/Firebase, Adjust, AppsFlyer, Meta, Mixpanel, Amplitude, Braze, Segment, ...)
- GA4 / Firebase Analytics protobuf decoding (`app-measurement.com/a`) with readable names and values
- Firebase measurement config decoding (`/config/app`): measurement ID, key events, sGTM endpoint
- Automatic server-side GTM detection from the Firebase config, custom sGTM domains
- Firebase SKAN (`/skan`) decoding
- Schema-less protobuf decoding for other binary payloads
- mitmweb content views: GA4 App Measurement, Firebase Config, Firebase SKAN, Tracking Protobuf
