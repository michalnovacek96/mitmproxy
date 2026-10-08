# GA4 / Firebase Analytics decoder for mitmproxy

See exactly what your mobile app sends to Google Analytics 4 — right in [mitmproxy](https://www.mitmproxy.org/).

The Firebase Analytics SDK (iOS & Android) sends events to `app-measurement.com/a` as compressed binary protobuf, which is unreadable in any proxy. This addon decodes it into plain events, parameters and user properties:

```yaml
# 3 event(s): deeplink_launch, view_item, user_engagement
events:

  - event: deeplink_launch
    time: 2026-10-07 14:44:01.656
    params:
      deeplink_destination: /shop/product/trail-runner-pro-x3
      firebase_event_origin: app
      firebase_error_value: deeplink_url_referrer
      firebase_error_length: 130
      firebase_error: 4 (parameter value too long)

  - event: view_item
    time: 2026-10-07 14:44:01.677
    params:
      currency: EUR
      value: 89
      items:
        - item_id: trail-runner-pro-x3
          item_name: Trail Runner Pro X3
          price: 89
          quantity: 1

  - event: user_engagement
    time: 2026-10-07 14:57:52.547
    params:
      engagement_time_msec: 13m 50s (830080 ms)
      firebase_event_origin: auto

user_properties:
  first_open_after_install: true
  lifetime_value_EUR: 89.00 EUR
  ga_session_id: 1791376498

device_app:
  app_id: com.example.app
  platform: ios
  os_version: 26.6
  consent_state: G1--
  timezone: UTC+02:00
```

## Features

- **Automatic** – GA4 requests open in the decoded view by default, no clicking around
- **Readable names** – Firebase short names are translated (`_e` → `user_engagement`, `_et` → `engagement_time_msec`, `_sid` → `ga_session_id`, …)
- **Readable values** – timestamps as dates, durations as `13m 50s`, LTV in currency, booleans as `true/false`
- **Ecommerce items** – nested `items[]` arrays are decoded
- **Firebase validation errors** – see when the SDK drops a parameter (e.g. value longer than 100 chars)
- **One-click filtering** – all GA4 requests are tagged, filter them with `~comment GA4`
- **All endpoints** – `app-measurement.com`, `region1.app-measurement.com`, `app-analytics-services.com`, `app-analytics-services-att.com` (iOS with ATT)
- **No dependencies** – a single Python file, works with the official mitmproxy installers

## Requirements

[mitmproxy](https://www.mitmproxy.org/) **12 or newer** (`brew install --cask mitmproxy` on macOS, or download from mitmproxy.org).

## Installation

### macOS / Linux – one command

```bash
curl -fsSL https://raw.githubusercontent.com/michalnovacek96/mitmproxy/main/install.sh | bash
```

This downloads the addon to `~/.mitmproxy/addons/` and registers it in `~/.mitmproxy/config.yaml`, so it loads every time you start `mitmweb`, `mitmproxy` or `mitmdump`.

To update later, just run the same command again.

### Manually (any OS)

Run mitmproxy with the script:

```bash
mitmweb -s ga4_app_measurement.py
```

Or add it permanently to `~/.mitmproxy/config.yaml` (on Windows `%USERPROFILE%\.mitmproxy\config.yaml`):

```yaml
scripts:
  - /full/path/to/ga4_app_measurement.py
```

## Usage

1. Start `mitmweb`.
2. Set your phone's Wi-Fi proxy to your computer's IP, port `8080`.
3. Open **http://mitm.it** on the phone and install + trust the mitmproxy certificate
   - **iOS:** Settings → General → VPN & Device Management → install, then Settings → General → About → Certificate Trust Settings → enable
   - **Android:** apps don't trust user certificates since Android 7 — use a debug build with a `network_security_config` that allows user CAs, an emulator or a rooted device
4. Use the app and type `~comment GA4` into the mitmweb search box.
5. Click a `POST /a` request → **Request** tab. Make sure the view selector (bottom right) is set to **auto**.

**Tip:** Firebase batches events and may upload them minutes later. Enable debug mode to get them almost instantly:

- **iOS:** add `-FIRDebugEnabled` to the scheme's launch arguments in Xcode
- **Android:** `adb shell setprop debug.firebase.analytics.app <package_name>`

`mitmdump` additionally prints one line per event to the console:

```
[GA4] view_item | currency=EUR, value=89, items=[...]
```

## Limitations

The protobuf schema is community reverse-engineered and not complete. A few fields are not known yet and are hidden from the view. Contributions to the schema are welcome at [lari/firebase-ga4-app-measurement-protobuf](https://github.com/lari/firebase-ga4-app-measurement-protobuf).

## Credits

- Protobuf schema: [lari/firebase-ga4-app-measurement-protobuf](https://github.com/lari/firebase-ga4-app-measurement-protobuf) by Lari Haataja (MIT)
- [mitmproxy](https://www.mitmproxy.org/)

## License

MIT
