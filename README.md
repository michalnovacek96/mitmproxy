# iOS App Tracking Debugger

A tool for QA-ing the outgoing analytics hits of an iOS app, built on top of [mitmproxy](https://www.mitmproxy.org/).

> **iOS only.** The decoder works with apps running on iOS.

## Tracking hits UI

Open **http://127.0.0.1:8082** while mitmweb is running. You get a live list of every analytics hit your app sends – one row per event – with the tool detected automatically. Click a tool at the top to filter, click a hit to see all its parameters.

![App Tracking Debugger UI](docs/screenshot.png)

Detected tools: GA4 (Firebase), GA4 (web), Firebase, Crashlytics, Adjust, AppsFlyer, Meta, Branch, Singular, Kochava, Airbridge, TikTok, Snapchat, Google Ads, Mixpanel, Amplitude, Segment, Braze, CleverTap, OneSignal, AppMetrica, RevenueCat, Sentry, Datadog, Clarity.

**Server-side GTM:** click **sGTM domains** and add your own measurement domain (e.g. `sgtm.example.com`). Hits sent there are shown as **sGTM** and GA4 payloads in them are decoded too. The list is saved and kept after restart.

## GA4 decoding

Most tracking hits are readable in a proxy as they are (JSON or query strings). GA4 is different: the Firebase Analytics SDK sends events to `app-measurement.com/a` as compressed binary protobuf, so you only see gibberish. This addon contains the special protobuf decoding logic for GA4 and turns it into plain events, parameters and user properties – in the hits UI and also directly in mitmweb (request view):

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

- **Live hits list** – every analytics event in one place, filter by tool, search events & params
- **sGTM support** – add your own server-side GTM domains
- **Automatic** – GA4 requests open in the decoded view in mitmweb by default
- **Readable names** – Firebase short names are translated (`_e` → `user_engagement`, `_et` → `engagement_time_msec`, `_sid` → `ga_session_id`, …)
- **Readable values** – timestamps as dates, durations as `13m 50s`, LTV in currency, booleans as `true/false`
- **Ecommerce items** – nested `items[]` arrays are decoded
- **Firebase validation errors** – see when the SDK drops a parameter (e.g. value longer than 100 chars)
- **Filtering in mitmweb** – tracking requests are tagged, filter them with `~marked` (all tools) or `~comment GA4`
- **All endpoints** – `app-measurement.com`, `region1.app-measurement.com`, `app-analytics-services.com`, `app-analytics-services-att.com` (iOS with ATT)
- **No dependencies** – a single Python file, works with the official mitmproxy installers

## Installation

### macOS

**1. Install mitmproxy** (version 12 or newer) using [Homebrew](https://brew.sh):

```bash
brew install --cask mitmproxy
```

No Homebrew? Download the installer from [mitmproxy.org/downloads](https://mitmproxy.org/downloads/).

**2. Install the addon:**

```bash
curl -fsSL https://raw.githubusercontent.com/michalnovacek96/mitmproxy/main/install.sh | bash
```

This downloads the addon to `~/.mitmproxy/addons/` and registers it in `~/.mitmproxy/config.yaml`, so it loads every time you start `mitmweb`. To update later, run the same command again.

### Windows

**1. Install mitmproxy** (version 12 or newer) – download and run the Windows installer from [mitmproxy.org/downloads](https://mitmproxy.org/downloads/).

**2. Install the addon:**

1. Download [`app_tracking_debugger.py`](https://raw.githubusercontent.com/michalnovacek96/mitmproxy/main/app_tracking_debugger.py) (right click → Save as).
2. Create the file `%USERPROFILE%\.mitmproxy\config.yaml` with this content (use the path where you saved the file):

   ```yaml
   scripts:
     - C:\Users\<you>\Downloads\app_tracking_debugger.py
   ```

Alternatively, skip the config and start mitmweb with the script each time:

```powershell
mitmweb -s C:\Users\<you>\Downloads\app_tracking_debugger.py
```

## Usage

1. Start `mitmweb`.
2. Find your computer's local IP address (the iPhone must be on the same Wi-Fi):
   - **macOS** (Terminal):
     ```bash
     ipconfig getifaddr en0 || ipconfig getifaddr en1
     ```
   - **Windows** (PowerShell):
     ```powershell
     (Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway }).IPv4Address.IPAddress
     ```
   - Or in the system network settings (Wi-Fi / Network → Details → IP address).
3. On the iPhone: Settings → Wi-Fi → (i) next to your network → Configure Proxy → **Manual**. Server = your computer's IP (e.g. `192.168.1.20`), Port = `8080`.
4. Open **http://mitm.it** on the iPhone and install the mitmproxy certificate: Settings → General → VPN & Device Management → install, then Settings → General → About → Certificate Trust Settings → enable
5. Use the app and open **http://127.0.0.1:8082** – the hits appear live.

In mitmweb itself (http://127.0.0.1:8081) you can filter tracking requests with `~marked`; a GA4 `POST /a` request shows decoded in the **Request** tab when the view selector (bottom right) is set to **auto**.

## Limitations

The protobuf schema is community reverse-engineered and not complete. A few fields are not known yet and are hidden from the view. Contributions to the schema are welcome at [lari/firebase-ga4-app-measurement-protobuf](https://github.com/lari/firebase-ga4-app-measurement-protobuf).

## Credits

- Protobuf schema: [lari/firebase-ga4-app-measurement-protobuf](https://github.com/lari/firebase-ga4-app-measurement-protobuf) by Lari Haataja (MIT)
- [mitmproxy](https://www.mitmproxy.org/)

## License

MIT
