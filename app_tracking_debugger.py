"""
iOS App Tracking Debugger (mitmproxy addon)

1. Tracking hits UI - http://127.0.0.1:8082
   Lists every outgoing analytics hit (GA4/Firebase, Adjust, AppsFlyer, Meta,
   Mixpanel, Amplitude, Braze, ... and your own sGTM domains), one row per event,
   with filters per tool.

2. GA4 decoder - the Firebase Analytics SDK sends events to app-measurement.com/a
   as binary protobuf. This addon decodes them into readable events, parameters
   and user properties (also as the "GA4 App Measurement" view in mitmweb).

Schema based on https://github.com/lari/firebase-ga4-app-measurement-protobuf
No dependencies, works with the official mitmproxy binaries. Requires mitmproxy 12+.

Usage:
    mitmweb -s app_tracking_debugger.py
"""

from __future__ import annotations

import base64
import gzip
import json
import logging
import os
import re
import struct
import threading
import urllib.parse
import zlib
from collections import deque
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from mitmproxy import contentviews, ctx, http

logger = logging.getLogger(__name__)

# Firebase Analytics endpoints (app-analytics-services-att.com = iOS with ATT)
HOST_SUFFIXES = (
    "app-measurement.com",
    "app-analytics-services.com",
    "app-analytics-services-att.com",
)

# --------------------------------------------------------------------------
# Schema (field number -> (name, type[, sub-schema]))
# types: int, sint (signed int64), str, ts (timestamp in ms), msg, float, double
# --------------------------------------------------------------------------

EVENT_PARAM = {
    1: ("name", "str"),
    2: ("string_value", "str"),
    3: ("int_value", "sint"),
    4: ("float_value", "float"),
    5: ("double_value", "double"),
}
# nested parameters (e.g. items[] in ecommerce events)
EVENT_PARAM[6] = ("nested", "msg", EVENT_PARAM)

EVENT = {
    1: ("param", "msg", EVENT_PARAM),
    2: ("name", "str"),
    3: ("timestamp_millis", "ts"),
    4: ("previous_timestamp_millis", "ts"),
}

USER_PROPERTY = {
    1: ("set_timestamp_millis", "ts"),
    2: ("name", "str"),
    3: ("string_value", "str"),
    4: ("int_value", "sint"),
    5: ("float_value", "float"),
    6: ("double_value", "double"),
}

BUNDLE = {
    1: ("protocol_version", "int"),
    2: ("event", "msg", EVENT),
    3: ("user_property", "msg", USER_PROPERTY),
    4: ("upload_timestamp_millis", "ts"),
    5: ("start_timestamp_millis", "ts"),
    6: ("end_timestamp_millis", "ts"),
    7: ("previous_bundle_end_timestamp_millis", "ts"),
    8: ("platform", "str"),
    9: ("operating_system_version", "str"),
    10: ("device_model", "str"),
    11: ("user_default_language", "str"),
    12: ("time_zone_offset_minutes", "sint"),
    13: ("install_source", "str"),
    14: ("app_id", "str"),
    16: ("app_version", "str"),
    17: ("gmp_version", "int"),
    18: ("uploading_gmp_version", "int"),
    19: ("resettable_device_id", "str"),
    20: ("npa_non_personalized_ads", "str"),
    21: ("app_instance_id", "str"),
    22: ("dev_cert_hash", "str"),
    23: ("bundle_sequential_index", "int"),
    25: ("gmp_app_id", "str"),
    26: ("previous_bundle_start_timestamp_millis", "ts"),
    27: ("resettable_device_id_alt", "str"),
    30: ("firebase_instance_id", "str"),
    31: ("app_version_major", "int"),
    35: ("unknown_35 (proto: target_os_version)", "str"),
    46: ("system_properties_dynamite_version", "str"),
    52: ("gcs_google_consent_state", "str"),
    71: ("consent_diagnostics", "str"),
    77: ("system_properties_delivery_index", "int"),
}

BATCH = {1: ("bundle", "msg", BUNDLE)}

# Short names used by the Firebase SDK
EVENT_NAMES = {
    "_s": "session_start",
    "_e": "user_engagement",
    "_vs": "screen_view",
    "_ab": "app_background",
    "_au": "app_update",
    "_f": "first_open",
    "_v": "first_visit",
    "_i": "app_install",
    "_ui": "app_uninstall",
    "_cd": "app_clear_data",
    "_ou": "os_update",
    "_in": "in_app_purchase",
    "_ar": "ad_reward",
    "_ai": "ad_impression",
    "_ac": "ad_click",
    "_ae": "app_exception",
    "_cmp": "firebase_campaign",
    "_err": "error",
    "_ssr": "screen_view (ssr)",
    "_nr": "notification_receive",
    "_no": "notification_open",
    "_nf": "notification_foreground",
    "_nd": "notification_dismiss",
}

PARAM_NAMES = {
    "_si": "firebase_screen_id",
    "_et": "engagement_time_msec",
    "_sc": "firebase_screen_class",
    "_sn": "firebase_screen",
    "_o": "firebase_event_origin",
    "_pn": "previous_screen",
    "_pc": "previous_screen_class",
    "_pi": "previous_screen_id",
    "_pv": "previous_app_version",
    "_err": "firebase_error",
    "_ev": "firebase_error_value",
    "_el": "firebase_error_length",
    "_r": "realtime",
    "_dbg": "ga_debug",
    "_c": "firebase_conversion",
    "_sid": "ga_session_id",
    "_sno": "ga_session_number",
    "_fr": "first_run",
    "_mst": "manual_screen_tracking",
}

USER_PROPERTY_NAMES = {
    "_fi": "first_open_after_install",
    "_fot": "first_open_time",
    "_sid": "ga_session_id",
    "_sno": "ga_session_number",
    "_lte": "lifetime_user_engagement",
    "_se": "session_user_engagement",
    "_id": "user_id",
    "_npa": "non_personalized_ads",
    "_ldl": "last_deep_link_referrer",
    "_lgclid": "last_gclid",
}


# --------------------------------------------------------------------------
# Protobuf wire parser
# --------------------------------------------------------------------------

class DecodeError(Exception):
    pass


def _varint(buf: bytes, pos: int) -> tuple[int, int]:
    result = shift = 0
    while True:
        if pos >= len(buf):
            raise DecodeError("truncated varint")
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, pos
        shift += 7
        if shift > 70:
            raise DecodeError("varint too long")


def parse_fields(buf: bytes) -> list[tuple[int, int, object]]:
    """Return [(field_no, wire_type, raw_value)]."""
    out = []
    pos = 0
    while pos < len(buf):
        key, pos = _varint(buf, pos)
        field, wt = key >> 3, key & 7
        if field == 0:
            raise DecodeError("field 0")
        if wt == 0:
            val, pos = _varint(buf, pos)
        elif wt == 1:
            if pos + 8 > len(buf):
                raise DecodeError("truncated fixed64")
            val = buf[pos:pos + 8]
            pos += 8
        elif wt == 2:
            ln, pos = _varint(buf, pos)
            if pos + ln > len(buf):
                raise DecodeError("truncated bytes")
            val = buf[pos:pos + ln]
            pos += ln
        elif wt == 5:
            if pos + 4 > len(buf):
                raise DecodeError("truncated fixed32")
            val = buf[pos:pos + 4]
            pos += 4
        else:
            raise DecodeError(f"unsupported wire type {wt}")
        out.append((field, wt, val))
    return out


def _signed(v: int) -> int:
    return v - (1 << 64) if v >= 1 << 63 else v


def _as_text(b: bytes) -> str | None:
    try:
        s = b.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if all(c.isprintable() or c in "\t\r\n" for c in s):
        return s
    return None


def _decode_unknown(wt: int, val):
    """Best-effort decoding for fields not in the schema."""
    if wt == 0:
        return _signed(val)
    if wt == 1:
        return f"{struct.unpack('<d', val)[0]!r} (fixed64 0x{val[::-1].hex()})"
    if wt == 5:
        return f"{struct.unpack('<f', val)[0]!r} (fixed32 0x{val[::-1].hex()})"
    txt = _as_text(val)
    if txt is not None:
        return txt
    try:
        sub = parse_fields(val)
        if sub:
            return {f"#{f}": _decode_unknown(w, v) for f, w, v in sub}
    except DecodeError:
        pass
    return f"<bytes {val.hex()}>"


def decode(buf: bytes, schema: dict) -> dict:
    """Decode a message using the schema -> dict {name: value | [values]}."""
    msg: dict = {}
    for field, wt, val in parse_fields(buf):
        spec = schema.get(field)
        if spec is None:
            key = f"unknown_{field}"
            value = _decode_unknown(wt, val)
            repeated = True
        else:
            key, typ = spec[0], spec[1]
            repeated = typ == "msg"
            if typ == "msg" and wt == 2:
                value = decode(val, spec[2])
            elif typ == "str" and wt == 2:
                value = val.decode("utf-8", "replace")
            elif typ in ("int", "sint", "ts") and wt == 0:
                value = _signed(val) if typ != "int" else val
                if typ == "ts":
                    value = ("ts", value)
            elif typ in ("float", "double") and wt in (1, 5):
                value = struct.unpack("<d" if wt == 1 else "<f", val)[0]
            else:
                value = _decode_unknown(wt, val)
        if repeated:
            msg.setdefault(key, []).append(value)
        elif key in msg:
            # repeated scalar field - turn into a list
            if not isinstance(msg[key], list):
                msg[key] = [msg[key]]
            msg[key].append(value)
        else:
            msg[key] = value
    return msg


# --------------------------------------------------------------------------
# Rendering (YAML-like)
# --------------------------------------------------------------------------

def _scalar(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, tuple) and v and v[0] == "ts":
        return _fmt_time(v[1])
    if isinstance(v, float):
        return f"{v:g}" if abs(v) < 1e15 else repr(v)
    if isinstance(v, str):
        if v == "" or v != v.strip() or "\n" in v:
            return '"' + v.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'
        return v
    return str(v)


def _fmt_time(ms: int) -> str:
    try:
        dt = datetime.fromtimestamp(ms / 1000, tz=timezone.utc).astimezone()
    except (OverflowError, OSError, ValueError):
        return str(ms)
    return dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def _fmt_duration(ms: int) -> str:
    sec = ms / 1000
    h, rem = divmod(int(sec), 3600)
    m, s = divmod(rem, 60)
    if h:
        txt = f"{h}h {m}m {s}s"
    elif m:
        txt = f"{m}m {s}s"
    else:
        txt = f"{sec:g}s"
    return f"{txt} ({ms} ms)"


# Firebase validation error codes (_err)
FIREBASE_ERRORS = {
    4: "parameter value too long",
}

DURATION_KEYS = {"engagement_time_msec", "lifetime_user_engagement", "session_user_engagement"}
BOOL_KEYS = {"first_open_after_install", "non_personalized_ads", "realtime", "ga_debug", "first_run"}
TIME_KEYS = {"first_open_time"}


def _readable(name: str, value):
    """Convert a value to a human-readable form based on the parameter name."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if name in DURATION_KEYS:
            return _fmt_duration(int(value))
        if name in BOOL_KEYS and value in (0, 1):
            return bool(value)
        if name in TIME_KEYS:
            return _fmt_time(int(value))
        if name == "firebase_error" and value in FIREBASE_ERRORS:
            return f"{value} ({FIREBASE_ERRORS[value]})"
    return value


def _raw_value(p: dict):
    for k in ("string_value", "int_value", "double_value", "float_value"):
        if k in p:
            return p[k]
    return None


def _params_to_map(params: list[dict]) -> dict:
    out = {}
    for p in params:
        raw = p.get("name", "?")
        name = PARAM_NAMES.get(raw, raw)
        if "nested" in p:
            # array of objects (items) - each element is a message of nested params
            out[name] = [_params_to_map(n.get("nested", [])) for n in p["nested"]]
        else:
            out[name] = _readable(name, _raw_value(p))
    return out


def _render(obj, indent: int = 0) -> list[str]:
    pad = "  " * indent
    lines: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                if not v:
                    lines.append(f"{pad}{k}: {'{}' if isinstance(v, dict) else '[]'}")
                else:
                    lines.append(f"{pad}{k}:")
                    lines += _render(v, indent + 1)
            else:
                lines.append(f"{pad}{k}: {_scalar(v)}")
    elif isinstance(obj, list):
        for item in obj:
            if isinstance(item, (dict, list)) and item:
                sub = _render(item, indent + 1)
                sub[0] = f"{pad}- {sub[0].lstrip()}"
                lines += sub
            else:
                lines.append(f"{pad}- {_scalar(item)}")
    else:
        lines.append(f"{pad}{_scalar(obj)}")
    return lines


def _event_name(ev: dict) -> str:
    raw = ev.get("name", "?")
    return EVENT_NAMES.get(raw, raw)


def _pretty_event(ev: dict) -> dict:
    out: dict = {"event": _event_name(ev)}
    if "timestamp_millis" in ev:
        out["time"] = ev["timestamp_millis"]
    out["params"] = _params_to_map(ev.get("param", []))
    return out


def _pretty_user_props(props: list[dict]) -> dict:
    out = {}
    for p in props:
        raw = p.get("name", "?")
        val = _raw_value(p)
        if raw.startswith("_ltv_") and isinstance(val, int):
            # lifetime value in micro units of the currency
            out[f"lifetime_value_{raw[5:]}"] = f"{val / 1_000_000:.2f} {raw[5:]}"
            continue
        name = USER_PROPERTY_NAMES.get(raw, raw)
        out[name] = _readable(name, val)
    return out


DEVICE_KEYS = {
    "app_id": "app_id",
    "app_version": "app_version",
    "platform": "platform",
    "operating_system_version": "os_version",
    "device_model": "device_model",
    "user_default_language": "language",
    "install_source": "install_source",
    "app_instance_id": "app_instance_id",
    "resettable_device_id": "advertising_id",
    "resettable_device_id_alt": "vendor_id",
    "firebase_instance_id": "firebase_instance_id",
    "gmp_app_id": "firebase_app_id",
    "gcs_google_consent_state": "consent_state",
    "npa_non_personalized_ads": "non_personalized_ads",
    "gmp_version": "sdk_version",
    "upload_timestamp_millis": "uploaded_at",
}


def _pretty_bundle(b: dict) -> dict:
    out: dict = {"events": [_pretty_event(e) for e in b.get("event", [])]}
    if "user_property" in b:
        out["user_properties"] = _pretty_user_props(b["user_property"])
    info: dict = {}
    for key, label in DEVICE_KEYS.items():
        if key in b:
            info[label] = b[key]
    if "time_zone_offset_minutes" in b:
        off = b["time_zone_offset_minutes"]
        info["timezone"] = f"UTC{'+' if off >= 0 else '-'}{abs(off) // 60:02d}:{abs(off) % 60:02d}"
    out["device_app"] = info
    return out


def unpack_body(data: bytes) -> bytes:
    if data[:2] == b"\x1f\x8b":
        return gzip.decompress(data)
    if data[:1] == b"\x78":
        try:
            return zlib.decompress(data)
        except zlib.error:
            pass
    return data


def decode_batch(data: bytes) -> dict:
    return decode(unpack_body(data), BATCH)


def render_batch(batch: dict) -> str:
    bundles = batch.get("bundle", [])
    lines: list[str] = []
    for i, b in enumerate(bundles):
        if i:
            lines.append("")
        names = ", ".join(_event_name(e) for e in b.get("event", []))
        lines.append(f"# {len(b.get('event', []))} event(s): {names}")
        for line in _render(_pretty_bundle(b)):
            # blank line before each event and each top-level section
            if line.startswith("  - event:") or (line and not line.startswith(" ") and line != "events:"):
                lines.append("")
            lines.append(line)
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# Tracking tools detection
# --------------------------------------------------------------------------

# key, label, color, host suffixes, path regex (None = any path)
TOOLS = [
    ("ga4", "GA4 (Firebase)", "#e8710a", HOST_SUFFIXES, r"^/a/?$"),
    ("ga4web", "GA4 (web)", "#f9ab00", ("google-analytics.com", "analytics.google.com"), r"/g/collect"),
    ("firebase", "Firebase", "#ffa000", (
        "firebaseinstallations.googleapis.com", "firebaseremoteconfig.googleapis.com",
        "firebaselogging-pa.googleapis.com", "firebasedynamiclinks.googleapis.com",
        "fcmtoken.googleapis.com", "firebase-settings.crashlytics.com",
    ), None),
    ("crashlytics", "Crashlytics", "#c62828", ("crashlyticsreports-pa.googleapis.com", "crashlytics.com"), None),
    ("adjust", "Adjust", "#1e88e5", ("adjust.com", "adjust.net.in", "adjust.world", "adjust.io"), None),
    ("appsflyer", "AppsFlyer", "#2e7d32", ("appsflyer.com", "appsflyersdk.com"), None),
    ("meta", "Meta", "#1877f2", ("graph.facebook.com",), None),
    ("branch", "Branch", "#0097c7", ("branch.io",), None),
    ("singular", "Singular", "#7b1fa2", ("singular.net",), None),
    ("kochava", "Kochava", "#546e7a", ("kochava.com",), None),
    ("airbridge", "Airbridge", "#3949ab", ("airbridge.io",), None),
    ("tiktok", "TikTok", "#ee1d52", ("business-api.tiktok.com", "analytics.tiktok.com"), None),
    ("snap", "Snapchat", "#b8a800", ("tr.snapchat.com", "tr-shadow.snapchat.com"), None),
    ("googleads", "Google Ads", "#34a853", ("googleadservices.com", "googleads.g.doubleclick.net"), None),
    ("mixpanel", "Mixpanel", "#7856ff", ("mixpanel.com",), None),
    ("amplitude", "Amplitude", "#1f5fd6", ("amplitude.com",), None),
    ("segment", "Segment", "#3c9c78", ("segment.io", "segment.com"), None),
    ("braze", "Braze", "#e0457b", ("braze.com", "braze.eu", "appboy.com"), None),
    ("clevertap", "CleverTap", "#d81b60", ("clevertap-prod.com", "wzrkt.com"), None),
    ("onesignal", "OneSignal", "#e54b4d", ("onesignal.com",), None),
    ("appmetrica", "AppMetrica", "#c79a00", ("appmetrica.yandex.net", "appmetrica.yandex.com"), None),
    ("revenuecat", "RevenueCat", "#f2545b", ("revenuecat.com",), None),
    ("sentry", "Sentry", "#6c5fc7", ("sentry.io",), None),
    ("datadog", "Datadog", "#632ca6", ("datadoghq.com", "datadoghq.eu"), None),
    ("clarity", "Clarity", "#0078d4", ("clarity.ms",), None),
]
SGTM = ("sgtm", "sGTM", "#0b8043")
OTHER = ("other", "Other", "#8a8a8a")

# Custom (server-side GTM) domains, editable from the UI, persisted to disk
DOMAINS_FILE = os.path.join(os.path.expanduser("~"), ".mitmproxy", "tracking_custom_domains.json")
CUSTOM_DOMAINS: set[str] = set()


def _load_domains() -> None:
    try:
        with open(DOMAINS_FILE) as f:
            CUSTOM_DOMAINS.update(d for d in json.load(f) if isinstance(d, str))
    except (OSError, ValueError):
        pass


def _save_domains() -> None:
    try:
        with open(DOMAINS_FILE, "w") as f:
            json.dump(sorted(CUSTOM_DOMAINS), f)
    except OSError as e:
        logger.warning(f"Could not save custom domains: {e}")


def _host_match(host: str, suffixes) -> bool:
    return any(host == s or host.endswith("." + s) for s in suffixes)


def detect_tool(host: str, path: str) -> str:
    if CUSTOM_DOMAINS and _host_match(host, CUSTOM_DOMAINS):
        return "sgtm"
    path = path.split("?")[0]
    for key, _, _, suffixes, path_re in TOOLS:
        if _host_match(host, suffixes) and (path_re is None or re.search(path_re, path)):
            return key
    return "other"


def _is_ga4(flow) -> bool:
    if not isinstance(flow, http.HTTPFlow):
        return False
    return detect_tool(flow.request.pretty_host, flow.request.path) in ("ga4", "sgtm")


# --------------------------------------------------------------------------
# Hit extraction (request -> list of events)
# --------------------------------------------------------------------------

STRONG_NAME_KEYS = ("_eventName", "eventName", "event_name", "event_type", "event", "en")
NAME_KEYS = STRONG_NAME_KEYS + ("name", "type")
LIST_KEYS = ("events", "batch", "custom_events", "data", "e", "payload")
MAX_TEXT = 5000


def _maybe_json(v):
    if isinstance(v, str) and v[:1] in "{[":
        try:
            return json.loads(v)
        except ValueError:
            pass
    return v


def _parse_form(text: str) -> dict:
    return {k: _maybe_json(v) for k, v in urllib.parse.parse_qsl(text, keep_blank_values=True)}


def _looks_like_form(text: str) -> bool:
    return "=" in text and not any(c.isspace() for c in text[:500])


def parse_body(req: http.Request):
    try:
        data = req.get_content()
    except ValueError:
        data = req.raw_content
    if not data:
        return None
    if data[:2] == b"\x1f\x8b":
        try:
            data = gzip.decompress(data)
        except OSError:
            pass
    text = _as_text(data)
    if text is None:
        return f"<binary {len(data)} bytes>"
    s = text.strip()
    if s[:1] in "{[":
        try:
            return json.loads(s)
        except ValueError:
            pass
    if "x-www-form-urlencoded" in req.headers.get("content-type", "") or _looks_like_form(s):
        return _parse_form(s)
    return s[:MAX_TEXT]


def _name_of(d: dict, keys=NAME_KEYS):
    for k in keys:
        v = d.get(k)
        if isinstance(v, str) and v:
            return v
    return None


def _event_list(obj):
    if isinstance(obj, list):
        if obj and all(isinstance(i, dict) for i in obj) and any(_name_of(i) for i in obj):
            return obj
        return None
    if isinstance(obj, dict):
        for k in LIST_KEYS:
            v = _maybe_json(obj.get(k))
            if isinstance(v, list):
                found = _event_list(v)
                if found:
                    return found
    return None


def _last_segment(path: str) -> str:
    segs = [s for s in path.split("?")[0].split("/") if s]
    return segs[-1] if segs else "/"


def _extract_ga4_app(body: bytes) -> list[tuple]:
    out = []
    for b in decode_batch(body).get("bundle", []):
        pb = _pretty_bundle(b)
        extra = {"user_properties": pb.get("user_properties", {}), "device_app": pb["device_app"]}
        for ev in b.get("event", []):
            ts = ev.get("timestamp_millis")
            out.append((_event_name(ev), _params_to_map(ev.get("param", [])), extra, ts[1] if ts else None))
    return out


def _extract_ga4_web(query: dict, body) -> list[tuple]:
    lines = []
    if isinstance(body, str):
        lines = [_parse_form(line) for line in body.splitlines() if line.strip()]
    elif isinstance(body, dict):
        lines = [body]
    if not lines:
        lines = [{}]
    return [(p.get("en", "page_view"), p, {}, None) for p in ({**query, **line} for line in lines)]


def _extract_generic(tool: str, host: str, path: str, query: dict, body) -> list[tuple]:
    # Mixpanel & co. send base64 / JSON in a "data" form field
    if isinstance(body, dict) and isinstance(body.get("data"), str):
        try:
            body = {**body, "data": json.loads(base64.b64decode(body["data"] + "==="))}
        except (ValueError, TypeError):
            pass

    items = _event_list(body)
    if items:
        context = {k: v for k, v in body.items() if not isinstance(v, list)} if isinstance(body, dict) else {}
        extra = {k: v for k, v in (("request", context), ("query", query)) if v}
        out = []
        for it in items:
            name = _name_of(it) or "?"
            if tool == "braze" and name == "ce" and isinstance(it.get("data"), dict) and it["data"].get("n"):
                name = it["data"]["n"]
            out.append((name, it, extra, None))
        return out

    params = dict(query)
    if isinstance(body, dict):
        params.update(body)
    elif body is not None:
        params["body"] = body
    name = _name_of(params, STRONG_NAME_KEYS) if params else None
    if tool == "adjust":
        name = _last_segment(path)
        if params.get("event_token"):
            name = f"event {params['event_token']}"
    elif tool == "appsflyer" and not name:
        name = host.split(".")[0]
    return [(name or _last_segment(path), params, {}, None)]


def _looks_like_ga4_batch(data: bytes) -> bool:
    try:
        return any(b.get("event") for b in decode_batch(data).get("bundle", []))
    except Exception:  # noqa: BLE001
        return False


def extract_hits(flow: http.HTTPFlow) -> list[dict]:
    req = flow.request
    host, path = req.pretty_host, req.path
    tool = detect_tool(host, path)
    query = {k: _maybe_json(v) for k, v in req.query.items(multi=False)} if req.query else {}

    raw = req.get_content(strict=False) or b""
    try:
        if tool == "ga4" or (tool == "sgtm" and _looks_like_ga4_batch(raw)):
            events = _extract_ga4_app(raw)
        else:
            body = parse_body(req)
            if tool == "ga4web" or (tool == "sgtm" and ("en" in query or isinstance(body, str) and "en=" in body)):
                events = _extract_ga4_web(query, body)
            else:
                events = _extract_generic(tool, host, path, query, body)
    except Exception as e:  # noqa: BLE001
        events = [(_last_segment(path), {"decode_error": str(e)}, {}, None)]

    status = flow.response.status_code if flow.response else ("error" if flow.error else None)
    sent = int(req.timestamp_start * 1000)
    return [
        {
            "tool": tool,
            "event": str(name),
            "time": ts or sent,
            "sent": sent,
            "method": req.method,
            "host": host,
            "url": req.pretty_url,
            "status": status,
            "flow_id": flow.id,
            "params": _jsonable(params),
            "extra": _jsonable(extra),
        }
        for name, params, extra, ts in (events or [(_last_segment(path), {}, {}, None)])
    ]


def _jsonable(obj):
    if isinstance(obj, tuple) and len(obj) == 2 and obj[0] == "ts":
        return _fmt_time(obj[1])
    if isinstance(obj, dict):
        return {str(k): _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_jsonable(v) for v in obj]
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    return str(obj)


# --------------------------------------------------------------------------
# Hit store + web UI server
# --------------------------------------------------------------------------

class HitStore:
    def __init__(self, maxlen: int = 5000):
        self.lock = threading.Lock()
        self.hits: deque = deque(maxlen=maxlen)
        self.next_id = 1
        self.gen = 0

    def add(self, hits: list[dict]) -> None:
        with self.lock:
            for h in hits:
                h["id"] = self.next_id
                self.next_id += 1
                self.hits.append(h)

    def since(self, after: int) -> tuple[int, list[dict]]:
        with self.lock:
            return self.gen, [h for h in self.hits if h["id"] > after]

    def clear(self) -> None:
        with self.lock:
            self.hits.clear()
            self.gen += 1

    def reclassify(self) -> None:
        """Re-run tool detection after custom domains changed (client reloads)."""
        with self.lock:
            for h in self.hits:
                h["tool"] = detect_tool(h["host"], urllib.parse.urlsplit(h["url"]).path)
            self.gen += 1


STORE = HitStore()


def _tools_payload() -> list[dict]:
    return [{"key": k, "label": label, "color": c} for k, label, c, *_ in TOOLS] + [
        {"key": k, "label": label, "color": c} for k, label, c in (SGTM, OTHER)
    ]


class _Handler(BaseHTTPRequestHandler):
    mitmweb_url: str | None = None

    def log_message(self, *args):  # silence access log
        pass

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code: int = 200) -> None:
        self._send(code, json.dumps(obj).encode(), "application/json")

    def do_GET(self):
        url = urllib.parse.urlsplit(self.path)
        if url.path == "/":
            self._send(200, UI_HTML.encode(), "text/html; charset=utf-8")
        elif url.path == "/api/hits":
            q = urllib.parse.parse_qs(url.query)
            try:
                after = int(q.get("after", ["0"])[0])
            except ValueError:
                after = 0
            gen, hits = STORE.since(after)
            self._json({
                "gen": gen,
                "hits": hits,
                "tools": _tools_payload(),
                "domains": sorted(CUSTOM_DOMAINS),
                "mitmweb": self.mitmweb_url,
            })
        else:
            self._send(404, b"not found", "text/plain")

    def do_POST(self):
        url = urllib.parse.urlsplit(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        data = self.rfile.read(length) if length else b""
        if url.path == "/api/clear":
            STORE.clear()
            self._json({"ok": True})
        elif url.path == "/api/domains":
            try:
                domains = json.loads(data or b"[]")
            except ValueError:
                return self._json({"error": "invalid JSON"}, 400)
            cleaned = set()
            for d in domains if isinstance(domains, list) else []:
                d = str(d).strip().lower()
                d = re.sub(r"^[a-z]+://", "", d).split("/")[0].split(":")[0]
                if d:
                    cleaned.add(d)
            CUSTOM_DOMAINS.clear()
            CUSTOM_DOMAINS.update(cleaned)
            _save_domains()
            STORE.reclassify()
            self._json({"domains": sorted(CUSTOM_DOMAINS)})
        else:
            self._send(404, b"not found", "text/plain")


# --------------------------------------------------------------------------
# mitmproxy integration
# --------------------------------------------------------------------------

class GA4AppMeasurement(contentviews.Contentview):
    name = "GA4 App Measurement"
    syntax_highlight = "yaml"

    def prettify(self, data: bytes, metadata: contentviews.Metadata) -> str:
        return render_batch(decode_batch(data))

    def render_priority(self, data: bytes, metadata: contentviews.Metadata) -> float:
        flow = metadata.flow
        if not data or flow is None or not _is_ga4(flow):
            return 0
        # request body only (the response is empty / unrelated)
        if metadata.http_message is not None and not isinstance(metadata.http_message, http.Request):
            return 0
        # custom sGTM domains also receive other formats - only claim real GA4 batches
        if detect_tool(flow.request.pretty_host, flow.request.path) == "sgtm" and not _looks_like_ga4_batch(data):
            return 0
        return 10


contentviews.add(GA4AppMeasurement)


class AppTrackingDebugger:
    def __init__(self):
        self.server: ThreadingHTTPServer | None = None

    def load(self, loader):
        loader.add_option("tracking_ui_port", int, 8082, "Port of the App Tracking Debugger UI (0 = off).")
        _load_domains()

    def running(self):
        port = ctx.options.tracking_ui_port
        if not port or self.server:
            return
        web_port = getattr(ctx.options, "web_port", None)
        _Handler.mitmweb_url = f"http://127.0.0.1:{web_port}" if web_port else None
        try:
            self.server = ThreadingHTTPServer(("127.0.0.1", port), _Handler)
        except OSError as e:
            logger.warning(f"App Tracking Debugger UI could not start on port {port}: {e}")
            return
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        logger.warning(f"App Tracking Debugger UI: http://127.0.0.1:{port}")

    def done(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None

    def request(self, flow: http.HTTPFlow) -> None:
        tool = detect_tool(flow.request.pretty_host, flow.request.path)
        if tool == "other":
            return
        # tag for quick filtering in mitmweb: ~comment GA4  /  ~marked
        flow.marked = ":bar_chart:"
        labels = {key: label for key, label, *_ in TOOLS}
        flow.comment = "GA4" if tool in ("ga4", "sgtm") else labels[tool]

    def response(self, flow: http.HTTPFlow) -> None:
        self._record(flow)

    def error(self, flow: http.HTTPFlow) -> None:
        if isinstance(flow, http.HTTPFlow):
            self._record(flow)

    def _record(self, flow: http.HTTPFlow) -> None:
        try:
            hits = extract_hits(flow)
        except Exception as e:  # noqa: BLE001
            logger.warning(f"Tracking hit extraction failed: {e}")
            return
        STORE.add(hits)
        for h in hits:
            if h["tool"] in ("ga4", "sgtm"):
                params = ", ".join(f"{k}={v}" for k, v in h["params"].items())
                logger.info(f"[{h['tool'].upper()}] {h['event']} | {params}")


addons = [AppTrackingDebugger()]


UI_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>App Tracking Debugger</title>
<style>
:root {
  --bg: #f6f7f9; --panel: #ffffff; --text: #1d2129; --muted: #6b7280; --line: #e5e7eb;
  --hover: #f1f5f9; --sel: #e8f0fe; --accent: #1a73e8; --err: #d93025;
  --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #111317; --panel: #1a1d23; --text: #e6e8eb; --muted: #9aa0a6; --line: #2a2e36;
    --hover: #22262e; --sel: #1f3350; --accent: #8ab4f8; --err: #f28b82;
  }
}
* { box-sizing: border-box; }
html, body { margin: 0; height: 100%; }
body { background: var(--bg); color: var(--text); font: 13px/1.4 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; display: flex; flex-direction: column; }
header { display: flex; align-items: center; gap: 12px; padding: 10px 16px; background: var(--panel); border-bottom: 1px solid var(--line); flex-wrap: wrap; }
header h1 { font-size: 15px; margin: 0; font-weight: 600; }
.dot { width: 8px; height: 8px; border-radius: 50%; background: #34a853; display: inline-block; margin-right: 6px; }
.paused .dot { background: var(--muted); }
.spacer { flex: 1; }
button, input { font: inherit; color: inherit; }
button { background: var(--panel); border: 1px solid var(--line); border-radius: 6px; padding: 5px 10px; cursor: pointer; }
button:hover { background: var(--hover); }
input[type=search], input[type=text] { background: var(--bg); border: 1px solid var(--line); border-radius: 6px; padding: 6px 10px; min-width: 0; }
#search { width: 260px; max-width: 100%; }
.bar { display: flex; gap: 6px; flex-wrap: wrap; padding: 10px 16px; background: var(--panel); border-bottom: 1px solid var(--line); align-items: center; }
.chip { display: inline-flex; align-items: center; gap: 6px; border: 1px solid var(--line); border-radius: 999px; padding: 3px 10px 3px 8px; cursor: pointer; user-select: none; background: var(--panel); }
.chip .sw { width: 10px; height: 10px; border-radius: 50%; }
.chip .n { color: var(--muted); font-variant-numeric: tabular-nums; }
.chip.on { border-color: var(--c); box-shadow: inset 0 0 0 1px var(--c); background: color-mix(in srgb, var(--c) 12%, var(--panel)); }
.chip.off { opacity: .55; }
.domains { display: none; gap: 8px; align-items: center; padding: 10px 16px; background: var(--panel); border-bottom: 1px solid var(--line); flex-wrap: wrap; }
.domains.open { display: flex; }
.domains input { width: 420px; max-width: 100%; }
.hint { color: var(--muted); }
main { flex: 1; display: flex; min-height: 0; }
#list { flex: 1 1 60%; overflow: auto; min-width: 0; }
#detail { flex: 1 1 40%; overflow: auto; border-left: 1px solid var(--line); background: var(--panel); padding: 16px; min-width: 0; }
table.hits { width: 100%; border-collapse: collapse; table-layout: fixed; }
.hits td { padding: 6px 10px; border-bottom: 1px solid var(--line); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.hits tr { cursor: pointer; }
.hits tr:hover td { background: var(--hover); }
.hits tr.sel td { background: var(--sel); }
.t { width: 112px; color: var(--muted); font-family: var(--mono); font-size: 12px; }
.tool { width: 128px; }
.ev { width: 30%; font-weight: 600; }
.pv { color: var(--muted); font-family: var(--mono); font-size: 12px; }
.st { width: 56px; text-align: right; font-family: var(--mono); font-size: 12px; color: var(--muted); }
.st.bad { color: var(--err); }
.badge { display: inline-block; padding: 1px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; color: #fff; background: var(--c); max-width: 100%; overflow: hidden; text-overflow: ellipsis; vertical-align: middle; }
.empty { padding: 40px 16px; text-align: center; color: var(--muted); }
#detail h2 { margin: 0 0 6px; font-size: 17px; word-break: break-all; }
.meta { color: var(--muted); font-size: 12px; margin-bottom: 12px; word-break: break-all; }
.meta div { margin: 2px 0; }
.actions { display: flex; gap: 8px; margin-bottom: 14px; flex-wrap: wrap; }
.actions a { color: var(--accent); text-decoration: none; border: 1px solid var(--line); border-radius: 6px; padding: 5px 10px; }
h3 { font-size: 12px; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); margin: 18px 0 6px; }
table.kv { width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 12px; }
.kv td { border-bottom: 1px solid var(--line); padding: 4px 6px; vertical-align: top; word-break: break-word; }
.kv td:first-child { width: 38%; color: var(--muted); }
.kv pre { margin: 0; white-space: pre-wrap; }
@media (max-width: 800px) {
  main { flex-direction: column; }
  #detail { border-left: 0; border-top: 1px solid var(--line); flex-basis: 50%; }
  .pv { display: none; }
  .ev { width: auto; }
  .tool { width: 104px; }
}
</style>
</head>
<body>
<header id="hdr">
  <h1><span class="dot"></span>App Tracking Debugger</h1>
  <span class="hint" id="count"></span>
  <span class="spacer"></span>
  <input type="search" id="search" placeholder="Search events &amp; params…">
  <button id="domainsBtn">sGTM domains</button>
  <button id="pause">Pause</button>
  <button id="clear">Clear</button>
</header>
<div class="domains" id="domains">
  <span>Custom sGTM domains:</span>
  <input type="text" id="domainsInput" placeholder="sgtm.example.com, data.example.cz">
  <button id="domainsSave">Save</button>
  <span class="hint">Comma separated. Subdomains match too.</span>
</div>
<div class="bar" id="chips"></div>
<main>
  <div id="list"></div>
  <div id="detail"><div class="empty">Select a hit to see its parameters.</div></div>
</main>
<script>
const S = { hits: [], gen: null, after: 0, tools: {}, toolOrder: [], sel: new Set(), q: "", selected: null, paused: false, mitmweb: null, domains: [] };
const $ = id => document.getElementById(id);
const esc = s => String(s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const store = {
  get(k, d) { try { const v = localStorage.getItem(k); return v === null ? d : JSON.parse(v); } catch (e) { return d; } },
  set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch (e) {} },
};
S.sel = new Set(store.get("atd.sel", []));
S.q = store.get("atd.q", "");
$("search").value = S.q;

function fmtTime(ms) {
  const d = new Date(ms);
  return d.toLocaleTimeString([], { hour12: false }) + "." + String(d.getMilliseconds()).padStart(3, "0");
}
function fmtVal(v) {
  if (v === null || v === undefined) return "";
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}
function preview(params) {
  const skip = new Set(["_eventName", "eventName", "event_name", "event_type", "event", "en", "name", "type"]);
  const flat = [];
  for (const [k, v] of Object.entries(params || {})) {
    if (v && typeof v === "object" && !Array.isArray(v)) flat.push(...Object.entries(v));
    else flat.push([k, v]);
  }
  return flat.filter(([k, v]) => typeof v !== "object" && !skip.has(k) && !/^(firebase_|_)/.test(k))
    .slice(0, 5).map(([k, v]) => k + "=" + fmtVal(v)).join("  ");
}
function visible(h) {
  if (S.sel.size ? !S.sel.has(h.tool) : h.tool === "other") return false;
  if (!S.q) return true;
  const q = S.q.toLowerCase();
  return h.event.toLowerCase().includes(q) || h.host.toLowerCase().includes(q) || JSON.stringify(h.params).toLowerCase().includes(q);
}
function tool(key) { return S.tools[key] || { label: key, color: "#888" }; }

function renderChips() {
  const counts = {};
  for (const h of S.hits) counts[h.tool] = (counts[h.tool] || 0) + 1;
  const keys = S.toolOrder.filter(k => counts[k] || S.sel.has(k));
  const total = S.hits.filter(h => h.tool !== "other").length;
  let html = `<span class="chip ${S.sel.size ? "off" : "on"}" style="--c:var(--accent)" data-k=""><span class="n">All tools</span> ${total}</span>`;
  for (const k of keys) {
    const t = tool(k);
    const cls = S.sel.size ? (S.sel.has(k) ? "on" : "off") : (k === "other" ? "off" : "");
    html += `<span class="chip ${cls}" style="--c:${t.color}" data-k="${esc(k)}"><span class="sw" style="background:${t.color}"></span>${esc(t.label)} <span class="n">${counts[k] || 0}</span></span>`;
  }
  if (!keys.length) html += `<span class="hint">Waiting for tracking requests…</span>`;
  $("chips").innerHTML = html;
}

function renderList() {
  const rows = [];
  let n = 0;
  for (let i = S.hits.length - 1; i >= 0; i--) {
    const h = S.hits[i];
    if (!visible(h)) continue;
    n++;
    if (rows.length >= 2000) continue;
    const t = tool(h.tool);
    const bad = h.status === "error" || (typeof h.status === "number" && h.status >= 400);
    rows.push(`<tr data-id="${h.id}" class="${h.id === S.selected ? "sel" : ""}">
      <td class="t">${fmtTime(h.time)}</td>
      <td class="tool"><span class="badge" style="--c:${t.color}">${esc(t.label)}</span></td>
      <td class="ev" title="${esc(h.event)}">${esc(h.event)}</td>
      <td class="pv">${esc(preview(h.params))}</td>
      <td class="st ${bad ? "bad" : ""}">${esc(h.status ?? "")}</td></tr>`);
  }
  $("list").innerHTML = rows.length ? `<table class="hits">${rows.join("")}</table>`
    : `<div class="empty">${S.hits.length ? "No hits match the filter." : "No hits yet. Use the app with the proxy enabled."}</div>`;
  $("count").textContent = `${n} hit${n === 1 ? "" : "s"}`;
}

function kvTable(obj) {
  const rows = Object.entries(obj || {}).map(([k, v]) =>
    `<tr><td>${esc(k)}</td><td>${typeof v === "object" && v !== null ? `<pre>${esc(JSON.stringify(v, null, 2))}</pre>` : esc(fmtVal(v))}</td></tr>`);
  return rows.length ? `<table class="kv">${rows.join("")}</table>` : `<div class="hint">—</div>`;
}

function renderDetail() {
  const h = S.hits.find(x => x.id === S.selected);
  if (!h) { $("detail").innerHTML = `<div class="empty">Select a hit to see its parameters.</div>`; return; }
  const t = tool(h.tool);
  let html = `<span class="badge" style="--c:${t.color}">${esc(t.label)}</span>
    <h2>${esc(h.event)}</h2>
    <div class="meta">
      <div>Event time: ${esc(new Date(h.time).toLocaleString())}</div>
      ${h.sent !== h.time ? `<div>Sent: ${esc(new Date(h.sent).toLocaleString())}</div>` : ""}
      <div>${esc(h.method)} ${esc(h.url)}</div>
      <div>Status: ${esc(h.status ?? "—")}</div>
    </div>
    <div class="actions">
      <button id="copy">Copy JSON</button>
      ${S.mitmweb ? `<a href="${esc(S.mitmweb)}/#/flows/${esc(h.flow_id)}/request" target="_blank" rel="noopener">Open in mitmweb</a>` : ""}
    </div>
    <h3>Parameters</h3>${kvTable(h.params)}`;
  for (const [name, sec] of Object.entries(h.extra || {})) html += `<h3>${esc(name.replace(/_/g, " "))}</h3>${kvTable(sec)}`;
  $("detail").innerHTML = html;
  $("copy").onclick = () => {
    const txt = JSON.stringify({ tool: t.label, event: h.event, params: h.params, ...h.extra }, null, 2);
    (navigator.clipboard ? navigator.clipboard.writeText(txt) : Promise.reject()).then(
      () => { $("copy").textContent = "Copied"; setTimeout(() => { const b = $("copy"); if (b) b.textContent = "Copy JSON"; }, 1200); },
      () => prompt("Copy:", txt));
  };
}

function render() { renderChips(); renderList(); }

async function poll() {
  if (!S.paused) {
    try {
      const r = await fetch(`/api/hits?after=${S.after}`);
      const d = await r.json();
      if (!S.toolOrder.length) {
        for (const t of d.tools) { S.tools[t.key] = t; S.toolOrder.push(t.key); }
      }
      S.mitmweb = d.mitmweb;
      if (JSON.stringify(d.domains) !== JSON.stringify(S.domains)) {
        S.domains = d.domains;
        if (document.activeElement !== $("domainsInput")) $("domainsInput").value = d.domains.join(", ");
      }
      if (d.gen !== S.gen) {
        // server list was cleared or reclassified -> reload everything
        const first = S.gen === null && S.after === 0;
        S.gen = d.gen; S.hits = []; S.after = 0;
        if (!first) { render(); renderDetail(); return poll(); }
      }
      if (d.hits.length) {
        S.hits.push(...d.hits);
        S.after = d.hits[d.hits.length - 1].id;
        render();
        if (S.selected) renderDetail();
      }
    } catch (e) {
      $("count").textContent = "Disconnected from mitmproxy";
    }
  }
  setTimeout(poll, 1000);
}

$("chips").addEventListener("click", e => {
  const c = e.target.closest(".chip"); if (!c) return;
  const k = c.dataset.k;
  if (!k) S.sel.clear();
  else if (S.sel.has(k)) S.sel.delete(k);
  else S.sel.add(k);
  store.set("atd.sel", [...S.sel]);
  render();
});
$("list").addEventListener("click", e => {
  const tr = e.target.closest("tr[data-id]"); if (!tr) return;
  S.selected = Number(tr.dataset.id);
  document.querySelectorAll(".hits tr.sel").forEach(x => x.classList.remove("sel"));
  tr.classList.add("sel");
  renderDetail();
});
$("search").addEventListener("input", e => { S.q = e.target.value.trim(); store.set("atd.q", S.q); renderList(); });
$("pause").onclick = () => {
  S.paused = !S.paused;
  $("pause").textContent = S.paused ? "Resume" : "Pause";
  $("hdr").classList.toggle("paused", S.paused);
};
$("clear").onclick = async () => { await fetch("/api/clear", { method: "POST" }); S.selected = null; renderDetail(); };
$("domainsBtn").onclick = () => $("domains").classList.toggle("open");
$("domainsSave").onclick = async () => {
  const list = $("domainsInput").value.split(/[\s,]+/).filter(Boolean);
  const r = await fetch("/api/domains", { method: "POST", body: JSON.stringify(list) });
  const d = await r.json();
  S.domains = d.domains; $("domainsInput").value = d.domains.join(", ");
  $("domainsSave").textContent = "Saved";
  setTimeout(() => $("domainsSave").textContent = "Save", 1200);
};
$("domainsInput").addEventListener("keydown", e => { if (e.key === "Enter") $("domainsSave").click(); });
render();
poll();
</script>
</body>
</html>
"""
