"""
GA4 / Firebase Analytics decoder for mitmproxy

Decodes the protobuf payload that the Firebase Analytics SDK (iOS / Android)
sends to https://app-measurement.com/a (and region1.*, app-analytics-services*.com)
and shows it as readable events, parameters and user properties.

Schema based on https://github.com/lari/firebase-ga4-app-measurement-protobuf

No dependencies (built-in protobuf wire parser), so it works with the official
mitmproxy binaries as well. Requires mitmproxy 12+.

Usage:
    mitmweb   -s ga4_app_measurement.py
    mitmproxy -s ga4_app_measurement.py
    mitmdump  -s ga4_app_measurement.py   # also prints decoded events to the console

GA4 requests automatically use the "GA4 App Measurement" view and are tagged
with the comment "GA4" -> filter them in mitmweb with:  ~comment GA4
"""

from __future__ import annotations

import gzip
import struct
import zlib
import logging
from datetime import datetime, timezone

from mitmproxy import contentviews, http

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
# mitmproxy integration
# --------------------------------------------------------------------------

def _is_ga4(flow) -> bool:
    return (
        isinstance(flow, http.HTTPFlow)
        and flow.request.pretty_host.endswith(HOST_SUFFIXES)
        and flow.request.path.split("?")[0].rstrip("/") in ("/a", "")
    )


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
        return 10


contentviews.add(GA4AppMeasurement)


class GA4Logger:
    """Tag GA4 flows (for filtering) and log decoded events to the console."""

    def request(self, flow: http.HTTPFlow) -> None:
        if not _is_ga4(flow):
            return
        # tag for quick filtering in mitmweb: ~comment GA4  (or ~marked)
        flow.marked = ":bar_chart:"
        flow.comment = "GA4"
        if not flow.request.content:
            return
        try:
            batch = decode_batch(flow.request.content)
        except Exception as e:  # noqa: BLE001
            logger.warning(f"GA4 decode failed: {e}")
            return
        for b in batch.get("bundle", []):
            for ev in b.get("event", []):
                p = _params_to_map(ev.get("param", []))
                params = ", ".join(f"{k}={_scalar(v) if not isinstance(v, list) else v}" for k, v in p.items())
                logger.info(f"[GA4] {_event_name(ev)} | {params}")


addons = [GA4Logger()]
