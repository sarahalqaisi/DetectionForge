from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


AUTH_FAILED_RE = re.compile(
    r"(?P<ts>\w{3}\s+\d+\s+\d+:\d+:\d+).*Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)",
    re.I,
)
AUTH_ACCEPTED_RE = re.compile(
    r"(?P<ts>\w{3}\s+\d+\s+\d+:\d+:\d+).*Accepted \S+ for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)",
    re.I,
)
NGINX_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) (?P<proto>[^"]+)" (?P<status>\d{3}) (?P<size>\d+|-) "(?P<ref>[^"]*)" "(?P<ua>[^"]*)"'
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def parse_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if value is None:
        return _now()
    text = str(value).strip()
    if not text:
        return _now()
    candidates = [text.replace("Z", "+00:00")]
    for candidate in candidates:
        try:
            parsed = datetime.fromisoformat(candidate)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    for fmt in ("%b %d %H:%M:%S", "%d/%b/%Y:%H:%M:%S %z", "%Y-%m-%d %H:%M:%S"):
        try:
            if fmt == "%b %d %H:%M:%S":
                parsed = datetime.strptime(f"{_now().year} {text}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
            else:
                parsed = datetime.strptime(text, fmt)
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed
        except ValueError:
            continue
    return _now()


def _valid_ip(value: Any) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def normalize_linux_auth(line: str) -> dict[str, Any] | None:
    match = AUTH_FAILED_RE.search(line)
    if match:
        return {
            "timestamp": parse_timestamp(match.group("ts")),
            "source": "linux_auth",
            "event_type": "failed_login",
            "severity": "medium",
            "source_ip": _valid_ip(match.group("ip")),
            "source_port": int(match.group("port")),
            "username": match.group("user"),
            "message": line.strip(),
            "raw_data": {"line": line.strip()},
        }
    match = AUTH_ACCEPTED_RE.search(line)
    if match:
        return {
            "timestamp": parse_timestamp(match.group("ts")),
            "source": "linux_auth",
            "event_type": "successful_login",
            "severity": "info",
            "source_ip": _valid_ip(match.group("ip")),
            "source_port": int(match.group("port")),
            "username": match.group("user"),
            "message": line.strip(),
            "raw_data": {"line": line.strip()},
        }
    lowered = line.lower()
    if "useradd" in lowered or "new user" in lowered:
        return {
            "timestamp": _now(),
            "source": "linux_auth",
            "event_type": "user_created",
            "severity": "medium",
            "message": line.strip(),
            "raw_data": {"line": line.strip()},
        }
    return None


def normalize_nginx(line: str) -> dict[str, Any] | None:
    match = NGINX_RE.search(line)
    if not match:
        return None
    path = match.group("path")
    event_type = "web_request"
    severity = "info"
    lowered = path.lower()
    if "../" in path or "%2e%2e" in lowered:
        event_type, severity = "directory_traversal", "high"
    elif any(token in lowered for token in ("union+select", "union%20select", "<script", "%3cscript")):
        event_type, severity = "web_attack", "high"
    return {
        "timestamp": parse_timestamp(match.group("ts")),
        "source": "nginx",
        "event_type": event_type,
        "severity": severity,
        "source_ip": _valid_ip(match.group("ip")),
        "message": f"{match.group('method')} {path} -> {match.group('status')}",
        "raw_data": {
            "method": match.group("method"),
            "path": path,
            "status": int(match.group("status")),
            "user_agent": match.group("ua"),
        },
    }


def normalize_suricata(record: dict[str, Any]) -> dict[str, Any]:
    event_type = str(record.get("event_type", "network_event"))
    severity = "info"
    message = event_type
    if event_type == "alert":
        alert = record.get("alert") or {}
        signature = alert.get("signature", "Suricata alert")
        severity_num = int(alert.get("severity", 3) or 3)
        severity = {1: "critical", 2: "high", 3: "medium"}.get(severity_num, "low")
        message = str(signature)
    elif event_type == "dns":
        message = f"DNS query: {(record.get('dns') or {}).get('rrname', 'unknown')}"
    return {
        "timestamp": parse_timestamp(record.get("timestamp")),
        "source": "suricata",
        "event_type": event_type,
        "severity": severity,
        "source_ip": _valid_ip(record.get("src_ip")),
        "destination_ip": _valid_ip(record.get("dest_ip")),
        "source_port": record.get("src_port"),
        "destination_port": record.get("dest_port"),
        "message": message,
        "raw_data": record,
    }


def _get_windows_field(record: dict[str, Any], *names: str) -> Any:
    lowered = {str(k).lower(): v for k, v in record.items()}
    for name in names:
        if name.lower() in lowered:
            return lowered[name.lower()]
    event_data = record.get("EventData") or record.get("event_data") or {}
    if isinstance(event_data, dict):
        lowered_event = {str(k).lower(): v for k, v in event_data.items()}
        for name in names:
            if name.lower() in lowered_event:
                return lowered_event[name.lower()]
    return None


def normalize_windows(record: dict[str, Any]) -> dict[str, Any]:
    event_id_raw = _get_windows_field(record, "EventID", "event_id")
    try:
        event_id = int(event_id_raw)
    except (TypeError, ValueError):
        event_id = 0
    event_map = {
        1: ("process_create", "info"),
        3: ("network_connection", "info"),
        1102: ("security_log_cleared", "critical"),
        4624: ("successful_login", "info"),
        4625: ("failed_login", "medium"),
        4688: ("process_create", "info"),
        4720: ("user_created", "high"),
        4728: ("user_added_to_privileged_group", "high"),
        7045: ("service_installed", "high"),
    }
    event_type, severity = event_map.get(event_id, ("windows_event", "info"))
    command_line = _get_windows_field(record, "CommandLine", "ProcessCommandLine")
    process_name = _get_windows_field(record, "Image", "NewProcessName", "ProcessName")
    username = _get_windows_field(record, "TargetUserName", "User", "SubjectUserName")
    source_ip = _get_windows_field(record, "IpAddress", "SourceIp", "SourceNetworkAddress")
    hostname = _get_windows_field(record, "Computer", "Hostname")
    message = _get_windows_field(record, "Message") or f"Windows event {event_id}"
    return {
        "timestamp": parse_timestamp(_get_windows_field(record, "UtcTime", "TimeCreated", "timestamp")),
        "source": "windows",
        "event_type": event_type,
        "severity": severity,
        "source_ip": _valid_ip(source_ip),
        "username": username,
        "hostname": hostname,
        "process_name": process_name,
        "command_line": command_line,
        "message": str(message),
        "raw_data": record,
    }


def normalize_generic(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "timestamp": parse_timestamp(record.get("timestamp")),
        "source": str(record.get("source", "generic")),
        "event_type": str(record.get("event_type", "generic_event")),
        "severity": str(record.get("severity", "info")).lower(),
        "source_ip": _valid_ip(record.get("source_ip")),
        "destination_ip": _valid_ip(record.get("destination_ip")),
        "source_port": record.get("source_port"),
        "destination_port": record.get("destination_port"),
        "username": record.get("username"),
        "hostname": record.get("hostname"),
        "process_name": record.get("process_name"),
        "command_line": record.get("command_line"),
        "message": str(record.get("message", "")),
        "raw_data": record,
    }


def normalize_record(record: dict[str, Any], source_type: str = "auto") -> dict[str, Any]:
    selected = source_type.lower()
    if selected == "auto":
        if "event_type" in record and any(k in record for k in ("src_ip", "dest_ip", "alert", "dns")):
            selected = "suricata"
        elif any(str(k).lower() in {"eventid", "event_id", "eventdata"} for k in record):
            selected = "windows"
        else:
            selected = "generic"
    if selected in {"suricata", "eve"}:
        return normalize_suricata(record)
    if selected in {"windows", "sysmon"}:
        return normalize_windows(record)
    return normalize_generic(record)


def normalize_text(content: str, source_type: str = "auto") -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    stripped = content.strip()
    if not stripped:
        return events

    if stripped.startswith("["):
        parsed = json.loads(stripped)
        if not isinstance(parsed, list):
            raise ValueError("JSON array expected")
        return [normalize_record(item, source_type) for item in parsed if isinstance(item, dict)]

    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("{"):
            try:
                record = json.loads(line)
                if isinstance(record, dict):
                    events.append(normalize_record(record, source_type))
                    continue
            except json.JSONDecodeError:
                pass
        selected = source_type.lower()
        normalized = None
        if selected in {"auto", "linux", "linux_auth", "auth"}:
            normalized = normalize_linux_auth(line)
        if normalized is None and selected in {"auto", "nginx", "web"}:
            normalized = normalize_nginx(line)
        if normalized is not None:
            events.append(normalized)
    return events


def normalize_file(path: str | Path, source_type: str = "auto") -> list[dict[str, Any]]:
    file_path = Path(path)
    return normalize_text(file_path.read_text(encoding="utf-8", errors="replace"), source_type)


def serializable_event(event: dict[str, Any]) -> dict[str, Any]:
    clean = dict(event)
    if isinstance(clean.get("timestamp"), datetime):
        clean["timestamp"] = clean["timestamp"].isoformat()
    return clean
