"""Feature engineering + input validation for flow records."""
import ipaddress
import math

VALID_PROTOCOLS = {"TCP", "UDP", "ICMP"}
MIN_DURATION = 1.0  # flows shorter than 1s are treated as 1s so rates are not inflated / divide-by-zero


class FlowValidationError(ValueError):
    """Raised when a flow record is malformed."""


def safe_div(a, b, default=0.0):
    try:
        return a / b if b else default
    except (TypeError, ZeroDivisionError):
        return default


def _num(value, default=0.0):
    """Convert to a finite float; missing / NaN / garbage -> default."""
    try:
        v = float(value)
        return v if math.isfinite(v) and v >= 0 else default
    except (TypeError, ValueError):
        return default


def _ip(value, name):
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        raise FlowValidationError(f"Invalid {name}: {value!r}")


def _port(value, name):
    try:
        p = int(value)
    except (TypeError, ValueError):
        raise FlowValidationError(f"Invalid {name}: {value!r}")
    if not 0 <= p <= 65535:
        raise FlowValidationError(f"Invalid {name}: {value!r} (must be 0-65535)")
    return p


def extract_network_features(flow):
    """Validate a raw flow dict and return a feature dict.

    Feature -> why a SOC analyst cares:
      packets_per_second / bytes_per_second : volume spikes (flooding, exfiltration)
      average_packet_size  : tiny packets = probing/handshakes, huge = bulk transfer
      connection_rate      : many connections/sec = scanning or abuse
      failure_ratio        : many failed attempts = brute-force-like or probing
      syn_ratio            : handshakes without data = SYN-heavy pattern
      unique_destination_ports/ips : fan-out = reconnaissance-like behaviour
    """
    if not isinstance(flow, dict):
        raise FlowValidationError("Flow must be a JSON object")
    protocol = str(flow.get("protocol", "")).strip().upper()
    if protocol not in VALID_PROTOCOLS:
        raise FlowValidationError(f"Unsupported protocol: {flow.get('protocol')!r}")
    warnings = []
    for key in ("packet_count", "byte_count", "duration_seconds"):
        if flow.get(key) in (None, ""):
            warnings.append(f"missing {key} (defaulted to 0)")

    packets = _num(flow.get("packet_count"))
    bytes_ = _num(flow.get("byte_count"))
    duration = _num(flow.get("duration_seconds"))
    conns = _num(flow.get("connection_count"), 1.0)
    failed = _num(flow.get("failed_connection_count"))
    syn = _num(flow.get("syn_count"))
    rst = _num(flow.get("rst_count"))
    eff = max(duration, MIN_DURATION)

    return {
        "source_ip": _ip(flow.get("source_ip"), "source_ip"),
        "destination_ip": _ip(flow.get("destination_ip"), "destination_ip"),
        "source_port": _port(flow.get("source_port", 0), "source_port"),
        "destination_port": _port(flow.get("destination_port", 0), "destination_port"),
        "protocol": protocol,
        "packet_count": packets, "byte_count": bytes_, "duration": duration,
        "bytes_per_second": bytes_ / eff,
        "packets_per_second": packets / eff,
        "average_packet_size": safe_div(bytes_, packets),
        "connection_count": conns, "failed_connection_count": failed,
        "failure_ratio": safe_div(failed, conns),
        "syn_count": syn, "rst_count": rst,
        "syn_ratio": safe_div(syn, packets),
        "unique_destination_ports": _num(flow.get("unique_destination_ports"), 1.0),
        "unique_destination_ips": _num(flow.get("unique_destination_ips"), 1.0),
        "connection_rate": conns / eff,
        "warnings": warnings,
    }
