#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import base64
import json
import math
import re
import statistics
from collections import defaultdict
from dataclasses import dataclass, asdict, field
from typing import Any, Dict, List, Optional, Tuple

from scapy.all import rdpcap, IP, IPv6, TCP, UDP, Raw
from scapy.layers.dns import DNS, DNSQR, DNSRR


HTTP_METHODS = [
    b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS", b"PATCH", b"CONNECT"
]

SUSPICIOUS_HTTP_PATTERNS = [
    rb"(?i)\bunion\s+select\b",
    rb"(?i)\bor\s+1=1\b",
    rb"(?i)\bdrop\s+table\b",
    rb"(?i)\bselect\s+\*\s+from\b",
    rb"(?i)\.\./\.\./",
    rb"(?i)<script>",
    rb"(?i)cmd\.exe",
    rb"(?i)powershell",
    rb"(?i)/bin/sh",
]

TLS_HANDSHAKE_TYPES = {
    0x01: "ClientHello",
    0x02: "ServerHello",
    0x0b: "Certificate",
    0x0e: "ServerHelloDone",
    0x10: "ClientKeyExchange",
    0x14: "Finished",
}

TLS_CONTENT_TYPES = {
    20: "change_cipher_spec",
    21: "alert",
    22: "handshake",
    23: "application_data",
}

STANDARD_TLS_PORTS = {443, 8443, 9443}


def safe_decode(data: bytes, limit: int = 512) -> str:
    if not data:
        return ""
    clipped = data[:limit]
    return clipped.decode("utf-8", errors="replace")


def is_printable_ratio_high(data: bytes, threshold: float = 0.85) -> bool:
    if not data:
        return False
    printable = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))
    return (printable / len(data)) >= threshold


def extract_printable_strings(data: bytes, min_len: int = 4, max_items: int = 10) -> List[str]:
    matches = re.findall(rb"[ -~]{%d,}" % min_len, data)
    results = []
    for m in matches[:max_items]:
        try:
            results.append(m.decode("utf-8", errors="replace"))
        except Exception:
            continue
    return results


def looks_like_base64(data: bytes) -> bool:
    if not data or len(data) < 16:
        return False
    stripped = re.sub(rb"\s+", b"", data)
    if len(stripped) % 4 != 0:
        return False
    if not re.fullmatch(rb"[A-Za-z0-9+/=]+", stripped):
        return False
    try:
        base64.b64decode(stripped, validate=True)
        return True
    except Exception:
        return False


def tcp_flags_to_list(flags: Any) -> List[str]:
    s = str(flags)
    flag_map = {
        "F": "FIN",
        "S": "SYN",
        "R": "RST",
        "P": "PSH",
        "A": "ACK",
        "U": "URG",
        "E": "ECE",
        "C": "CWR",
    }
    return [flag_map[ch] for ch in s if ch in flag_map]


def get_ip_tuple(pkt) -> Tuple[Optional[str], Optional[str], Optional[int], Optional[int], str]:
    proto = "UNKNOWN"
    src_ip = dst_ip = None
    sport = dport = None

    if IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
    elif IPv6 in pkt:
        src_ip = pkt[IPv6].src
        dst_ip = pkt[IPv6].dst

    if TCP in pkt:
        proto = "TCP"
        sport = int(pkt[TCP].sport)
        dport = int(pkt[TCP].dport)
    elif UDP in pkt:
        proto = "UDP"
        sport = int(pkt[UDP].sport)
        dport = int(pkt[UDP].dport)

    return src_ip, dst_ip, sport, dport, proto


def reverse_flow_key(key: Tuple[str, str, int, int, str]) -> Tuple[str, str, int, int, str]:
    src_ip, dst_ip, sport, dport, proto = key
    return (dst_ip, src_ip, dport, sport, proto)


def canonical_flow_key(
    src_ip: Optional[str],
    dst_ip: Optional[str],
    sport: Optional[int],
    dport: Optional[int],
    proto: str
) -> Tuple[str, str, int, int, str]:
    a = (src_ip or "?", dst_ip or "?", int(sport or 0), int(dport or 0), proto)
    b = reverse_flow_key(a)
    return min(a, b)


def detect_http(payload: bytes) -> Optional[Dict[str, Any]]:
    if not payload:
        return None

    first_line = payload.split(b"\r\n", 1)[0]

    for method in HTTP_METHODS:
        if first_line.startswith(method + b" "):
            line = safe_decode(first_line, 300)
            return {
                "type": "http_request",
                "first_line": line,
            }

    if payload.startswith(b"HTTP/1."):
        line = safe_decode(first_line, 300)
        return {
            "type": "http_response",
            "first_line": line,
        }

    return None


def detect_tls(payload: bytes) -> Optional[Dict[str, Any]]:
    """
    Very lightweight TLS record detector.
    Does not fully parse TLS; only identifies likely TLS record / handshake.
    """
    if not payload or len(payload) < 6:
        return None

    content_type = payload[0]
    version_major = payload[1]
    version_minor = payload[2]

    if content_type not in TLS_CONTENT_TYPES:
        return None
    if version_major != 3:
        return None

    result: Dict[str, Any] = {
        "record_type": TLS_CONTENT_TYPES.get(content_type, f"unknown_{content_type}"),
        "version": f"{version_major}.{version_minor}",
    }

    if content_type == 22 and len(payload) >= 9:
        hs_type = payload[5]
        result["handshake_type"] = TLS_HANDSHAKE_TYPES.get(hs_type, f"unknown_{hs_type}")

    return result


@dataclass
class PacketSemantic:
    index: int
    timestamp: float
    src_ip: Optional[str]
    dst_ip: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    packet_len: int
    tcp_flags: List[str] = field(default_factory=list)
    dns: Optional[Dict[str, Any]] = None
    http: Optional[Dict[str, Any]] = None
    tls: Optional[Dict[str, Any]] = None
    payload_preview: str = ""
    printable_strings: List[str] = field(default_factory=list)
    semantic_tags: List[str] = field(default_factory=list)
    observations: List[str] = field(default_factory=list)


@dataclass
class FlowSummary:
    flow_key: Tuple[str, str, int, int, str]
    packet_count: int = 0
    total_bytes: int = 0
    start_time: float = 0.0
    end_time: float = 0.0
    protocols_seen: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    observations: List[str] = field(default_factory=list)
    intervals: List[float] = field(default_factory=list)


class ParserAgent:
    def __init__(self) -> None:
        self.flows: Dict[Tuple[str, str, int, int, str], FlowSummary] = {}
        self.flow_timestamps: Dict[Tuple[str, str, int, int, str], List[float]] = defaultdict(list)
        self.packet_outputs: List[PacketSemantic] = []

    def parse_pcap(self, pcap_path: str) -> Dict[str, Any]:
        packets = rdpcap(pcap_path)

        for idx, pkt in enumerate(packets, start=1):
            parsed = self.parse_packet(idx, pkt)
            if parsed is not None:
                self.packet_outputs.append(parsed)

        self.post_process_flows()

        return {
            "summary": {
                "total_packets_parsed": len(self.packet_outputs),
                "total_flows": len(self.flows),
            },
            "flows": [asdict(v) for v in self.flows.values()],
            "packets": [asdict(p) for p in self.packet_outputs],
        }

    def parse_packet(self, idx: int, pkt) -> Optional[PacketSemantic]:
        src_ip, dst_ip, sport, dport, proto = get_ip_tuple(pkt)

        if src_ip is None and dst_ip is None:
            src_ip = "unknown"
            dst_ip = "unknown"
            sport = None
            dport = None
            proto = "UNKNOWN"

        packet_len = len(pkt)
        timestamp = float(pkt.time)

        result = PacketSemantic(
            index=idx,
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=sport,
            dst_port=dport,
            protocol=proto,
            packet_len=packet_len,
        )

        flow_key = canonical_flow_key(src_ip, dst_ip, sport, dport, proto)
        self.update_flow_basic(flow_key, timestamp, packet_len, proto)

        payload = b""
        if Raw in pkt:
            payload = bytes(pkt[Raw].load)

        if TCP in pkt:
            result.tcp_flags = tcp_flags_to_list(pkt[TCP].flags)
            self.handle_tcp_semantics(pkt, result, payload)

        if UDP in pkt:
            self.handle_udp_semantics(pkt, result, payload)

        if DNS in pkt:
            self.handle_dns(pkt, result)

        if Raw in pkt:
            payload = bytes(pkt[Raw].load)

            text = payload.decode(errors="ignore").lower()

            if "login" in text:
                result.semantic_tags.append("telnet_login_prompt")

            if "password" in text:
                result.semantic_tags.append("telnet_password_prompt")

            if re.search(r"[a-z0-9]{3,}@", text):
                result.semantic_tags.append("possible_username")

            if len(text.strip()) > 0:
                result.semantic_tags.append("telnet_data")

        if dport == 23 or sport == 23:
            result.semantic_tags.append("telnet_detected")
            result.observations.append("Telnet communication observed (port 23).")

        if payload:
            result.payload_preview = safe_decode(payload, 200)
            result.printable_strings = extract_printable_strings(payload)

            if looks_like_base64(payload[:256]):
                result.semantic_tags.append("possible_base64_payload")
                result.observations.append("Payload exhibits Base64-like encoding characteristics.")

            if is_printable_ratio_high(payload):
                result.semantic_tags.append("mostly_printable_payload")

        self.apply_generic_semantics(result)
        self.update_flow_from_packet(flow_key, result)

        return result

    def update_flow_basic(
        self,
        flow_key: Tuple[str, str, int, int, str],
        timestamp: float,
        packet_len: int,
        proto: str,
    ) -> None:
        if flow_key not in self.flows:
            self.flows[flow_key] = FlowSummary(
                flow_key=flow_key,
                packet_count=0,
                total_bytes=0,
                start_time=timestamp,
                end_time=timestamp,
                protocols_seen=[proto],
            )

        flow = self.flows[flow_key]
        flow.packet_count += 1
        flow.total_bytes += packet_len
        flow.end_time = timestamp
        if proto not in flow.protocols_seen:
            flow.protocols_seen.append(proto)

        self.flow_timestamps[flow_key].append(timestamp)

    def update_flow_from_packet(
        self,
        flow_key: Tuple[str, str, int, int, str],
        pkt_sem: PacketSemantic,
    ) -> None:
        flow = self.flows[flow_key]
        for tag in pkt_sem.semantic_tags:
            if tag not in flow.tags:
                flow.tags.append(tag)
        for obs in pkt_sem.observations:
            if obs not in flow.observations:
                flow.observations.append(obs)

    def handle_tcp_semantics(self, pkt, result: PacketSemantic, payload: bytes) -> None:
        sport = int(pkt[TCP].sport)
        dport = int(pkt[TCP].dport)

        if result.tcp_flags == ["SYN"]:
            result.semantic_tags.append("tcp_syn")
            result.observations.append("TCP connection initiation observed.")

        if "RST" in result.tcp_flags:
            result.semantic_tags.append("tcp_reset")
            result.observations.append("TCP reset observed.")

        http_info = detect_http(payload)
        if http_info:
            result.http = http_info
            result.semantic_tags.append("http_detected")
            result.observations.append(f"HTTP content detected: {http_info['type']}.")

            for pattern in SUSPICIOUS_HTTP_PATTERNS:
                if re.search(pattern, payload):
                    result.semantic_tags.append("suspicious_http_payload")
                    result.observations.append(
                        "HTTP payload contains suspicious command / injection / traversal pattern."
                    )
                    break

        tls_info = detect_tls(payload)
        if tls_info:
            result.tls = tls_info
            result.semantic_tags.append("tls_detected")
            result.observations.append(
                f"TLS record detected ({tls_info.get('record_type')}"
                + (
                    f", {tls_info.get('handshake_type')})"
                    if tls_info.get("handshake_type")
                    else ")"
                )
            )

            if dport not in STANDARD_TLS_PORTS and sport not in STANDARD_TLS_PORTS:
                result.semantic_tags.append("tls_on_nonstandard_port")
                result.observations.append(
                    "TLS-like communication detected on a non-standard port."
                )

    def handle_udp_semantics(self, pkt, result: PacketSemantic, payload: bytes) -> None:
        sport = int(pkt[UDP].sport)
        dport = int(pkt[UDP].dport)

        if dport == 53 or sport == 53:
            result.semantic_tags.append("dns_transport")

        if payload and len(payload) > 300 and dport not in (53, 123, 161):
            result.semantic_tags.append("large_udp_payload")
            result.observations.append(
                "Large UDP payload observed on a non-typical service port."
            )

    def handle_dns(self, pkt, result: PacketSemantic) -> None:
        dns_layer = pkt[DNS]
        dns_info: Dict[str, Any] = {
            "qr": int(dns_layer.qr),
            "opcode": int(dns_layer.opcode),
            "rcode": int(dns_layer.rcode),
            "qdcount": int(dns_layer.qdcount),
            "ancount": int(dns_layer.ancount),
            "queries": [],
            "answers": [],
        }

        if dns_layer.qdcount > 0 and isinstance(dns_layer.qd, DNSQR):
            qname = safe_decode(bytes(dns_layer.qd.qname)).strip(".")
            dns_info["queries"].append(qname)

            result.semantic_tags.append("dns_query")
            result.observations.append(f"DNS query observed for domain: {qname}")

            if len(qname) > 50:
                result.semantic_tags.append("long_dns_query")
                result.observations.append(
                    "Unusually long DNS query name observed, potentially algorithmic."
                )

        if dns_layer.ancount > 0:
            ans = dns_layer.an
            try:
                for _ in range(int(dns_layer.ancount)):
                    if isinstance(ans, DNSRR):
                        rrname = safe_decode(bytes(ans.rrname)).strip(".")
                        rdata = str(ans.rdata)
                        dns_info["answers"].append({"name": rrname, "rdata": rdata})
                        ans = ans.payload
            except Exception:
                pass

        result.dns = dns_info

    def apply_generic_semantics(self, result: PacketSemantic) -> None:
        if result.payload_preview:
            low = result.payload_preview.lower()

            if "user-agent" in low:
                result.semantic_tags.append("user_agent_present")

            if "powershell" in low or "cmd.exe" in low or "/bin/sh" in low:
                result.semantic_tags.append("possible_command_execution")
                result.observations.append(
                    "Payload includes strings associated with command execution."
                )

            if "select " in low or "union select" in low or "drop table" in low:
                result.semantic_tags.append("possible_sql_injection")
                result.observations.append(
                    "Payload includes strings associated with SQL injection."
                )

            if "../" in low:
                result.semantic_tags.append("possible_path_traversal")
                result.observations.append(
                    "Payload includes path traversal indicators."
                )

    def post_process_flows(self) -> None:
        for flow_key, timestamps in self.flow_timestamps.items():
            if len(timestamps) >= 3:
                intervals = [
                    round(timestamps[i] - timestamps[i - 1], 6)
                    for i in range(1, len(timestamps))
                ]
                self.flows[flow_key].intervals = intervals

                if len(intervals) >= 3:
                    mean_iv = statistics.mean(intervals)
                    stdev_iv = statistics.pstdev(intervals) if len(intervals) > 1 else 0.0

                    if mean_iv > 1.0 and stdev_iv < max(0.5, mean_iv * 0.1):
                        if "possible_beaconing" not in self.flows[flow_key].tags:
                            self.flows[flow_key].tags.append("possible_beaconing")
                        self.flows[flow_key].observations.append(
                            f"Flow shows relatively periodic packet intervals "
                            f"(mean={mean_iv:.3f}s, stdev={stdev_iv:.3f}s), "
                            f"which may indicate beacon-like behavior."
                        )


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="PCAP Parser Agent")
    parser.add_argument("pcap", help="Path to input .pcap or .pcapng file")
    parser.add_argument(
        "-o", "--output",
        default="parser_output.json",
        help="Output JSON path (default: parser_output.json)"
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output"
    )
    return parser


def main() -> None:
    args = build_argument_parser().parse_args()

    agent = ParserAgent()
    result = agent.parse_pcap(args.pcap)

    with open(args.output, "w", encoding="utf-8") as f:
        if args.pretty:
            json.dump(result, f, ensure_ascii=False, indent=2)
        else:
            json.dump(result, f, ensure_ascii=False)

    print(f"[+] Parsed packets : {result['summary']['total_packets_parsed']}")
    print(f"[+] Total flows    : {result['summary']['total_flows']}")
    print(f"[+] Output written : {args.output}")


if __name__ == "__main__":
    main()