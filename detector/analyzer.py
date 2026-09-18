from collections import defaultdict
from datetime import datetime
import time

from . import state

ip_counter = defaultdict(int)
_last_window_reset = time.time()


def _classify_protocol(pkt):
    if pkt.haslayer("TCP"):
        flags = pkt["TCP"].flags
        if "S" in str(flags) and "A" not in str(flags):
            return "TCP SYN"
        return "TCP"
    if pkt.haslayer("UDP"):
        return "UDP"
    if pkt.haslayer("ICMP"):
        return "ICMP"
    return "Other"


def _severity(rate, threshold):
    if rate > threshold * 5:
        return "critical"
    if rate > threshold * 2:
        return "high"
    return "medium"


def analyze_packet(pkt):
    global _last_window_reset

    if not pkt.haslayer("IP"):
        return

    src = pkt["IP"].src
    dst = pkt["IP"].dst
    proto = _classify_protocol(pkt)

    if state.self_ip and dst != state.self_ip:
        return

    with state.lock:
        ip_counter[src] += 1
        state._second_counter += 1
        rate = ip_counter[src]

        if rate > state.threshold and src not in state.alerted_ips:
            state.alerted_ips.add(src)
            state.alerts.insert(0, {
                "ip": src,
                "dst": dst,
                "protocol": proto,
                "packets": rate,
                "severity": _severity(rate, state.threshold),
                "type": "Possible DoS",
                "time": datetime.now().strftime("%H:%M:%S"),
            })
            if len(state.alerts) > 500:
                state.alerts.pop()

    now = time.time()
    if now - _last_window_reset > state.window_seconds:
        with state.lock:
            ip_counter.clear()
            state.alerted_ips.clear()
        _last_window_reset = now


def tick_traffic_history():
    with state.lock:
        state.traffic_history.append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "count": state._second_counter,
        })
        if len(state.traffic_history) > state.MAX_HISTORY:
            state.traffic_history.pop(0)
        state._second_counter = 0
