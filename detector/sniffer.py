from scapy.all import sniff, get_if_addr

from . import state
from .analyzer import analyze_packet


def _stop_filter(_pkt):
    return not state.running


def start_sniff(interface):
    state.running = True
    state.current_interface = interface

    try:
        state.self_ip = get_if_addr(interface)
        if state.self_ip in (None, "0.0.0.0"):
            state.self_ip = None
    except Exception:
        state.self_ip = None

    try:
        sniff(
            iface=interface,
            prn=analyze_packet,
            stop_filter=_stop_filter,
            store=False,
        )
    finally:
        state.running = False
