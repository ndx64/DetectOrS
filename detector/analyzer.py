"""
Logic phân tích packet để phát hiện khả năng DoS.

Cải tiến so với bản gốc:
- Alert chỉ tạo MỘT LẦN khi 1 IP vừa vượt ngưỡng trong window hiện tại
  (bản cũ tạo alert lặp lại ở MỌI packet tiếp theo -> spam alert).
- Alert có timestamp, dst IP/port, protocol, packet rate, severity.
- Phân loại sơ bộ loại traffic (TCP SYN / UDP / ICMP / khác) dựa trên
  layer của packet, thay vì gộp chung "Possible DoS".
- Ghi nhận traffic_history (packet/giây) để frontend vẽ chart traffic
  thật thay vì dữ liệu random.

Fix (so với bản test thực tế trên SYN/UDP/ICMP flood):
- CHỈ đếm traffic ĐI VÀO máy đang chạy detector (dst == IP của interface
  đang sniff). Bản cũ đếm cả 2 chiều, nên khi máy nạn nhân tự động trả
  lời (TCP RST/ACK, ICMP Echo Reply...) thì chính máy nạn nhân cũng bị
  gắn nhãn "nguồn tấn công" -> false positive ngược chiều.
"""
from collections import defaultdict
from datetime import datetime
import time

from . import state

ip_counter = defaultdict(int)
_last_window_reset = time.time()


def _classify_protocol(pkt):
    if pkt.haslayer("TCP"):
        flags = pkt["TCP"].flags
        # 'S' flag = SYN, không có ACK -> điển hình SYN flood
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
    """Được gọi cho mỗi packet bắt được từ sniffer."""
    global _last_window_reset

    if not pkt.haslayer("IP"):
        return

    src = pkt["IP"].src
    dst = pkt["IP"].dst
    proto = _classify_protocol(pkt)

    # --- Fix: chỉ đếm traffic đi VÀO máy đang giám sát ---
    # Nếu chưa xác định được IP của interface (self_ip chưa set), tạm thời
    # vẫn đếm hết để không làm gián đoạn hệ thống, nhưng log cảnh báo.
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
            # giới hạn số alert lưu trong bộ nhớ
            if len(state.alerts) > 500:
                state.alerts.pop()

    # reset bộ đếm mỗi window_seconds giây
    now = time.time()
    if now - _last_window_reset > state.window_seconds:
        with state.lock:
            ip_counter.clear()
            state.alerted_ips.clear()
        _last_window_reset = now


def tick_traffic_history():
    """
    Gọi mỗi giây (từ một timer thread riêng trong app.py) để chốt lại
    số packet đã thấy trong giây vừa qua và đẩy vào traffic_history.
    """
    with state.lock:
        state.traffic_history.append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "count": state._second_counter,
        })
        if len(state.traffic_history) > state.MAX_HISTORY:
            state.traffic_history.pop(0)
        state._second_counter = 0
