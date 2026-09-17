"""
Trạng thái dùng chung giữa sniffer thread và Flask routes.
Dùng threading.Lock vì sniffer chạy trên background thread
còn Flask routes đọc/ghi từ request thread khác.
"""
import threading

lock = threading.Lock()

running = False
current_interface = None
self_ip = None            # IP của interface đang sniff -> dùng để lọc traffic inbound
threshold = 100          # số packet/nguồn trong 1 window để coi là khả nghi
window_seconds = 10       # độ dài cửa sổ đếm

alerts = []               # list các alert đã phát hiện (mới nhất ở đầu)
alerted_ips = set()       # IP đã bị alert trong window hiện tại (tránh spam)

# lịch sử packet/giây để vẽ chart traffic thật (thay vì random ở frontend)
traffic_history = []      # list[{"time": iso_str, "count": int}]
MAX_HISTORY = 300         # giữ tối đa 300 điểm (~5 phút nếu tick mỗi giây)
_second_counter = 0       # đếm packet trong giây hiện tại


def reset():
    """Dùng khi nhấn Clear trên UI hoặc khi stop hệ thống."""
    global alerts, alerted_ips, traffic_history, _second_counter
    with lock:
        alerts = []
        alerted_ips = set()
        traffic_history = []
        _second_counter = 0
