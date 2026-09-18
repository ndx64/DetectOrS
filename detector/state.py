import threading

lock = threading.Lock()

running = False
current_interface = None
self_ip = None
threshold = 100
window_seconds = 10

alerts = []
alerted_ips = set()

traffic_history = []
MAX_HISTORY = 300
_second_counter = 0


def reset():
    global alerts, alerted_ips, traffic_history, _second_counter
    with lock:
        alerts = []
        alerted_ips = set()
        traffic_history = []
        _second_counter = 0
