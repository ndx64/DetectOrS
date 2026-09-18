import csv
import io
import threading
import time
from datetime import datetime

from flask import Flask, render_template, request, jsonify, Response

from detector import state
from detector.sniffer import start_sniff
from detector.analyzer import tick_traffic_history

app = Flask(__name__)


def _traffic_history_ticker():
    """Runs in the background, recording the packet count into traffic_history every second."""
    while True:
        time.sleep(1)
        tick_traffic_history()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/interfaces")
def interfaces():
    from scapy.all import get_if_list
    return jsonify({"interfaces": get_if_list()})


@app.route("/start", methods=["POST"])
def start():
    data = request.get_json(silent=True) or {}
    iface = data.get("interface")
    threshold = data.get("threshold")
    window = data.get("window_seconds")

    if not iface:
        return jsonify({"error": "Missing 'interface'"}), 400

    with state.lock:
        if threshold:
            state.threshold = int(threshold)
        if window:
            state.window_seconds = int(window)

    if not state.running:
        t = threading.Thread(target=start_sniff, args=(iface,))
        t.daemon = True
        t.start()

    return jsonify({"status": "started", "interface": iface})


@app.route("/stop", methods=["POST"])
def stop():
    state.running = False
    return jsonify({"status": "stopped"})


@app.route("/clear", methods=["POST"])
def clear():
    state.reset()
    return jsonify({"status": "cleared"})


@app.route("/alerts")
def alerts():
    with state.lock:
        return jsonify(state.alerts)


@app.route("/stats")
def stats():
    """Data used to render the real traffic chart + system status."""
    with state.lock:
        return jsonify({
            "running": state.running,
            "interface": state.current_interface,
            "threshold": state.threshold,
            "history": state.traffic_history,
            "alert_count": len(state.alerts),
        })


@app.route("/export")
def export_alerts():
    """
    Exports all current alerts to a file.
    Use the query param ?format=txt (default) or ?format=csv
    Example: GET /export?format=csv
    """
    fmt = request.args.get("format", "txt").lower()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    with state.lock:
        alerts_snapshot = list(state.alerts)
        interface = state.current_interface
        threshold = state.threshold
        window = state.window_seconds

    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["source_ip", "destination_ip", "protocol", "packets", "severity", "time"])
        for a in alerts_snapshot:
            writer.writerow([a.get("ip"), a.get("dst"), a.get("protocol"),
                              a.get("packets"), a.get("severity"), a.get("time")])
        filename = f"dos_alerts_{ts}.csv"
        return Response(
            buf.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )

    
    lines = []
    lines.append("=" * 60)
    lines.append("DoS Attack Detection - Alert Export")
    lines.append(f"Exported at   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Interface     : {interface}")
    lines.append(f"Threshold     : {threshold} packets / {window}s window")
    lines.append(f"Total alerts  : {len(alerts_snapshot)}")
    lines.append("=" * 60)
    lines.append("")

    if not alerts_snapshot:
        lines.append("(No alerts were recorded during this session)")
    else:
        for i, a in enumerate(alerts_snapshot, 1):
            lines.append(
                f"[{i}] {a.get('time')}  |  {a.get('ip')} -> {a.get('dst')}  |  "
                f"{a.get('protocol')}  |  {a.get('packets')} packets  |  "
                f"severity: {str(a.get('severity')).upper()}"
            )

    filename = f"dos_alerts_{ts}.txt"
    return Response(
        "\n".join(lines),
        mimetype="text/plain",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


if __name__ == "__main__":
    ticker = threading.Thread(target=_traffic_history_ticker, daemon=True)
    ticker.start()
    app.run(debug=True)
