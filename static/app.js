let running = false
let scanTimer = 0
let timerInterval = null
let pollInterval = null
let attackCount = 0
let alerts = []
let selectedInterface = null

let maxPoints = 30
let maxScanTime = 30

const ctx = document.getElementById("trafficChart").getContext("2d")

const chart = new Chart(ctx, {
  type: "line",
  data: {
    labels: [],
    datasets: [{
      label: "Packets/sec",
      data: [],
      borderColor: "#38bdf8",
      backgroundColor: "rgba(56,189,248,0.2)",
      fill: true,
      tension: 0.4,
      borderWidth: 2,
      pointRadius: 3,
      pointBackgroundColor: "#38bdf8",
      pointBorderColor: "#0b1120",
      pointBorderWidth: 1
    }]
  },
  options: {
    animation: {
      duration: 500,
      easing: "easeOutQuart"
    },
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { labels: { color: "#94a3b8" } }
    },
    scales: {
      x: { ticks: { color: "#64748b" }, grid: { color: "#1f2937" } },
      y: { beginAtZero: true, ticks: { color: "#64748b" }, grid: { color: "#1f2937" } }
    }
  }
})

async function loadInterfaces() {
  try {
    const res = await fetch("/interfaces")
    const data = await res.json()
    const select = document.getElementById("interfaceSelect")
    select.innerHTML = ""
    data.interfaces.forEach(iface => {
      const opt = document.createElement("option")
      opt.value = iface
      opt.innerText = iface
      select.appendChild(opt)
    })
    if (data.interfaces.length > 0) {
      selectedInterface = data.interfaces[0]
    }
  } catch (err) {
    console.error("Không lấy được danh sách interface:", err)
  }
}

function changeInterface() {
  selectedInterface = document.getElementById("interfaceSelect").value
}

async function startSystem() {
  if (running) return

  if (!selectedInterface) {
    alert("Chưa chọn network interface.")
    return
  }

  try {
    const res = await fetch("/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ interface: selectedInterface })
    })
    if (!res.ok) {
      const err = await res.json()
      alert("Không thể bắt đầu: " + (err.error || res.statusText))
      return
    }
  } catch (err) {
    alert("Lỗi kết nối tới backend: " + err)
    return
  }

  running = true
  const statusEl = document.getElementById("statusLabel")
  statusEl.innerText = "Đang chạy"
  statusEl.className = "value status-running"

  timerInterval = setInterval(() => {
    scanTimer++
    document.getElementById("timer").innerText = scanTimer
    if (scanTimer >= maxScanTime) {
      stopSystem()
    }
  }, 1000)

  pollInterval = setInterval(pollBackend, 1000)
}

async function stopSystem() {
  running = false
  clearInterval(timerInterval)
  clearInterval(pollInterval)
  const statusEl = document.getElementById("statusLabel")
  statusEl.innerText = "Đã dừng"
  statusEl.className = "value status-stopped"

  try {
    await fetch("/stop", { method: "POST" })
  } catch (err) {
    console.error("Lỗi khi gọi /stop:", err)
  }
}

async function clearSystem() {
  await stopSystem()

  scanTimer = 0
  attackCount = 0
  alerts = []

  document.getElementById("timer").innerText = 0
  document.getElementById("attackCount").innerText = 0
  document.getElementById("attackType").innerText = "None"
  const statusEl = document.getElementById("statusLabel")
  statusEl.innerText = "Chưa chạy"
  statusEl.className = "value status-stopped"

  chart.data.labels = []
  chart.data.datasets[0].data = []
  chart.update()

  updateTable()

  try {
    await fetch("/clear", { method: "POST" })
  } catch (err) {
    console.error("Lỗi khi gọi /clear:", err)
  }
}

function changeRange() {
  let val = parseInt(document.getElementById("timeRange").value)
  maxPoints = val
  maxScanTime = val
}

function exportAlerts() {
  const fmt = document.getElementById("exportFormat").value
  window.location.href = `/export?format=${fmt}`
}

function updateTable() {
  const table = document.getElementById("alertTable")

  if (alerts.length === 0) {
    table.innerHTML = `<tr class="empty-row"><td colspan="6">Chưa có cảnh báo nào</td></tr>`
    return
  }

  table.innerHTML = ""
  alerts.forEach(a => {
    table.innerHTML += `
      <tr class="sev-${a.severity || "medium"}">
        <td>${a.ip}</td>
        <td>${a.dst || "-"}</td>
        <td>${a.protocol || "-"}</td>
        <td>${a.packets}</td>
        <td><span class="sev-badge">${(a.severity || "medium").toUpperCase()}</span></td>
        <td>${a.time}</td>
      </tr>
    `
  })
}

async function pollBackend() {
  if (!running) return

  try {
    const [statsRes, alertsRes] = await Promise.all([
      fetch("/stats"),
      fetch("/alerts")
    ])
    const stats = await statsRes.json()
    const newAlerts = await alertsRes.json()

    const history = stats.history.slice(-maxPoints)
    chart.data.labels = history.map(h => h.time)
    chart.data.datasets[0].data = history.map(h => h.count)
    chart.update()

    if (newAlerts.length !== alerts.length) {
      alerts = newAlerts
      attackCount = alerts.length
      const countEl = document.getElementById("attackCount")
      countEl.innerText = attackCount
      countEl.className = attackCount > 0 ? "value attack-detected" : "value"
      document.getElementById("attackType").innerText =
        attackCount > 0 ? (alerts[0].protocol + " flood (nghi vấn)") : "None"
      updateTable()
    }

    if (!stats.running) {
      stopSystem()
    }
  } catch (err) {
    console.error("Lỗi khi poll backend:", err)
  }
}

window.addEventListener("DOMContentLoaded", loadInterfaces)
