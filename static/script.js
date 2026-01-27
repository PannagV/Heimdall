const statusEl = document.getElementById('status');
const alertsEl = document.getElementById('alerts');
const alertCountEl = document.getElementById('alertCount');
const startBtn = document.getElementById('startBtn');
const stopBtn = document.getElementById('stopBtn');
const clearBtn = document.getElementById('clearBtn');

const ifaceSelect = document.getElementById('iface');
const configInput = document.getElementById('config');
const logTypeSelect = document.getElementById('logType');

const navItems = document.querySelectorAll('.nav-item');
const panels = document.querySelectorAll('.panel');
const sectionTitle = document.getElementById('sectionTitle');
const sectionSubtitle = document.getElementById('sectionSubtitle');

const metricTotal = document.getElementById('metricTotal');
const metric24h = document.getElementById('metric24h');
const metricCritical = document.getElementById('metricCritical');
const metricTopClass = document.getElementById('metricTopClass');
const priorityList = document.getElementById('priorityList');
const classificationList = document.getElementById('classificationList');
const protocolList = document.getElementById('protocolList');
const signatureList = document.getElementById('signatureList');
const priorityChartEl = document.getElementById('priorityChart');
const classificationChartEl = document.getElementById('classificationChart');
const hourlyChartEl = document.getElementById('hourlyChart');

let lastAlertId = 0;
let alertCount = 0;

let priorityChart = null;
let classificationChart = null;
let hourlyChart = null;

const chartPalette = ['#6ee7ff', '#a855f7', '#f97316', '#22c55e', '#facc15'];

const sectionCopy = {
  monitor: {
    title: 'Heimdall IDS Monitor',
    subtitle: 'Live alerts from Suricata fast.log or eve.json',
  },
  dashboard: {
    title: 'Alert Dashboard',
    subtitle: 'Metrics from the stored security alerts',
  },
};

function renderStatus(running, logType) {
  statusEl.textContent = running ? `Running (log: ${logType})` : 'Stopped';
  statusEl.className = running ? 'status running' : 'status stopped';
}

async function fetchStatus() {
  const res = await fetch('/api/status');
  const data = await res.json();
  renderStatus(data.running, data.log_type);
}

async function fetchInterfaces() {
  try {
    const res = await fetch('/api/interfaces');
    const data = await res.json();
    const interfaces = data.interfaces || [];
    if (!interfaces.length) return;

    const current = ifaceSelect.value;
    ifaceSelect.innerHTML = '';
    interfaces.forEach(iface => {
      const option = document.createElement('option');
      option.value = iface;
      option.textContent = iface;
      ifaceSelect.appendChild(option);
    });
    if (interfaces.includes(current)) {
      ifaceSelect.value = current;
    }
  } catch (err) {
    // ignore transient errors
  }
}

function formatEndpoint(endpoint) {
  if (!endpoint) return '';
  const ip = endpoint.ip || '';
  const port = endpoint.port !== null && endpoint.port !== undefined ? `:${endpoint.port}` : '';
  return `${ip}${port}`.trim();
}

function formatAlert(alert) {
  const lines = [];
  const signature = alert?.alert?.signature;
  const classification = alert?.alert?.category;
  const severity = alert?.event?.severity;
  const protocol = alert?.network?.protocol || alert?.network?.transport;
  const src = formatEndpoint(alert?.source);
  const dst = formatEndpoint(alert?.destination);

  if (signature) lines.push(signature);
  if (classification) lines.push(classification);
  if (severity !== null && severity !== undefined) lines.push(`Severity: ${severity}`);
  if (protocol) lines.push(`Protocol: ${protocol}`);
  if (src || dst) lines.push(`${src || ''} -> ${dst || ''}`.trim());
  if (alert?.timestamp) lines.push(alert.timestamp);
  return lines.join(' • ');
}

function addAlertCard(alert) {
  const card = document.createElement('div');
  card.className = 'alert-card';
  const title = document.createElement('div');
  title.className = 'alert-title';
  title.textContent = alert?.alert?.signature || 'Heimdall Alert';

  const meta = document.createElement('div');
  meta.className = 'alert-meta';
  meta.textContent = formatAlert(alert);

  card.appendChild(title);
  card.appendChild(meta);
  alertsEl.prepend(card);
}

function setActiveSection(section) {
  navItems.forEach(item => {
    item.classList.toggle('active', item.dataset.section === section);
  });
  panels.forEach(panel => {
    panel.classList.toggle('active', panel.dataset.section === section);
  });

  const copy = sectionCopy[section];
  if (copy) {
    sectionTitle.textContent = copy.title;
    sectionSubtitle.textContent = copy.subtitle;
  }
}

function renderList(el, items) {
  el.innerHTML = '';
  if (!items || !items.length) {
    const li = document.createElement('li');
    li.textContent = 'No data yet';
    el.appendChild(li);
    return;
  }
  items.forEach(item => {
    const li = document.createElement('li');
    const label = document.createElement('span');
    label.textContent = item.label || 'Unknown';
    const value = document.createElement('span');
    value.textContent = item.count ?? 0;
    li.appendChild(label);
    li.appendChild(value);
    el.appendChild(li);
  });
}

function updateDashboard(metrics) {
  metricTotal.textContent = metrics.total ?? 0;
  metric24h.textContent = metrics.last_24h ?? 0;
  metricCritical.textContent = metrics.critical ?? 0;
  metricTopClass.textContent = metrics.top_classification || '-';

  renderList(priorityList, metrics.by_priority);
  renderList(classificationList, metrics.by_classification);
  renderList(protocolList, metrics.by_protocol);
  renderList(signatureList, metrics.top_signatures);

  updateCharts(metrics);
}

function initCharts() {
  if (!window.Chart) return;
  if (priorityChartEl) {
    priorityChart = new Chart(priorityChartEl, {
      type: 'pie',
      data: {
        labels: [],
        datasets: [
          {
            data: [],
            backgroundColor: chartPalette,
            borderColor: '#000000',
            borderWidth: 1,
          },
        ],
      },
      options: {
        plugins: {
          legend: { labels: { color: '#ffffff' } },
        },
      },
    });
  }

  if (classificationChartEl) {
    classificationChart = new Chart(classificationChartEl, {
      type: 'bar',
      data: {
        labels: [],
        datasets: [
          {
            label: 'Alerts',
            data: [],
            backgroundColor: '#a855f7',
            borderColor: '#6ee7ff',
            borderWidth: 1,
          },
        ],
      },
      options: {
        responsive: true,
        scales: {
          x: { ticks: { color: '#cfcfcf' }, grid: { color: '#1f1f1f' } },
          y: { ticks: { color: '#cfcfcf' }, grid: { color: '#1f1f1f' } },
        },
        plugins: {
          legend: { display: false },
        },
      },
    });
  }

  if (hourlyChartEl) {
    hourlyChart = new Chart(hourlyChartEl, {
      type: 'line',
      data: {
        labels: [],
        datasets: [
          {
            label: 'Alerts per hour',
            data: [],
            borderColor: '#6ee7ff',
            backgroundColor: 'rgba(110, 231, 255, 0.2)',
            tension: 0.35,
            fill: true,
          },
        ],
      },
      options: {
        responsive: true,
        scales: {
          x: { ticks: { color: '#cfcfcf' }, grid: { color: '#1f1f1f' } },
          y: { ticks: { color: '#cfcfcf' }, grid: { color: '#1f1f1f' } },
        },
        plugins: {
          legend: { display: false },
        },
      },
    });
  }
}

function updateCharts(metrics) {
  if (priorityChart && metrics.by_priority) {
    const labels = metrics.by_priority.map(item => item.label || 'Unknown');
    const data = metrics.by_priority.map(item => item.count ?? 0);
    priorityChart.data.labels = labels;
    priorityChart.data.datasets[0].data = data;
    priorityChart.update();
  }

  if (classificationChart && metrics.by_classification) {
    const labels = metrics.by_classification.map(item => item.label || 'Unknown');
    const data = metrics.by_classification.map(item => item.count ?? 0);
    classificationChart.data.labels = labels;
    classificationChart.data.datasets[0].data = data;
    classificationChart.update();
  }

  if (hourlyChart && metrics.hourly_counts) {
    const labels = metrics.hourly_counts.map(item => item.label || '');
    const data = metrics.hourly_counts.map(item => item.count ?? 0);
    hourlyChart.data.labels = labels;
    hourlyChart.data.datasets[0].data = data;
    hourlyChart.update();
  }
}

async function pollAlerts() {
  try {
    const res = await fetch(`/api/alerts?since=${lastAlertId}`);
    const data = await res.json();
    data.alerts.forEach(alert => {
      lastAlertId = Math.max(lastAlertId, alert.id || 0);
      addAlertCard(alert);
      alertCount += 1;
    });
    alertCountEl.textContent = alertCount;
  } catch (err) {
    // ignore transient errors
  }
}

async function fetchMetrics() {
  try {
    const res = await fetch('/api/metrics');
    const data = await res.json();
    updateDashboard(data);
  } catch (err) {
    // ignore transient errors
  }
}

startBtn.addEventListener('click', async () => {
  const payload = {
    iface: ifaceSelect.value,
    config: configInput.value.trim(),
    log_type: logTypeSelect.value,
  };
  const res = await fetch('/api/start', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  const data = await res.json();
  if (data.status === 'error') {
    alert(data.message || 'Failed to start Suricata');
  }
  fetchStatus();
});

stopBtn.addEventListener('click', async () => {
  await fetch('/api/stop', { method: 'POST' });
  fetchStatus();
});

clearBtn.addEventListener('click', async () => {
  await fetch('/api/clear', { method: 'POST' });
  alertsEl.innerHTML = '';
  alertCount = 0;
  lastAlertId = 0;
  alertCountEl.textContent = '0';
});

navItems.forEach(item => {
  item.addEventListener('click', () => {
    setActiveSection(item.dataset.section);
    if (item.dataset.section === 'dashboard') {
      fetchMetrics();
    }
  });
});

fetchStatus();
fetchInterfaces();
initCharts();
setActiveSection('dashboard');
fetchMetrics();
setInterval(fetchStatus, 5000);
setInterval(pollAlerts, 1500);
setInterval(fetchMetrics, 5000);
