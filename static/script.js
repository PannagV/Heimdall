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

const eventsTableBody = document.querySelector('#eventsTable tbody');
const incidentsTableBody = document.querySelector('#incidentsTable tbody');
const eventCountEl = document.getElementById('eventCount');
const incidentCountEl = document.getElementById('incidentCount');
const refreshEventsBtn = document.getElementById('refreshEventsBtn');
const eventsQueryInput = document.getElementById('eventsQueryInput');
const runEventsQueryBtn = document.getElementById('runEventsQueryBtn');
const clearEventsQueryBtn = document.getElementById('clearEventsQueryBtn');
const eventsQueryStatus = document.getElementById('eventsQueryStatus');

const rulesEditor = document.getElementById('rulesEditor');
const rulesPathEl = document.getElementById('rulesPath');
const rulesStatusEl = document.getElementById('rulesStatus');
const reloadRulesBtn = document.getElementById('reloadRulesBtn');
const formatRulesBtn = document.getElementById('formatRulesBtn');
const saveRulesBtn = document.getElementById('saveRulesBtn');

const loginPage = document.getElementById('loginPage');
const appShell = document.getElementById('appShell');
const authForm = document.getElementById('authForm');
const authUsername = document.getElementById('authUsername');
const authPassword = document.getElementById('authPassword');
const authError = document.getElementById('authError');
const logoutBtn = document.getElementById('logoutBtn');
const userChip = document.getElementById('userChip');

let accessToken = null;
let refreshToken = sessionStorage.getItem('heimdall_refresh_token');

let lastAlertId = 0;
let alertCount = 0;

let pollingStarted = false;
let pollingIntervals = [];

let alertPollInFlight = false;
let alertStreamController = null;
let alertStreamReader = null;
let alertStreamBuffer = '';
let alertStreamRetry = null;
let alertPollTimer = null;
let alertStreamOpen = false;
let lastStreamMessageAt = 0;

let priorityChart = null;
let classificationChart = null;
let hourlyChart = null;

let currentEventsQuery = '';

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
  incidents: {
    title: 'Events & Incidents',
    subtitle: 'Inspect normalized events and manage active incidents',
  },
  rules: {
    title: 'Correlation Rules',
    subtitle: 'Review and update correlation rules in real time',
  },
};

function renderStatus(running, logType) {
  statusEl.textContent = running ? `Running (log: ${logType})` : 'Stopped';
  statusEl.className = running ? 'status running' : 'status stopped';
}

function showLoginPage(message) {
  if (loginPage) loginPage.classList.remove('hidden');
  if (appShell) appShell.classList.add('hidden');
  if (authError) authError.textContent = message || '';
}

function hideLoginPage() {
  if (loginPage) loginPage.classList.add('hidden');
  if (appShell) appShell.classList.remove('hidden');
  if (authError) authError.textContent = '';
}

function startPolling() {
  if (pollingStarted) return;
  pollingStarted = true;
  startAlertStream();
  startAlertPollingFallback();
  pollingIntervals = [
    setInterval(fetchStatus, 5000),
    setInterval(fetchMetrics, 5000),
    setInterval(() => {
      const activeSection = document.querySelector('.panel.active')?.dataset.section;
      if (activeSection === 'incidents') {
        fetchEvents();
        fetchIncidents();
      }
    }, 7000),
  ];
}

function stopPolling() {
  pollingIntervals.forEach(timerId => clearInterval(timerId));
  pollingIntervals = [];
  pollingStarted = false;
  stopAlertStream();
  stopAlertPollingFallback();
}

function setUserChip(user) {
  if (!userChip) return;
  if (!user) {
    userChip.textContent = 'Signed out';
    return;
  }
  const label = user.username || user.email || user.user_id || 'Signed in';
  const role = user.role ? ` • ${user.role}` : '';
  userChip.textContent = `${label}${role}`;
}

function handleSseChunk(chunk) {
  if (!chunk) return;
  const lines = chunk.split('\n');
  let dataLines = [];
  let id = null;
  lines.forEach(line => {
    if (line.startsWith(':')) return;
    if (line.startsWith('data:')) {
      dataLines.push(line.slice(5).trimStart());
    } else if (line.startsWith('id:')) {
      id = line.slice(3).trim();
    }
  });
  const data = dataLines.join('\n').trim();
  if (!data) return;
  try {
    const alert = JSON.parse(data);
    const eventId = Number(id) || alert.id || 0;
    lastAlertId = Math.max(lastAlertId, eventId);
    lastStreamMessageAt = Date.now();
    addAlertCard(alert);
    alertCount += 1;
    alertCountEl.textContent = alertCount;
  } catch (err) {
    // ignore malformed payloads
  }
}

async function startAlertStream() {
  if (alertStreamController || !accessToken) return;
  const controller = new AbortController();
  alertStreamController = controller;
  const headers = {
    Authorization: `Bearer ${accessToken}`,
    'Cache-Control': 'no-cache',
  };
  if (lastAlertId) headers['Last-Event-ID'] = String(lastAlertId);
  const url = `/api/alerts/stream?since=${lastAlertId}`;

  try {
    const res = await fetch(url, {
      method: 'GET',
      headers,
      cache: 'no-store',
      signal: controller.signal,
    });

    if (res.status === 401 && refreshToken) {
      const refreshed = await refreshAccessToken();
      if (refreshed) {
        alertStreamController = null;
        return startAlertStream();
      }
    }

    if (!res.ok || !res.body) {
      throw new Error('stream failed');
    }

    alertStreamOpen = true;
    lastStreamMessageAt = Date.now();
    stopAlertPollingFallback();

    const reader = res.body.getReader();
    alertStreamReader = reader;
    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const chunks = buffer.split('\n\n');
      buffer = chunks.pop() || '';
      chunks.forEach(handleSseChunk);
    }
    alertStreamBuffer = buffer;
  } catch (err) {
    if (controller.signal.aborted) return;
  } finally {
    alertStreamOpen = false;
    if (alertStreamController === controller) {
      alertStreamController = null;
      alertStreamReader = null;
    }
    startAlertPollingFallback();
    if (!pollingStarted || alertStreamRetry) return;
    alertStreamRetry = setTimeout(async () => {
      alertStreamRetry = null;
      if (!pollingStarted) return;
      if (refreshToken) {
        const refreshed = await refreshAccessToken();
        if (!refreshed) return;
      }
      startAlertStream();
    }, 1000);
  }
}

function stopAlertStream() {
  if (alertStreamController) {
    alertStreamController.abort();
    alertStreamController = null;
  }
  if (alertStreamReader) {
    alertStreamReader.cancel();
    alertStreamReader = null;
  }
  alertStreamOpen = false;
  if (alertStreamRetry) {
    clearTimeout(alertStreamRetry);
    alertStreamRetry = null;
  }
}

function startAlertPollingFallback() {
  if (alertPollTimer) return;
  alertPollTimer = setInterval(() => {
    if (alertStreamOpen) return;
    pollAlerts();
  }, 500);
}

function stopAlertPollingFallback() {
  if (!alertPollTimer) return;
  clearInterval(alertPollTimer);
  alertPollTimer = null;
}

async function authFetch(url, options = {}, retry = true) {
  const headers = options.headers ? { ...options.headers } : {};
  if (accessToken) headers.Authorization = `Bearer ${accessToken}`;
  const response = await fetch(url, { ...options, headers });
  if (response.status === 401 && refreshToken && retry) {
    const refreshed = await refreshAccessToken();
    if (refreshed) {
      return authFetch(url, options, false);
    }
    showLoginPage('Session expired. Please sign in again.');
  }
  return response;
}

async function refreshAccessToken() {
  try {
    const res = await fetch('/api/auth/refresh', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });
    if (!res.ok) return false;
    const data = await res.json();
    accessToken = data.access_token;
    refreshToken = data.refresh_token;
    sessionStorage.setItem('heimdall_refresh_token', refreshToken);
    if (pollingStarted) {
      stopAlertStream();
      startAlertStream();
    }
    if (pollingStarted) {
      startAlertPollingFallback();
    }
    return true;
  } catch (err) {
    return false;
  }
}

async function loadCurrentUser() {
  try {
    const res = await authFetch('/api/auth/me');
    if (!res.ok) return;
    const data = await res.json();
    setUserChip({ user_id: data.user_id, role: data.role });
  } catch (err) {
    // ignore
  }
}

async function fetchStatus() {
  const res = await authFetch('/api/status');
  const data = await res.json();
  renderStatus(data.running, data.log_type);
}

async function fetchInterfaces() {
  try {
    const res = await authFetch('/api/interfaces');
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

  if (section === 'incidents') {
    fetchEvents();
    fetchIncidents();
  }
  if (section === 'rules') {
    fetchRules();
  }
}

function formatIncidentBadge(incident) {
  if (!incident) return '-';
  return incident.id || incident.incident_id || '-';
}

function setEventsQueryStatus(message, isError = false) {
  if (!eventsQueryStatus) return;
  eventsQueryStatus.textContent = message;
  eventsQueryStatus.classList.toggle('error', isError);
}

function renderEvents(events) {
  if (!eventsTableBody) return;
  eventsTableBody.innerHTML = '';
  eventCountEl.textContent = events.length;
  if (!events.length) {
    const row = document.createElement('tr');
    const cell = document.createElement('td');
    cell.colSpan = 6;
    cell.textContent = 'No events available.';
    row.appendChild(cell);
    eventsTableBody.appendChild(row);
    return;
  }

  events.forEach(event => {
    const row = document.createElement('tr');
    const source = formatEndpoint(event.source);
    const destination = formatEndpoint(event.destination);

    row.innerHTML = `
      <td>${event.timestamp || '-'}</td>
      <td>${event?.event?.severity ?? '-'}</td>
      <td>${event?.alert?.signature || '-'}</td>
      <td>${source || '-'}</td>
      <td>${destination || '-'}</td>
      <td>${formatIncidentBadge(event.incident)}</td>
    `;
    eventsTableBody.appendChild(row);
  });
}

function renderIncidents(incidents) {
  if (!incidentsTableBody) return;
  incidentsTableBody.innerHTML = '';
  incidentCountEl.textContent = incidents.length;
  if (!incidents.length) {
    const row = document.createElement('tr');
    const cell = document.createElement('td');
    cell.colSpan = 6;
    cell.textContent = 'No incidents available.';
    row.appendChild(cell);
    incidentsTableBody.appendChild(row);
    return;
  }

  incidents.forEach(incident => {
    const row = document.createElement('tr');
    const isClosed = incident.status === 'closed';
    row.innerHTML = `
      <td>${incident.incident_id || '-'}</td>
      <td>${incident.status || '-'}</td>
      <td>${incident.priority || '-'}</td>
      <td>${incident.category || '-'}</td>
      <td>${incident.last_seen || '-'}</td>
      <td>
        <button class="ghost" data-incident="${incident.incident_id}" ${isClosed ? 'disabled' : ''}>
          ${isClosed ? 'Closed' : 'Close'}
        </button>
      </td>
    `;
    incidentsTableBody.appendChild(row);
  });
}

async function fetchEvents() {
  try {
    const query = (eventsQueryInput?.value || currentEventsQuery || '').trim();
    currentEventsQuery = query;

    const endpoint = query ? '/api/events/search' : '/api/events';
    const params = new URLSearchParams({ limit: '200' });
    if (query) {
      params.set('q', query);
    }

    const res = await authFetch(`${endpoint}?${params.toString()}`);
    const data = await res.json();

    if (!res.ok) {
      const position = Number.isInteger(data.position) ? data.position + 1 : null;
      const suffix = position ? ` (at character ${position})` : '';
      setEventsQueryStatus(`${data.message || 'Search failed.'}${suffix}`, true);
      renderEvents([]);
      return;
    }

    renderEvents(data.events || []);

    if (query) {
      const sortSummary = (data.query_meta?.sort || [])
        .map(item => `${item.field} ${item.direction.toUpperCase()}`)
        .join(', ');
      const details = sortSummary ? ` Sorted by ${sortSummary}.` : '';
      setEventsQueryStatus(`Showing ${data.events?.length || 0} matching events.${details}`);
    } else {
      setEventsQueryStatus('Showing latest events (default sort by timestamp DESC).');
    }
  } catch (err) {
    setEventsQueryStatus('Failed to load events.', true);
  }
}

async function fetchIncidents() {
  try {
    const res = await authFetch('/api/incidents?limit=200');
    const data = await res.json();
    renderIncidents(data.incidents || []);
  } catch (err) {
    // ignore
  }
}

async function closeIncident(incidentId) {
  if (!incidentId) return;
  try {
    await authFetch(`/api/incidents/${incidentId}/close`, { method: 'POST' });
    fetchIncidents();
  } catch (err) {
    // ignore
  }
}

function setRulesStatus(message, isError = false) {
  if (!rulesStatusEl) return;
  rulesStatusEl.textContent = message;
  rulesStatusEl.style.color = isError ? '#ffb3b3' : '#cfcfcf';
}

async function fetchRules() {
  try {
    const res = await authFetch('/api/rules');
    const data = await res.json();
    if (rulesPathEl) rulesPathEl.textContent = data.path || 'Rules file';
    if (rulesEditor) rulesEditor.value = data.raw || '';
    setRulesStatus('Loaded current rules.');
  } catch (err) {
    setRulesStatus('Failed to load rules.', true);
  }
}

function formatRules() {
  if (!rulesEditor) return;
  try {
    const parsed = JSON.parse(rulesEditor.value || '[]');
    rulesEditor.value = JSON.stringify(parsed, null, 2);
    setRulesStatus('Formatted JSON successfully.');
  } catch (err) {
    setRulesStatus('Invalid JSON. Cannot format.', true);
  }
}

async function saveRules() {
  if (!rulesEditor) return;
  try {
    const res = await authFetch('/api/rules', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ raw: rulesEditor.value }),
    });
    const data = await res.json();
    if (res.ok) {
      setRulesStatus('Rules saved and reloaded.');
    } else {
      setRulesStatus(data.message || 'Failed to save rules.', true);
    }
  } catch (err) {
    setRulesStatus('Failed to save rules.', true);
  }
}

async function handleLogin(event) {
  event.preventDefault();
  if (!authUsername || !authPassword) return;
  const username = authUsername.value.trim();
  const password = authPassword.value;
  if (!username || !password) {
    if (authError) authError.textContent = 'Enter your username and password.';
    return;
  }
  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    const data = await res.json();
    if (!res.ok) {
      if (authError) authError.textContent = data.message || 'Login failed.';
      return;
    }
    accessToken = data.access_token;
    refreshToken = data.refresh_token;
    sessionStorage.setItem('heimdall_refresh_token', refreshToken);
    hideLoginPage();
    await loadCurrentUser();
    await bootData();
    startPolling();
  } catch (err) {
    if (authError) authError.textContent = 'Login failed. Try again.';
  }
}

async function handleLogout() {
  try {
    if (refreshToken) {
      await fetch('/api/auth/logout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: refreshToken }),
      });
    }
  } catch (err) {
    // ignore
  }
  accessToken = null;
  refreshToken = null;
  sessionStorage.removeItem('heimdall_refresh_token');
  stopPolling();
  setUserChip(null);
  showLoginPage('You have been signed out.');
}

async function bootData() {
  await fetchStatus();
  await fetchInterfaces();
  await fetchMetrics();
  if (priorityChartEl) initCharts();
  pollAlerts();
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
  if (alertPollInFlight) return;
  alertPollInFlight = true;
  try {
    const res = await authFetch(`/api/alerts?since=${lastAlertId}`);
    const data = await res.json();
    data.alerts.forEach(alert => {
      lastAlertId = Math.max(lastAlertId, alert.id || 0);
      addAlertCard(alert);
      alertCount += 1;
    });
    alertCountEl.textContent = alertCount;
  } catch (err) {
    // ignore transient errors
  } finally {
    alertPollInFlight = false;
  }
}

async function fetchMetrics() {
  try {
    const res = await authFetch('/api/metrics');
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
  const res = await authFetch('/api/start', {
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
  await authFetch('/api/stop', { method: 'POST' });
  fetchStatus();
});

clearBtn.addEventListener('click', async () => {
  await authFetch('/api/clear', { method: 'POST' });
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

if (authForm) {
  authForm.addEventListener('submit', handleLogin);
}

if (logoutBtn) {
  logoutBtn.addEventListener('click', handleLogout);
}

if (refreshEventsBtn) {
  refreshEventsBtn.addEventListener('click', () => {
    fetchEvents();
    fetchIncidents();
  });
}

if (runEventsQueryBtn) {
  runEventsQueryBtn.addEventListener('click', () => {
    fetchEvents();
  });
}

if (clearEventsQueryBtn) {
  clearEventsQueryBtn.addEventListener('click', () => {
    if (eventsQueryInput) {
      eventsQueryInput.value = '';
    }
    currentEventsQuery = '';
    fetchEvents();
  });
}

if (eventsQueryInput) {
  eventsQueryInput.addEventListener('keydown', event => {
    if (event.key !== 'Enter') return;
    event.preventDefault();
    fetchEvents();
  });
}

if (incidentsTableBody) {
  incidentsTableBody.addEventListener('click', event => {
    const button = event.target.closest('button[data-incident]');
    if (!button) return;
    const incidentId = button.dataset.incident;
    closeIncident(incidentId);
  });
}

if (reloadRulesBtn) reloadRulesBtn.addEventListener('click', fetchRules);
if (formatRulesBtn) formatRulesBtn.addEventListener('click', formatRules);
if (saveRulesBtn) saveRulesBtn.addEventListener('click', saveRules);

async function initAuthSession() {
  if (refreshToken) {
    const refreshed = await refreshAccessToken();
    if (refreshed) {
      hideLoginPage();
      return true;
    }
  }
  showLoginPage('Please sign in to continue.');
  return false;
}

setActiveSection('dashboard');

initAuthSession().then(async authenticated => {
  if (!authenticated) return;
  await loadCurrentUser();
  await bootData();
  startPolling();
});
