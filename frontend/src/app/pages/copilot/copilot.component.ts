import { Component, inject, signal, computed } from '@angular/core';
import { CommonModule } from '@angular/common';
import { CopilotService, CopilotAssessment } from '../../services/copilot.service';

/* ──────────────────────────────────────────────────────────────
   AiCopilotComponent – "AI SOC Copilot"
   Split-pane view:
     Left  → Evidence selection grid (log rows with checkboxes)
     Right → AI Assessment panel (trigger analysis, view results)
   ────────────────────────────────────────────────────────────── */

@Component({
  selector: 'app-ai-copilot',
  standalone: true,
  imports: [CommonModule],
  template: `
    <!-- ───── Header ───── -->
    <div class="panel-header animate-fade-in">
      <div>
        <h2>AI SOC Copilot</h2>
        <p>Select security events and let the AI assess the threat level, MITRE mapping, and justification.</p>
      </div>
      <div class="header-actions">
        <span class="pill">{{ selectedCount() }} selected</span>
        <button class="btn btn-ghost btn-sm" (click)="toggleSelectAll()">
          {{ allSelected() ? 'Deselect All' : 'Select All' }}
        </button>
      </div>
    </div>

    <!-- ───── Split Pane ───── -->
    <div class="copilot-grid">

      <!-- ── Left Column: Evidence Selection ── -->
      <div class="section-card evidence-panel">
        <div class="section-header">
          <h3>Evidence Logs</h3>
          <span class="pill">{{ logs().length }} logs</span>
        </div>
        <div class="table-wrapper">
          <table class="data-table">
            <thead>
              <tr>
                <th class="chk-col">
                  <input
                    type="checkbox"
                    [checked]="allSelected()"
                    (change)="toggleSelectAll()"
                    title="Select / deselect all"
                  />
                </th>
                <th>Timestamp</th>
                <th>Severity</th>
                <th>Signature</th>
                <th>Src IP</th>
                <th>Dst IP</th>
                <th>Protocol</th>
              </tr>
            </thead>
            <tbody>
              @for (log of logs(); track log._id) {
                <tr
                  [class.row-selected]="log._selected"
                  (click)="toggleLog(log)"
                >
                  <td class="chk-col" (click)="$event.stopPropagation()">
                    <input
                      type="checkbox"
                      [checked]="log._selected"
                      (change)="toggleLog(log)"
                    />
                  </td>
                  <td>{{ log.timestamp }}</td>
                  <td>
                    <span [class]="'severity-' + log.event.severity">
                      {{ severityLabel(log.event.severity) }}
                    </span>
                  </td>
                  <td>{{ log.alert?.signature || '—' }}</td>
                  <td class="mono">{{ log.source?.ip || '—' }}</td>
                  <td class="mono">{{ log.destination?.ip || '—' }}</td>
                  <td>{{ log.network?.transport || '—' }}</td>
                </tr>
              }
            </tbody>
          </table>
        </div>

        <!-- Expand selected log as raw JSON -->
        @if (selectedCount() === 1) {
          <div class="json-preview">
            <h4>Selected Log (Raw JSON)</h4>
            <pre>{{ prettySelected() }}</pre>
          </div>
        }
      </div>

      <!-- ── Right Column: AI Assessment Panel ── -->
      <div class="section-card assessment-panel">
        <div class="section-header">
          <h3>AI Assessment</h3>
        </div>

        <!-- Action button -->
        <button
          class="btn btn-primary btn-full assess-btn"
          [disabled]="selectedCount() === 0 || loading()"
          (click)="runAssessment()"
        >
          @if (loading()) {
            <span class="spinner"></span> Analysing…
          } @else {
             Assess Selected Logs
          }
        </button>

        <!-- Loading skeleton -->
        @if (loading()) {
          <div class="skeleton-wrap animate-pulse">
            <div class="skel-line skel-w60"></div>
            <div class="skel-line skel-w80"></div>
            <div class="skel-line skel-w40"></div>
            <div class="skel-line skel-w90"></div>
            <div class="skel-line skel-w70"></div>
          </div>
        }

        <!-- Error message -->
        @if (error()) {
          <div class="error-banner animate-fade-in">
            <strong>Assessment failed</strong>
            <p>{{ error() }}</p>
            <button class="btn btn-ghost btn-sm" (click)="error.set('')">Dismiss</button>
          </div>
        }

        <!-- Results -->
        @if (result() && !loading()) {
          <div class="result-card animate-fade-in">
            <!-- Severity banner -->
            <div class="result-severity" [class]="'sev-' + result()!.severity.toLowerCase()">
              <span class="sev-label">Severity</span>
              <span class="sev-value">{{ result()!.severity }}</span>
            </div>

            <!-- Key-value details -->
            <div class="result-details">
              <div class="detail-row">
                <span class="detail-label">MITRE Tactic</span>
                <span class="detail-value">{{ result()!.mitre_tactic }}</span>
              </div>
              <div class="detail-row">
                <span class="detail-label">MITRE Technique</span>
                <span class="detail-value">{{ result()!.mitre_technique }}</span>
              </div>
              <div class="detail-row">
                <span class="detail-label">Confidence</span>
                <span class="detail-value">
                  <span class="confidence-bar-track">
                    <span
                      class="confidence-bar-fill"
                      [style.width.%]="result()!.confidence_score"
                      [class]="'sev-fill-' + result()!.severity.toLowerCase()"
                    ></span>
                  </span>
                  {{ result()!.confidence_score }}%
                </span>
              </div>
            </div>

            <!-- Justification -->
            <div class="result-justification">
              <span class="detail-label">Justification</span>
              <p>{{ result()!.justification }}</p>
            </div>
          </div>
        }

        <!-- Empty state (no results yet, nothing loading) -->
        @if (!result() && !loading() && !error()) {
          <div class="empty-assessment">
            <div class="empty-icon"></div>
            <p>Select one or more evidence logs and click <strong>Assess</strong> to get an AI-powered threat analysis.</p>
          </div>
        }
      </div>
    </div>
  `,
  styles: [`
    /* ── host ── */
    :host { display: block; }

    /* ── header ── */
    .panel-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 24px;
      gap: 16px;
      flex-wrap: wrap;
    }
    .panel-header h2 { font-size: 20px; margin-bottom: 4px; }
    .panel-header p  { font-size: 13px; }
    .header-actions  { display: flex; gap: 10px; align-items: center; }

    /* ── split pane ── */
    .copilot-grid {
      display: grid;
      grid-template-columns: 1.4fr 1fr;
      gap: 20px;
      align-items: start;
    }
    @media (max-width: 1100px) {
      .copilot-grid { grid-template-columns: 1fr; }
    }

    /* ── cards ── */
    .section-card {
      padding: 22px;
      border-radius: var(--radius-lg);
      background: var(--bg-surface);
      border: 1px solid var(--border);
    }
    .section-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 16px;
    }
    .section-header h3 { font-size: 16px; }

    /* ── table tweaks ── */
    .chk-col { width: 36px; text-align: center; }
    .chk-col input[type="checkbox"] {
      accent-color: var(--cyan);
      width: 15px;
      height: 15px;
      cursor: pointer;
    }
    .data-table tbody tr { cursor: pointer; }
    .row-selected { background: rgba(110, 231, 255, 0.07) !important; }
    .mono {
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
    }

    /* ── JSON preview ── */
    .json-preview {
      margin-top: 16px;
      padding: 14px;
      background: var(--bg-input);
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      max-height: 220px;
      overflow: auto;
    }
    .json-preview h4 {
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--text-secondary);
      margin-bottom: 8px;
    }
    .json-preview pre {
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
      color: var(--cyan);
      white-space: pre-wrap;
      word-break: break-all;
    }

    /* ── assess button ── */
    .assess-btn {
      margin-bottom: 20px;
      font-size: 15px;
      padding: 14px;
    }

    /* ── spinner ── */
    .spinner {
      width: 16px;
      height: 16px;
      border: 2px solid rgba(0,0,0,0.2);
      border-top-color: #000;
      border-radius: 50%;
      display: inline-block;
      animation: spin 0.6s linear infinite;
    }
    @keyframes spin { to { transform: rotate(360deg); } }

    /* ── skeleton loader ── */
    .skeleton-wrap {
      display: flex;
      flex-direction: column;
      gap: 12px;
      padding: 20px 0;
    }
    .skel-line {
      height: 14px;
      border-radius: 6px;
      background: var(--bg-hover);
    }
    .skel-w40 { width: 40%; }
    .skel-w60 { width: 60%; }
    .skel-w70 { width: 70%; }
    .skel-w80 { width: 80%; }
    .skel-w90 { width: 90%; }

    /* ── error banner ── */
    .error-banner {
      padding: 16px;
      border-radius: var(--radius-sm);
      background: rgba(239, 68, 68, 0.1);
      border: 1px solid rgba(239, 68, 68, 0.3);
      color: var(--red);
      margin-bottom: 16px;
    }
    .error-banner strong { display: block; margin-bottom: 4px; }
    .error-banner p { font-size: 13px; margin-bottom: 10px; color: var(--text-secondary); }

    /* ── result card ── */
    .result-card {
      border: 1px solid var(--border);
      border-radius: var(--radius-md);
      overflow: hidden;
    }

    /* severity banner */
    .result-severity {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 16px 20px;
      font-weight: 700;
    }
    .sev-label {
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      opacity: 0.85;
    }
    .sev-value { font-size: 20px; }

    /* severity colour mapping */
    .sev-critical {
      background: rgba(239, 68, 68, 0.15);
      color: var(--red);
      border-bottom: 2px solid var(--red);
    }
    .sev-high {
      background: rgba(249, 115, 22, 0.15);
      color: var(--orange);
      border-bottom: 2px solid var(--orange);
    }
    .sev-medium {
      background: rgba(250, 204, 21, 0.15);
      color: var(--yellow);
      border-bottom: 2px solid var(--yellow);
    }
    .sev-low {
      background: rgba(34, 197, 94, 0.12);
      color: var(--green);
      border-bottom: 2px solid var(--green);
    }

    /* detail rows */
    .result-details {
      padding: 16px 20px;
      display: flex;
      flex-direction: column;
      gap: 14px;
    }
    .detail-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
    }
    .detail-label {
      font-size: 12px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--text-secondary);
      flex-shrink: 0;
    }
    .detail-value {
      font-size: 14px;
      font-weight: 500;
      text-align: right;
      display: flex;
      align-items: center;
      gap: 10px;
    }

    /* confidence bar */
    .confidence-bar-track {
      width: 100px;
      height: 6px;
      background: var(--bg-hover);
      border-radius: 3px;
      overflow: hidden;
      display: inline-block;
    }
    .confidence-bar-fill {
      height: 100%;
      border-radius: 3px;
      transition: width 0.4s ease;
    }
    .sev-fill-critical { background: var(--red); }
    .sev-fill-high     { background: var(--orange); }
    .sev-fill-medium   { background: var(--yellow); }
    .sev-fill-low      { background: var(--green); }

    /* justification */
    .result-justification {
      padding: 16px 20px;
      border-top: 1px solid var(--border);
    }
    .result-justification p {
      margin-top: 8px;
      font-size: 14px;
      line-height: 1.65;
      color: var(--text-secondary);
    }

    /* empty state */
    .empty-assessment {
      text-align: center;
      padding: 48px 20px;
      color: var(--text-muted);
    }
    .empty-icon {
      font-size: 42px;
      margin-bottom: 12px;
    }
    .empty-assessment p {
      font-size: 14px;
      max-width: 320px;
      margin: 0 auto;
      line-height: 1.6;
    }
  `],
})
export class AiCopilotComponent {
  private copilotService = inject(CopilotService);

  /* ── state signals ── */
  logs      = signal<any[]>(MOCK_LOGS);      // seed with mock data for UI testing
  loading   = signal(false);
  error     = signal('');
  result    = signal<CopilotAssessment | null>(null);

  /* ── computed helpers ── */
  selectedCount = computed(() => this.logs().filter(l => l._selected).length);
  allSelected   = computed(() => this.logs().length > 0 && this.logs().every(l => l._selected));

  /** Toggle selection on a single log row */
  toggleLog(log: any): void {
    this.logs.update(list =>
      list.map(l => l._id === log._id ? { ...l, _selected: !l._selected } : l),
    );
  }

  /** Select / deselect all rows */
  toggleSelectAll(): void {
    const target = !this.allSelected();
    this.logs.update(list => list.map(l => ({ ...l, _selected: target })));
  }

  /** Return a human-readable severity label from numeric HCES severity */
  severityLabel(sev: number): string {
    return { 1: 'Critical', 2: 'High', 3: 'Medium', 4: 'Low' }[sev] ?? `${sev}`;
  }

  /** Pretty-print the single selected log as JSON */
  prettySelected(): string {
    const sel = this.logs().find(l => l._selected);
    if (!sel) return '';
    // strip internal _selected flag before display
    const { _selected, ...clean } = sel;
    return JSON.stringify(clean, null, 2);
  }

  /** Call the backend AI assessment endpoint with all selected logs */
  runAssessment(): void {
    const selected = this.logs()
      .filter(l => l._selected)
      .map(({ _selected, ...rest }) => rest);        // strip UI-only key

    if (selected.length === 0) return;

    // prevent double-submit
    this.loading.set(true);
    this.error.set('');
    this.result.set(null);

    this.copilotService.assessLogs(selected).subscribe({
      next: res => {
        this.result.set(res);
        this.loading.set(false);
      },
      error: err => {
        const msg =
          err?.error?.message ||
          err?.message ||
          'An unexpected error occurred. Please try again.';
        this.error.set(msg);
        this.loading.set(false);
      },
    });
  }
}


/* ─────────────────────────────────────────────────────────
   MOCK DATA — realistic Suricata-like HCES events so the
   UI can be tested before the backend is fully wired up.
   ───────────────────────────────────────────────────────── */
const MOCK_LOGS: any[] = [
  {
    _id: 'mock-001',
    timestamp: '2026-02-25T08:12:33.412Z',
    event: { kind: 'alert', category: 'intrusion_detection', type: 'alert', severity: 1 },
    alert: { signature: 'ET MALWARE Win32/Emotet Activity (POST)', signature_id: 2027863, category: 'A Network Trojan was Detected' },
    source: { ip: '192.168.1.105', port: 49832 },
    destination: { ip: '203.0.113.45', port: 443 },
    network: { transport: 'tcp', protocol: 'tls' },
    raw_event: { data: { flow_id: 11928374650 } },
  },
  {
    _id: 'mock-002',
    timestamp: '2026-02-25T08:12:34.001Z',
    event: { kind: 'alert', category: 'intrusion_detection', type: 'alert', severity: 2 },
    alert: { signature: 'ET SCAN Nmap Scripting Engine User-Agent', signature_id: 2024364, category: 'Attempted Information Leak' },
    source: { ip: '10.0.0.200', port: 54210 },
    destination: { ip: '192.168.1.1', port: 80 },
    network: { transport: 'tcp', protocol: 'http' },
    raw_event: { data: { flow_id: 22018475312 } },
  },
  {
    _id: 'mock-003',
    timestamp: '2026-02-25T08:13:01.789Z',
    event: { kind: 'alert', category: 'intrusion_detection', type: 'alert', severity: 1 },
    alert: { signature: 'ET TROJAN CobaltStrike Beacon C2 Activity', signature_id: 2032484, category: 'A Network Trojan was Detected' },
    source: { ip: '192.168.1.42', port: 60113 },
    destination: { ip: '198.51.100.77', port: 8443 },
    network: { transport: 'tcp', protocol: 'tls' },
    raw_event: { data: { flow_id: 33019582742 } },
  },
  {
    _id: 'mock-004',
    timestamp: '2026-02-25T08:14:22.555Z',
    event: { kind: 'alert', category: 'intrusion_detection', type: 'alert', severity: 3 },
    alert: { signature: 'ET POLICY DNS Query to .onion Domain', signature_id: 2025446, category: 'Potentially Bad Traffic' },
    source: { ip: '192.168.1.88', port: 52334 },
    destination: { ip: '8.8.8.8', port: 53 },
    network: { transport: 'udp', protocol: 'dns' },
    raw_event: { data: { flow_id: 44027193856 } },
  },
  {
    _id: 'mock-005',
    timestamp: '2026-02-25T08:15:10.321Z',
    event: { kind: 'alert', category: 'intrusion_detection', type: 'alert', severity: 2 },
    alert: { signature: 'ET EXPLOIT Possible Apache Log4j RCE Attempt', signature_id: 2034647, category: 'Attempted Administrator Privilege Gain' },
    source: { ip: '45.33.32.156', port: 12345 },
    destination: { ip: '192.168.1.10', port: 8080 },
    network: { transport: 'tcp', protocol: 'http' },
    raw_event: { data: { flow_id: 55034827411 } },
  },
  {
    _id: 'mock-006',
    timestamp: '2026-02-25T08:16:45.112Z',
    event: { kind: 'alert', category: 'intrusion_detection', type: 'alert', severity: 4 },
    alert: { signature: 'ET INFO Observed External IP Lookup (ifconfig.me)', signature_id: 2022082, category: 'Misc activity' },
    source: { ip: '192.168.1.55', port: 48291 },
    destination: { ip: '34.117.59.81', port: 443 },
    network: { transport: 'tcp', protocol: 'tls' },
    raw_event: { data: { flow_id: 66048293105 } },
  },
  {
    _id: 'mock-007',
    timestamp: '2026-02-25T08:17:02.880Z',
    event: { kind: 'alert', category: 'intrusion_detection', type: 'alert', severity: 1 },
    alert: { signature: 'ET MALWARE Trickbot Checkin', signature_id: 2028765, category: 'A Network Trojan was Detected' },
    source: { ip: '192.168.1.130', port: 50741 },
    destination: { ip: '185.220.101.34', port: 447 },
    network: { transport: 'tcp', protocol: 'tls' },
    raw_event: { data: { flow_id: 77052918430 } },
  },
  {
    _id: 'mock-008',
    timestamp: '2026-02-25T08:18:33.200Z',
    event: { kind: 'alert', category: 'intrusion_detection', type: 'alert', severity: 3 },
    alert: { signature: 'ET POLICY Outbound SSH Connection', signature_id: 2001219, category: 'Potential Corporate Privacy Violation' },
    source: { ip: '192.168.1.77', port: 33210 },
    destination: { ip: '151.101.1.140', port: 22 },
    network: { transport: 'tcp', protocol: 'ssh' },
    raw_event: { data: { flow_id: 88061029544 } },
  },
];
