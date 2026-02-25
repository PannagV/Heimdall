import { Component, inject, signal, OnInit, OnDestroy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ApiService } from '../../services/api.service';
import { AlertService } from '../../services/alert.service';

@Component({
  selector: 'app-monitor',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <!-- Controls -->
    <section class="controls animate-fade-in">
      <div class="field">
        <label for="iface">Interface</label>
        <select id="iface" [(ngModel)]="selectedIface">
          @for (iface of interfaces(); track iface) {
            <option [value]="iface">{{ iface }}</option>
          }
        </select>
      </div>
      <div class="field">
        <label for="config">Config path</label>
        <input id="config" type="text" [(ngModel)]="configPath" />
      </div>
      <div class="field">
        <label for="logType">Log type</label>
        <select id="logType" [(ngModel)]="logType">
          <option value="eve.json">eve.json</option>
          <option value="fast.log">fast.log</option>
        </select>
      </div>
      <div class="control-actions">
        <button class="btn btn-primary" (click)="onStart()">Start Suricata</button>
        <button class="btn btn-default" (click)="onStop()">Stop Suricata</button>
        <button class="btn btn-ghost" (click)="onClear()">Clear Alerts</button>
      </div>
    </section>

    <!-- Alert Feed -->
    <section class="alerts-section">
      <div class="alerts-header">
        <h3>Live Alerts</h3>
        <span class="pill">{{ alertService.count() }} alerts</span>
      </div>
      <div class="alert-feed">
        @for (alert of alertService.alerts(); track $index) {
          <div class="alert-card animate-slide-in">
            <div class="alert-card-header">
              <span class="alert-title">{{ alert?.alert?.signature || 'Heimdall Alert' }}</span>
              @if (alert?.event?.severity) {
                <span
                  class="badge"
                  [class.badge-danger]="alert.event.severity <= 1"
                  [class.badge-warning]="alert.event.severity === 2"
                  [class.badge-info]="alert.event.severity >= 3"
                >
                  Sev {{ alert.event.severity }}
                </span>
              }
            </div>
            <div class="alert-meta">
              @if (alert?.alert?.category) {
                <span class="meta-tag">{{ alert.alert.category }}</span>
              }
              @if (alert?.network?.protocol || alert?.network?.transport) {
                <span class="meta-tag">{{ alert.network.protocol || alert.network.transport }}</span>
              }
              @if (alert?.source?.ip) {
                <span class="meta-flow">
                  {{ formatEndpoint(alert.source) }} → {{ formatEndpoint(alert.destination) }}
                </span>
              }
              @if (alert?.timestamp) {
                <span class="meta-time">{{ alert.timestamp }}</span>
              }
            </div>
          </div>
        } @empty {
          <div class="empty-state">
            <p>No alerts yet. Start Suricata and monitor network traffic to see live alerts here.</p>
          </div>
        }
      </div>
    </section>
  `,
  styles: [`
    :host { display: block; }
    .controls {
      padding: 22px;
      background: var(--gradient-subtle);
      border-radius: var(--radius-lg);
      border: 1px solid var(--border);
      display: grid;
      gap: 16px;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      margin-bottom: 28px;
    }
    .control-actions {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      align-items: flex-end;
    }
    .alerts-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 16px;
    }
    .alerts-header h3 { font-size: 18px; }
    .alert-feed {
      display: grid;
      gap: 10px;
      max-height: calc(100vh - 380px);
      overflow-y: auto;
    }
    .alert-card {
      padding: 16px 20px;
      border-radius: var(--radius-md);
      background: var(--bg-surface);
      border: 1px solid var(--border);
      transition: border-color 0.2s;
    }
    .alert-card:hover {
      border-color: var(--border-hover);
    }
    .alert-card-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 12px;
      margin-bottom: 8px;
    }
    .alert-title {
      font-weight: 700;
      font-size: 14px;
      color: var(--text);
    }
    .alert-meta {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      align-items: center;
      font-size: 12px;
      color: var(--text-secondary);
    }
    .meta-tag {
      padding: 2px 8px;
      border-radius: var(--radius-sm);
      background: var(--bg-elevated);
      border: 1px solid var(--border);
      font-size: 11px;
    }
    .meta-flow {
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px;
      color: var(--cyan);
    }
    .meta-time {
      color: var(--text-muted);
      font-size: 11px;
    }
    .empty-state {
      text-align: center;
      padding: 60px 20px;
      color: var(--text-muted);
    }
  `],
})
export class MonitorComponent implements OnInit, OnDestroy {
  private api = inject(ApiService);
  alertService = inject(AlertService);

  interfaces = signal<string[]>([]);
  selectedIface = '';
  configPath = '/etc/suricata/suricata.yaml';
  logType = 'eve.json';

  ngOnInit(): void {
    this.api.getInterfaces().subscribe({
      next: data => {
        const ifaces = data.interfaces || [];
        this.interfaces.set(ifaces);
        if (ifaces.length) this.selectedIface = ifaces[0];
      },
      error: () => {},
    });
    this.alertService.startStream();
  }

  ngOnDestroy(): void {
    this.alertService.stopStream();
  }

  onStart(): void {
    this.api
      .startSuricata({
        iface: this.selectedIface,
        config: this.configPath,
        log_type: this.logType,
      })
      .subscribe({
        next: data => {
          if (data.status === 'error') {
            alert(data.message || 'Failed to start Suricata');
          }
        },
        error: () => alert('Failed to start Suricata'),
      });
  }

  onStop(): void {
    this.api.stopSuricata().subscribe({ error: () => {} });
  }

  onClear(): void {
    this.api.clearAlerts().subscribe({
      next: () => this.alertService.clearAlerts(),
      error: () => {},
    });
  }

  formatEndpoint(ep: any): string {
    if (!ep) return '';
    const ip = ep.ip || '';
    const port = ep.port != null ? `:${ep.port}` : '';
    return `${ip}${port}` || '';
  }
}
