import { Component, inject, signal, OnInit, OnDestroy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ApiService } from '../../services/api.service';

@Component({
  selector: 'app-events',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="panel-header animate-fade-in">
      <div>
        <h2>Normalized Events &amp; Incidents</h2>
        <p>Latest HCES events stored in MongoDB and active incident tracking.</p>
      </div>
      <div class="header-actions">
        <button class="btn btn-ghost" (click)="refresh()">
          ↻ Refresh
        </button>
      </div>
    </div>

    <div class="split-grid">
      <!-- Events Table -->
      <div class="section-card">
        <div class="section-header">
          <h3>Events</h3>
          <span class="pill">{{ events().length }}</span>
        </div>
        <div class="table-wrapper">
          <table class="data-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Severity</th>
                <th>Signature</th>
                <th>Source</th>
                <th>Destination</th>
                <th>Incident</th>
              </tr>
            </thead>
            <tbody>
              @for (event of events(); track $index) {
                <tr>
                  <td>{{ event.timestamp || '—' }}</td>
                  <td>
                    <span [class]="'severity-' + (event?.event?.severity || 4)">
                      {{ event?.event?.severity ?? '—' }}
                    </span>
                  </td>
                  <td>{{ event?.alert?.signature || '—' }}</td>
                  <td class="mono">{{ formatEndpoint(event?.source) }}</td>
                  <td class="mono">{{ formatEndpoint(event?.destination) }}</td>
                  <td>
                    @if (event?.incident) {
                      <span class="badge badge-info">
                        {{ event.incident.id || event.incident.incident_id || '—' }}
                      </span>
                    } @else {
                      <span class="text-muted">—</span>
                    }
                  </td>
                </tr>
              } @empty {
                <tr>
                  <td colspan="6" class="empty-state">No events available.</td>
                </tr>
              }
            </tbody>
          </table>
        </div>
      </div>

      <!-- Incidents Table -->
      <div class="section-card">
        <div class="section-header">
          <h3>Incidents</h3>
          <span class="pill">{{ incidents().length }}</span>
        </div>
        <div class="table-wrapper">
          <table class="data-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Status</th>
                <th>Priority</th>
                <th>Category</th>
                <th>Last Seen</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              @for (incident of incidents(); track incident.incident_id) {
                <tr>
                  <td class="mono">{{ incident.incident_id || '—' }}</td>
                  <td>
                    <span
                      class="badge"
                      [class.badge-warning]="incident.status === 'open'"
                      [class.badge-neutral]="incident.status === 'closed'"
                    >
                      {{ incident.status || '—' }}
                    </span>
                  </td>
                  <td>{{ incident.priority || '—' }}</td>
                  <td>{{ incident.category || '—' }}</td>
                  <td>{{ incident.last_seen || '—' }}</td>
                  <td>
                    <button
                      class="btn btn-sm"
                      [class.btn-danger]="incident.status !== 'closed'"
                      [class.btn-ghost]="incident.status === 'closed'"
                      [disabled]="incident.status === 'closed'"
                      (click)="closeIncident(incident.incident_id)"
                    >
                      {{ incident.status === 'closed' ? 'Closed' : 'Close' }}
                    </button>
                  </td>
                </tr>
              } @empty {
                <tr>
                  <td colspan="6" class="empty-state">No incidents available.</td>
                </tr>
              }
            </tbody>
          </table>
        </div>
      </div>
    </div>
  `,
  styles: [`
    :host { display: block; }
    .panel-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 24px;
      gap: 16px;
      flex-wrap: wrap;
    }
    .panel-header h2 {
      font-size: 20px;
      margin-bottom: 4px;
    }
    .panel-header p {
      font-size: 13px;
    }
    .header-actions {
      display: flex;
      gap: 10px;
    }
    .split-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
      gap: 20px;
    }
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
    .mono {
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
    }
    .text-muted {
      color: var(--text-muted);
    }
    .empty-state {
      text-align: center;
      padding: 32px;
      color: var(--text-muted);
    }
  `],
})
export class EventsComponent implements OnInit, OnDestroy {
  private api = inject(ApiService);

  events = signal<any[]>([]);
  incidents = signal<any[]>([]);
  private interval: any;

  ngOnInit(): void {
    this.refresh();
    this.interval = setInterval(() => this.refresh(), 7000);
  }

  ngOnDestroy(): void {
    clearInterval(this.interval);
  }

  refresh(): void {
    this.api.getEvents().subscribe({
      next: data => this.events.set(data.events || []),
      error: () => {},
    });
    this.api.getIncidents().subscribe({
      next: data => this.incidents.set(data.incidents || []),
      error: () => {},
    });
  }

  closeIncident(id: string): void {
    if (!id) return;
    this.api.closeIncident(id).subscribe({
      next: () => {
        this.api.getIncidents().subscribe({
          next: data => this.incidents.set(data.incidents || []),
          error: () => {},
        });
      },
      error: () => {},
    });
  }

  formatEndpoint(ep: any): string {
    if (!ep) return '—';
    const ip = ep.ip || '';
    const port = ep.port != null ? `:${ep.port}` : '';
    return `${ip}${port}` || '—';
  }
}
