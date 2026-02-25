import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

@Injectable({ providedIn: 'root' })
export class ApiService {
  private http = inject(HttpClient);

  /* ── Suricata control ── */

  getStatus(): Observable<{ running: boolean; log_type: string }> {
    return this.http.get<{ running: boolean; log_type: string }>('/api/status');
  }

  getInterfaces(): Observable<{ interfaces: string[] }> {
    return this.http.get<{ interfaces: string[] }>('/api/interfaces');
  }

  startSuricata(payload: {
    iface: string;
    config: string;
    log_type: string;
  }): Observable<any> {
    return this.http.post('/api/start', payload);
  }

  stopSuricata(): Observable<any> {
    return this.http.post('/api/stop', {});
  }

  /* ── Alerts ── */

  getAlerts(since: number): Observable<{ alerts: any[]; latest_id: number }> {
    return this.http.get<{ alerts: any[]; latest_id: number }>(
      `/api/alerts?since=${since}`
    );
  }

  clearAlerts(): Observable<any> {
    return this.http.post('/api/clear', {});
  }

  /* ── Metrics ── */

  getMetrics(): Observable<any> {
    return this.http.get('/api/metrics');
  }

  /* ── Events & Incidents ── */

  getEvents(limit = 200): Observable<{ events: any[] }> {
    return this.http.get<{ events: any[] }>(`/api/events?limit=${limit}`);
  }

  getIncidents(
    limit = 200,
    status?: string
  ): Observable<{ incidents: any[] }> {
    let url = `/api/incidents?limit=${limit}`;
    if (status) url += `&status=${status}`;
    return this.http.get<{ incidents: any[] }>(url);
  }

  closeIncident(id: string): Observable<any> {
    return this.http.post(`/api/incidents/${id}/close`, {});
  }

  /* ── Correlation rules ── */

  getRules(): Observable<{ path: string; raw: string; rules: any[] }> {
    return this.http.get<{ path: string; raw: string; rules: any[] }>(
      '/api/rules'
    );
  }

  saveRules(raw: string): Observable<any> {
    return this.http.put('/api/rules', { raw });
  }

  /* ── Health ── */

  getHealth(): Observable<{ status: string }> {
    return this.http.get<{ status: string }>('/api/health');
  }
}
