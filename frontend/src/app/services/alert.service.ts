import { Injectable, inject, signal, NgZone } from '@angular/core';
import { AuthService } from './auth.service';

@Injectable({ providedIn: 'root' })
export class AlertService {
  private ngZone = inject(NgZone);
  private authService = inject(AuthService);

  private _alerts = signal<any[]>([]);
  private _count = signal<number>(0);
  private lastAlertId = 0;
  private controller: AbortController | null = null;
  private retryTimeout: any = null;
  private running = false;

  readonly alerts = this._alerts.asReadonly();
  readonly count = this._count.asReadonly();

  startStream(): void {
    if (this.running) return;
    this.running = true;
    this.connectStream();
  }

  stopStream(): void {
    this.running = false;
    if (this.controller) {
      this.controller.abort();
      this.controller = null;
    }
    if (this.retryTimeout) {
      clearTimeout(this.retryTimeout);
      this.retryTimeout = null;
    }
  }

  clearAlerts(): void {
    this._alerts.set([]);
    this._count.set(0);
    this.lastAlertId = 0;
  }

  private connectStream(): void {
    if (!this.running) return;

    const token = this.authService.getAccessToken();
    if (!token) {
      this.scheduleRetry();
      return;
    }

    const controller = new AbortController();
    this.controller = controller;
    const url = `/api/alerts/stream?since=${this.lastAlertId}&token=${encodeURIComponent(token)}`;

    fetch(url, {
      signal: controller.signal,
      headers: { 'Cache-Control': 'no-cache' },
    })
      .then(async response => {
        if (!response.ok || !response.body) {
          throw new Error(`Stream response ${response.status}`);
        }

        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';

        while (true) {
          const { value, done } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          const chunks = buffer.split('\n\n');
          buffer = chunks.pop() || '';
          for (const chunk of chunks) {
            this.handleChunk(chunk);
          }
        }
      })
      .catch(() => {
        /* ignored — will retry */
      })
      .finally(() => {
        if (this.controller === controller) {
          this.controller = null;
        }
        this.scheduleRetry();
      });
  }

  private scheduleRetry(): void {
    if (!this.running || this.retryTimeout) return;
    this.retryTimeout = setTimeout(() => {
      this.retryTimeout = null;
      this.connectStream();
    }, 3000);
  }

  private handleChunk(chunk: string): void {
    const lines = chunk.split('\n');
    let data = '';
    let id: string | null = null;

    for (const line of lines) {
      if (line.startsWith(':')) continue;
      if (line.startsWith('data:')) {
        data += line.slice(5).trimStart();
      } else if (line.startsWith('id:')) {
        id = line.slice(3).trim();
      }
    }

    if (!data) return;

    try {
      const alert = JSON.parse(data);
      const eventId = Number(id) || alert.id || 0;
      this.lastAlertId = Math.max(this.lastAlertId, eventId);

      this.ngZone.run(() => {
        this._alerts.update(alerts => {
          const updated = [alert, ...alerts];
          return updated.length > 500 ? updated.slice(0, 500) : updated;
        });
        this._count.update(c => c + 1);
      });
    } catch {
      /* ignore malformed payloads */
    }
  }
}
