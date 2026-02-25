import { Component, inject, signal, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ApiService } from '../../services/api.service';

@Component({
  selector: 'app-rules',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div class="rules-header animate-fade-in">
      <div>
        <h2>Correlation Rule Set</h2>
        <p>Edit and deploy rule updates without restarting the service.</p>
      </div>
      <div class="rules-actions">
        @if (rulesPath()) {
          <span class="pill">{{ rulesPath() }}</span>
        }
        <button class="btn btn-ghost btn-sm" (click)="loadRules()">↻ Reload</button>
        <button class="btn btn-ghost btn-sm" (click)="formatRules()">Format JSON</button>
        <button class="btn btn-primary btn-sm" (click)="saveRules()">Save Rules</button>
      </div>
    </div>

    <div class="rules-grid">
      <div class="editor-card">
        <textarea
          class="rules-textarea"
          [(ngModel)]="rulesText"
          spellcheck="false"
          placeholder="Loading rules..."
        ></textarea>
        <div
          class="rules-status"
          [class.error]="statusError()"
        >
          {{ statusMessage() }}
        </div>
      </div>

      <div class="guide-card">
        <h3>Guidance</h3>
        <ul>
          <li>Keep rules as a JSON array or &#123; "rules": [] &#125;.</li>
          <li>Use <strong>match</strong>, <strong>group_by</strong>, and <strong>threshold</strong> to define correlation logic.</li>
          <li>Save to push updates to the correlation engine immediately.</li>
          <li>Changes take effect without restarting the service.</li>
        </ul>

        <h3 style="margin-top: 24px;">Rule Structure</h3>
        <div class="rule-example">
          <pre [innerText]="exampleRule"></pre>
        </div>
      </div>
    </div>
  `,
  styles: [`
    :host { display: block; }
    .rules-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 24px;
      flex-wrap: wrap;
      gap: 16px;
    }
    .rules-header h2 {
      font-size: 20px;
      margin-bottom: 4px;
    }
    .rules-actions {
      display: flex;
      gap: 10px;
      align-items: center;
      flex-wrap: wrap;
    }
    .rules-grid {
      display: grid;
      grid-template-columns: minmax(400px, 2fr) minmax(260px, 1fr);
      gap: 20px;
    }
    @media (max-width: 900px) {
      .rules-grid {
        grid-template-columns: 1fr;
      }
    }
    .editor-card {
      padding: 22px;
      border-radius: var(--radius-lg);
      background: var(--bg-surface);
      border: 1px solid var(--border);
    }
    .rules-textarea {
      width: 100%;
      min-height: 480px;
      padding: 16px;
      border-radius: var(--radius-md);
      border: 1px solid var(--border);
      background: var(--bg-input);
      color: var(--text);
      font-family: 'JetBrains Mono', 'SFMono-Regular', 'Consolas', monospace;
      font-size: 13px;
      line-height: 1.7;
      resize: vertical;
      outline: none;
      transition: border-color 0.2s;
    }
    .rules-textarea:focus {
      border-color: var(--cyan);
    }
    .rules-status {
      margin-top: 16px;
      padding: 10px 16px;
      border-radius: var(--radius-sm);
      background: var(--bg-elevated);
      border: 1px solid var(--border);
      font-size: 13px;
      color: var(--text-secondary);
    }
    .rules-status.error {
      color: var(--red);
      border-color: rgba(239, 68, 68, 0.3);
      background: rgba(239, 68, 68, 0.05);
    }
    .guide-card {
      padding: 22px;
      border-radius: var(--radius-lg);
      background: var(--bg-surface);
      border: 1px solid var(--border);
    }
    .guide-card h3 {
      font-size: 16px;
      margin-bottom: 16px;
    }
    .guide-card ul {
      padding-left: 20px;
      color: var(--text-secondary);
      font-size: 14px;
      line-height: 1.8;
    }
    .guide-card strong { color: var(--text); }
    .guide-card code {
      padding: 2px 6px;
      background: var(--bg-elevated);
      border-radius: 4px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
      color: var(--cyan);
    }
    .rule-example {
      margin-top: 12px;
      padding: 14px;
      border-radius: var(--radius-sm);
      background: var(--bg-input);
      border: 1px solid var(--border);
      overflow-x: auto;
    }
    .rule-example pre {
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px;
      line-height: 1.6;
      color: var(--text-secondary);
      white-space: pre-wrap;
      margin: 0;
    }
  `],
})
export class RulesComponent implements OnInit {
  private api = inject(ApiService);

  rulesText = '';
  rulesPath = signal('');
  statusMessage = signal('Ready');
  statusError = signal(false);

  exampleRule = `{
  "name": "Port Scan Detection",
  "match": {
    "alert.category": "Attempted Information Leak"
  },
  "group_by": ["source.ip"],
  "threshold": 10,
  "window_minutes": 5,
  "priority": "high"
}`;

  ngOnInit(): void {
    this.loadRules();
  }

  loadRules(): void {
    this.api.getRules().subscribe({
      next: data => {
        this.rulesText = data.raw || '';
        this.rulesPath.set(data.path || '');
        this.setStatus('Rules loaded successfully.', false);
      },
      error: () => this.setStatus('Failed to load rules.', true),
    });
  }

  formatRules(): void {
    try {
      const parsed = JSON.parse(this.rulesText || '[]');
      this.rulesText = JSON.stringify(parsed, null, 2);
      this.setStatus('Formatted JSON successfully.', false);
    } catch {
      this.setStatus('Invalid JSON. Cannot format.', true);
    }
  }

  saveRules(): void {
    this.setStatus('Saving…', false);
    this.api.saveRules(this.rulesText).subscribe({
      next: data => {
        if (data.status === 'updated') {
          this.setStatus('Rules saved and correlation engine reloaded.', false);
        } else {
          this.setStatus(data.message || 'Failed to save.', true);
        }
      },
      error: err =>
        this.setStatus(err.error?.message || 'Failed to save rules.', true),
    });
  }

  private setStatus(msg: string, isError: boolean): void {
    this.statusMessage.set(msg);
    this.statusError.set(isError);
  }
}
