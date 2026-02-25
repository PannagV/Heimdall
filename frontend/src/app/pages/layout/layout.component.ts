import { Component, inject, signal, OnInit, OnDestroy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterOutlet, RouterLink, RouterLinkActive, Router, NavigationEnd } from '@angular/router';
import { filter } from 'rxjs';
import { AuthService } from '../../services/auth.service';
import { ApiService } from '../../services/api.service';

@Component({
  selector: 'app-layout',
  standalone: true,
  imports: [CommonModule, RouterOutlet, RouterLink, RouterLinkActive],
  template: `
    <div class="app-shell">
      <aside class="sidebar">
        <div class="brand">
          <div class="brand-title">
            <span class="brand-icon"><img src="/icon.png" alt="Heimdall" /></span>
            <h1>Heimdall</h1>
          </div>
          <p>Security Telemetry Console</p>
        </div>
        <nav class="nav">
          <a routerLink="/dashboard" routerLinkActive="active" class="nav-item">
            <span class="nav-icon"></span>
            <span>Dashboard</span>
          </a>
          <a routerLink="/monitor" routerLinkActive="active" class="nav-item">
            <span class="nav-icon"></span>
            <span>Live IDS Monitor</span>
          </a>
          <a routerLink="/events" routerLinkActive="active" class="nav-item">
            <span class="nav-icon"></span>
            <span>Events &amp; Incidents</span>
          </a>
          <a routerLink="/rules" routerLinkActive="active" class="nav-item">
            <span class="nav-icon"></span>
            <span>Correlation Rules</span>
          </a>
          <a routerLink="/copilot" routerLinkActive="active" class="nav-item">
            <span class="nav-icon"></span>
            <span>AI Copilot</span>
          </a>
        </nav>
        <div class="sidebar-footer">
          <div class="version-badge">Heimdall v1.0</div>
        </div>
      </aside>

      <main class="main-content">
        <header class="topbar">
          <div class="topbar-info">
            <h2>{{ pageTitle() }}</h2>
            <p>{{ pageSubtitle() }}</p>
          </div>
          <div class="topbar-actions">
            <div
              class="status-badge"
              [class.running]="status()?.running"
              [class.stopped]="!status()?.running"
            >
              <span class="status-dot"></span>
              {{ status()?.running ? 'Running (' + status()?.log_type + ')' : 'Stopped' }}
            </div>
            <div class="user-chip">{{ auth.userLabel() }}</div>
            <button class="btn btn-ghost btn-sm" (click)="onLogout()">Log out</button>
          </div>
        </header>
        <div class="page-content">
          <router-outlet />
        </div>
      </main>
    </div>
  `,
  styles: [`
    .app-shell {
      display: flex;
      height: 100vh;
      overflow: hidden;
    }
    .sidebar {
      width: 270px;
      min-width: 270px;
      padding: 28px 20px;
      border-right: 1px solid var(--border);
      background: linear-gradient(180deg, #050505 0%, #111 100%);
      display: flex;
      flex-direction: column;
      gap: 32px;
      overflow-y: auto;
    }
    .brand h1 {
      font-size: 22px;
      margin: 0;
    }
    .brand {
      width: 100%;
    }
    .brand-title {
      display: flex;
      align-items: center;
      gap: 10px;
      justify-content: center;
    }
    .brand-icon {
      width: 24px;
      height: 24px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
    }
    .brand-icon img {
      width: 100%;
      height: 100%;
      object-fit: contain;
      display: block;
    }
    .brand p {
      font-size: 13px;
      color: var(--text-secondary);
      margin-top: 4px;
      text-align: center;
    }
    .nav {
      display: flex;
      flex-direction: column;
      gap: 6px;
    }
    .nav-item {
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 12px 16px;
      border-radius: var(--radius-sm);
      border: 1px solid transparent;
      background: transparent;
      color: var(--text-secondary);
      font-weight: 600;
      font-size: 14px;
      text-decoration: none;
      transition: all 0.2s;
      cursor: pointer;
    }
    .nav-item:hover {
      background: var(--bg-hover);
      border-color: var(--border);
      color: var(--text);
      text-decoration: none;
    }
    .nav-item.active {
      background: var(--gradient);
      color: #000;
      border-color: transparent;
    }
    .nav-icon {
      font-size: 16px;
      width: 20px;
      text-align: center;
    }
    .sidebar-footer {
      margin-top: auto;
      padding-top: 16px;
      border-top: 1px solid var(--border);
    }
    .version-badge {
      font-size: 11px;
      color: var(--text-muted);
      text-align: center;
    }
    .main-content {
      flex: 1;
      display: flex;
      flex-direction: column;
      overflow: hidden;
    }
    .topbar {
      padding: 20px 32px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 24px;
      border-bottom: 1px solid var(--border);
      background: var(--bg-base);
      flex-shrink: 0;
    }
    .topbar-info h2 {
      font-size: 22px;
      margin-bottom: 4px;
    }
    .topbar-info p {
      font-size: 13px;
      margin: 0;
    }
    .topbar-actions {
      display: flex;
      align-items: center;
      gap: 12px;
      flex-wrap: wrap;
      justify-content: flex-end;
    }
    .status-badge {
      padding: 8px 16px;
      border-radius: var(--radius-full);
      font-weight: 600;
      font-size: 13px;
      border: 1px solid var(--border);
      background: var(--bg-elevated);
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .status-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: var(--text-muted);
    }
    .status-badge.running {
      background: rgba(34, 197, 94, 0.1);
      color: var(--green);
      border-color: rgba(34, 197, 94, 0.3);
    }
    .status-badge.running .status-dot {
      background: var(--green);
      box-shadow: 0 0 6px var(--green);
    }
    .status-badge.stopped {
      background: rgba(239, 68, 68, 0.1);
      color: var(--red);
      border-color: rgba(239, 68, 68, 0.3);
    }
    .status-badge.stopped .status-dot {
      background: var(--red);
    }
    .user-chip {
      padding: 8px 14px;
      border-radius: var(--radius-full);
      background: var(--bg-elevated);
      border: 1px solid var(--border);
      color: var(--text-secondary);
      font-size: 13px;
      font-weight: 500;
    }
    .page-content {
      flex: 1;
      overflow-y: auto;
      padding: 28px 32px 60px;
    }
  `],
})
export class LayoutComponent implements OnInit, OnDestroy {
  auth = inject(AuthService);
  private api = inject(ApiService);
  private router = inject(Router);

  status = signal<{ running: boolean; log_type: string } | null>(null);
  pageTitle = signal('Alert Dashboard');
  pageSubtitle = signal('Metrics from stored security alerts');

  private statusInterval: any;

  private pageMeta: Record<string, { title: string; subtitle: string }> = {
    '/dashboard': {
      title: 'Alert Dashboard',
      subtitle: 'Metrics from stored security alerts',
    },
    '/monitor': {
      title: 'Heimdall IDS Monitor',
      subtitle: 'Live alerts from Suricata fast.log or eve.json',
    },
    '/events': {
      title: 'Events & Incidents',
      subtitle: 'Inspect normalized events and manage active incidents',
    },
    '/rules': {
      title: 'Correlation Rules',
      subtitle: 'Review and update correlation rules in real time',
    },
    '/copilot': {
      title: 'AI SOC Copilot',
      subtitle: 'AI-powered threat assessment and MITRE ATT&CK mapping',
    },
  };

  ngOnInit(): void {
    this.fetchStatus();
    this.statusInterval = setInterval(() => this.fetchStatus(), 5000);

    this.router.events
      .pipe(filter((e): e is NavigationEnd => e instanceof NavigationEnd))
      .subscribe(e => {
        const url = e.urlAfterRedirects || e.url;
        const meta = this.pageMeta[url] || this.pageMeta['/dashboard'];
        this.pageTitle.set(meta.title);
        this.pageSubtitle.set(meta.subtitle);
      });

    // Set initial page meta
    const url = this.router.url;
    const meta = this.pageMeta[url] || this.pageMeta['/dashboard'];
    this.pageTitle.set(meta.title);
    this.pageSubtitle.set(meta.subtitle);
  }

  ngOnDestroy(): void {
    clearInterval(this.statusInterval);
  }

  onLogout(): void {
    this.auth.logout();
  }

  private fetchStatus(): void {
    this.api.getStatus().subscribe({
      next: data => this.status.set(data),
      error: () => {},
    });
  }
}
