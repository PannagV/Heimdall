import { Component, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { AuthService } from '../../services/auth.service';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div class="login-page">
      <div class="login-card animate-fade-in">
        <div class="login-brand">
          <img class="brand-shield" src="/hsoclogo.png" alt="Heimdall" />
          <p class="brand-tagline">Security Telemetry Console</p>
        </div>
        <div class="login-panel">
          <h2>Sign in</h2>
          <p class="login-subtitle">Access dashboards and incident response workflows.</p>
          <form (ngSubmit)="onLogin()">
            <div class="field">
              <label for="username">Username or email</label>
              <input
                id="username"
                type="text"
                [(ngModel)]="username"
                name="username"
                autocomplete="username"
                placeholder="Enter your username"
              />
            </div>
            <div class="field" style="margin-top: 16px">
              <label for="password">Password</label>
              <input
                id="password"
                type="password"
                [(ngModel)]="password"
                name="password"
                autocomplete="current-password"
                placeholder="Enter your password"
              />
            </div>
            <div class="auth-actions">
              <button
                type="submit"
                class="btn btn-primary btn-full"
                [disabled]="loading()"
              >
                {{ loading() ? 'Signing in…' : 'Sign In' }}
              </button>
            </div>
            @if (error()) {
              <div class="auth-error animate-fade-in">{{ error() }}</div>
            }
          </form>
        </div>
      </div>
    </div>
  `,
  styles: [`
    .login-page {
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 40px 20px;
      background:
        radial-gradient(circle at top left, rgba(110, 231, 255, 0.12), transparent 40%),
        radial-gradient(circle at bottom right, rgba(168, 85, 247, 0.16), transparent 35%),
        #0d0d0d;
    }
    .login-card {
      width: min(520px, 94vw);
      padding: 36px 36px 32px;
      border-radius: var(--radius-xl);
      background: #000;
      border: 1px solid var(--border);
      box-shadow: var(--shadow-lg);
    }
    .login-brand {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      text-align: center;
      margin-bottom: 12px;
    }
    .brand-shield {
      width: min(220px, 70%);
      max-height: 160px;
      object-fit: contain;
      display: block;
      margin: 0 auto;
    }
    .brand-tagline {
      margin: 2px 0 0;
      color: var(--text-secondary);
      font-size: 15px;
    }
    .login-panel {
      background: var(--bg-surface);
      border-radius: var(--radius-lg);
      border: 1px solid var(--border);
      padding: 36px;
    }
    .login-panel h2 {
      font-size: 24px;
      margin-bottom: 8px;
    }
    .login-subtitle {
      font-size: 14px;
      margin-bottom: 28px !important;
    }
    .auth-actions {
      margin-top: 28px;
    }
    .auth-error {
      margin-top: 16px;
      padding: 10px 14px;
      border-radius: var(--radius-sm);
      background: rgba(239, 68, 68, 0.1);
      color: var(--red);
      font-size: 13px;
      border: 1px solid rgba(239, 68, 68, 0.2);
    }
  `],
})
export class LoginComponent {
  private auth = inject(AuthService);
  private router = inject(Router);

  username = '';
  password = '';
  error = signal('');
  loading = signal(false);

  onLogin(): void {
    if (!this.username.trim() || !this.password) {
      this.error.set('Enter your username and password.');
      return;
    }
    this.loading.set(true);
    this.error.set('');

    this.auth.login(this.username.trim(), this.password).subscribe({
      next: () => {
        this.auth.loadCurrentUser().subscribe({
          next: () => this.router.navigate(['/']),
          error: () => this.router.navigate(['/']),
        });
      },
      error: err => {
        this.loading.set(false);
        this.error.set(err.error?.message || 'Login failed. Try again.');
      },
    });
  }
}
