import { Injectable, signal, computed, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Router } from '@angular/router';
import { Observable, tap, catchError, of, finalize, shareReplay } from 'rxjs';

export interface AuthTokens {
  access_token: string;
  refresh_token: string;
}

export interface UserInfo {
  user_id: string;
  role: string;
  username?: string;
  email?: string;
}

@Injectable({ providedIn: 'root' })
export class AuthService {
  private http = inject(HttpClient);
  private router = inject(Router);

  private accessToken = signal<string | null>(null);
  private refreshTokenValue = signal<string | null>(
    sessionStorage.getItem('heimdall_refresh_token')
  );
  private currentUser = signal<UserInfo | null>(null);
  private refreshInFlight$: Observable<AuthTokens | null> | null = null;

  readonly isAuthenticated = computed(() => !!this.accessToken());
  readonly user = computed(() => this.currentUser());
  readonly userLabel = computed(() => {
    const u = this.currentUser();
    if (!u) return 'Signed out';
    const name = u.username || u.email || u.user_id || 'User';
    return u.role ? `${name} • ${u.role}` : name;
  });

  getAccessToken(): string | null {
    return this.accessToken();
  }

  getRefreshToken(): string | null {
    return this.refreshTokenValue();
  }

  login(username: string, password: string): Observable<AuthTokens> {
    return this.http
      .post<AuthTokens>('/api/auth/login', { username, password })
      .pipe(
        tap(tokens => {
          this.accessToken.set(tokens.access_token);
          this.refreshTokenValue.set(tokens.refresh_token);
          sessionStorage.setItem('heimdall_refresh_token', tokens.refresh_token);
        })
      );
  }

  loadCurrentUser(): Observable<UserInfo> {
    return this.http.get<UserInfo>('/api/auth/me').pipe(
      tap(user => this.currentUser.set(user))
    );
  }

  logout(): void {
    const rt = this.refreshTokenValue();
    if (rt) {
      this.http
        .post('/api/auth/logout', { refresh_token: rt })
        .subscribe({ error: () => {} });
    }
    this.accessToken.set(null);
    this.refreshTokenValue.set(null);
    this.currentUser.set(null);
    sessionStorage.removeItem('heimdall_refresh_token');
    this.router.navigate(['/login']);
  }

  refreshAccessToken(): Observable<AuthTokens | null> {
    if (this.refreshInFlight$) {
      return this.refreshInFlight$;
    }

    const rt = this.refreshTokenValue();
    if (!rt) return of(null);

    this.refreshInFlight$ = this.http
      .post<AuthTokens>('/api/auth/refresh', { refresh_token: rt })
      .pipe(
        tap(tokens => {
          this.accessToken.set(tokens.access_token);
          this.refreshTokenValue.set(tokens.refresh_token);
          sessionStorage.setItem('heimdall_refresh_token', tokens.refresh_token);
        }),
        catchError(() => {
          this.performLogout();
          return of(null);
        }),
        finalize(() => {
          this.refreshInFlight$ = null;
        }),
        shareReplay(1)
      );

    return this.refreshInFlight$;
  }

  tryRestoreSession(): Observable<boolean> {
    const rt = this.refreshTokenValue();
    if (!rt) return of(false);

    return new Observable(observer => {
      this.refreshAccessToken().subscribe({
        next: tokens => {
          if (tokens) {
            this.loadCurrentUser().subscribe({
              next: () => {
                observer.next(true);
                observer.complete();
              },
              error: () => {
                observer.next(true);
                observer.complete();
              },
            });
          } else {
            observer.next(false);
            observer.complete();
          }
        },
        error: () => {
          observer.next(false);
          observer.complete();
        },
      });
    });
  }

  private performLogout(): void {
    this.accessToken.set(null);
    this.refreshTokenValue.set(null);
    this.currentUser.set(null);
    sessionStorage.removeItem('heimdall_refresh_token');
    this.router.navigate(['/login']);
  }
}
