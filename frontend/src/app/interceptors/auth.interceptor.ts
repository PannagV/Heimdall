import { inject } from '@angular/core';
import {
  HttpInterceptorFn,
  HttpErrorResponse,
} from '@angular/common/http';
import { catchError, switchMap, throwError } from 'rxjs';
import { AuthService } from '../services/auth.service';

export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const authService = inject(AuthService);

  // Skip auth endpoints — they handle tokens themselves
  if (req.url.includes('/api/auth/')) {
    return next(req);
  }

  const token = authService.getAccessToken();
  const authReq = token
    ? req.clone({ setHeaders: { Authorization: `Bearer ${token}` } })
    : req;

  return next(authReq).pipe(
    catchError((error: HttpErrorResponse) => {
      if (error.status === 401 && authService.getRefreshToken()) {
        return authService.refreshAccessToken().pipe(
          switchMap(result => {
            if (result) {
              const retryReq = req.clone({
                setHeaders: {
                  Authorization: `Bearer ${result.access_token}`,
                },
              });
              return next(retryReq);
            }
            return throwError(() => error);
          })
        );
      }
      return throwError(() => error);
    })
  );
};
