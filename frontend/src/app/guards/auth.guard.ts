import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { map } from 'rxjs';
import { AuthService } from '../services/auth.service';

export const authGuard: CanActivateFn = () => {
  const authService = inject(AuthService);
  const router = inject(Router);

  if (authService.isAuthenticated()) {
    return true;
  }

  // Try to restore session from stored refresh token
  return authService.tryRestoreSession().pipe(
    map(restored => {
      if (restored) return true;
      router.navigate(['/login']);
      return false;
    })
  );
};
