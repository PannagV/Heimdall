import { Routes } from '@angular/router';
import { authGuard } from './guards/auth.guard';

export const routes: Routes = [
  {
    path: 'login',
    loadComponent: () =>
      import('./pages/login/login.component').then(m => m.LoginComponent),
  },
  {
    path: '',
    loadComponent: () =>
      import('./pages/layout/layout.component').then(m => m.LayoutComponent),
    canActivate: [authGuard],
    children: [
      { path: '', redirectTo: 'dashboard', pathMatch: 'full' },
      {
        path: 'dashboard',
        loadComponent: () =>
          import('./pages/dashboard/dashboard.component').then(m => m.DashboardComponent),
      },
      {
        path: 'monitor',
        loadComponent: () =>
          import('./pages/monitor/monitor.component').then(m => m.MonitorComponent),
      },
      {
        path: 'events',
        loadComponent: () =>
          import('./pages/events/events.component').then(m => m.EventsComponent),
      },
      {
        path: 'rules',
        loadComponent: () =>
          import('./pages/rules/rules.component').then(m => m.RulesComponent),
      },
      {
        path: 'copilot',
        loadComponent: () =>
          import('./pages/copilot/copilot.component').then(m => m.AiCopilotComponent),
      },
    ],
  },
  { path: '**', redirectTo: '' },
];
