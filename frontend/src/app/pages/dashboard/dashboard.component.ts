import {
  Component,
  inject,
  signal,
  OnInit,
  OnDestroy,
  AfterViewInit,
  ViewChild,
  ElementRef,
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { ApiService } from '../../services/api.service';
import { Chart, registerables } from 'chart.js';

Chart.register(...registerables);

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [CommonModule],
  template: `
    <!-- Metric Cards -->
    <section class="metrics-grid animate-fade-in">
      <div class="metric-card">
        <div class="metric-label">Total Alerts</div>
        <div class="metric-value">{{ metrics().total ?? 0 }}</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Last 24 Hours</div>
        <div class="metric-value">{{ metrics().last_24h ?? 0 }}</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Critical Priority</div>
        <div class="metric-value critical">{{ metrics().critical ?? 0 }}</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Top Classification</div>
        <div class="metric-value text-val">{{ metrics().top_classification || '—' }}</div>
      </div>
    </section>

    <!-- Charts -->
    <section class="charts-grid">
      <div class="chart-card">
        <h3>Priority Distribution</h3>
        <canvas #priorityCanvas></canvas>
      </div>
      <div class="chart-card">
        <h3>Top Classifications</h3>
        <canvas #classificationCanvas></canvas>
      </div>
      <div class="chart-card">
        <h3>Alerts by Hour (24h)</h3>
        <canvas #hourlyCanvas></canvas>
      </div>
    </section>

    <!-- Lists -->
    <section class="lists-grid">
      <div class="list-card">
        <h3>Priority Distribution</h3>
        <ul class="metric-list">
          @for (item of metrics().by_priority || []; track item.label) {
            <li>
              <span>{{ item.label || 'Unknown' }}</span>
              <span>{{ item.count ?? 0 }}</span>
            </li>
          } @empty {
            <li class="empty-item">No data yet</li>
          }
        </ul>
      </div>
      <div class="list-card">
        <h3>Top Classifications</h3>
        <ul class="metric-list">
          @for (item of metrics().by_classification || []; track item.label) {
            <li>
              <span>{{ item.label || 'Unknown' }}</span>
              <span>{{ item.count ?? 0 }}</span>
            </li>
          } @empty {
            <li class="empty-item">No data yet</li>
          }
        </ul>
      </div>
      <div class="list-card">
        <h3>Protocol Mix</h3>
        <ul class="metric-list">
          @for (item of metrics().by_protocol || []; track item.label) {
            <li>
              <span>{{ item.label || 'Unknown' }}</span>
              <span>{{ item.count ?? 0 }}</span>
            </li>
          } @empty {
            <li class="empty-item">No data yet</li>
          }
        </ul>
      </div>
      <div class="list-card">
        <h3>Top Signatures</h3>
        <ul class="metric-list">
          @for (item of metrics().top_signatures || []; track item.label) {
            <li>
              <span>{{ item.label || 'Unknown' }}</span>
              <span>{{ item.count ?? 0 }}</span>
            </li>
          } @empty {
            <li class="empty-item">No data yet</li>
          }
        </ul>
      </div>
    </section>
  `,
  styles: [`
    :host {
      display: block;
    }
    .metrics-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 16px;
      margin-bottom: 28px;
    }
    .metric-card {
      padding: 22px;
      border-radius: var(--radius-lg);
      background: var(--gradient-subtle);
      border: 1px solid var(--border);
      transition: border-color 0.2s;
    }
    .metric-card:hover {
      border-color: var(--border-hover);
    }
    .metric-label {
      font-size: 12px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--text-secondary);
    }
    .metric-value {
      font-size: 32px;
      font-weight: 700;
      margin-top: 8px;
    }
    .metric-value.critical {
      color: var(--red);
    }
    .metric-value.text-val {
      font-size: 18px;
      word-break: break-word;
    }
    .charts-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      gap: 16px;
      margin-bottom: 28px;
    }
    .chart-card {
      padding: 22px;
      border-radius: var(--radius-lg);
      background: linear-gradient(180deg, rgba(20, 20, 20, 0.95) 0%, rgba(12, 12, 12, 0.95) 100%);
      border: 1px solid var(--border);
      box-shadow: inset 0 0 0 1px rgba(110, 231, 255, 0.05), 0 8px 26px rgba(0, 0, 0, 0.25);
      transition: transform 0.2s ease, border-color 0.2s ease;
    }
    .chart-card:hover {
      transform: translateY(-2px);
      border-color: var(--border-hover);
    }
    .chart-card h3 {
      font-size: 15px;
      margin-bottom: 16px;
      color: #f3f3f3;
      letter-spacing: 0.01em;
    }
    .chart-card canvas {
      width: 100% !important;
      height: 240px !important;
    }
    .lists-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 16px;
    }
    .list-card {
      padding: 22px;
      border-radius: var(--radius-lg);
      background: var(--bg-surface);
      border: 1px solid var(--border);
    }
    .list-card h3 {
      font-size: 15px;
      margin-bottom: 16px;
    }
    .metric-list {
      list-style: none;
      display: grid;
      gap: 8px;
    }
    .metric-list li {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      padding-bottom: 8px;
      border-bottom: 1px dashed var(--border);
      font-size: 13px;
      color: var(--text-secondary);
    }
    .metric-list li span:last-child {
      color: var(--text);
      font-weight: 600;
    }
    .empty-item {
      color: var(--text-muted) !important;
      font-style: italic;
    }
  `],
})
export class DashboardComponent implements OnInit, OnDestroy, AfterViewInit {
  private api = inject(ApiService);

  metrics = signal<any>({});

  @ViewChild('priorityCanvas') priorityCanvas!: ElementRef<HTMLCanvasElement>;
  @ViewChild('classificationCanvas') classificationCanvas!: ElementRef<HTMLCanvasElement>;
  @ViewChild('hourlyCanvas') hourlyCanvas!: ElementRef<HTMLCanvasElement>;

  private priorityChart: Chart | null = null;
  private classificationChart: Chart | null = null;
  private hourlyChart: Chart | null = null;
  private interval: any;

  private readonly palette = ['#6ee7ff', '#a855f7', '#f97316', '#22c55e', '#facc15'];

  ngOnInit(): void {
    this.fetchMetrics();
    this.interval = setInterval(() => this.fetchMetrics(), 5000);
  }

  ngAfterViewInit(): void {
    this.initCharts();
  }

  ngOnDestroy(): void {
    clearInterval(this.interval);
    this.priorityChart?.destroy();
    this.classificationChart?.destroy();
    this.hourlyChart?.destroy();
  }

  private fetchMetrics(): void {
    this.api.getMetrics().subscribe({
      next: data => {
        this.metrics.set(data);
        this.updateCharts(data);
      },
      error: () => {},
    });
  }

  private initCharts(): void {
    // Priority pie chart
    if (this.priorityCanvas) {
      this.priorityChart = new Chart(this.priorityCanvas.nativeElement, {
        type: 'doughnut',
        data: {
          labels: [],
          datasets: [{
            data: [],
            backgroundColor: this.palette,
            borderColor: '#0f0f0f',
            borderWidth: 3,
            hoverOffset: 8,
            spacing: 2,
          }],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          cutout: '68%',
          animation: {
            animateRotate: true,
            animateScale: true,
            duration: 700,
          },
          plugins: {
            legend: {
              position: 'bottom',
              labels: {
                color: '#d6d6d6',
                padding: 16,
                usePointStyle: true,
                pointStyle: 'circle',
                boxWidth: 10,
                boxHeight: 10,
                font: { family: 'Space Grotesk', size: 12 },
              },
            },
            tooltip: {
              backgroundColor: 'rgba(14, 14, 14, 0.95)',
              borderColor: 'rgba(110, 231, 255, 0.25)',
              borderWidth: 1,
              padding: 10,
              displayColors: true,
              titleColor: '#ffffff',
              bodyColor: '#d8d8d8',
            },
          },
        },
      });
    }

    // Classification bar chart
    if (this.classificationCanvas) {
      const barCtx = this.classificationCanvas.nativeElement.getContext('2d');
      const barGradient = barCtx
        ? (() => {
            const gradient = barCtx.createLinearGradient(0, 0, 0, 240);
            gradient.addColorStop(0, 'rgba(168, 85, 247, 0.95)');
            gradient.addColorStop(1, 'rgba(110, 231, 255, 0.55)');
            return gradient;
          })()
        : '#a855f7';

      this.classificationChart = new Chart(this.classificationCanvas.nativeElement, {
        type: 'bar',
        data: {
          labels: [],
          datasets: [{
            label: 'Alerts',
            data: [],
            backgroundColor: barGradient,
            borderColor: 'rgba(110, 231, 255, 0.9)',
            borderWidth: 1.2,
            borderRadius: 10,
            borderSkipped: false,
            maxBarThickness: 28,
          }],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          scales: {
            x: {
              ticks: { color: '#9ca3af', font: { family: 'Space Grotesk' } },
              grid: { display: false },
              border: { display: false },
            },
            y: {
              ticks: { color: '#9ca3af', font: { family: 'Space Grotesk' } },
              grid: { color: 'rgba(255,255,255,0.06)' },
              border: { display: false },
            },
          },
          plugins: {
            legend: { display: false },
            tooltip: {
              backgroundColor: 'rgba(14, 14, 14, 0.95)',
              borderColor: 'rgba(168, 85, 247, 0.35)',
              borderWidth: 1,
              padding: 10,
              titleColor: '#ffffff',
              bodyColor: '#d8d8d8',
            },
          },
        },
      });
    }

    // Hourly line chart
    if (this.hourlyCanvas) {
      const lineCtx = this.hourlyCanvas.nativeElement.getContext('2d');
      const lineFill = lineCtx
        ? (() => {
            const gradient = lineCtx.createLinearGradient(0, 0, 0, 260);
            gradient.addColorStop(0, 'rgba(110, 231, 255, 0.35)');
            gradient.addColorStop(1, 'rgba(110, 231, 255, 0.02)');
            return gradient;
          })()
        : 'rgba(110, 231, 255, 0.15)';

      this.hourlyChart = new Chart(this.hourlyCanvas.nativeElement, {
        type: 'line',
        data: {
          labels: [],
          datasets: [{
            label: 'Alerts per hour',
            data: [],
            borderColor: '#6ee7ff',
            backgroundColor: lineFill,
            borderWidth: 2.5,
            tension: 0.42,
            fill: true,
            pointRadius: 2.5,
            pointHoverRadius: 5,
            pointBackgroundColor: '#6ee7ff',
            pointBorderColor: '#0d0d0d',
            pointBorderWidth: 1.5,
          }],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          scales: {
            x: {
              ticks: { color: '#9ca3af', font: { family: 'Space Grotesk' } },
              grid: { display: false },
              border: { display: false },
            },
            y: {
              ticks: { color: '#9ca3af', font: { family: 'Space Grotesk' } },
              grid: { color: 'rgba(255,255,255,0.06)' },
              border: { display: false },
            },
          },
          plugins: {
            legend: { display: false },
            tooltip: {
              mode: 'index',
              intersect: false,
              backgroundColor: 'rgba(14, 14, 14, 0.95)',
              borderColor: 'rgba(110, 231, 255, 0.35)',
              borderWidth: 1,
              padding: 10,
              titleColor: '#ffffff',
              bodyColor: '#d8d8d8',
            },
          },
          interaction: {
            mode: 'nearest',
            axis: 'x',
            intersect: false,
          },
        },
      });
    }
  }

  private updateCharts(data: any): void {
    if (this.priorityChart && data.by_priority) {
      this.priorityChart.data.labels = data.by_priority.map((i: any) => i.label || 'Unknown');
      this.priorityChart.data.datasets[0].data = data.by_priority.map((i: any) => i.count ?? 0);
      this.priorityChart.update();
    }
    if (this.classificationChart && data.by_classification) {
      this.classificationChart.data.labels = data.by_classification.map((i: any) => i.label || 'Unknown');
      this.classificationChart.data.datasets[0].data = data.by_classification.map((i: any) => i.count ?? 0);
      this.classificationChart.update();
    }
    if (this.hourlyChart && data.hourly_counts) {
      this.hourlyChart.data.labels = data.hourly_counts.map((i: any) => i.label || '');
      this.hourlyChart.data.datasets[0].data = data.hourly_counts.map((i: any) => i.count ?? 0);
      this.hourlyChart.update();
    }
  }
}
