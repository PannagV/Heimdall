import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

/* ── Data contract for the AI Copilot assessment response ── */
export interface CopilotAssessment {
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  mitre_tactic: string;
  mitre_technique: string;
  confidence_score: number;       // 0–100
  justification: string;
}

/**
 * CopilotService – data-layer service for the AI SOC Copilot feature.
 * Sends selected log objects to the backend Gemini-powered assessment
 * endpoint and returns the structured response.
 */
@Injectable({ providedIn: 'root' })
export class CopilotService {
  private http = inject(HttpClient);

  /**
   * POST the selected log objects to the AI assessment endpoint.
   * @param selectedLogs Array of raw log / event JSON objects the analyst selected.
   * @returns Observable emitting the structured CopilotAssessment.
   */
  assessLogs(selectedLogs: any[]): Observable<CopilotAssessment> {
    return this.http.post<CopilotAssessment>(
      '/api/v1/copilot/assess',
      selectedLogs,
    );
  }
}
