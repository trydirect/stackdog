import axios, { AxiosInstance } from 'axios';
import { SecurityStatus, Threat, ThreatStatistics } from '../types/security';
import { Alert, AlertStats, AlertFilter } from '../types/alerts';
import { Container, QuarantineRequest } from '../types/containers';
import { resolveApiPort } from './ports';
import { defaultApiUrl, readEnv } from './env';

const env = readEnv();
const apiPort = resolveApiPort(env);
const API_BASE_URL = env.REACT_APP_API_URL || defaultApiUrl(apiPort);

class ApiService {
  public api: AxiosInstance;

  constructor() {
    this.api = axios.create({
      baseURL: API_BASE_URL,
      timeout: 10000,
      headers: {
        'Content-Type': 'application/json',
      },
    });
  }

  private firstNumber(...values: unknown[]): number | null {
    return (values.find((value) => typeof value === 'number') as number | undefined) ?? null;
  }

  private firstString(...values: unknown[]): string | null {
    return (
      (values.find((value) => typeof value === 'string' && value.length > 0) as string | undefined) ??
      null
    );
  }

  private normalizeSecurityStatus(payload: Record<string, unknown>): SecurityStatus {
    return {
      overallScore: (payload.overallScore ?? payload.overall_score ?? 0) as number,
      activeThreats: (payload.activeThreats ?? payload.active_threats ?? 0) as number,
      quarantinedContainers: (payload.quarantinedContainers ?? payload.quarantined_containers ?? 0) as number,
      alertsNew: (payload.alertsNew ?? payload.alerts_new ?? 0) as number,
      alertsAcknowledged: (payload.alertsAcknowledged ?? payload.alerts_acknowledged ?? 0) as number,
      lastUpdated: (payload.lastUpdated ?? payload.last_updated ?? new Date().toISOString()) as string,
    };
  }

  private normalizeThreatStatistics(payload: Record<string, unknown>): ThreatStatistics {
    return {
      totalThreats: (payload.totalThreats ?? payload.total_threats ?? 0) as number,
      bySeverity: (payload.bySeverity ?? payload.by_severity ?? {}) as ThreatStatistics['bySeverity'],
      byType: (payload.byType ?? payload.by_type ?? {}) as Record<string, number>,
      trend: (payload.trend ?? 'stable') as ThreatStatistics['trend'],
    };
  }

  private normalizeAlert(payload: Record<string, unknown>): Alert {
    return {
      id: (payload.id ?? '') as string,
      alertType: (payload.alertType ?? payload.alert_type ?? 'SystemEvent') as Alert['alertType'],
      severity: (payload.severity ?? 'Info') as Alert['severity'],
      message: (payload.message ?? '') as string,
      status: (payload.status ?? 'New') as Alert['status'],
      timestamp: (payload.timestamp ?? new Date().toISOString()) as string,
      metadata: payload.metadata as Record<string, string> | undefined,
    };
  }

  private normalizeAlertStats(payload: Record<string, unknown>): AlertStats {
    return {
      totalCount: (payload.totalCount ?? payload.total_count ?? 0) as number,
      newCount: (payload.newCount ?? payload.new_count ?? 0) as number,
      acknowledgedCount: (payload.acknowledgedCount ?? payload.acknowledged_count ?? 0) as number,
      resolvedCount: (payload.resolvedCount ?? payload.resolved_count ?? 0) as number,
      falsePositiveCount: (payload.falsePositiveCount ?? payload.false_positive_count ?? 0) as number,
    };
  }

  // Security Status
  async getSecurityStatus(): Promise<SecurityStatus> {
    const response = await this.api.get('/security/status');
    return this.normalizeSecurityStatus(response.data as Record<string, unknown>);
  }

  async getThreats(): Promise<Threat[]> {
    const response = await this.api.get('/threats');
    return response.data;
  }

  async getThreatStatistics(): Promise<ThreatStatistics> {
    const response = await this.api.get('/threats/statistics');
    return this.normalizeThreatStatistics(response.data as Record<string, unknown>);
  }

  // Alerts
  async getAlerts(filter?: AlertFilter): Promise<Alert[]> {
    const params = new URLSearchParams();
    if (filter?.severity) {
      filter.severity.forEach(s => params.append('severity', s));
    }
    if (filter?.status) {
      filter.status.forEach(s => params.append('status', s));
    }
    const response = await this.api.get('/alerts', { params });
    return (response.data as Array<Record<string, unknown>>).map((alert) => this.normalizeAlert(alert));
  }

  async getAlertStats(): Promise<AlertStats> {
    const response = await this.api.get('/alerts/stats');
    return this.normalizeAlertStats(response.data as Record<string, unknown>);
  }

  async acknowledgeAlert(alertId: string): Promise<void> {
    await this.api.post(`/alerts/${alertId}/acknowledge`);
  }

  async resolveAlert(alertId: string, note?: string): Promise<void> {
    await this.api.post(`/alerts/${alertId}/resolve`, { note });
  }

  // Containers
  async getContainers(): Promise<Container[]> {
    const response = await this.api.get('/containers');
    const raw = response.data as Array<Record<string, any>>;
    return raw.map((item) => {
      const securityStatus = item.securityStatus ?? item.security_status ?? {};
      const networkActivity = item.networkActivity ?? item.network_activity ?? {};

        return {
          id: item.id ?? '',
          name: item.name ?? item.id ?? 'unknown',
          image: item.image ?? 'unknown',
          status: item.status ?? 'Running',
          securityStatus: {
            state: securityStatus.state ?? 'Secure',
            threats: securityStatus.threats ?? 0,
            vulnerabilities: this.firstNumber(securityStatus.vulnerabilities),
            lastScan: this.firstString(securityStatus.lastScan, securityStatus.last_scan),
          },
          riskScore: item.riskScore ?? item.risk_score ?? 0,
          networkActivity: {
            inboundConnections: this.firstNumber(
              networkActivity.inboundConnections,
              networkActivity.inbound_connections,
            ),
            outboundConnections: this.firstNumber(
              networkActivity.outboundConnections,
              networkActivity.outbound_connections,
            ),
            blockedConnections: this.firstNumber(
              networkActivity.blockedConnections,
              networkActivity.blocked_connections,
            ),
            receivedBytes: this.firstNumber(
              networkActivity.receivedBytes,
              networkActivity.received_bytes,
            ),
            transmittedBytes: this.firstNumber(
              networkActivity.transmittedBytes,
              networkActivity.transmitted_bytes,
            ),
            receivedPackets: this.firstNumber(
              networkActivity.receivedPackets,
              networkActivity.received_packets,
            ),
            transmittedPackets: this.firstNumber(
              networkActivity.transmittedPackets,
              networkActivity.transmitted_packets,
            ),
            suspiciousActivity: networkActivity.suspiciousActivity ?? networkActivity.suspicious_activity ?? false,
          },
          createdAt: item.createdAt ?? item.created_at ?? new Date().toISOString(),
      } as Container;
    });
  }

  async quarantineContainer(request: QuarantineRequest): Promise<void> {
    await this.api.post(`/containers/${request.containerId}/quarantine`, {
      reason: request.reason,
    });
  }

  async releaseContainer(containerId: string): Promise<void> {
    await this.api.post(`/containers/${containerId}/release`);
  }
}

export const apiService = new ApiService();
export default apiService;
