// Security types

export interface SecurityStatus {
  overallScore: number;
  activeThreats: number;
  quarantinedContainers: number;
  alertsNew: number;
  alertsAcknowledged: number;
  lastUpdated: string;
}

export interface Threat {
  id: string;
  type: string;
  severity: 'Info' | 'Low' | 'Medium' | 'High' | 'Critical';
  score: number;
  source: string;
  timestamp: string;
  status: 'New' | 'Investigating' | 'Mitigated' | 'Resolved';
}

export interface ThreatStatistics {
  totalThreats: number;
  bySeverity: {
    Info: number;
    Low: number;
    Medium: number;
    High: number;
    Critical: number;
  };
  byType: Record<string, number>;
  trend: 'increasing' | 'decreasing' | 'stable';
}
