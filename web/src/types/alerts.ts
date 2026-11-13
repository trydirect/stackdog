// Alert types

export interface Alert {
  id: string;
  alertType: AlertType;
  severity: AlertSeverity;
  message: string;
  status: AlertStatus;
  timestamp: string;
  sourceEvent?: any;
  metadata?: Record<string, string>;
}

export type AlertType = 
  | 'ThreatDetected'
  | 'AnomalyDetected'
  | 'RuleViolation'
  | 'ThresholdExceeded'
  | 'QuarantineApplied'
  | 'SystemEvent';

export type AlertSeverity = 'Info' | 'Low' | 'Medium' | 'High' | 'Critical';

export type AlertStatus = 'New' | 'Acknowledged' | 'Resolved' | 'FalsePositive';

export interface AlertStats {
  totalCount: number;
  newCount: number;
  acknowledgedCount: number;
  resolvedCount: number;
  falsePositiveCount: number;
}

export interface AlertFilter {
  severity?: AlertSeverity[];
  status?: AlertStatus[];
  type?: AlertType[];
  dateFrom?: string;
  dateTo?: string;
}
