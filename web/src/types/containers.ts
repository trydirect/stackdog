// Container types

export interface Container {
  id: string;
  name: string;
  image: string;
  status: ContainerStatus;
  securityStatus: SecurityStatus;
  riskScore: number;
  networkActivity: NetworkActivity;
  createdAt: string;
}

export type ContainerStatus = 'Running' | 'Stopped' | 'Paused' | 'Quarantined';

export interface SecurityStatus {
  state: 'Secure' | 'AtRisk' | 'Compromised' | 'Quarantined';
  threats: number;
  vulnerabilities: number | null;
  lastScan: string | null;
}

export interface NetworkActivity {
  inboundConnections: number | null;
  outboundConnections: number | null;
  blockedConnections: number | null;
  receivedBytes: number | null;
  transmittedBytes: number | null;
  receivedPackets: number | null;
  transmittedPackets: number | null;
  suspiciousActivity: boolean;
}

export interface QuarantineRequest {
  containerId: string;
  reason: string;
}
