import apiService from '../api';

// Mock axios
jest.mock('axios', () => ({
  create: () => ({
    get: jest.fn(),
    post: jest.fn(),
  }),
}));

describe('API Service', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('maps snake_case security status fields to camelCase', async () => {
    const mockStatus = {
      overall_score: 85,
      active_threats: 3,
      quarantined_containers: 1,
      alerts_new: 5,
      alerts_acknowledged: 2,
      last_updated: new Date().toISOString(),
    };

    (apiService.api.get as jest.Mock).mockResolvedValue({ data: mockStatus });

    const status = await apiService.getSecurityStatus();

    expect(apiService.api.get).toHaveBeenCalledWith('/security/status');
    expect(status).toEqual({
      overallScore: 85,
      activeThreats: 3,
      quarantinedContainers: 1,
      alertsNew: 5,
      alertsAcknowledged: 2,
      lastUpdated: mockStatus.last_updated,
    });
  });

  test('maps snake_case alerts and alert stats from the API', async () => {
    const mockAlerts = [
      {
        id: 'alert-1',
        alert_type: 'ThreatDetected',
        severity: 'High',
        message: 'Test alert',
        status: 'New',
        timestamp: new Date().toISOString(),
        metadata: { source: 'api' },
      },
    ];
    const mockAlertStats = {
      total_count: 8,
      new_count: 5,
      acknowledged_count: 2,
      resolved_count: 1,
    };

    (apiService.api.get as jest.Mock)
      .mockResolvedValueOnce({ data: mockAlerts })
      .mockResolvedValueOnce({ data: mockAlertStats });

    const alerts = await apiService.getAlerts();
    const stats = await apiService.getAlertStats();

    expect(apiService.api.get).toHaveBeenCalledWith('/alerts', expect.anything());
    expect(apiService.api.get).toHaveBeenCalledWith('/alerts/stats');
    expect(alerts).toEqual([
      {
        id: 'alert-1',
        alertType: 'ThreatDetected',
        severity: 'High',
        message: 'Test alert',
        status: 'New',
        timestamp: mockAlerts[0].timestamp,
        metadata: { source: 'api' },
      },
    ]);
    expect(stats).toEqual({
      totalCount: 8,
      newCount: 5,
      acknowledgedCount: 2,
      resolvedCount: 1,
      falsePositiveCount: 0,
    });
  });

  test('maps snake_case threat statistics from the API', async () => {
    const mockThreatStats = {
      total_threats: 3,
      by_severity: {
        Critical: 1,
        High: 2,
      },
      by_type: {
        ThreatDetected: 2,
        ThresholdExceeded: 1,
      },
      trend: 'increasing',
    };

    (apiService.api.get as jest.Mock).mockResolvedValue({ data: mockThreatStats });

    const stats = await apiService.getThreatStatistics();

    expect(apiService.api.get).toHaveBeenCalledWith('/threats/statistics');
    expect(stats).toEqual({
      totalThreats: 3,
      bySeverity: {
        Critical: 1,
        High: 2,
      },
      byType: {
        ThreatDetected: 2,
        ThresholdExceeded: 1,
      },
      trend: 'increasing',
    });
  });

  test('acknowledges alert via API', async () => {
    (apiService.api.post as jest.Mock).mockResolvedValue({});

    await apiService.acknowledgeAlert('alert-123');

    expect(apiService.api.post).toHaveBeenCalledWith('/alerts/alert-123/acknowledge');
  });

  test('resolves alert via API', async () => {
    (apiService.api.post as jest.Mock).mockResolvedValue({});

    await apiService.resolveAlert('alert-123', 'Issue resolved');

    expect(apiService.api.post).toHaveBeenCalledWith('/alerts/alert-123/resolve', {
      note: 'Issue resolved',
    });
  });

  test('fetches containers from API', async () => {
    const mockContainers = [
      {
        id: 'container-1',
        name: 'test-container',
        status: 'Running',
        securityStatus: { state: 'Secure' as const },
        riskScore: 10,
      },
    ];

    (apiService.api.get as jest.Mock).mockResolvedValue({ data: mockContainers });

    const containers = await apiService.getContainers();

    expect(apiService.api.get).toHaveBeenCalledWith('/containers');
    expect(containers).toEqual([
      {
        id: 'container-1',
        name: 'test-container',
        image: 'unknown',
        status: 'Running',
        securityStatus: {
          state: 'Secure',
          threats: 0,
          vulnerabilities: null,
          lastScan: null,
        },
        riskScore: 10,
        networkActivity: {
          inboundConnections: null,
          outboundConnections: null,
          blockedConnections: null,
          receivedBytes: null,
          transmittedBytes: null,
          receivedPackets: null,
          transmittedPackets: null,
          suspiciousActivity: false,
        },
        createdAt: expect.any(String),
      },
    ]);
  });

  test('quarantines container via API', async () => {
    (apiService.api.post as jest.Mock).mockResolvedValue({});

    await apiService.quarantineContainer({
      containerId: 'container-123',
      reason: 'Suspicious activity',
    });

    expect(apiService.api.post).toHaveBeenCalledWith(
      '/containers/container-123/quarantine',
      { reason: 'Suspicious activity' }
    );
  });
});
