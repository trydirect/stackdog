import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import AlertPanel from '../AlertPanel';
import { alertIdFromHash } from '../AlertPanel';
import apiService from '../../services/api';
import webSocketService from '../../services/websocket';

// Mock services
jest.mock('../../services/api');
jest.mock('../../services/websocket');

const mockAlerts = [
  {
    id: 'alert-1',
    alertType: 'ThreatDetected' as const,
    severity: 'High' as const,
    message: 'Suspicious activity detected',
    status: 'New' as const,
    timestamp: new Date().toISOString(),
  },
  {
    id: 'alert-2',
    alertType: 'RuleViolation' as const,
    severity: 'Medium' as const,
    message: 'Rule violation detected',
    status: 'Acknowledged' as const,
    timestamp: new Date().toISOString(),
  },
];

describe('AlertPanel Component', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (apiService.getAlerts as jest.Mock).mockResolvedValue(mockAlerts);
    (apiService.getAlertStats as jest.Mock).mockResolvedValue({
      totalCount: 10,
      newCount: 5,
      acknowledgedCount: 3,
      resolvedCount: 2,
    });
    (webSocketService.connect as jest.Mock).mockResolvedValue(undefined);
    (webSocketService.subscribe as jest.Mock).mockReturnValue(() => {});
    (webSocketService.disconnect as jest.Mock).mockImplementation(() => {});
  });

  test('lists alerts correctly', async () => {
    render(<AlertPanel />);

    expect(await screen.findByText('Suspicious activity detected')).toBeInTheDocument();

    expect(screen.getByText('Rule violation detected')).toBeInTheDocument();
  });

  test('filters alerts by severity', async () => {
    render(<AlertPanel />);

    expect(await screen.findByText('Suspicious activity detected')).toBeInTheDocument();

    const severityFilter = screen.getByLabelText('Filter by severity');
    fireEvent.change(severityFilter, { target: { value: 'High' } });

    await waitFor(() => {
      expect(apiService.getAlerts).toHaveBeenLastCalledWith({ severity: ['High'] });
    });
  });

  test('filters alerts by status', async () => {
    render(<AlertPanel />);

    expect(await screen.findByText('Suspicious activity detected')).toBeInTheDocument();

    const statusFilter = screen.getByLabelText('Filter by status');
    fireEvent.change(statusFilter, { target: { value: 'New' } });

    await waitFor(() => {
      expect(apiService.getAlerts).toHaveBeenLastCalledWith({ status: ['New'] });
    });
  });

  test('acknowledge alert works', async () => {
    (apiService.acknowledgeAlert as jest.Mock).mockResolvedValue({});

    render(<AlertPanel />);

    expect(await screen.findByText('Suspicious activity detected')).toBeInTheDocument();

    const acknowledgeButton = screen.getAllByText('Acknowledge')[0];
    fireEvent.click(acknowledgeButton);

    await waitFor(() => {
      expect(apiService.acknowledgeAlert).toHaveBeenCalledWith('alert-1');
    });
  });

  test('resolve alert works', async () => {
    (apiService.resolveAlert as jest.Mock).mockResolvedValue({});

    render(<AlertPanel />);

    expect(await screen.findByText('Suspicious activity detected')).toBeInTheDocument();

    const resolveButton = screen.getAllByText('Resolve')[0];
    fireEvent.click(resolveButton);

    await waitFor(() => {
      expect(apiService.resolveAlert).toHaveBeenCalledWith('alert-1', 'Resolved via dashboard');
    });
  });

  test('displays alert statistics', async () => {
    render(<AlertPanel />);

    await waitFor(() => {
      expect(screen.getByText('10')).toBeInTheDocument();
    });

    expect(screen.getByText('5')).toBeInTheDocument(); // New
    expect(screen.getByText('3')).toBeInTheDocument(); // Acknowledged
    expect(screen.getByText('2')).toBeInTheDocument(); // Resolved
  });

  test('pagination works', async () => {
    const manyAlerts = Array.from({ length: 25 }, (_, i) => ({
      id: `alert-${i}`,
      alertType: 'ThreatDetected' as const,
      severity: 'High' as const,
      message: `Alert ${i}`,
      status: 'New' as const,
      timestamp: new Date().toISOString(),
    }));

    (apiService.getAlerts as jest.Mock).mockResolvedValue(manyAlerts);

    render(<AlertPanel />);

    expect(await screen.findByText('Alert 0')).toBeInTheDocument();

    // Should show first 10 alerts
    expect(screen.getByText('Alert 0')).toBeInTheDocument();
    expect(screen.queryByText('Alert 15')).not.toBeInTheDocument();

    // Click next page
    const nextPageButton = screen.getByText('Next');
    fireEvent.click(nextPageButton);

    await waitFor(() => {
      expect(screen.getByText('Alert 10')).toBeInTheDocument();
    });
  });

  test('bulk actions work', async () => {
    (apiService.acknowledgeAlert as jest.Mock).mockResolvedValue({});

    render(<AlertPanel />);

    expect(await screen.findByText('Suspicious activity detected')).toBeInTheDocument();

    const selectAllCheckbox = screen.getByLabelText('Select all alerts');
    fireEvent.click(selectAllCheckbox);

    const bulkAcknowledgeButton = await screen.findByText(/Acknowledge Selected/);
    fireEvent.click(bulkAcknowledgeButton);

    await waitFor(() => {
      expect(apiService.acknowledgeAlert).toHaveBeenCalledTimes(2);
      expect(apiService.acknowledgeAlert).toHaveBeenCalledWith('alert-1');
      expect(apiService.acknowledgeAlert).toHaveBeenCalledWith('alert-2');
    });
  });
});

describe('alertIdFromHash', () => {
  it('reads the id out of a notification deep link', () => {
    expect(alertIdFromHash('#alerts/abc-123')).toBe('abc-123');
    expect(alertIdFromHash('alerts/abc-123')).toBe('abc-123');
  });

  it('decodes ids that were percent-encoded in the URL', () => {
    expect(alertIdFromHash('#alerts/a%2Fb')).toBe('a/b');
  });

  it('ignores hashes that are not alert links', () => {
    expect(alertIdFromHash('#alerts')).toBeNull();
    expect(alertIdFromHash('#containers')).toBeNull();
    expect(alertIdFromHash('')).toBeNull();
  });
});
