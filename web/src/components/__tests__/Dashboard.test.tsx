import React from 'react';
import { act, render, screen, waitFor } from '@testing-library/react';
import Dashboard from '../Dashboard';
import apiService from '../../services/api';
import webSocketService from '../../services/websocket';

jest.mock('../../services/api');
jest.mock('../../services/websocket');
jest.mock('../AlertPanel', () => () => <div>AlertPanel</div>);
jest.mock('../ContainerList', () => () => <div>ContainerList</div>);
jest.mock('../ThreatMap', () => () => <div>ThreatMap</div>);
jest.mock('../SecurityScore', () => ({ score }: { score: number }) => (
  <div>SecurityScore:{score}</div>
));

describe('Dashboard Component', () => {
  const baseStatus = {
    overallScore: 88,
    activeThreats: 2,
    quarantinedContainers: 1,
    alertsNew: 4,
    alertsAcknowledged: 3,
    lastUpdated: '2026-04-04T08:00:00.000Z',
  };

  const subscriptions = new Map<string, (payload?: any) => void>();

  beforeEach(() => {
    jest.clearAllMocks();
    subscriptions.clear();
    (apiService.getSecurityStatus as jest.Mock).mockResolvedValue(baseStatus);
    (webSocketService.connect as jest.Mock).mockResolvedValue(undefined);
    (webSocketService.subscribe as jest.Mock).mockImplementation((event, handler) => {
      subscriptions.set(event, handler);
      return () => subscriptions.delete(event);
    });
    (webSocketService.disconnect as jest.Mock).mockImplementation(() => {});
  });

  test('loads and displays security status summary', async () => {
    render(<Dashboard />);

    expect(await screen.findByText('SecurityScore:88')).toBeInTheDocument();
    expect(screen.getByText('2')).toBeInTheDocument();
    expect(screen.getByText('1')).toBeInTheDocument();
    expect(screen.getByText('4')).toBeInTheDocument();
    expect(screen.getByText('AlertPanel')).toBeInTheDocument();
    expect(screen.getByText('ContainerList')).toBeInTheDocument();
    expect(screen.getByText('ThreatMap')).toBeInTheDocument();
  });

  test('shows an error state when status loading fails', async () => {
    (apiService.getSecurityStatus as jest.Mock).mockRejectedValue(new Error('boom'));

    render(<Dashboard />);

    expect(await screen.findByText('Failed to load security status')).toBeInTheDocument();
  });

  test('applies websocket stats updates to the rendered summary', async () => {
    render(<Dashboard />);

    expect(await screen.findByText('SecurityScore:88')).toBeInTheDocument();

    await act(async () => {
      subscriptions.get('stats:updated')?.({
        overallScore: 65,
        activeThreats: 5,
        alertsNew: 6,
      });
    });

    expect(screen.getByText('SecurityScore:65')).toBeInTheDocument();
    expect(screen.getByText('5')).toBeInTheDocument();
    expect(screen.getByText('6')).toBeInTheDocument();
  });

  test('refreshes security status when an alert is created and disconnects on unmount', async () => {
    const { unmount } = render(<Dashboard />);

    expect(await screen.findByText('SecurityScore:88')).toBeInTheDocument();

    (apiService.getSecurityStatus as jest.Mock).mockResolvedValueOnce({
      ...baseStatus,
      activeThreats: 3,
    });

    await act(async () => {
      subscriptions.get('alert:created')?.();
    });

    await waitFor(() => {
      expect(apiService.getSecurityStatus).toHaveBeenCalledTimes(2);
    });

    unmount();
    expect(webSocketService.disconnect).toHaveBeenCalled();
  });
});
