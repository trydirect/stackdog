import React from 'react';
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react';
import ContainerList from '../ContainerList';
import apiService from '../../services/api';

// Mock services
jest.mock('../../services/api');

const mockContainers = [
  {
    id: 'container-1',
    name: 'web-server',
    image: 'nginx:latest',
    status: 'Running' as const,
    securityStatus: {
      state: 'Secure' as const,
      threats: 0,
      vulnerabilities: null,
      lastScan: null,
    },
    riskScore: 10,
    networkActivity: {
      inboundConnections: null,
      outboundConnections: null,
      blockedConnections: null,
      receivedBytes: 1024,
      transmittedBytes: 2048,
      receivedPackets: 5,
      transmittedPackets: 3,
      suspiciousActivity: false,
    },
    createdAt: new Date().toISOString(),
  },
  {
    id: 'container-2',
    name: 'database',
    image: 'postgres:13',
    status: 'Running' as const,
    securityStatus: {
      state: 'AtRisk' as const,
      threats: 2,
      vulnerabilities: null,
      lastScan: null,
    },
    riskScore: 65,
    networkActivity: {
      inboundConnections: null,
      outboundConnections: null,
      blockedConnections: null,
      receivedBytes: 4096,
      transmittedBytes: 8192,
      receivedPackets: 10,
      transmittedPackets: 5,
      suspiciousActivity: true,
    },
    createdAt: new Date().toISOString(),
  },
];

describe('ContainerList Component', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (apiService.getContainers as jest.Mock).mockResolvedValue(mockContainers);
  });

  test('displays container list', async () => {
    render(<ContainerList />);

    await waitFor(() => {
      expect(screen.getByText('web-server')).toBeInTheDocument();
    });

    expect(screen.getByText('database')).toBeInTheDocument();
  });

  test('shows security status per container', async () => {
    render(<ContainerList />);

    expect(await screen.findByText('web-server')).toBeInTheDocument();

    expect(screen.getByText('Secure')).toBeInTheDocument();
    expect(screen.getByText('AtRisk')).toBeInTheDocument();
  });

  test('displays risk scores', async () => {
    render(<ContainerList />);

    await waitFor(() => {
      expect(screen.getByText('web-server')).toBeInTheDocument();
    });

    expect(screen.getByText('10')).toBeInTheDocument(); // Risk score
    expect(screen.getByText('65')).toBeInTheDocument();
  });

  test('quarantine button works', async () => {
    (apiService.quarantineContainer as jest.Mock).mockResolvedValue({});

    render(<ContainerList />);

    expect(await screen.findByText('database')).toBeInTheDocument();

    const quarantineButton = screen.getAllByText('Quarantine')[1];
    fireEvent.click(quarantineButton);

    // Should show confirmation modal
    expect(screen.getByText('Confirm Quarantine')).toBeInTheDocument();

    const confirmButton = screen.getByText('Confirm');
    fireEvent.click(confirmButton);

    await waitFor(() => {
      expect(apiService.quarantineContainer).toHaveBeenCalledWith({
        containerId: 'container-2',
        reason: expect.any(String),
      });
    });
  });

  test('release button works', async () => {
    const quarantinedContainer = {
      ...mockContainers[0],
      status: 'Quarantined' as const,
    };

    (apiService.getContainers as jest.Mock).mockResolvedValue([quarantinedContainer]);
    (apiService.releaseContainer as jest.Mock).mockResolvedValue({});

    render(<ContainerList />);

    await waitFor(() => {
      expect(screen.getByText('web-server')).toBeInTheDocument();
    });

    const releaseButton = screen.getByText('Release');
    fireEvent.click(releaseButton);

    await waitFor(() => {
      expect(apiService.releaseContainer).toHaveBeenCalledWith('container-1');
    });
  });

  test('shows release action when security state is quarantined', async () => {
    const quarantinedBySecurityState = {
      ...mockContainers[0],
      status: 'Running' as const,
      securityStatus: {
        ...mockContainers[0].securityStatus,
        state: 'Quarantined' as const,
      },
    };

    (apiService.getContainers as jest.Mock).mockResolvedValue([quarantinedBySecurityState]);

    render(<ContainerList />);

    expect(await screen.findByText('web-server')).toBeInTheDocument();
    expect(screen.getAllByText('Quarantined').length).toBeGreaterThanOrEqual(2);
    expect(screen.getByText('Release')).toBeInTheDocument();
    expect(screen.queryByText('Quarantine')).not.toBeInTheDocument();
  });

  test('keeps security-state quarantine visible in the Quarantined filter', async () => {
    const quarantined = {
      ...mockContainers[0],
      securityStatus: { ...mockContainers[0].securityStatus, state: 'Quarantined' as const },
    };
    (apiService.getContainers as jest.Mock).mockResolvedValue([quarantined, mockContainers[1]]);
    render(<ContainerList />);
    expect(await screen.findByText('web-server')).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText('Filter by status'), { target: { value: 'Quarantined' } });
    expect(await screen.findByText('web-server')).toBeInTheDocument();
    expect(screen.queryByText('database')).not.toBeInTheDocument();
    expect(screen.getByText('Release')).toBeInTheDocument();
  });

  test('shows complete identifiers, timestamps and unavailable metrics in the details dialog', async () => {
    const id = 'a'.repeat(64);
    (apiService.getContainers as jest.Mock).mockResolvedValue([{ ...mockContainers[0], id }]);
    render(<ContainerList />);
    fireEvent.click(await screen.findByText('Details'));

    const dialog = await screen.findByRole('dialog', { name: 'Container Details' });
    expect(within(dialog).getByText(id)).toBeInTheDocument();
    expect(within(dialog).getByText('1.0 KB')).toBeInTheDocument();
    expect(within(dialog).getAllByText('Unavailable')).toHaveLength(2);
    expect(dialog.querySelector('time')).toHaveAttribute('datetime', mockContainers[0].createdAt);

    fireEvent.click(within(dialog).getByText('Close'));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  });

  test('filters by status', async () => {
    render(<ContainerList />);

    expect(await screen.findByText('web-server')).toBeInTheDocument();

    const statusFilter = screen.getByLabelText('Filter by status');
    fireEvent.change(statusFilter, { target: { value: 'Running' } });

    await waitFor(() => {
      expect(apiService.getContainers).toHaveBeenCalledTimes(2);
    });
    expect(screen.getByText('web-server')).toBeInTheDocument();
    expect(screen.getByText('database')).toBeInTheDocument();
  });

  test('shows network activity', async () => {
    render(<ContainerList />);

    await waitFor(() => {
      expect(screen.getByText('database')).toBeInTheDocument();
    });

    // Should show network activity details
    expect(screen.getByText(/10 pkts/)).toBeInTheDocument();
    expect(screen.getAllByText(/5 pkts/).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/n\/a/).length).toBeGreaterThan(0);
  });
});
