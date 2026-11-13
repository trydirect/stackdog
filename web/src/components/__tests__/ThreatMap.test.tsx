import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import ThreatMap from '../ThreatMap';
import apiService from '../../services/api';

// Mock services
jest.mock('../../services/api');

const mockThreats = [
  {
    id: 'threat-1',
    type: 'CryptoMiner',
    severity: 'High' as const,
    score: 85,
    source: 'container-1',
    timestamp: new Date().toISOString(),
    status: 'New' as const,
  },
  {
    id: 'threat-2',
    type: 'ContainerEscape',
    severity: 'Critical' as const,
    score: 95,
    source: 'container-2',
    timestamp: new Date().toISOString(),
    status: 'Investigating' as const,
  },
  {
    id: 'threat-3',
    type: 'NetworkScanner',
    severity: 'Medium' as const,
    score: 55,
    source: 'container-1',
    timestamp: new Date().toISOString(),
    status: 'Mitigated' as const,
  },
];

const mockStatistics = {
  totalThreats: 10,
  bySeverity: {
    Info: 1,
    Low: 2,
    Medium: 3,
    High: 3,
    Critical: 1,
  },
  byType: {
    CryptoMiner: 3,
    ContainerEscape: 2,
    NetworkScanner: 5,
  },
  trend: 'increasing' as const,
};

describe('ThreatMap Component', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (apiService.getThreats as jest.Mock).mockResolvedValue(mockThreats);
    (apiService.getThreatStatistics as jest.Mock).mockResolvedValue(mockStatistics);
  });

  test('displays threat type distribution', async () => {
    render(<ThreatMap />);

    expect(await screen.findByText('Threat Type Distribution')).toBeInTheDocument();

    expect(screen.getByText('CryptoMiner')).toBeInTheDocument();
    expect(screen.getByText('ContainerEscape')).toBeInTheDocument();
    expect(screen.getByText('NetworkScanner')).toBeInTheDocument();
  });

  test('displays severity breakdown', async () => {
    render(<ThreatMap />);

    expect(await screen.findByText('Severity Breakdown')).toBeInTheDocument();

    expect(screen.getByText('Recent Threats')).toBeInTheDocument();
    expect(screen.getByText('Score: 95')).toBeInTheDocument();
  });

  test('displays threat timeline', async () => {
    render(<ThreatMap />);

    expect(await screen.findByText('Threat Timeline')).toBeInTheDocument();

    expect(screen.getByText('Total Threats')).toBeInTheDocument();
    expect(screen.getByText('10')).toBeInTheDocument();
  });

  test('charts are interactive', async () => {
    render(<ThreatMap />);

    expect(await screen.findByText('Threat Type Distribution')).toBeInTheDocument();

    expect(screen.getByText('Score: 85')).toBeInTheDocument();
    expect(screen.getAllByText('container-1')).toHaveLength(2);
  });

  test('filters by date range', async () => {
    render(<ThreatMap />);

    expect(await screen.findByText('Threat Type Distribution')).toBeInTheDocument();

    const dateFromInput = screen.getByLabelText('From');
    const dateToInput = screen.getByLabelText('To');

    fireEvent.change(dateFromInput, { target: { value: '2026-01-01' } });
    fireEvent.change(dateToInput, { target: { value: '2026-12-31' } });

    await waitFor(() => {
      expect(apiService.getThreats).toHaveBeenCalledTimes(3);
      expect(apiService.getThreatStatistics).toHaveBeenCalledTimes(3);
    });
  });
});
