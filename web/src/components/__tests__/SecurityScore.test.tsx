import React from 'react';
import { render, screen } from '@testing-library/react';
import SecurityScore from '../SecurityScore';

describe('SecurityScore Component', () => {
  test('renders secure label for high scores', () => {
    render(<SecurityScore score={88} />);

    expect(screen.getByText('88')).toBeInTheDocument();
    expect(screen.getByText('Secure')).toBeInTheDocument();
  });

  test('renders moderate and at-risk thresholds correctly', () => {
    const { rerender } = render(<SecurityScore score={65} />);
    expect(screen.getByText('Moderate')).toBeInTheDocument();

    rerender(<SecurityScore score={45} />);
    expect(screen.getByText('At Risk')).toBeInTheDocument();
  });

  test('renders critical label and gauge rotation for low scores', () => {
    const { container } = render(<SecurityScore score={20} />);

    expect(screen.getByText('Critical')).toBeInTheDocument();
    const gaugeFill = container.querySelector('.gauge-fill');
    expect(gaugeFill).toHaveStyle({ transform: 'rotate(-54deg)' });
  });
});
