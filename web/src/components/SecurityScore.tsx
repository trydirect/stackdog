import React from 'react';
import { Card } from 'react-bootstrap';
import './SecurityScore.css';

interface SecurityScoreProps {
  score: number;
}

const SecurityScore: React.FC<SecurityScoreProps> = ({ score }) => {
  const getScoreColor = (score: number): string => {
    if (score >= 80) return '#047857'; // Green
    if (score >= 60) return '#92400e'; // Orange
    if (score >= 40) return '#c2410c'; // Dark Orange
    return '#b42318'; // Red
  };

  const getScoreLabel = (score: number): string => {
    if (score >= 80) return 'Secure';
    if (score >= 60) return 'Moderate';
    if (score >= 40) return 'At Risk';
    return 'Critical';
  };

  const rotation = (score / 100) * 180 - 90;

  return (
    <Card className="security-score-card">
      <Card.Body>
        <Card.Title>Security Score</Card.Title>
        <div className="gauge-container">
          <div className="gauge" role="meter" aria-label="Security Score" aria-valuenow={score} aria-valuemin={0} aria-valuemax={100}>
            <div className="gauge-background">
              <div className="gauge-fill" style={{ transform: `rotate(${rotation}deg)` }} />
            </div>
            <div className="gauge-cover">
              <span className="gauge-value">{score}</span>
            </div>
          </div>
        </div>
        <div className="score-label" style={{ color: getScoreColor(score) }}>
          {getScoreLabel(score)}
        </div>
      </Card.Body>
    </Card>
  );
};

export default SecurityScore;
