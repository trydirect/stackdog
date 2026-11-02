import React, { useEffect, useState } from 'react';
import { Container, Row, Col, Card, Spinner, Alert as BootstrapAlert } from 'react-bootstrap';
import apiService from '../services/api';
import webSocketService from '../services/websocket';
import { SecurityStatus } from '../types/security';
import SecurityScore from './SecurityScore';
import AlertPanel from './AlertPanel';
import ContainerList from './ContainerList';
import ThreatMap from './ThreatMap';
import './Dashboard.css';

const Dashboard: React.FC = () => {
  const [securityStatus, setSecurityStatus] = useState<SecurityStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadSecurityStatus();
    setupWebSocket();

    return () => {
      webSocketService.disconnect();
    };
  }, []);

  const loadSecurityStatus = async () => {
    try {
      setLoading(true);
      const status = await apiService.getSecurityStatus();
      setSecurityStatus(status);
      setError(null);
    } catch (err) {
      setError('Failed to load security status');
      console.error('Error loading security status:', err);
    } finally {
      setLoading(false);
    }
  };

  const setupWebSocket = async () => {
    try {
      await webSocketService.connect();

      // Subscribe to real-time updates
      webSocketService.subscribe('stats:updated', (data: Partial<SecurityStatus>) => {
        setSecurityStatus(prev => prev ? { ...prev, ...data } : null);
      });

      webSocketService.subscribe('alert:created', () => {
        // Refresh status when new alert is created
        loadSecurityStatus();
      });
    } catch (err) {
      console.error('Failed to connect WebSocket:', err);
    }
  };

  if (loading) {
    return (
      <Container className="dashboard-loading">
        <Spinner animation="border" role="status">
          <span className="visually-hidden">Loading...</span>
        </Spinner>
      </Container>
    );
  }

  if (error) {
    return (
      <Container className="dashboard-error">
        <BootstrapAlert variant="danger" onClose={() => setError(null)} dismissible>
          {error}
        </BootstrapAlert>
      </Container>
    );
  }

  return (
    <Container as="main" fluid className="dashboard">
      <Row className="mb-4">
        <Col>
          <div className="dashboard-topbar">
            <h1>Overview</h1>
          </div>
          <p className="dashboard-subtitle">
            Real-time security monitoring for containers and Linux servers
          </p>
        </Col>
      </Row>

      {/* Security Score Card */}
      <Row id="overview" className="g-3 mb-4">
        <Col md={6} lg={3}>
          <SecurityScore score={securityStatus?.overallScore || 0} />
        </Col>
        <Col md={6} lg={3}>
          <Card className="stat-card">
            <Card.Body>
              <Card.Title>Active Threats</Card.Title>
              <Card.Text className="stat-value">
                {(securityStatus?.activeThreats || 0).toLocaleString()}
              </Card.Text>
            </Card.Body>
          </Card>
        </Col>
        <Col md={6} lg={3}>
          <Card className="stat-card">
            <Card.Body>
              <Card.Title>Quarantined</Card.Title>
              <Card.Text className="stat-value">
                {(securityStatus?.quarantinedContainers || 0).toLocaleString()}
              </Card.Text>
            </Card.Body>
          </Card>
        </Col>
        <Col md={6} lg={3}>
          <Card className="stat-card">
            <Card.Body>
              <Card.Title>New Alerts</Card.Title>
              <Card.Text className="stat-value">
                {(securityStatus?.alertsNew || 0).toLocaleString()}
              </Card.Text>
            </Card.Body>
          </Card>
        </Col>
      </Row>

      {/* Threat Map */}
      <Row id="threats" className="mb-4">
        <Col>
          <ThreatMap />
        </Col>
      </Row>

      {/* Alerts and Containers */}
      <Row className="g-4">
        <Col id="alerts" xs={12}>
          <AlertPanel />
        </Col>
        <Col id="containers" xs={12}>
          <ContainerList />
        </Col>
      </Row>

      {/* Last Updated */}
      <Row className="mt-4">
        <Col>
          <p className="last-updated">
            Last updated: {securityStatus?.lastUpdated 
              ? new Date(securityStatus.lastUpdated).toLocaleString()
              : 'Never'
            }
          </p>
        </Col>
      </Row>
    </Container>
  );
};

export default Dashboard;
