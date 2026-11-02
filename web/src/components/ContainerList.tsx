import React, { useEffect, useState } from 'react';
import { Card, Button, Form, Badge, Modal, Spinner, Alert as BootstrapAlert } from 'react-bootstrap';
import apiService from '../services/api';
import { Container, ContainerStatus } from '../types/containers';
import './ContainerList.css';
import './DetailsModal.css';

const ContainerList: React.FC = () => {
  const [containers, setContainers] = useState<Container[]>([]);
  const [loading, setLoading] = useState(true);
  const [filterStatus, setFilterStatus] = useState<ContainerStatus | ''>('');
  const [showModal, setShowModal] = useState(false);
  const [selectedContainer, setSelectedContainer] = useState<Container | null>(null);
  const [showQuarantineModal, setShowQuarantineModal] = useState(false);
  const [quarantineReason, setQuarantineReason] = useState('');

  useEffect(() => {
    loadContainers();
  }, [filterStatus]);

  const loadContainers = async () => {
    try {
      setLoading(true);
      const data = await apiService.getContainers();
      setContainers(filterStatus ? data.filter((c: Container) => (c.securityStatus.state === 'Quarantined' ? 'Quarantined' : c.status) === filterStatus) : data);
    } catch (err) {
      console.error('Error loading containers:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleQuarantine = async () => {
    if (!selectedContainer) return;
    try {
      await apiService.quarantineContainer({
        containerId: selectedContainer.id,
        reason: quarantineReason || 'Quarantined via dashboard',
      });
      setShowQuarantineModal(false);
      loadContainers();
    } catch (err) {
      console.error('Failed to quarantine container:', err);
    }
  };

  const handleRelease = async (containerId: string) => {
    try {
      await apiService.releaseContainer(containerId);
      loadContainers();
    } catch (err) {
      console.error('Failed to release container:', err);
    }
  };

  const getStatusBadge = (status: ContainerStatus) => {
    const variants: Record<ContainerStatus, string> = {
      Running: 'success',
      Stopped: 'secondary',
      Paused: 'warning',
      Quarantined: 'danger',
    };
    return variants[status];
  };

  const getSecurityBadge = (state: string) => {
    const variants: Record<string, string> = {
      Secure: 'success',
      AtRisk: 'warning',
      Compromised: 'danger',
      Quarantined: 'danger',
    };
    return variants[state] || 'secondary';
  };

  const getRiskColor = (score: number) => {
    if (score < 30) return '#047857';
    if (score < 60) return '#92400e';
    return '#b42318';
  };

  const formatCount = (value: number | null) => (value === null ? 'n/a' : value.toLocaleString());

  const formatBytes = (value: number | null) => {
    if (value === null) return 'n/a';
    if (value < 1024) return `${value} B`;
    if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
    if (value < 1024 * 1024 * 1024) return `${(value / (1024 * 1024)).toFixed(1)} MB`;
    return `${(value / (1024 * 1024 * 1024)).toFixed(1)} GB`;
  };

  const formatDateTime = (value: string | null) => (value ? new Date(value).toLocaleString() : 'Unavailable');

  return (
    <Card className="container-list">
      <Card.Header>
        <Card.Title>Containers</Card.Title>
      </Card.Header>
      <Card.Body>
        <Form.Group className="container-filter mb-4">
          <Form.Label>Filter by status</Form.Label>
          <Form.Select
            aria-label="Filter by status"
            value={filterStatus}
            onChange={(e) => setFilterStatus(e.target.value as ContainerStatus | '')}
          >
            <option value="">All Statuses</option>
            <option value="Running">Running</option>
            <option value="Stopped">Stopped</option>
            <option value="Paused">Paused</option>
            <option value="Quarantined">Quarantined</option>
          </Form.Select>
        </Form.Group>

        {loading ? (
          <div className="text-center">
            <Spinner animation="border" role="status"><span className="visually-hidden">Loading containers...</span></Spinner>
          </div>
        ) : (
          <div className="container-items">
            {containers.length === 0 && <p className="container-empty" role="status">No containers match the selected status.</p>}
            {containers.map((container) => {
              const isQuarantined = container.status === 'Quarantined' || container.securityStatus.state === 'Quarantined';

              return (
                <article key={container.id} className="container-item" aria-label={container.name}>
                  <div className="container-header">
                    <h5>{container.name}</h5>
                    <Badge bg={getStatusBadge(isQuarantined ? 'Quarantined' : container.status)}>
                      {isQuarantined ? 'Quarantined' : container.status}
                    </Badge>
                  </div>
                  <div className="container-details">
                    <p className="container-image"><span>Image</span><code>{container.image}</code></p>
                    <div className="container-security">
                      <div><span>Security</span><Badge bg={getSecurityBadge(container.securityStatus.state)}>{container.securityStatus.state}</Badge></div>
                      <div><span>Risk Score</span><strong style={{ color: getRiskColor(container.riskScore) }}>{container.riskScore}</strong></div>
                    </div>
                    <dl className="network-activity">
                      <div><dt>Received</dt><dd>{formatCount(container.networkActivity.receivedPackets)} pkts</dd></div>
                      <div><dt>Sent</dt><dd>{formatCount(container.networkActivity.transmittedPackets)} pkts</dd></div>
                      <div><dt>Blocked</dt><dd>{formatCount(container.networkActivity.blockedConnections)}</dd></div>
                    </dl>
                    {container.networkActivity.suspiciousActivity && <Badge bg="danger">Suspicious</Badge>}
                  </div>
                  <div className="container-actions">
                    <Button variant="outline-primary" size="sm" onClick={() => {
                      setSelectedContainer(container);
                      setShowModal(true);
                    }}>Details</Button>
                    {!isQuarantined && container.status === 'Running' && (
                      <Button variant="outline-danger" size="sm" onClick={() => {
                        setSelectedContainer(container);
                        setShowQuarantineModal(true);
                      }}>Quarantine</Button>
                    )}
                    {isQuarantined && (
                      <Button variant="outline-success" size="sm" onClick={() => handleRelease(container.id)}>Release</Button>
                    )}
                  </div>
                </article>
              );
            })}
          </div>
        )}
      </Card.Body>

      {/* Detail Modal */}
      <Modal className="security-details-modal container-details-modal" size="lg" centered scrollable aria-labelledby="container-details-title" show={showModal} onHide={() => setShowModal(false)}>
        <Modal.Header closeButton>
          <Modal.Title as="h2" id="container-details-title">Container Details</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          {selectedContainer && (
            <dl className="detail-grid">
              <dt>Name</dt><dd>{selectedContainer.name}</dd>
              <dt>ID</dt><dd><code>{selectedContainer.id}</code></dd>
              <dt>Image</dt><dd><code>{selectedContainer.image}</code></dd>
              <dt>Status</dt><dd>{selectedContainer.securityStatus.state === 'Quarantined' ? 'Quarantined' : selectedContainer.status}</dd>
              <dt>Security</dt><dd>{selectedContainer.securityStatus.state}</dd>
              <dt>Risk Score</dt><dd>{selectedContainer.riskScore}</dd>
              <dt>Threats</dt><dd>{selectedContainer.securityStatus.threats}</dd>
              <dt>Vulnerabilities</dt><dd>{selectedContainer.securityStatus.vulnerabilities ?? 'Unavailable'}</dd>
              <dt>Created</dt><dd><time dateTime={selectedContainer.createdAt}>{formatDateTime(selectedContainer.createdAt)}</time></dd>
              <dt>Last Scan</dt><dd>{formatDateTime(selectedContainer.securityStatus.lastScan)}</dd>
              <dt>RX Traffic</dt><dd>{formatBytes(selectedContainer.networkActivity.receivedBytes)}</dd>
              <dt>TX Traffic</dt><dd>{formatBytes(selectedContainer.networkActivity.transmittedBytes)}</dd>
              <dt>RX Packets</dt><dd>{formatCount(selectedContainer.networkActivity.receivedPackets)}</dd>
              <dt>TX Packets</dt><dd>{formatCount(selectedContainer.networkActivity.transmittedPackets)}</dd>
              <dt>Blocked Connections</dt><dd>{formatCount(selectedContainer.networkActivity.blockedConnections)}</dd>
            </dl>
          )}
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={() => setShowModal(false)}>Close</Button>
        </Modal.Footer>
      </Modal>

      {/* Quarantine Modal */}
      <Modal className="security-details-modal container-quarantine-modal" centered aria-labelledby="container-quarantine-title" show={showQuarantineModal} onHide={() => setShowQuarantineModal(false)}>
        <Modal.Header closeButton>
          <Modal.Title as="h2" id="container-quarantine-title">Confirm Quarantine</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <p>Are you sure you want to quarantine this container?</p>
          <Form.Group controlId="quarantine-reason">
            <Form.Label>Reason</Form.Label>
            <Form.Control
              as="textarea"
              rows={3}
              value={quarantineReason}
              onChange={(e) => setQuarantineReason(e.target.value)}
              placeholder="Enter reason for quarantine..."
            />
          </Form.Group>
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={() => setShowQuarantineModal(false)}>Cancel</Button>
          <Button variant="danger" onClick={handleQuarantine}>Confirm</Button>
        </Modal.Footer>
      </Modal>
    </Card>
  );
};

export default ContainerList;
