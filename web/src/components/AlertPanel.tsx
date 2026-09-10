import React, { useEffect, useState } from 'react';
import { Card, Button, Form, Table, Badge, Modal, Spinner, Alert as BootstrapAlert, Pagination } from 'react-bootstrap';
import apiService from '../services/api';
import webSocketService from '../services/websocket';
import { Alert, AlertSeverity, AlertStatus, AlertFilter, AlertStats } from '../types/alerts';
import './AlertPanel.css';

const ITEMS_PER_PAGE = 10;

/** Read an alert id out of a "#alerts/{id}" location hash. */
export const alertIdFromHash = (hash: string): string | null => {
  const match = /^#?alerts\/(.+)$/.exec(hash);
  return match ? decodeURIComponent(match[1]) : null;
};

const AlertPanel: React.FC = () => {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [stats, setStats] = useState<AlertStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<AlertFilter>({});
  const [selectedAlerts, setSelectedAlerts] = useState<Set<string>>(new Set());
  const [currentPage, setCurrentPage] = useState(1);
  const [showModal, setShowModal] = useState(false);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadAlerts();
    loadStats();
    setupWebSocket();

    return () => {
      webSocketService.disconnect();
    };
  }, [filter]);

  // Deep link: notifications carry #alerts/{id}, which opens that alert's
  // details directly instead of leaving the operator to hunt through the list.
  useEffect(() => {
    const openFromHash = () => {
      const id = alertIdFromHash(window.location.hash);
      if (!id) {
        setShowModal(false);
        return;
      }
      const alert = alerts.find(a => a.id === id);
      if (alert) {
        setSelectedAlert(alert);
        setShowModal(true);
      }
    };

    openFromHash();
    window.addEventListener('hashchange', openFromHash);
    return () => window.removeEventListener('hashchange', openFromHash);
  }, [alerts]);

  const openDetails = (alert: Alert) => {
    setSelectedAlert(alert);
    setShowModal(true);
    window.location.hash = `alerts/${alert.id}`;
  };

  const closeDetails = () => {
    setShowModal(false);
    if (alertIdFromHash(window.location.hash)) {
      window.location.hash = 'alerts';
    }
  };

  const loadAlerts = async () => {
    try {
      setLoading(true);
      const data = await apiService.getAlerts(filter);
      setAlerts(data);
      setError(null);
    } catch (err) {
      setError('Failed to load alerts');
      console.error('Error loading alerts:', err);
    } finally {
      setLoading(false);
    }
  };

  const loadStats = async () => {
    try {
      const data = await apiService.getAlertStats();
      setStats(data);
    } catch (err) {
      console.error('Error loading stats:', err);
    }
  };

  const setupWebSocket = async () => {
    try {
      await webSocketService.connect();

      webSocketService.subscribe('alert:created', () => {
        loadAlerts();
        loadStats();
      });

      webSocketService.subscribe('alert:updated', () => {
        loadAlerts();
        loadStats();
      });
    } catch (err) {
      console.error('Failed to connect WebSocket:', err);
    }
  };

  const handleAcknowledge = async (alertId: string) => {
    try {
      await apiService.acknowledgeAlert(alertId);
      loadAlerts();
      loadStats();
    } catch (err) {
      console.error('Failed to acknowledge alert:', err);
    }
  };

  const handleResolve = async (alertId: string) => {
    try {
      await apiService.resolveAlert(alertId, 'Resolved via dashboard');
      loadAlerts();
      loadStats();
    } catch (err) {
      console.error('Failed to resolve alert:', err);
    }
  };

  const handleBulkAcknowledge = async () => {
    try {
      for (const alertId of selectedAlerts) {
        await apiService.acknowledgeAlert(alertId);
      }
      setSelectedAlerts(new Set());
      loadAlerts();
      loadStats();
    } catch (err) {
      console.error('Failed to bulk acknowledge:', err);
    }
  };

  const handleSelectAll = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.checked) {
      setSelectedAlerts(new Set(alerts.map(a => a.id)));
    } else {
      setSelectedAlerts(new Set());
    }
  };

  const handleSelectAlert = (alertId: string) => {
    const newSelected = new Set(selectedAlerts);
    if (newSelected.has(alertId)) {
      newSelected.delete(alertId);
    } else {
      newSelected.add(alertId);
    }
    setSelectedAlerts(newSelected);
  };

  const getSeverityBadge = (severity: AlertSeverity) => {
    const variants: Record<AlertSeverity, string> = {
      Info: 'info',
      Low: 'success',
      Medium: 'warning',
      High: 'danger',
      Critical: 'danger',
    };
    return variants[severity];
  };

  const getStatusBadge = (status: AlertStatus) => {
    const variants: Record<AlertStatus, string> = {
      New: 'primary',
      Acknowledged: 'warning',
      Resolved: 'success',
      FalsePositive: 'secondary',
    };
    return variants[status];
  };

  const paginatedAlerts = alerts.slice(
    (currentPage - 1) * ITEMS_PER_PAGE,
    currentPage * ITEMS_PER_PAGE
  );

  const totalPages = Math.ceil(alerts.length / ITEMS_PER_PAGE);

  return (
    <Card className="alert-panel">
      <Card.Header>
        <Card.Title>Recent Alerts</Card.Title>
      </Card.Header>
      <Card.Body>
        {error && (
          <BootstrapAlert variant="danger" onClose={() => setError(null)} dismissible>
            {error}
          </BootstrapAlert>
        )}

        {/* Statistics */}
        {stats && (
          <div className="alert-stats mb-3">
            <div className="stat-item">
              <span className="stat-label">Total</span>
              <span className="stat-value">{stats.totalCount}</span>
            </div>
            <div className="stat-item">
              <span className="stat-label">New</span>
              <span className="stat-value new">{stats.newCount}</span>
            </div>
            <div className="stat-item">
              <span className="stat-label">Acknowledged</span>
              <span className="stat-value acknowledged">{stats.acknowledgedCount}</span>
            </div>
            <div className="stat-item">
              <span className="stat-label">Resolved</span>
              <span className="stat-value resolved">{stats.resolvedCount}</span>
            </div>
          </div>
        )}

        {/* Filters */}
        <div className="alert-filters mb-3">
          <Form.Group className="filter-group">
            <Form.Label>Filter by severity</Form.Label>
            <Form.Select
              aria-label="Filter by severity"
              onChange={(e) => setFilter({ ...filter, severity: e.target.value ? [e.target.value as AlertSeverity] : undefined })}
            >
              <option value="">All Severities</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
              <option value="Info">Info</option>
            </Form.Select>
          </Form.Group>

          <Form.Group className="filter-group">
            <Form.Label>Filter by status</Form.Label>
            <Form.Select
              aria-label="Filter by status"
              onChange={(e) => setFilter({ ...filter, status: e.target.value ? [e.target.value as AlertStatus] : undefined })}
            >
              <option value="">All Statuses</option>
              <option value="New">New</option>
              <option value="Acknowledged">Acknowledged</option>
              <option value="Resolved">Resolved</option>
            </Form.Select>
          </Form.Group>
        </div>

        {/* Bulk Actions */}
        {selectedAlerts.size > 0 && (
          <div className="bulk-actions mb-3">
            <Button variant="warning" size="sm" onClick={handleBulkAcknowledge}>
              Acknowledge Selected ({selectedAlerts.size})
            </Button>
          </div>
        )}

        {/* Alerts Table */}
        {loading ? (
          <div className="text-center">
            <Spinner animation="border" />
          </div>
        ) : (
          <>
            <Table hover responsive>
              <thead>
                <tr>
                  <th>
                    <Form.Check
                      aria-label="Select all alerts"
                      onChange={handleSelectAll}
                    />
                  </th>
                  <th>Severity</th>
                  <th>Type</th>
                  <th>Message</th>
                  <th>Status</th>
                  <th>Time</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {paginatedAlerts.map((alert) => (
                  <tr key={alert.id}>
                    <td>
                      <Form.Check
                        checked={selectedAlerts.has(alert.id)}
                        onChange={() => handleSelectAlert(alert.id)}
                      />
                    </td>
                    <td>
                      <Badge bg={getSeverityBadge(alert.severity)}>{alert.severity}</Badge>
                    </td>
                    <td>{alert.alertType}</td>
                    <td>{alert.message}</td>
                    <td>
                      <Badge bg={getStatusBadge(alert.status)}>{alert.status}</Badge>
                    </td>
                    <td>{new Date(alert.timestamp).toLocaleString()}</td>
                    <td>
                      {alert.status === 'New' && (
                        <Button
                          variant="outline-warning"
                          size="sm"
                          onClick={() => handleAcknowledge(alert.id)}
                        >
                          Acknowledge
                        </Button>
                      )}
                      {alert.status !== 'Resolved' && (
                        <Button
                          variant="outline-success"
                          size="sm"
                          className="ms-1"
                          onClick={() => handleResolve(alert.id)}
                        >
                          Resolve
                        </Button>
                      )}
                      <Button
                        variant="outline-primary"
                        size="sm"
                        className="ms-1"
                        onClick={() => openDetails(alert)}
                      >
                        Details
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </Table>

            {/* Pagination */}
            {totalPages > 1 && (
              <Pagination className="justify-content-center">
                <Pagination.Prev
                  onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                  disabled={currentPage === 1}
                />
                {[...Array(totalPages)].map((_, i) => (
                  <Pagination.Item
                    key={i + 1}
                    active={i + 1 === currentPage}
                    onClick={() => setCurrentPage(i + 1)}
                  >
                    {i + 1}
                  </Pagination.Item>
                ))}
                <Pagination.Next
                  onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                  disabled={currentPage === totalPages}
                />
              </Pagination>
            )}
          </>
        )}
      </Card.Body>

      {/* Alert Detail Modal */}
      <Modal show={showModal} onHide={closeDetails}>
        <Modal.Header closeButton>
          <Modal.Title>Alert Details</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          {selectedAlert && (
            <div>
              <p><strong>Type:</strong> {selectedAlert.alertType}</p>
              <p><strong>Severity:</strong> {selectedAlert.severity}</p>
              <p><strong>Status:</strong> {selectedAlert.status}</p>
              <p><strong>Message:</strong> {selectedAlert.message}</p>
              <p><strong>Time:</strong> {new Date(selectedAlert.timestamp).toLocaleString()}</p>
              {selectedAlert.metadata && (
                <div>
                  <strong>Metadata:</strong>
                  <pre>{JSON.stringify(selectedAlert.metadata, null, 2)}</pre>
                </div>
              )}
            </div>
          )}
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={closeDetails}>
            Close
          </Button>
        </Modal.Footer>
      </Modal>
    </Card>
  );
};

export default AlertPanel;
