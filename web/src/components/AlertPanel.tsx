import React, { useEffect, useState } from 'react';
import { Card, Button, Form, Table, Badge, Modal, Spinner, Alert as BootstrapAlert, Pagination } from 'react-bootstrap';
import apiService from '../services/api';
import webSocketService from '../services/websocket';
import { Alert, AlertSeverity, AlertStatus, AlertFilter, AlertStats } from '../types/alerts';
import './AlertPanel.css';
import './DetailsModal.css';

const ITEMS_PER_PAGE = 10;

/** Read an alert id out of a "#alerts/{id}" location hash. */
export const alertIdFromHash = (hash: string): string | null => {
  const match = /^#?alerts\/(.+)$/.exec(hash);
  return match ? decodeURIComponent(match[1]) : null;
};

/** Page numbers around `current`, plus first, last and ellipses. Rendering
 *  every page button overflowed the card once alert counts reached five
 *  digits; this keeps the row short whatever the total. */
export const pageItems = (current: number, total: number): (number | 'ellipsis')[] => {
  if (total <= 9) {
    return Array.from({ length: total }, (_, index) => index + 1);
  }
  const wanted = new Set([1, total, current - 1, current, current + 1]);
  if (current <= 4) {
    [2, 3, 4, 5].forEach((page) => wanted.add(page));
  }
  if (current >= total - 3) {
    [total - 1, total - 2, total - 3, total - 4].forEach((page) => wanted.add(page));
  }
  const items: (number | 'ellipsis')[] = [];
  let previous = 0;
  for (const page of [...wanted]
    .filter((page) => page >= 1 && page <= total)
    .sort((a, b) => a - b)) {
    if (previous && page - previous > 1) {
      items.push('ellipsis');
    }
    items.push(page);
    previous = page;
  }
  return items;
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
    // A new filter shrinks the list; staying on page 500 of what used to be
    // 2700 pages shows an empty table behind a pagination row that no longer
    // matches. Start over.
    setCurrentPage(1);
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

        <div className="alert-toolbar">
          {/* Statistics */}
          {stats && (
            <div className="alert-stats">
              <div className="stat-item">
                <span className="stat-label">Total</span>
                <span className="stat-value">{stats.totalCount.toLocaleString()}</span>
              </div>
              <div className="stat-item">
                <span className="stat-label">New</span>
                <span className="stat-value new">{stats.newCount.toLocaleString()}</span>
              </div>
              <div className="stat-item">
                <span className="stat-label">Acknowledged</span>
                <span className="stat-value acknowledged">{stats.acknowledgedCount.toLocaleString()}</span>
              </div>
              <div className="stat-item">
                <span className="stat-label">Resolved</span>
                <span className="stat-value resolved">{stats.resolvedCount.toLocaleString()}</span>
              </div>
            </div>
          )}

          {/* Filters */}
          <div className="alert-filters">
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

        </div>

        {!loading && alerts.length > 0 && (
          <Form.Check
            className="alert-selection"
            label="Select all alerts"
            id="select-all-alerts"
            checked={selectedAlerts.size === alerts.length}
            onChange={handleSelectAll}
          />
        )}

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
            <Spinner animation="border" role="status"><span className="visually-hidden">Loading alerts...</span></Spinner>
          </div>
        ) : (
          <>
            <Table hover responsive className="alerts-table">
              <caption className="visually-hidden">Recent security alerts</caption>
              <colgroup>
                <col className="select-column" />
                <col className="severity-column" />
                <col className="type-column" />
                <col />
                <col className="status-column" />
                <col className="time-column" />
                <col className="actions-column" />
              </colgroup>
              <thead>
                <tr>
                  <th>
                    <span className="visually-hidden">Select</span>
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
                        aria-label={`Select alert ${alert.id}`}
                        checked={selectedAlerts.has(alert.id)}
                        onChange={() => handleSelectAlert(alert.id)}
                      />
                    </td>
                    <td data-label="Severity">
                      <Badge bg={getSeverityBadge(alert.severity)}>{alert.severity}</Badge>
                    </td>
                    <td data-label="Type" className="alert-type">{alert.alertType.replace(/([a-z])([A-Z])/g, '$1 $2')}</td>
                    <td data-label="Message" className="alert-message">
                      {alert.message.split(/((?:sha256:)?[a-f0-9]{64})/gi).map((part, index) =>
                        /^(?:sha256:)?[a-f0-9]{64}$/i.test(part)
                          ? <code key={index} className="alert-hash">{part}</code>
                          : part
                      )}
                    </td>
                    <td data-label="Status">
                      <Badge bg={getStatusBadge(alert.status)}>{alert.status}</Badge>
                    </td>
                    <td data-label="Time" className="alert-time">
                      <time dateTime={alert.timestamp}>
                        <span>{new Date(alert.timestamp).toLocaleDateString()}</span>
                        <span>{new Date(alert.timestamp).toLocaleTimeString()}</span>
                      </time>
                    </td>
                    <td className="alert-action-cell">
                      <div className="alert-actions">
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
                            onClick={() => handleResolve(alert.id)}
                          >
                            Resolve
                          </Button>
                        )}
                        <Button
                          variant="outline-primary"
                          size="sm"
                          onClick={() => openDetails(alert)}
                        >
                          Details
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </Table>

            {!error && alerts.length === 0 && <p className="alert-empty" role="status">No alerts match the selected filters.</p>}
          </>
        )}
      </Card.Body>
      {!loading && alerts.length > 0 && (
        <Card.Footer className="alert-footer">
          <span className="alert-page-summary">
            {(currentPage - 1) * ITEMS_PER_PAGE + 1}–{Math.min(currentPage * ITEMS_PER_PAGE, alerts.length)} of {alerts.length.toLocaleString()} alerts
          </span>

          {totalPages > 1 && (
            <nav aria-label="Alert pages">
              <Pagination size="sm">
                <Pagination.Prev
                  onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                  disabled={currentPage === 1}
                />
                {pageItems(currentPage, totalPages).map((item, index) =>
                  item === 'ellipsis' ? (
                    <Pagination.Ellipsis key={`gap-${index}`} disabled />
                  ) : (
                    <Pagination.Item
                      key={item}
                      active={item === currentPage}
                      onClick={() => setCurrentPage(item)}
                    >
                      {item}
                    </Pagination.Item>
                  )
                )}
                <Pagination.Next
                  onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                  disabled={currentPage === totalPages}
                />
              </Pagination>
            </nav>
          )}
        </Card.Footer>
      )}

      {/* Alert Detail Modal */}
      <Modal className="security-details-modal alert-details-modal" size="lg" centered scrollable aria-labelledby="alert-details-title" show={showModal} onHide={closeDetails}>
        <Modal.Header closeButton>
          <Modal.Title as="h2" id="alert-details-title">Alert Details</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          {selectedAlert && (
            <>
              <dl className="detail-grid">
                <dt>ID</dt><dd><code>{selectedAlert.id}</code></dd>
                <dt>Type</dt><dd>{selectedAlert.alertType}</dd>
                <dt>Severity</dt><dd><Badge bg={getSeverityBadge(selectedAlert.severity)}>{selectedAlert.severity}</Badge></dd>
                <dt>Status</dt><dd>{selectedAlert.status}</dd>
                <dt>Time</dt><dd><time dateTime={selectedAlert.timestamp}>{new Date(selectedAlert.timestamp).toLocaleString()}</time></dd>
                <dt>Message</dt><dd className="detail-message">{selectedAlert.message}</dd>
              </dl>
              {selectedAlert.metadata && (
                <section className="detail-metadata" aria-label="Alert metadata">
                  <h3>Metadata</h3>
                  <pre>{JSON.stringify(selectedAlert.metadata, null, 2)}</pre>
                </section>
              )}
            </>
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
