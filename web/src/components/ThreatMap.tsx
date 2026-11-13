import React, { useEffect, useState } from 'react';
import { Card, Form, Spinner } from 'react-bootstrap';
import { BarChart, Bar, PieChart, Pie, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, Cell } from 'recharts';
import apiService from '../services/api';
import { Threat, ThreatStatistics } from '../types/security';
import './ThreatMap.css';

const SEVERITY_COLORS: Record<string, string> = { Info: '#3674b5', Low: '#148267', Medium: '#b7790b', High: '#c45a24', Critical: '#b83244' };

const ThreatMap: React.FC = () => {
  const [threats, setThreats] = useState<Threat[]>([]);
  const [statistics, setStatistics] = useState<ThreatStatistics | null>(null);
  const [loading, setLoading] = useState(true);
  const [dateFrom, setDateFrom] = useState('');
  const [dateTo, setDateTo] = useState('');

  useEffect(() => {
    loadData();
  }, [dateFrom, dateTo]);

  const loadData = async () => {
    try {
      setLoading(true);
      const [threatsData, statsData] = await Promise.all([
        apiService.getThreats(),
        apiService.getThreatStatistics(),
      ]);
      setThreats(threatsData);
      setStatistics(statsData);
    } catch (err) {
      console.error('Error loading threat data:', err);
    } finally {
      setLoading(false);
    }
  };

  const getTypeData = () => {
    if (!statistics) return [];
    const byType = statistics.byType || {};
    return Object.entries(byType).map(([name, value]) => ({
      name,
      value,
    }));
  };

  const getSeverityData = () => {
    if (!statistics) return [];
    const bySeverity = statistics.bySeverity || {};
    return Object.entries(bySeverity).map(([name, value]) => ({
      name,
      value,
    }));
  };

  const getTimelineData = () => {
    // Group threats by date
    const grouped: Record<string, number> = {};
    threats.forEach((threat) => {
      const date = new Date(threat.timestamp).toLocaleDateString();
      grouped[date] = (grouped[date] || 0) + 1;
    });
    return Object.entries(grouped)
      .slice(-7)
      .map(([date, count]) => ({ date, count }));
  };

  return (
    <Card className="threat-map">
      <Card.Header>
        <Card.Title>Threat Map</Card.Title>
      </Card.Header>
      <Card.Body>
        {/* Date Filter */}
        <div className="threat-toolbar">
          <div className="threat-filters">
            <Form.Group className="filter-group">
              <Form.Label>From</Form.Label>
              <Form.Control
                type="date"
                value={dateFrom}
                onChange={(e) => setDateFrom(e.target.value)}
                aria-label="From"
              />
            </Form.Group>
            <Form.Group className="filter-group">
              <Form.Label>To</Form.Label>
              <Form.Control
                type="date"
                value={dateTo}
                onChange={(e) => setDateTo(e.target.value)}
                aria-label="To"
              />
            </Form.Group>
          </div>

          {/* Statistics Summary */}
          {statistics && (
            <div className="threat-summary">
              <div className="summary-item">
                <span className="summary-label">Total Threats</span>
                <span className="summary-value">{statistics.totalThreats.toLocaleString()}</span>
              </div>
              <div className="summary-item">
                <span className="summary-label">Trend</span>
                <span className={`summary-value ${statistics.trend}`}>
                  {statistics.trend}
                </span>
              </div>
            </div>
          )}

        </div>

        {loading ? (
          <div className="text-center">
            <Spinner animation="border" role="status"><span className="visually-hidden">Loading threats...</span></Spinner>
          </div>
        ) : (
          <>
            {/* Charts Row 1 */}
            <div className="charts-row">
              <div className="chart-container">
                <h5>Threat Type Distribution</h5>
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={getTypeData()} layout="vertical" margin={{ top: 8, right: 20, bottom: 8, left: 0 }} accessibilityLayer>
                    <CartesianGrid strokeDasharray="3 3" horizontal={false} stroke="#e5eaf0" />
                    <XAxis type="number" allowDecimals={false} tick={{ fontSize: 11, fill: '#526379' }} tickLine={false} axisLine={false} tickFormatter={value => Intl.NumberFormat(undefined, { notation: 'compact' }).format(value)} />
                    <YAxis type="category" dataKey="name" width={124} tick={{ fontSize: 11, fill: '#526379' }} tickLine={false} axisLine={false} tickFormatter={(value: string) => value.length > 20 ? `${value.slice(0, 18)}…` : value} />
                    <Tooltip cursor={{ fill: '#eff5ff' }} />
                    <Bar dataKey="value" name="Threats" fill="#3866b7" maxBarSize={32} radius={[0, 4, 4, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>

              <div className="chart-container">
                <h5>Severity Breakdown</h5>
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie
                      data={getSeverityData()}
                      cx="50%"
                      cy="43%"
                      innerRadius={48}
                      outerRadius={80}
                      paddingAngle={2}
                      nameKey="name"
                      dataKey="value"
                    >
                      {getSeverityData().map((entry) => (
                        <Cell key={entry.name} fill={SEVERITY_COLORS[entry.name] || '#526379'} />
                      ))}
                    </Pie>
                    <Tooltip />
                    <Legend iconType="circle" iconSize={8} verticalAlign="bottom" wrapperStyle={{ fontSize: 12, paddingTop: 12 }} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Charts Row 2 */}
            <div className="charts-row">
              <div className="chart-container full-width">
                <h5>Threat Timeline</h5>
                <ResponsiveContainer width="100%" height={300}>
                  <LineChart data={getTimelineData()} margin={{ top: 12, right: 20, bottom: 8, left: 0 }} accessibilityLayer>
                    <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#e5eaf0" />
                    <XAxis dataKey="date" tick={{ fontSize: 11, fill: '#526379' }} minTickGap={24} tickLine={false} axisLine={false} />
                    <YAxis width={48} allowDecimals={false} tick={{ fontSize: 11, fill: '#526379' }} tickLine={false} axisLine={false} tickFormatter={value => Intl.NumberFormat(undefined, { notation: 'compact' }).format(value)} />
                    <Tooltip />
                    <Line type="monotone" dataKey="count" stroke="#3866b7" strokeWidth={2} dot={false} activeDot={{ r: 5 }} name="Total Threats" />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Recent Threats List */}
            <div className="recent-threats">
              <h5>Recent Threats</h5>
              <div className="threat-list">
                {threats.length === 0 && <p className="threat-empty" role="status">No recent threats.</p>}
                {threats.slice(0, 5).map((threat) => (
                  <div key={threat.id} className="threat-item">
                    <div className="threat-info">
                      <span className="threat-type">{threat.type}</span>
                      <span className="threat-source">{threat.source}</span>
                    </div>
                    <div className="threat-meta">
                      <Badge severity={threat.severity}>{threat.severity}</Badge>
                      <span className="threat-score">Score: {threat.score}</span>
                      <time className="threat-time" dateTime={threat.timestamp}>{new Date(threat.timestamp).toLocaleString()}</time>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </>
        )}
      </Card.Body>
    </Card>
  );
};

const Badge: React.FC<{ severity: string; children: React.ReactNode }> = ({ severity, children }) => (
  <span className={`threat-badge severity-${severity.toLowerCase()}`}>{children}</span>
);

export default ThreatMap;
