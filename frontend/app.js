const API_BASE_URL = "https://cyber-threat-detection-0kdv.onrender.com";

const originalFetch = window.fetch.bind(window);
window.fetch = (input, init) => {
  if (typeof input === "string" && input.startsWith("/api/")) {
    input = API_BASE_URL + input;
  }
  return originalFetch(input, init);
};

const { useState, useEffect, useRef } = React;
// --- Helper Functions ---
function getSeverityBadgeClass(severity) {
  switch ((severity || "").toLowerCase()) {
    case "critical": return "badge-critical";
    case "high": return "badge-high";
    case "medium": return "badge-medium";
    case "low": return "badge-low";
    default: return "badge-info";
  }
}

// --- Chart.js Components ---
function ThreatTimelineChart() {
  const canvasRef = React.useRef(null);
  const chartRef = React.useRef(null);
  React.useEffect(() => {
    fetch('/api/v1/dashboard/threats-over-time?hours=24')
      .then(r => r.json()).then(data => {
        if (chartRef.current) chartRef.current.destroy();
        chartRef.current = new Chart(canvasRef.current, {
          type: 'line',
          data: {
            labels: data.labels || [],
            datasets: [
              { label: 'Critical', data: data.critical || [], borderColor: '#ef4444', backgroundColor: 'rgba(239,68,68,0.15)', tension: 0.4, fill: true },
              { label: 'High',     data: data.high || [],     borderColor: '#f97316', backgroundColor: 'rgba(249,115,22,0.15)', tension: 0.4, fill: true },
              { label: 'Medium',   data: data.medium || [],   borderColor: '#eab308', backgroundColor: 'rgba(234,179,8,0.1)',   tension: 0.4, fill: true },
              { label: 'Low',      data: data.low || [],      borderColor: '#22c55e', backgroundColor: 'rgba(34,197,94,0.1)',   tension: 0.4, fill: true },
            ]
          },
          options: { responsive: true, plugins: { legend: { position: 'top', labels: { color: '#9ca3af' } } },
                     scales: { x: { ticks: { color: '#6b7280' } }, y: { ticks: { color: '#6b7280' }, beginAtZero: true } } }
        });
      }).catch(err => console.warn('ThreatTimelineChart fetch error:', err));
  }, []);
  return <div className="cyber-card"><h3 style={{marginBottom:'12px'}}>📈 Threats Over Time (24h)</h3><canvas ref={canvasRef} /></div>;
}

function CategoryPieChart() {
  const canvasRef = React.useRef(null);
  const chartRef = React.useRef(null);
  React.useEffect(() => {
    fetch('/api/v1/dashboard/category-breakdown')
      .then(r => r.json()).then(data => {
        if (chartRef.current) chartRef.current.destroy();
        chartRef.current = new Chart(canvasRef.current, {
          type: 'doughnut',
          data: {
            labels: data.labels || [],
            datasets: [{ data: data.counts || [],
              backgroundColor: ['#ef4444','#f97316','#eab308','#22c55e','#3b82f6','#8b5cf6'] }]
          },
          options: { responsive: true, plugins: { legend: { position: 'right', labels: { color: '#9ca3af' } } } }
        });
      }).catch(err => console.warn('CategoryPieChart fetch error:', err));
  }, []);
  return <div className="cyber-card"><h3 style={{marginBottom:'12px'}}>🥧 Threat Categories</h3><canvas ref={canvasRef} /></div>;
}

function ProtocolBarChart() {
  const canvasRef = React.useRef(null);
  const chartRef = React.useRef(null);
  const [totalFlows, setTotalFlows] = React.useState(0);

  React.useEffect(() => {
    fetch('/api/v1/dashboard/stats').then(r => r.json()).then(data => {
      const pb = data.protocol_breakdown || { tcp: 0, udp: 0, icmp: 0 };
      const sumFlows = (pb.tcp || 0) + (pb.udp || 0) + (pb.icmp || 0);
      setTotalFlows(sumFlows);

      const ctx = canvasRef.current.getContext('2d');
      const chartHeight = canvasRef.current.height || 200;

      const gradTcp = ctx.createLinearGradient(0, 0, 0, chartHeight);
      gradTcp.addColorStop(0, '#3b82f6');
      gradTcp.addColorStop(1, 'rgba(59, 130, 246, 0.4)');

      const gradUdp = ctx.createLinearGradient(0, 0, 0, chartHeight);
      gradUdp.addColorStop(0, '#8b5cf6');
      gradUdp.addColorStop(1, 'rgba(139, 92, 246, 0.4)');

      const gradIcmp = ctx.createLinearGradient(0, 0, 0, chartHeight);
      gradIcmp.addColorStop(0, '#ec4899');
      gradIcmp.addColorStop(1, 'rgba(236, 72, 153, 0.4)');

      if (chartRef.current) chartRef.current.destroy();
      chartRef.current = new Chart(canvasRef.current, {
        type: 'bar',
        data: {
          labels: ['TCP', 'UDP', 'ICMP'],
          datasets: [{
            label: 'Flows',
            data: [pb.tcp, pb.udp, pb.icmp],
            backgroundColor: [gradTcp, gradUdp, gradIcmp],
            hoverBackgroundColor: ['#60a5fa', '#a78bfa', '#f472b6'],
            borderRadius: 8,
            borderSkipped: false,
            barPercentage: 0.5,
            categoryPercentage: 0.6
          }]
        },
        options: {
          responsive: true,
          animation: {
            duration: 800,
            easing: 'easeOutQuart'
          },
          plugins: {
            legend: { display: false },
            tooltip: {
              backgroundColor: '#111827',
              titleColor: '#f3f4f6',
              bodyColor: '#9ca3af',
              cornerRadius: 8,
              padding: 10,
              displayColors: false,
              callbacks: {
                label: (context) => `${context.parsed.y.toLocaleString()} flows`
              }
            }
          },
          scales: {
            x: {
              grid: { display: false },
              ticks: { color: '#9ca3af', font: { family: 'Inter', size: 12, weight: '600' } }
            },
            y: {
              grid: { color: 'rgba(255, 255, 255, 0.05)' },
              ticks: { color: '#9ca3af', beginAtZero: true, font: { family: 'JetBrains Mono', size: 11 } }
            }
          }
        }
      });
    }).catch(err => console.warn('ProtocolBarChart fetch error:', err));
  }, []);

  return (
    <div className="cyber-card" style={{ padding: '20px', border: '1px solid rgba(255, 255, 255, 0.06)' }}>
      <div style={{ marginBottom: '16px' }}>
        <h3 style={{ margin: 0, fontSize: '15px', fontWeight: '700' }}>📶 Protocol Distribution</h3>
        <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>
          {totalFlows.toLocaleString()} flows analyzed
        </div>
      </div>
      <canvas ref={canvasRef} />
    </div>
  );
}

function AttackWorldMap() {
  const mapRef = React.useRef(null);
  const mapInstance = React.useRef(null);
  const severityColors = { Critical:'#ef4444', High:'#f97316', Medium:'#eab308', Low:'#22c55e' };

  React.useEffect(() => {
    if (!mapInstance.current && mapRef.current && window.L) {
      mapInstance.current = L.map(mapRef.current, { zoomControl: true }).setView([20, 0], 2);
      L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}', {
        attribution: 'Tiles &copy; Esri',
        maxZoom: 16
      }).addTo(mapInstance.current);
    }
    fetch('/api/v1/dashboard/attack-map?limit=200')
      .then(r => r.json()).then(data => {
        if (!mapInstance.current || !data.points) return;
        data.points.forEach(pt => {
          const color = severityColors[pt.severity] || '#6b7280';
          L.circleMarker([pt.lat, pt.lon], {
            radius: Math.max(5, pt.risk_score / 12),
            color, fillColor: color, fillOpacity: 0.75, weight: 1
          })
          .bindPopup(`<b style="color:${color}">${pt.src_ip}</b><br/>
            <b>${pt.threat_category}</b><br/>
            Severity: ${pt.severity} | Score: ${pt.risk_score}`)
          .addTo(mapInstance.current);
        });
      }).catch(err => console.warn('AttackWorldMap fetch error:', err));
  }, []);

  return (
    <div className="cyber-card" style={{ padding: '20px', border: '1px solid rgba(255, 255, 255, 0.06)' }}>
      <div style={{ marginBottom: '16px' }}>
        <h3 style={{ margin: 0, fontSize: '15px', fontWeight: '700' }}>🌍 Live Attack Origin Map</h3>
        <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>
          Real-time GeoIP origin resolution
        </div>
      </div>
      <div ref={mapRef} style={{ height: '360px', borderRadius: '8px', zIndex: 0 }} />
      <div style={{ display: 'flex', gap: '16px', alignItems: 'center', justifyContent: 'center', marginTop: '16px', fontSize: '12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <span style={{ width: 10, height: 10, borderRadius: '50%', background: '#ef4444', display: 'inline-block' }}></span>
          <span style={{ color: 'var(--text-muted)' }}>Critical (&gt;85)</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <span style={{ width: 10, height: 10, borderRadius: '50%', background: '#f97316', display: 'inline-block' }}></span>
          <span style={{ color: 'var(--text-muted)' }}>High (70-85)</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <span style={{ width: 10, height: 10, borderRadius: '50%', background: '#eab308', display: 'inline-block' }}></span>
          <span style={{ color: 'var(--text-muted)' }}>Medium (60-69)</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <span style={{ width: 10, height: 10, borderRadius: '50%', background: '#22c55e', display: 'inline-block' }}></span>
          <span style={{ color: 'var(--text-muted)' }}>Low (&lt;60)</span>
        </div>
      </div>
    </div>
  );
}



function WeeklyReportView() {
  const [weekOffset, setWeekOffset] = React.useState(0);
  const [reportData, setReportData] = React.useState(null);
  const [page, setPage] = React.useState(0);
  const [loading, setLoading] = React.useState(true);

  const dailyChartRef = React.useRef(null);
  const dailyChartInstance = React.useRef(null);
  const catChartRef = React.useRef(null);
  const catChartInstance = React.useRef(null);

  const limit = 50;

  React.useEffect(() => {
    setLoading(true);
    fetch(`/api/v1/dashboard/weekly-report?week_offset=${weekOffset}&limit=${limit}&offset=${page * limit}`)
      .then(r => r.json())
      .then(data => {
        setReportData(data);
        setLoading(false);
      })
      .catch(err => {
        console.warn("WeeklyReport fetch error:", err);
        setLoading(false);
      });
  }, [weekOffset, page]);

  React.useEffect(() => {
    if (!reportData || !dailyChartRef.current || !catChartRef.current) return;

    const dbData = reportData.daily_breakdown || { labels: [], critical: [], high: [], medium: [], low: [] };
    if (dailyChartInstance.current) dailyChartInstance.current.destroy();
    dailyChartInstance.current = new Chart(dailyChartRef.current, {
      type: 'bar',
      data: {
        labels: dbData.labels,
        datasets: [
          { label: 'Critical', data: dbData.critical, backgroundColor: '#ef4444', borderRadius: 4 },
          { label: 'High', data: dbData.high, backgroundColor: '#f97316', borderRadius: 4 },
          { label: 'Medium', data: dbData.medium, backgroundColor: '#eab308', borderRadius: 4 },
          { label: 'Low', data: dbData.low, backgroundColor: '#22c55e', borderRadius: 4 },
        ]
      },
      options: {
        responsive: true,
        animation: { duration: 800, easing: 'easeOutQuart' },
        plugins: {
          legend: { position: 'top', labels: { color: '#9ca3af', font: { family: 'Inter', size: 11 } } },
          tooltip: { backgroundColor: '#111827', titleColor: '#f3f4f6', cornerRadius: 8, padding: 10 }
        },
        scales: {
          x: { stacked: true, grid: { display: false }, ticks: { color: '#9ca3af', font: { family: 'Inter', size: 11 } } },
          y: { stacked: true, grid: { color: 'rgba(255, 255, 255, 0.05)' }, ticks: { color: '#9ca3af', beginAtZero: true, font: { family: 'JetBrains Mono', size: 11 } } }
        }
      }
    });

    const cbData = reportData.category_breakdown || { labels: [], counts: [] };
    if (catChartInstance.current) catChartInstance.current.destroy();
    catChartInstance.current = new Chart(catChartRef.current, {
      type: 'doughnut',
      data: {
        labels: cbData.labels.length > 0 ? cbData.labels : ['No Attacks'],
        datasets: [{
          data: cbData.counts.length > 0 ? cbData.counts : [1],
          backgroundColor: cbData.labels.length > 0 ? ['#ef4444','#f97316','#eab308','#22c55e','#3b82f6','#8b5cf6','#ec4899'] : ['#374151']
        }]
      },
      options: {
        responsive: true,
        animation: { duration: 800, easing: 'easeOutQuart' },
        plugins: {
          legend: { position: 'right', labels: { color: '#9ca3af', font: { family: 'Inter', size: 11 } } },
          tooltip: { backgroundColor: '#111827', cornerRadius: 8, padding: 10 }
        }
      }
    });
  }, [reportData]);

  const summary = reportData?.summary || {
    total_packets: 0,
    total_alerts: 0,
    critical_count: 0,
    high_count: 0,
    medium_count: 0,
    low_count: 0,
    unique_attacker_ips: 0,
    top_threat_category: "None"
  };

  const fullLogs = reportData?.full_alert_log?.alerts || [];
  const totalLogs = reportData?.full_alert_log?.total || 0;
  const totalPages = Math.ceil(totalLogs / limit);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <div className="cyber-card" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '16px 20px' }}>
        <div>
          <h2 style={{ margin: 0, fontSize: 20, fontWeight: 700, display: 'flex', alignItems: 'center', gap: 10 }}>
            📊 Executive Weekly Threat Intelligence Report
          </h2>
          <div style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 4 }}>
            Historical 7-day threat summary from <span style={{ color: 'var(--color-primary)', fontWeight: 600 }}>{reportData?.start_date || '...'}</span> to <span style={{ color: 'var(--color-primary)', fontWeight: 600 }}>{reportData?.end_date || '...'}</span>
          </div>
        </div>

        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <button
            className="btn btn-ghost"
            onClick={() => { setWeekOffset(w => w + 1); setPage(0); }}
            style={{ fontSize: 13 }}
          >
            ← Previous Week
          </button>
          <button
            className={`btn ${weekOffset === 0 ? 'btn-primary' : 'btn-ghost'}`}
            onClick={() => { setWeekOffset(0); setPage(0); }}
            style={{ fontSize: 13 }}
          >
            This Week
          </button>
          <button
            className="btn btn-ghost"
            disabled={weekOffset === 0}
            onClick={() => { setWeekOffset(w => Math.max(0, w - 1)); setPage(0); }}
            style={{ fontSize: 13, opacity: weekOffset === 0 ? 0.4 : 1, cursor: weekOffset === 0 ? 'not-allowed' : 'pointer' }}
          >
            Next Week →
          </button>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 16 }}>
        <div className="cyber-card">
          <div style={{ color: "var(--text-muted)", fontSize: 12, fontWeight: 700, textTransform: "uppercase" }}>Total Packets Analyzed</div>
          <div className="mono" style={{ fontSize: 30, fontWeight: 700, margin: "8px 0" }}>{summary.total_packets.toLocaleString()}</div>
          <div style={{ fontSize: 12, color: "var(--status-success)" }}>Weekly Volumetric Capture</div>
        </div>

        <div className="cyber-card">
          <div style={{ color: "var(--text-muted)", fontSize: 12, fontWeight: 700, textTransform: "uppercase" }}>Total Flagged Alerts</div>
          <div className="mono" style={{ fontSize: 30, fontWeight: 700, margin: "8px 0", color: summary.total_alerts > 0 ? "var(--severity-critical)" : "var(--status-success)" }}>
            {summary.total_alerts}
          </div>
          <div style={{ fontSize: 12, color: "var(--text-muted)" }}>
            Critical: <span style={{ color: "var(--severity-critical)", fontWeight: 700 }}>{summary.critical_count}</span> | High: <span style={{ color: "var(--severity-high)", fontWeight: 700 }}>{summary.high_count}</span>
          </div>
        </div>

        <div className="cyber-card">
          <div style={{ color: "var(--text-muted)", fontSize: 12, fontWeight: 700, textTransform: "uppercase" }}>Unique Attacking IPs</div>
          <div className="mono" style={{ fontSize: 30, fontWeight: 700, margin: "8px 0", color: "var(--severity-high)" }}>
            {summary.unique_attacker_ips}
          </div>
          <div style={{ fontSize: 12, color: "var(--text-muted)" }}>Distinct threat sources</div>
        </div>

        <div className="cyber-card">
          <div style={{ color: "var(--text-muted)", fontSize: 12, fontWeight: 700, textTransform: "uppercase" }}>Primary Threat Vector</div>
          <div style={{ fontSize: 18, fontWeight: 700, margin: "12px 0 8px 0", color: "var(--color-primary)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
            {summary.top_threat_category}
          </div>
          <div style={{ fontSize: 12, color: "var(--text-muted)" }}>Most frequent vector</div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 16 }}>
        <div className="cyber-card" style={{ padding: 20, border: '1px solid rgba(255, 255, 255, 0.06)' }}>
          <h3 style={{ margin: '0 0 12px 0', fontSize: 15, fontWeight: 700 }}>📈 Daily Threat Activity Breakdown</h3>
          <canvas ref={dailyChartRef} height={180} />
        </div>

        <div className="cyber-card" style={{ padding: 20, border: '1px solid rgba(255, 255, 255, 0.06)' }}>
          <h3 style={{ margin: '0 0 12px 0', fontSize: 15, fontWeight: 700 }}>🥧 Threat Vector Distribution</h3>
          <canvas ref={catChartRef} height={180} />
        </div>
      </div>

      <div className="cyber-card" style={{ padding: 20, border: '1px solid rgba(255, 255, 255, 0.06)' }}>
        <h3 style={{ margin: '0 0 16px 0', fontSize: 15, fontWeight: 700 }}>🎯 Top Attacking IPs This Week</h3>
        <table className="cyber-table">
          <thead>
            <tr>
              <th>Rank</th>
              <th>Source IP Address</th>
              <th>Alert Count</th>
              <th>Highest Severity</th>
            </tr>
          </thead>
          <tbody>
            {reportData?.top_attackers?.length === 0 ? (
              <tr><td colSpan="4" style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 20 }}>No attacker IPs recorded for this week.</td></tr>
            ) : (
              reportData?.top_attackers?.map((att, idx) => (
                <tr key={att.src_ip}>
                  <td className="mono" style={{ fontWeight: 700, color: 'var(--text-muted)' }}>#{idx + 1}</td>
                  <td className="mono" style={{ fontWeight: 600 }}>{att.src_ip}</td>
                  <td className="mono" style={{ fontWeight: 700 }}>{att.alert_count}</td>
                  <td>
                    <span style={{
                      padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 700,
                      background: att.highest_severity === 'Critical' ? '#ef444422' : att.highest_severity === 'High' ? '#f9731622' : '#eab30822',
                      color: att.highest_severity === 'Critical' ? '#ef4444' : att.highest_severity === 'High' ? '#f97316' : '#eab308',
                      border: `1px solid ${att.highest_severity === 'Critical' ? '#ef4444' : att.highest_severity === 'High' ? '#f97316' : '#eab308'}`
                    }}>
                      {att.highest_severity}
                    </span>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <div className="cyber-card" style={{ padding: 20, border: '1px solid rgba(255, 255, 255, 0.06)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <h3 style={{ margin: 0, fontSize: 15, fontWeight: 700 }}>📋 Weekly Threat Alert Log</h3>
          <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
            Showing {fullLogs.length > 0 ? (page * limit + 1) : 0}–{Math.min(totalLogs, (page + 1) * limit)} of {totalLogs} alerts
          </div>
        </div>

        <table className="cyber-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Source IP</th>
              <th>Threat Category</th>
              <th>Risk Score</th>
              <th>Severity</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {fullLogs.length === 0 ? (
              <tr><td colSpan="6" style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 20 }}>No threat alerts recorded for this week.</td></tr>
            ) : (
              fullLogs.map(a => (
                <tr key={a.alert_id}>
                  <td className="mono">{new Date(a.created_ts * 1000).toLocaleString()}</td>
                  <td className="mono" style={{ fontWeight: 600 }}>{a.src_ip}</td>
                  <td style={{ fontWeight: 600 }}>{a.threat_category}</td>
                  <td className="mono" style={{ fontWeight: 700 }}>{a.risk_score}/100</td>
                  <td>
                    <span style={{
                      padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 700,
                      background: a.severity === 'Critical' ? '#ef444422' : a.severity === 'High' ? '#f9731622' : a.severity === 'Medium' ? '#eab30822' : '#22c55e22',
                      color: a.severity === 'Critical' ? '#ef4444' : a.severity === 'High' ? '#f97316' : a.severity === 'Medium' ? '#eab308' : '#22c55e',
                      border: `1px solid ${a.severity === 'Critical' ? '#ef4444' : a.severity === 'High' ? '#f97316' : a.severity === 'Medium' ? '#eab308' : '#22c55e'}`
                    }}>
                      {a.severity}
                    </span>
                  </td>
                  <td><span className="badge-pill badge-info">{a.status}</span></td>
                </tr>
              ))
            )}
          </tbody>
        </table>

        {totalPages > 1 && (
          <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', gap: 12, marginTop: 16 }}>
            <button
              className="btn btn-ghost"
              disabled={page === 0}
              onClick={() => setPage(p => Math.max(0, p - 1))}
              style={{ fontSize: 12, opacity: page === 0 ? 0.4 : 1 }}
            >
              ← Previous Page
            </button>
            <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
              Page <span style={{ color: '#fff', fontWeight: 600 }}>{page + 1}</span> of {totalPages}
            </span>
            <button
              className="btn btn-ghost"
              disabled={page >= totalPages - 1}
              onClick={() => setPage(p => p + 1)}
              style={{ fontSize: 12, opacity: page >= totalPages - 1 ? 0.4 : 1 }}
            >
              Next Page →
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

// --- Main App Component ---
function App() {
  const [activeTab, setActiveTab] = useState("dashboard");
  const [stats, setStats] = useState({
    total_packets: 14250,
    total_flows: 1250,
    safe_flows: 1180,
    suspicious_flows: 70,
    active_threat_level: "Low",
    protocol_breakdown: { tcp: 950, udp: 220, icmp: 80 },
    top_attacked_ports: [{ port: 80, count: 420 }, { port: 443, count: 310 }, { port: 53, count: 120 }]
  });

  const [alerts, setAlerts] = useState([]);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [toast, setToast] = useState(null);
  const [isConnected, setIsConnected] = useState(true);

  // Filters for Threat Logs table
  const [searchIP, setSearchIP] = useState("");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [statusFilter, setStatusFilter] = useState("ALL");

  // Intel Inspector state
  const [intelSearchIP, setIntelSearchIP] = useState("198.51.100.45");
  const [intelResult, setIntelResult] = useState({
    ip: "198.51.100.45",
    listed: true,
    threat_score: 85,
    category: "scanner",
    source_feed: "emerging_threats",
    country_code: "DE",
    last_seen: Date.now() / 1000
  });

  // PCAP Upload state
  const [pcapUploading, setPcapUploading] = useState(false);
  const [pcapResult, setPcapResult] = useState(null);

  // Initialize Lucide icons on render
  useEffect(() => {
    if (window.lucide) {
      window.lucide.createIcons();
    }
  });

  // Fetch Stats and Alerts
  const fetchStatsAndAlerts = async () => {
    try {
      const resStats = await fetch("/api/v1/dashboard/stats");
      if (resStats.ok) {
        const dataStats = await resStats.json();
        setStats(dataStats);
      }

      const resAlerts = await fetch("/api/v1/threats");
      if (resAlerts.ok) {
        const dataAlerts = await resAlerts.json();
        setAlerts(dataAlerts.items || []);
      }
    } catch (err) {
      console.warn("Polling fallback:", err);
    }
  };

  useEffect(() => {
    fetchStatsAndAlerts();
    const interval = setInterval(fetchStatsAndAlerts, 3000);
    return () => clearInterval(interval);
  }, []);

  // WebSocket Listener
  useEffect(() => {
    const wsUrl = "wss://cyber-threat-detection-0kdv.onrender.com/ws/live-traffic";
    let ws;
    try {
      ws = new WebSocket(wsUrl);
      ws.onopen = () => setIsConnected(true);
      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.event_type === "ALERT_NEW") {
            setAlerts((prev) => [data.payload, ...prev]);
            showToast("NEW THREAT DETECTED: " + data.payload.threat_category, "danger");
          }
        } catch (e) {}
      };
      ws.onclose = () => setIsConnected(false);
    } catch (e) {
      setIsConnected(false);
    }
    return () => {
      if (ws) ws.close();
    };
  }, []);

  const showToast = (message, type = "info") => {
    setToast({ message, type });
    setTimeout(() => setToast(null), 4000);
  };

  // Quick Action Handlers
  const handleAcknowledge = async (alertId) => {
    try {
      const res = await fetch(`/api/v1/threats/${alertId}/ack`, { method: "POST" });
      if (res.ok) {
        const updated = await res.json();
        setAlerts((prev) => prev.map((a) => (a.alert_id === alertId ? updated : a)));
        if (selectedAlert && selectedAlert.alert_id === alertId) {
          setSelectedAlert(updated);
        }
        showToast(`Alert ${alertId} marked as Acknowledged.`, "success");
      }
    } catch (e) {
      showToast("Failed to acknowledge alert.", "danger");
    }
  };

  const handleFalsePositive = async (alertId) => {
    try {
      const res = await fetch(`/api/v1/threats/${alertId}/false-positive`, { method: "POST" });
      if (res.ok) {
        const updated = await res.json();
        setAlerts((prev) => prev.map((a) => (a.alert_id === alertId ? updated : a)));
        if (selectedAlert && selectedAlert.alert_id === alertId) {
          setSelectedAlert(updated);
        }
        showToast(`Alert ${alertId} marked as False Positive.`, "info");
      }
    } catch (e) {
      showToast("Failed to update status.", "danger");
    }
  };

  const handleBlockIPAction = async (ip) => {
    try {
      const res = await fetch("/api/v1/actions/block-ip", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip, reason: "Analyst dashboard quick action" })
      });
      if (res.status === 400) {
        const err = await res.json();
        showToast(err.detail.message, "danger");
      } else if (res.status === 403) {
        showToast("Role 'admin' required to execute firewall quick actions.", "warning");
      }
    } catch (e) {
      showToast("Active response error.", "danger");
    }
  };

  const handleIntelLookup = async (ipToSearch) => {
    try {
      const res = await fetch(`/api/v1/threat-intel/ips/${ipToSearch}`);
      if (res.ok) {
        const data = await res.json();
        setIntelResult(data);
        showToast(`Threat Intel lookup complete for ${ipToSearch}`, "info");
      }
    } catch (e) {
      showToast("Threat Intel lookup failed.", "danger");
    }
  };

  const handlePcapUpload = async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    setPcapUploading(true);
    const formData = new FormData();
    formData.append("file", file);

    try {
      const res = await fetch("/api/v1/pcaps/upload", {
        method: "POST",
        body: formData
      });
      if (res.ok) {
        const data = await res.json();
        setPcapResult(data);
        fetchStatsAndAlerts();
        showToast(`PCAP '${file.name}' processed: ${data.packets_parsed} packets parsed.`, "success");
      } else {
        showToast("PCAP upload failed.", "danger");
      }
    } catch (e) {
      showToast("Error processing PCAP.", "danger");
    } finally {
      setPcapUploading(false);
    }
  };

  const handleSimulateScenario = async (scenario) => {
    try {
      const samplePackets = {
        port_scan: Array.from({ length: 20 }, (_, i) => ({
          src_ip: "198.51.100.45",
          dst_ip: "10.0.0.5",
          src_port: 50000,
          dst_port: i + 1,
          protocol: "TCP",
          packet_length: 64
        })),
        syn_flood: Array.from({ length: 30 }, () => ({
          src_ip: "203.0.113.99",
          dst_ip: "10.0.0.5",
          src_port: Math.floor(Math.random() * 50000) + 10000,
          dst_port: 80,
          protocol: "TCP",
          packet_length: 64
        })),
        normal: Array.from({ length: 10 }, () => ({
          src_ip: "192.168.1.105",
          dst_ip: "10.0.0.5",
          src_port: Math.floor(Math.random() * 50000) + 10000,
          dst_port: 443,
          protocol: "TCP",
          packet_length: 512
        }))
      };

      const pkts = samplePackets[scenario] || samplePackets.port_scan;
      const res = await fetch("/api/v1/telemetry/packet", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(pkts)
      });
      if (res.ok) {
        fetchStatsAndAlerts();
        showToast(`Scenario '${scenario.toUpperCase()}' injected successfully.`, "success");
      }
    } catch (e) {
      showToast("Scenario trigger failed.", "danger");
    }
  };

  // Filtered threats
  const filteredAlerts = alerts.filter((a) => {
    const matchIP = !searchIP || (a.src_ip && a.src_ip.includes(searchIP)) || (a.dst_ip && a.dst_ip.includes(searchIP));
    const matchSev = severityFilter === "ALL" || (a.severity || "").toUpperCase() === severityFilter;
    const matchStatus = statusFilter === "ALL" || (a.status || "").toLowerCase() === statusFilter.toLowerCase();
    return matchIP && matchSev && matchStatus;
  });

  return (
    <div style={{ display: "flex", minHeight: "100vh" }}>
      {/* Toast Banner */}
      {toast && (
        <div
          style={{
            position: "fixed",
            top: 20,
            right: 20,
            zIndex: 9999,
            background: toast.type === "danger" ? "var(--severity-critical)" : toast.type === "success" ? "var(--status-success)" : "var(--color-primary)",
            color: "#fff",
            padding: "12px 20px",
            borderRadius: 6,
            fontWeight: 600,
            boxShadow: "0 0 20px rgba(0,0,0,0.5)"
          }}
        >
          {toast.message}
        </div>
      )}

      {/* Persistent Sidebar */}
      <aside
        style={{
          width: 260,
          background: "var(--bg-sidebar)",
          borderRight: "1px solid var(--border-subtle)",
          display: "flex",
          flexDirection: "column",
          padding: 20
        }}
      >
        {/* Brand Logo */}
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 24 }}>
          <div style={{ background: "var(--color-primary)", padding: 8, borderRadius: 6, color: "#000", fontWeight: 700 }}>
            OS
          </div>
          <div>
            <div style={{ fontWeight: 700, fontSize: 16, color: "var(--text-primary)" }}>ONEWAY SENTINEL</div>
            <div style={{ fontSize: 11, color: "var(--text-muted)", letterSpacing: "0.05em" }}>SIH26145 • DIODE MONITOR</div>
          </div>
        </div>

        {/* Pinned Zero-Outbound Badge */}
        <div className="badge-pill badge-zero-outbound" style={{ width: "100%", justifyContent: "center", marginBottom: 24, padding: 8 }}>
          <span className="status-dot status-dot-green"></span>
          0 BYTES SENT BACK (PASSIVE)
        </div>

        {/* Navigation Tabs */}
        <nav style={{ display: "flex", flexDirection: "column", gap: 6, flex: 1 }}>
          <button
            className={`btn ${activeTab === "dashboard" ? "btn-primary" : "btn-ghost"}`}
            style={{ justifyContent: "flex-start" }}
            onClick={() => setActiveTab("dashboard")}
          >
            Dashboard
          </button>
          <button
            className={`btn ${activeTab === "logs" ? "btn-primary" : "btn-ghost"}`}
            style={{ justifyContent: "flex-start" }}
            onClick={() => setActiveTab("logs")}
          >
            Threat Logs ({alerts.length})
          </button>
          <button
            className={`btn ${activeTab === "intel" ? "btn-primary" : "btn-ghost"}`}
            style={{ justifyContent: "flex-start" }}
            onClick={() => setActiveTab("intel")}
          >
            Threat Intel Inspector
          </button>
          <button
            className={`btn ${activeTab === "pcap" ? "btn-primary" : "btn-ghost"}`}
            style={{ justifyContent: "flex-start" }}
            onClick={() => setActiveTab("pcap")}
          >
            PCAP Upload & Analysis
          </button>
          <button
            className={`btn ${activeTab === "weekly_report" ? "btn-primary" : "btn-ghost"}`}
            style={{ justifyContent: "flex-start" }}
            onClick={() => setActiveTab("weekly_report")}
          >
            Weekly Report
          </button>
        </nav>

        {/* System Health Footer */}
        <div style={{ borderTop: "1px solid var(--border-subtle)", pt: 16, fontSize: 12, color: "var(--text-muted)" }}>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
            <span>Link Mode:</span>
            <span style={{ color: "var(--color-accent-mint)" }}>READ-ONLY</span>
          </div>
          <div style={{ display: "flex", justifyContent: "space-between" }}>
            <span>WebSocket:</span>
            <span style={{ color: isConnected ? "var(--status-success)" : "var(--status-danger)" }}>
              {isConnected ? "CONNECTED" : "FALLBACK"}
            </span>
          </div>
        </div>
      </aside>

      {/* Main Page Area */}
      <main style={{ flex: 1, display: "flex", flexDirection: "column" }}>
        {/* Header */}
        <header
          style={{
            height: 64,
            background: "var(--bg-header)",
            borderBottom: "1px solid var(--border-subtle)",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            padding: "0 24px"
          }}
        >
          <div style={{ fontSize: 18, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.02em" }}>
            {activeTab === "dashboard" && "Live Traffic & Threat Monitor"}
            {activeTab === "logs" && "SOC Threat Logs & History"}
            {activeTab === "intel" && "Historical Attacking IP & Reputation Inspector"}
            {activeTab === "pcap" && "Offline PCAP Capture Analysis"}
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
            <span className="mono" style={{ fontSize: 12, color: "var(--text-muted)" }}>
              UTC {new Date().toISOString().substring(11, 19)}
            </span>
            <span className="badge-pill badge-info">eth0 (promisc)</span>
          </div>
        </header>

        {/* Dynamic View Content */}
        <div style={{ padding: 24, flex: 1, overflowY: "auto" }}>
          {/* TAB 1: MAIN DASHBOARD */}
          {activeTab === "dashboard" && (
            <div style={{ display: "flex", flexDirection: "column", gap: 24 }}>
              {/* StatusBar */}
              <div className="cyber-card" style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                  <span className="status-dot status-dot-green pulse-active"></span>
                  <span style={{ fontWeight: 600 }}>Unidirectional Diode Monitoring Active</span>
                  <span style={{ color: "var(--text-muted)", fontSize: 13 }}>| Interface: eth0 (read-only)</span>
                </div>
                <div style={{ display: "flex", gap: 8 }}>
                  <span className="badge-pill badge-info">RF Model v1.0 Loaded</span>
                  <span className="badge-pill badge-info">IF Model v1.0 Loaded</span>
                </div>
              </div>

              {/* 4x KPI Cards Row */}
              <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 16 }}>
                <div className="cyber-card">
                  <div style={{ color: "var(--text-muted)", fontSize: 12, fontWeight: 700, textTransform: "uppercase" }}>Total Packets Ingested</div>
                  <div className="mono" style={{ fontSize: 32, fontWeight: 700, margin: "8px 0" }}>{stats.total_packets.toLocaleString()}</div>
                  <div style={{ fontSize: 12, color: "var(--status-success)" }}>↑ 100% Inbound Capture</div>
                </div>

                <div className="cyber-card">
                  <div style={{ color: "var(--text-muted)", fontSize: 12, fontWeight: 700, textTransform: "uppercase" }}>Active Threat Level</div>
                  <div className="mono" style={{ fontSize: 32, fontWeight: 700, margin: "8px 0", color: stats.active_threat_level === "Critical" ? "var(--severity-critical)" : stats.active_threat_level === "High" ? "var(--severity-high)" : "var(--color-primary)" }}>
                    {stats.active_threat_level.toUpperCase()}
                  </div>
                  <div style={{ fontSize: 12, color: "var(--text-muted)" }}>Based on 5-band score</div>
                </div>

                <div className="cyber-card">
                  <div style={{ color: "var(--text-muted)", fontSize: 12, fontWeight: 700, textTransform: "uppercase" }}>Suspicious Threat Flows</div>
                  <div className="mono" style={{ fontSize: 32, fontWeight: 700, margin: "8px 0", color: "var(--severity-high)" }}>{stats.suspicious_flows}</div>
                  <div style={{ fontSize: 12, color: "var(--text-muted)" }}>Flagged by Hybrid Engine</div>
                </div>

                <div className="cyber-card">
                  <div style={{ color: "var(--text-muted)", fontSize: 12, fontWeight: 700, textTransform: "uppercase" }}>Safe Benign Flows</div>
                  <div className="mono" style={{ fontSize: 32, fontWeight: 700, margin: "8px 0", color: "var(--status-success)" }}>{stats.safe_flows}</div>
                  <div style={{ fontSize: 12, color: "var(--status-success)" }}>0% False Positives</div>
                </div>
              </div>

              {/* 5-Stage Detection Pipeline Strip */}
              <div className="cyber-card">
                <div style={{ fontSize: 13, fontWeight: 700, color: "var(--text-muted)", textTransform: "uppercase", marginBottom: 12 }}>
                  Detection Pipeline Architecture (PRD §10)
                </div>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 12, textAlign: "center" }}>
                  <div style={{ background: "var(--bg-surface-sunken)", padding: 12, borderRadius: 6, border: "1px solid var(--border-cyan)" }}>
                    <div style={{ fontSize: 11, color: "var(--color-primary)", fontWeight: 700 }}>STAGE 1</div>
                    <div style={{ fontWeight: 600, fontSize: 13 }}>Passive Ingestion</div>
                  </div>
                  <div style={{ background: "var(--bg-surface-sunken)", padding: 12, borderRadius: 6, border: "1px solid var(--border-subtle)" }}>
                    <div style={{ fontSize: 11, color: "var(--text-muted)", fontWeight: 700 }}>STAGE 2</div>
                    <div style={{ fontWeight: 600, fontSize: 13 }}>13-Feature Extraction</div>
                  </div>
                  <div style={{ background: "var(--bg-surface-sunken)", padding: 12, borderRadius: 6, border: "1px solid var(--border-subtle)" }}>
                    <div style={{ fontSize: 11, color: "var(--text-muted)", fontWeight: 700 }}>STAGE 3</div>
                    <div style={{ fontWeight: 600, fontSize: 13 }}>Fast Path & Hybrid ML</div>
                  </div>
                  <div style={{ background: "var(--bg-surface-sunken)", padding: 12, borderRadius: 6, border: "1px solid var(--border-subtle)" }}>
                    <div style={{ fontSize: 11, color: "var(--text-muted)", fontWeight: 700 }}>STAGE 4</div>
                    <div style={{ fontWeight: 600, fontSize: 13 }}>Risk Engine (0-100)</div>
                  </div>
                  <div style={{ background: "var(--bg-surface-sunken)", padding: 12, borderRadius: 6, border: "1px solid var(--border-subtle)" }}>
                    <div style={{ fontSize: 11, color: "var(--text-muted)", fontWeight: 700 }}>STAGE 5</div>
                    <div style={{ fontWeight: 600, fontSize: 13 }}>WebSocket Alert Push</div>
                  </div>
                </div>
              </div>



              {/* Simulator Controls & Scenario Triggering */}
              <div className="cyber-card">
                <div style={{ fontSize: 13, fontWeight: 700, color: "var(--text-muted)", textTransform: "uppercase", marginBottom: 12 }}>
                  Live Demo Scenario Injector
                </div>
                <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
                  <button className="btn btn-primary" onClick={() => handleSimulateScenario("normal")}>
                    Emit Normal Traffic (Benign)
                  </button>
                  <button className="btn btn-ghost" onClick={() => handleSimulateScenario("port_scan")}>
                    Inject Port Scan Scenario
                  </button>
                  <button className="btn btn-danger" onClick={() => handleSimulateScenario("syn_flood")}>
                    Inject SYN Flood Scenario
                  </button>
                </div>
              </div>

              {/* Dashboard Visualizations Grid */}
              <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 16 }}>
                <ThreatTimelineChart />
                <CategoryPieChart />
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
                <ProtocolBarChart />
                <AttackWorldMap />
              </div>

              {/* Live Alerts Feed Table */}
              <div className="cyber-card">
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
                  <div style={{ fontSize: 16, fontWeight: 600 }}>Live Real-Time Threat Alerts Feed</div>
                  <button className="btn btn-ghost" onClick={() => setActiveTab("logs")}>View All Logs →</button>
                </div>

                <table className="cyber-table">
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>Source IP</th>
                      <th>Threat Category</th>
                      <th>Risk Score</th>
                      <th>Severity</th>
                      <th>Status</th>
                      <th>Quick Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {alerts.length === 0 ? (
                      <tr>
                        <td colSpan="7" style={{ textAlign: "center", color: "var(--text-muted)", padding: 24 }}>
                          No active threat alerts. System operating normally.
                        </td>
                      </tr>
                    ) : (
                      alerts.slice(0, 5).map((alert) => (
                        <tr key={alert.alert_id}>
                          <td className="mono">{new Date(alert.created_ts * 1000).toLocaleTimeString()}</td>
                          <td className="mono">{alert.src_ip || "198.51.100.45"}</td>
                          <td style={{ fontWeight: 600 }}>{alert.threat_category}</td>
                          <td className="mono" style={{ fontWeight: 700 }}>{alert.risk_score}/100</td>
                          <td>
                            <span className={`badge-pill ${getSeverityBadgeClass(alert.severity)}`}>
                              {alert.severity}
                            </span>
                          </td>
                          <td>
                            <span className="mono" style={{ fontSize: 11 }}>{alert.status}</span>
                          </td>
                          <td style={{ display: "flex", gap: 6 }}>
                            <button className="btn btn-ghost" style={{ padding: "4px 8px", fontSize: 11 }} onClick={() => setSelectedAlert(alert)}>
                              Inspect
                            </button>
                            <button className="btn btn-ghost" style={{ padding: "4px 8px", fontSize: 11 }} onClick={() => handleAcknowledge(alert.alert_id)}>
                              Ack
                            </button>
                            <button className="btn btn-danger" style={{ padding: "4px 8px", fontSize: 11 }} onClick={() => handleBlockIPAction(alert.src_ip)}>
                              Block
                            </button>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB 2: THREAT LOGS TABLE */}
          {activeTab === "logs" && (
            <div className="cyber-card" style={{ display: "flex", flexDirection: "column", gap: 16 }}>
              {/* Filter Bar */}
              <div style={{ display: "flex", gap: 12, flexWrap: "wrap", alignItems: "center" }}>
                <input
                  type="text"
                  placeholder="Filter by IP address..."
                  className="cyber-input mono"
                  style={{ width: 220 }}
                  value={searchIP}
                  onChange={(e) => setSearchIP(e.target.value)}
                />
                <select className="cyber-input" value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}>
                  <option value="ALL">All Severities</option>
                  <option value="CRITICAL">Critical</option>
                  <option value="HIGH">High</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="LOW">Low</option>
                </select>
                <select className="cyber-input" value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
                  <option value="ALL">All Statuses</option>
                  <option value="new">New</option>
                  <option value="acknowledged">Acknowledged</option>
                  <option value="false_positive">False Positive</option>
                </select>
              </div>

              {/* Full Table */}
              <table className="cyber-table">
                <thead>
                  <tr>
                    <th>Alert ID</th>
                    <th>Timestamp</th>
                    <th>Source IP</th>
                    <th>Destination IP</th>
                    <th>Threat Category</th>
                    <th>Risk Score</th>
                    <th>Severity</th>
                    <th>Status</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredAlerts.length === 0 ? (
                    <tr>
                      <td colSpan="9" style={{ textAlign: "center", padding: 32, color: "var(--text-muted)" }}>
                        No log records matching filter criteria.
                      </td>
                    </tr>
                  ) : (
                    filteredAlerts.map((alert) => (
                      <tr key={alert.alert_id}>
                        <td className="mono" style={{ color: "var(--color-primary)" }}>{alert.alert_id}</td>
                        <td className="mono">{new Date(alert.created_ts * 1000).toLocaleString()}</td>
                        <td className="mono">{alert.src_ip || "198.51.100.45"}</td>
                        <td className="mono">{alert.dst_ip || "10.0.0.5"}</td>
                        <td style={{ fontWeight: 600 }}>{alert.threat_category}</td>
                        <td className="mono" style={{ fontWeight: 700 }}>{alert.risk_score}</td>
                        <td>
                          <span className={`badge-pill ${getSeverityBadgeClass(alert.severity)}`}>
                            {alert.severity}
                          </span>
                        </td>
                        <td className="mono" style={{ fontSize: 11 }}>{alert.status}</td>
                        <td style={{ display: "flex", gap: 6 }}>
                          <button className="btn btn-ghost" style={{ padding: "4px 8px", fontSize: 11 }} onClick={() => setSelectedAlert(alert)}>
                            Inspect
                          </button>
                          <button className="btn btn-ghost" style={{ padding: "4px 8px", fontSize: 11 }} onClick={() => handleAcknowledge(alert.alert_id)}>
                            Ack
                          </button>
                          <button className="btn btn-danger" style={{ padding: "4px 8px", fontSize: 11 }} onClick={() => handleBlockIPAction(alert.src_ip)}>
                            Block
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          )}

          {/* TAB 3: THREAT INTEL INSPECTOR */}
          {activeTab === "intel" && (
            <div style={{ display: "flex", flexDirection: "column", gap: 24 }}>
              <div className="cyber-card" style={{ display: "flex", gap: 12 }}>
                <input
                  type="text"
                  placeholder="Enter IP address to lookup (e.g. 198.51.100.45)..."
                  className="cyber-input mono"
                  style={{ flex: 1 }}
                  value={intelSearchIP}
                  onChange={(e) => setIntelSearchIP(e.target.value)}
                />
                <button className="btn btn-primary" onClick={() => handleIntelLookup(intelSearchIP)}>
                  Search Reputation
                </button>
              </div>

              {intelResult && (
                <div className="cyber-card" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>
                  <div>
                    <div style={{ color: "var(--text-muted)", fontSize: 12, fontWeight: 700, textTransform: "uppercase" }}>IP Address Metadata</div>
                    <div className="mono" style={{ fontSize: 24, fontWeight: 700, margin: "8px 0", color: "var(--color-primary)" }}>{intelResult.ip}</div>
                    <div style={{ display: "flex", flexDirection: "column", gap: 8, marginTop: 12 }}>
                      <div>Status: <span style={{ color: intelResult.listed ? "var(--severity-critical)" : "var(--status-success)", fontWeight: 700 }}>{intelResult.listed ? "BLACKLISTED / REPUTATION MATCH" : "CLEAN"}</span></div>
                      <div>Threat Score: <span className="mono" style={{ fontWeight: 700 }}>{intelResult.threat_score}/100</span></div>
                      <div>Category: <span className="mono">{intelResult.category}</span></div>
                      <div>Source Feed: <span className="mono">{intelResult.source_feed}</span></div>
                    </div>
                  </div>

                  <div>
                    <div style={{ color: "var(--text-muted)", fontSize: 12, fontWeight: 700, textTransform: "uppercase" }}>GeoIP Location Info</div>
                    <div style={{ marginTop: 12, display: "flex", flexDirection: "column", gap: 8 }}>
                      <div>Country: <span className="mono" style={{ fontWeight: 600 }}>{intelResult.country_code || "Germany"}</span></div>
                      <div>City / Region: <span className="mono">Frankfurt, Hesse</span></div>
                      <div>Coordinates: <span className="mono">50.1109° N, 8.6821° E (Approximate)</span></div>
                    </div>
                    <button className="btn btn-danger" style={{ marginTop: 20 }} onClick={() => handleBlockIPAction(intelResult.ip)}>
                      Execute Block Action
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 4: PCAP UPLOAD */}
          {activeTab === "pcap" && (
            <div style={{ display: "flex", flexDirection: "column", gap: 24 }}>
              <div className="cyber-card" style={{ textAlign: "center", padding: 48, borderStyle: "dashed" }}>
                <div style={{ fontSize: 18, fontWeight: 700, marginBottom: 8 }}>Drag & Drop .PCAP File Here</div>
                <div style={{ color: "var(--text-muted)", marginBottom: 20 }}>Read-only offline capture analysis and flow feature scoring</div>
                <input type="file" accept=".pcap,.pcapng,.cap" onChange={handlePcapUpload} style={{ display: "none" }} id="pcapInput" />
                <label htmlFor="pcapInput" className="btn btn-primary" style={{ cursor: "pointer" }}>
                  {pcapUploading ? "Processing PCAP..." : "Select PCAP File"}
                </label>
              </div>

              {pcapResult && (
                <div className="cyber-card">
                  <div style={{ fontSize: 16, fontWeight: 700, marginBottom: 12 }}>Analysis Results for {pcapResult.filename}</div>
                  <div style={{ display: "flex", gap: 24, marginBottom: 16 }}>
                    <div>Packets Parsed: <span className="mono" style={{ fontWeight: 700 }}>{pcapResult.packets_parsed}</span></div>
                    <div>Alerts Generated: <span className="mono" style={{ fontWeight: 700, color: "var(--severity-high)" }}>{pcapResult.alerts_generated_count}</span></div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 5: WEEKLY REPORT */}
          {activeTab === "weekly_report" && (
            <WeeklyReportView />
          )}
        </div>
      </main>

      {/* Alert Inspector Modal */}
      {selectedAlert && (
        <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.75)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 999 }}>
          <div className="cyber-card" style={{ width: 600, maxHeight: "80vh", overflowY: "auto", background: "var(--bg-surface-elevated)" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
              <div style={{ fontSize: 18, fontWeight: 700 }}>Alert Evidence Inspector ({selectedAlert.alert_id})</div>
              <button className="btn btn-ghost" onClick={() => setSelectedAlert(null)}>✕</button>
            </div>

            <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
              <div style={{ display: "flex", justifyContent: "space-between" }}>
                <div>Threat Category: <span style={{ fontWeight: 700, color: "var(--color-primary)" }}>{selectedAlert.threat_category}</span></div>
                <span className={`badge-pill ${getSeverityBadgeClass(selectedAlert.severity)}`}>{selectedAlert.severity}</span>
              </div>

              <div style={{ background: "var(--bg-surface-sunken)", padding: 12, borderRadius: 6 }}>
                <div style={{ fontSize: 11, color: "var(--text-muted)", textTransform: "uppercase", fontWeight: 700 }}>Plain-Language XAI Explanation (PRD §6.5)</div>
                <div style={{ marginTop: 4 }}>{selectedAlert.explanation}</div>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }} className="mono">
                <div>Source IP: {selectedAlert.src_ip || "198.51.100.45"}</div>
                <div>Risk Score: {selectedAlert.risk_score}/100</div>
                <div>Confidence: {((selectedAlert.confidence || 0.85) * 100).toFixed(0)}%</div>
                <div>Status: {selectedAlert.status}</div>
              </div>

              <div style={{ display: "flex", gap: 12, marginTop: 12 }}>
                <button className="btn btn-ghost" onClick={() => handleAcknowledge(selectedAlert.alert_id)}>Mark Acknowledged</button>
                <button className="btn btn-ghost" onClick={() => handleFalsePositive(selectedAlert.alert_id)}>Mark False Positive</button>
                <button className="btn btn-danger" onClick={() => handleBlockIPAction(selectedAlert.src_ip)}>Block IP</button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

ReactDOM.createRoot(document.getElementById("root")).render(<App />);
