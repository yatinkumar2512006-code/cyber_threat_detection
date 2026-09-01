# 🛠️ Implementation Plan — OneWay Sentinel Upgrades

## What We Are Adding

| Feature | Status |
|---------|--------|
| 📊 Dashboard Graphs (Chart.js) | 🆕 New |
| 🗺️ Live Attack World Map (Leaflet.js) | 🆕 New |
| ⚔️ Kali Linux Manual Attack Simulator Panel | 🆕 New |
| 🎚️ Risk Score Threshold Recalibration | 🔧 Modify |

---

## PART 1 — Risk Score Threshold Recalibration

### Your New Thresholds

| Score Range | Severity |
|-------------|----------|
| > 85 | 🔴 Critical |
| 70 – 85 | 🟠 High |
| 60 – 70 | 🟡 Medium |
| < 60 | 🟢 Low |

---

#### [MODIFY] [`severity_mapper.py`](file:///C:/Users/hp/Downloads/cyber_threat_detection-master/cyber_threat_detection-master/backend/risk/severity_mapper.py)

**Current code (lines 7–16):**
```python
if s <= 19:
    return "Informational"
elif s <= 39:
    return "Low"
elif s <= 59:
    return "Medium"
elif s <= 79:
    return "High"
else:
    return "Critical"
```

**Replace with:**
```python
if s < 60:
    return "Low"
elif s < 70:
    return "Medium"
elif s <= 85:
    return "High"
else:
    return "Critical"
```

> [!NOTE]
> "Informational" severity is removed. Now only 4 bands: Low / Medium / High / Critical.

---

#### [MODIFY] [`config/settings.py`](file:///C:/Users/hp/Downloads/cyber_threat_detection-master/cyber_threat_detection-master/config/settings.py)

```python
ALERT_THRESHOLD: int = 60        # was 40
CRITICAL_THRESHOLD: int = 85     # was 80
```

---

#### [MODIFY] [`config/default.yaml`](file:///C:/Users/hp/Downloads/cyber_threat_detection-master/cyber_threat_detection-master/config/default.yaml)

```yaml
pipeline:
  alert_threshold: 60        # was 40
  critical_threshold: 85     # was 80
```

---

#### [MODIFY] [`storage/models_orm.py`](file:///C:/Users/hp/Downloads/cyber_threat_detection-master/cyber_threat_detection-master/storage/models_orm.py) Line 86

Update the SQLite `CheckConstraint` for severity to remove "Informational":
```python
CheckConstraint("severity IN ('Low', 'Medium', 'High', 'Critical')")
```

---

## PART 2 — Dashboard Graphs (Chart.js)

Chart.js CDN is already loaded in `index.html`. We just need new API endpoints + React chart components.

---

#### [MODIFY] [`backend/api/routes_dashboard.py`](file:///C:/Users/hp/Downloads/cyber_threat_detection-master/cyber_threat_detection-master/backend/api/routes_dashboard.py)

Add **2 new endpoints**:

**Endpoint 1 — Threats Over Time (line chart):**
```python
@router.get("/api/v1/dashboard/threats-over-time")
def threats_over_time(
    hours: int = Query(24, ge=1, le=168),
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user)
):
    from datetime import datetime
    cutoff = time.time() - (hours * 3600)
    alerts = db.query(AlertORM).filter(AlertORM.created_ts >= cutoff).all()
    buckets = {}
    for alert in alerts:
        hour_key = int(alert.created_ts // 3600) * 3600
        if hour_key not in buckets:
            buckets[hour_key] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        buckets[hour_key][alert.severity] = buckets[hour_key].get(alert.severity, 0) + 1
    sorted_buckets = sorted(buckets.items())
    return {
        "labels":   [datetime.utcfromtimestamp(ts).strftime("%H:%M") for ts, _ in sorted_buckets],
        "critical": [v["Critical"] for _, v in sorted_buckets],
        "high":     [v["High"]     for _, v in sorted_buckets],
        "medium":   [v["Medium"]   for _, v in sorted_buckets],
        "low":      [v["Low"]      for _, v in sorted_buckets],
    }
```

**Endpoint 2 — Category Breakdown (doughnut chart):**
```python
@router.get("/api/v1/dashboard/category-breakdown")
def category_breakdown(
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user)
):
    results = (
        db.query(AlertORM.threat_category, func.count(AlertORM.alert_id))
        .group_by(AlertORM.threat_category)
        .all()
    )
    return {"labels": [r[0] for r in results], "counts": [r[1] for r in results]}
```

---

#### [MODIFY] [`frontend/app.js`](file:///C:/Users/hp/Downloads/cyber_threat_detection-master/cyber_threat_detection-master/frontend/app.js)

Add 3 chart components and mount them in Dashboard:

**1. Threat Timeline (Line Chart):**
```jsx
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
            labels: data.labels,
            datasets: [
              { label: 'Critical', data: data.critical, borderColor: '#ef4444', backgroundColor: 'rgba(239,68,68,0.15)', tension: 0.4, fill: true },
              { label: 'High',     data: data.high,     borderColor: '#f97316', backgroundColor: 'rgba(249,115,22,0.15)', tension: 0.4, fill: true },
              { label: 'Medium',   data: data.medium,   borderColor: '#eab308', backgroundColor: 'rgba(234,179,8,0.1)',   tension: 0.4, fill: true },
              { label: 'Low',      data: data.low,      borderColor: '#22c55e', backgroundColor: 'rgba(34,197,94,0.1)',   tension: 0.4, fill: true },
            ]
          },
          options: { responsive: true, plugins: { legend: { position: 'top', labels: { color: '#9ca3af' } } },
                     scales: { x: { ticks: { color: '#6b7280' } }, y: { ticks: { color: '#6b7280' }, beginAtZero: true } } }
        });
      });
  }, []);
  return <div className="card"><h3 style={{marginBottom:'12px'}}>📈 Threats Over Time (24h)</h3><canvas ref={canvasRef} /></div>;
}
```

**2. Category Breakdown (Doughnut):**
```jsx
function CategoryPieChart() {
  const canvasRef = React.useRef(null);
  React.useEffect(() => {
    fetch('/api/v1/dashboard/category-breakdown')
      .then(r => r.json()).then(data => {
        new Chart(canvasRef.current, {
          type: 'doughnut',
          data: {
            labels: data.labels,
            datasets: [{ data: data.counts,
              backgroundColor: ['#ef4444','#f97316','#eab308','#22c55e','#3b82f6','#8b5cf6'] }]
          },
          options: { responsive: true, plugins: { legend: { position: 'right', labels: { color: '#9ca3af' } } } }
        });
      });
  }, []);
  return <div className="card"><h3 style={{marginBottom:'12px'}}>🥧 Threat Categories</h3><canvas ref={canvasRef} /></div>;
}
```

**3. Protocol Bar Chart:**
```jsx
function ProtocolBarChart() {
  const canvasRef = React.useRef(null);
  React.useEffect(() => {
    fetch('/api/v1/dashboard/stats').then(r => r.json()).then(data => {
      const pb = data.protocol_breakdown;
      new Chart(canvasRef.current, {
        type: 'bar',
        data: {
          labels: ['TCP', 'UDP', 'ICMP'],
          datasets: [{ label: 'Flows', data: [pb.tcp, pb.udp, pb.icmp],
            backgroundColor: ['#3b82f6','#8b5cf6','#ec4899'] }]
        },
        options: { responsive: true, plugins: { legend: { display: false } },
                   scales: { x: { ticks: { color: '#9ca3af' } }, y: { ticks: { color: '#9ca3af' }, beginAtZero: true } } }
      });
    });
  }, []);
  return <div className="card"><h3 style={{marginBottom:'12px'}}>📶 Protocol Distribution</h3><canvas ref={canvasRef} /></div>;
}
```

---

## PART 3 — Live Attack World Map (Leaflet.js)

---

#### [MODIFY] [`frontend/index.html`](file:///C:/Users/hp/Downloads/cyber_threat_detection-master/cyber_threat_detection-master/frontend/index.html)

Add inside `<head>` before `</head>`:
```html
<!-- Leaflet.js Map -->
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
```

---

#### [MODIFY] [`backend/api/routes_dashboard.py`](file:///C:/Users/hp/Downloads/cyber_threat_detection-master/cyber_threat_detection-master/backend/api/routes_dashboard.py)

Add attack-map endpoint:
```python
@router.get("/api/v1/dashboard/attack-map")
def attack_map_data(
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user)
):
    import json
    alerts = (
        db.query(AlertORM, FlowORM.src_ip)
        .join(FlowORM, AlertORM.flow_id == FlowORM.flow_id)
        .order_by(AlertORM.created_ts.desc())
        .limit(limit).all()
    )
    points = []
    for alert, src_ip in alerts:
        geo = json.loads(alert.geolocation) if isinstance(alert.geolocation, str) else alert.geolocation
        lat, lon = geo.get("lat"), geo.get("lon")
        if lat is not None and lon is not None:
            points.append({
                "src_ip": src_ip, "lat": lat, "lon": lon,
                "severity": alert.severity,
                "threat_category": alert.threat_category,
                "risk_score": alert.risk_score
            })
    return {"points": points}
```

---

#### [MODIFY] [`frontend/app.js`](file:///C:/Users/hp/Downloads/cyber_threat_detection-master/cyber_threat_detection-master/frontend/app.js)

Add `AttackWorldMap` component:
```jsx
function AttackWorldMap() {
  const mapRef = React.useRef(null);
  const mapInstance = React.useRef(null);
  const severityColors = { Critical:'#ef4444', High:'#f97316', Medium:'#eab308', Low:'#22c55e' };

  React.useEffect(() => {
    if (!mapInstance.current && mapRef.current) {
      mapInstance.current = L.map(mapRef.current, { zoomControl: true }).setView([20, 0], 2);
      L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        attribution: '© OpenStreetMap © CARTO'
      }).addTo(mapInstance.current);
    }
    fetch('/api/v1/dashboard/attack-map?limit=200')
      .then(r => r.json()).then(data => {
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
      });
  }, []);

  return (
    <div className="card">
      <h3 style={{ marginBottom: '12px' }}>🌍 Live Attack Origin Map</h3>
      <div ref={mapRef} style={{ height: '420px', borderRadius: '8px', zIndex: 0 }} />
    </div>
  );
}
```

> [!IMPORTANT]
> Map markers will cluster at Frankfurt until real MaxMind GeoIP is integrated. The structure is ready — when GeoIP works, markers auto-spread globally.

---

## PART 4 — Kali Linux Manual Attack Simulator

---

#### [NEW] `backend/api/routes_simulator.py`

```python
import time, random
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from backend.api.deps import require_role, CurrentUser
from backend.pipeline.orchestrator import orchestrator
from network.flow_models import ValidatedPacket

router = APIRouter(prefix="/api/v1/simulator", tags=["Attack Simulator"])

KALI_SCENARIOS = {
    "port_scan": {
        "description": "Nmap SYN Port Scan (nmap -sS -p 1-1000)",
        "packets": lambda src: [
            ValidatedPacket(src_ip=src, dst_ip="192.168.1.1",
                src_port=random.randint(40000,60000), dst_port=p,
                protocol="TCP", packet_length=64,
                timestamp=time.time()+i*0.001, tcp_flags="S")
            for i, p in enumerate(random.sample(range(1,1024), 50))
        ]
    },
    "network_scan": {
        "description": "Nmap Network Sweep (nmap -sn 192.168.1.0/24)",
        "packets": lambda src: [
            ValidatedPacket(src_ip=src, dst_ip=f"192.168.1.{h}",
                src_port=random.randint(40000,60000), dst_port=80,
                protocol="TCP", packet_length=64,
                timestamp=time.time()+i*0.005, tcp_flags="S")
            for i, h in enumerate(random.sample(range(1,255), 30))
        ]
    },
    "ddos_flood": {
        "description": "SYN Flood DDoS (hping3 --flood -S --rand-source)",
        "packets": lambda src: [
            ValidatedPacket(src_ip=src, dst_ip="192.168.1.1",
                src_port=random.randint(1024,65535), dst_port=80,
                protocol="TCP", packet_length=64,
                timestamp=time.time()+i*0.0005, tcp_flags="S")
            for i in range(260)
        ]
    },
    "data_exfiltration": {
        "description": "Large data transfer exfiltration (scp/curl)",
        "packets": lambda src: [
            ValidatedPacket(src_ip=src, dst_ip="10.0.0.100",
                src_port=random.randint(40000,60000), dst_port=443,
                protocol="TCP", packet_length=random.randint(1200,1500),
                timestamp=time.time()+i*0.02, tcp_flags="PA")
            for i in range(60)
        ]
    },
    "beaconing": {
        "description": "C2 Beaconing heartbeat (Metasploit meterpreter)",
        "packets": lambda src: [
            ValidatedPacket(src_ip=src, dst_ip="10.10.10.10",
                src_port=4444, dst_port=443,
                protocol="TCP", packet_length=128,
                timestamp=time.time()+i*2.0, tcp_flags="PA")
            for i in range(10)
        ]
    },
}

class AttackSimRequest(BaseModel):
    scenario: str
    src_ip: Optional[str] = "192.168.100.200"

@router.get("/scenarios")
def list_scenarios(current_user: CurrentUser = Depends(require_role(["analyst","admin"]))):
    return {k: v["description"] for k, v in KALI_SCENARIOS.items()}

@router.post("/attack", status_code=202)
def run_attack(
    req: AttackSimRequest,
    current_user: CurrentUser = Depends(require_role(["analyst","admin"]))
):
    key = req.scenario.lower().replace("-","_")
    if key not in KALI_SCENARIOS:
        raise HTTPException(400, detail={"code":"UNKNOWN_SCENARIO",
            "message": f"Available: {list(KALI_SCENARIOS.keys())}"})
    
    scenario = KALI_SCENARIOS[key]
    packets = scenario["packets"](req.src_ip)
    alerts = []
    
    for pkt in packets:
        alert = orchestrator.process_packet(pkt, source="simulator_attack")
        if alert:
            alerts.append(alert["payload"])
    
    for flow in orchestrator.aggregator.flush_expired_flows(current_ts=time.time()+30.0):
        alert = orchestrator.process_flow(flow)
        if alert:
            alerts.append(alert["payload"])
    
    return {
        "status": "simulated",
        "scenario": key,
        "description": scenario["description"],
        "src_ip": req.src_ip,
        "packets_injected": len(packets),
        "alerts_generated": len(alerts),
        "alerts": alerts
    }
```

---

#### [MODIFY] [`backend/api/main.py`](file:///C:/Users/hp/Downloads/cyber_threat_detection-master/cyber_threat_detection-master/backend/api/main.py)

Add after existing router imports:
```python
from backend.api.routes_simulator import router as simulator_router
```
And register it:
```python
app.include_router(simulator_router)
```

---

#### [MODIFY] [`frontend/app.js`](file:///C:/Users/hp/Downloads/cyber_threat_detection-master/cyber_threat_detection-master/frontend/app.js)

Add `KaliAttackPanel` component:
```jsx
const ATTACK_SCENARIOS = [
  { key:"port_scan",         label:"⚡ Port Scan",         color:"#f97316", desc:"nmap -sS -p1-1000" },
  { key:"network_scan",      label:"🔭 Network Scan",      color:"#eab308", desc:"nmap -sn sweep" },
  { key:"ddos_flood",        label:"💥 DDoS SYN Flood",    color:"#ef4444", desc:"hping3 --flood" },
  { key:"data_exfiltration", label:"📤 Data Exfiltration", color:"#8b5cf6", desc:"scp/curl large transfer" },
  { key:"beaconing",         label:"📡 C2 Beaconing",      color:"#ec4899", desc:"Meterpreter heartbeat" },
];

function KaliAttackPanel() {
  const [srcIp, setSrcIp] = React.useState("192.168.100.200");
  const [loading, setLoading] = React.useState(null);
  const [result, setResult] = React.useState(null);

  const runAttack = (key) => {
    setLoading(key); setResult(null);
    fetch('/api/v1/simulator/attack', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scenario: key, src_ip: srcIp })
    }).then(r => r.json()).then(d => { setResult(d); setLoading(null); })
      .catch(() => setLoading(null));
  };

  return (
    <div className="card" style={{ border:'1px solid #ef444488' }}>
      <h3>⚔️ Kali Linux Attack Simulator</h3>
      <p style={{ color:'#6b7280', fontSize:'13px', margin:'6px 0 14px' }}>
        Inject real attack traffic patterns through the live AI detection pipeline.
      </p>
      <div style={{ marginBottom:'14px' }}>
        <label style={{ fontSize:'12px', color:'#9ca3af' }}>Attacker Source IP (simulated Kali)</label>
        <input value={srcIp} onChange={e => setSrcIp(e.target.value)}
          style={{ display:'block', marginTop:'4px', padding:'8px 12px',
            background:'#111827', color:'#e5e7eb', border:'1px solid #374151',
            borderRadius:'6px', fontFamily:'JetBrains Mono', fontSize:'13px', width:'220px' }} />
      </div>

      <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:'10px' }}>
        {ATTACK_SCENARIOS.map(s => (
          <button key={s.key} onClick={() => runAttack(s.key)} disabled={!!loading}
            style={{ padding:'12px 14px', borderRadius:'8px', cursor: loading ? 'not-allowed' : 'pointer',
              background: loading === s.key ? '#1f2937' : '#0f172a',
              border:`1px solid ${s.color}80`, color: s.color,
              fontSize:'13px', fontWeight:'600', textAlign:'left', transition:'all 0.2s' }}>
            <div>{s.label}</div>
            <div style={{ fontSize:'11px', color:'#6b7280', marginTop:'2px' }}>{s.desc}</div>
            {loading === s.key && <div style={{ marginTop:'4px', color:'#9ca3af', fontSize:'11px' }}>⏳ Injecting packets...</div>}
          </button>
        ))}
      </div>

      {result && (
        <div style={{ marginTop:'16px', padding:'14px', background:'#0a0f1a',
          borderRadius:'8px', fontFamily:'JetBrains Mono', fontSize:'12px',
          border:'1px solid #1e293b' }}>
          <div style={{ color:'#22c55e', marginBottom:'8px' }}>
            ✓ {result.description}
          </div>
          <div style={{ color:'#6b7280' }}>
            Packets injected: <span style={{ color:'#e5e7eb' }}>{result.packets_injected}</span>
            {' | '}
            Alerts: <span style={{ color: result.alerts_generated > 0 ? '#ef4444' : '#22c55e', fontWeight:'bold' }}>
              {result.alerts_generated}
            </span>
          </div>
          {result.alerts && result.alerts.slice(0,4).map((a, i) => (
            <div key={i} style={{ marginTop:'6px', padding:'8px', background:'#111827',
              borderRadius:'6px', borderLeft:`3px solid ${
                a.severity==='Critical'?'#ef4444':a.severity==='High'?'#f97316':'#eab308'}` }}>
              <span style={{ color: a.severity==='Critical'?'#ef4444':a.severity==='High'?'#f97316':'#eab308',
                fontWeight:'bold' }}>[{a.severity}]</span>{' '}
              <span style={{ color:'#e5e7eb' }}>{a.threat_category}</span>{' '}
              <span style={{ color:'#6b7280', float:'right' }}>Score: {a.risk_score}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
```

---

## PART 5 — Critical Bug Fixes (Do Alongside)

| Fix | File | Line | Change |
|-----|------|------|--------|
| Wrong status code | `routes_auth.py` | 22 | `HTTP_211_CREATED` → `HTTP_201_CREATED` |
| CORS misconfiguration | `main.py` | 36 | `allow_origins=["*"]` → `["http://localhost:8000"]` |
| Wrong source tag | `routes_telemetry.py` | 48 | `source="live"` → `source="telemetry_api"` |
| Missing `__init__.py` | 5 directories | — | Create empty `__init__.py` in `backend/`, `backend/api/`, `backend/core/`, `ml/`, `network/` |
| JWT secret resets | `.env.example` | — | Add `JWT_SECRET_KEY=your-secret-key-here` |

---

## 📋 File Summary

| Action | File |
|--------|------|
| 🔧 Modify | `backend/risk/severity_mapper.py` |
| 🔧 Modify | `config/settings.py` |
| 🔧 Modify | `config/default.yaml` |
| 🔧 Modify | `storage/models_orm.py` |
| 🔧 Modify | `backend/api/routes_dashboard.py` (3 new endpoints) |
| 🔧 Modify | `backend/api/main.py` (register simulator router) |
| 🔧 Modify | `frontend/index.html` (add Leaflet CDN) |
| 🔧 Modify | `frontend/app.js` (4 new components) |
| 🆕 Create | `backend/api/routes_simulator.py` |
| 🆕 Create | `backend/__init__.py` |
| 🆕 Create | `backend/api/__init__.py` |
| 🆕 Create | `backend/core/__init__.py` |
| 🆕 Create | `ml/__init__.py` |
| 🆕 Create | `network/__init__.py` |

---

## Verification Steps

```bash
# 1. Start server
uvicorn backend.api.main:app --reload --port 8000

# 2. Test simulator
curl -X POST http://localhost:8000/api/v1/simulator/attack \
  -H "Content-Type: application/json" \
  -d '{"scenario":"port_scan","src_ip":"192.168.100.200"}'
# Expected: alerts with severity "High" or "Critical"

# 3. Test DDoS → should be Critical (risk > 85)
curl -X POST http://localhost:8000/api/v1/simulator/attack \
  -d '{"scenario":"ddos_flood"}' -H "Content-Type: application/json"

# 4. Test chart endpoints
curl http://localhost:8000/api/v1/dashboard/threats-over-time
curl http://localhost:8000/api/v1/dashboard/category-breakdown
curl http://localhost:8000/api/v1/dashboard/attack-map

# 5. Open browser → http://localhost:8000
#    - Graphs should appear on dashboard
#    - World map should render
#    - Attack panel: click DDoS → results console fills with Critical alerts
```
