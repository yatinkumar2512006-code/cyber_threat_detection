import time
from typing import Dict, Any, List
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, desc

from storage.db import get_db
from storage.models_orm import FlowORM, AlertORM
from backend.api.deps import get_current_user, CurrentUser

router = APIRouter(tags=["Dashboard"])


@router.get("/api/v1/dashboard/stats")
@router.get("/api/stats/live")
def get_dashboard_stats(
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user)
):
    """
    Returns real-time dashboard volumetric overview, active threat counts, and top attacked ports.
    Calculated directly from SQLite database records.
    """
    # 1. Total packets and flows count
    total_packets = db.query(func.sum(FlowORM.packet_count)).scalar() or 0
    total_flows = db.query(func.count(FlowORM.flow_id)).scalar() or 0

    # 2. Alerts breakdown
    total_alerts = db.query(func.count(AlertORM.alert_id)).scalar() or 0
    critical_alerts = db.query(func.count(AlertORM.alert_id)).filter(AlertORM.severity == "Critical").scalar() or 0
    high_alerts = db.query(func.count(AlertORM.alert_id)).filter(AlertORM.severity == "High").scalar() or 0

    suspicious_flows = total_alerts
    safe_flows = max(0, total_flows - suspicious_flows)

    # 3. Active Threat Level
    if critical_alerts > 0:
        active_threat_level = "Critical"
    elif high_alerts > 0:
        active_threat_level = "High"
    elif total_alerts > 0:
        active_threat_level = "Medium"
    else:
        active_threat_level = "Low"

    # 4. Protocol Breakdown
    tcp_flows = db.query(func.count(FlowORM.flow_id)).filter(FlowORM.protocol == "TCP").scalar() or 0
    udp_flows = db.query(func.count(FlowORM.flow_id)).filter(FlowORM.protocol == "UDP").scalar() or 0
    icmp_flows = db.query(func.count(FlowORM.flow_id)).filter(FlowORM.protocol == "ICMP").scalar() or 0

    # 5. Top Attacked Destination Ports
    top_ports_query = (
        db.query(FlowORM.dst_port, func.count(FlowORM.dst_port).label("count"))
        .group_by(FlowORM.dst_port)
        .order_by(desc("count"))
        .limit(5)
        .all()
    )
    top_attacked_ports = [{"port": p[0], "count": p[1]} for p in top_ports_query]

    return {
        "total_packets": int(total_packets),
        "total_flows": int(total_flows),
        "safe_flows": int(safe_flows),
        "suspicious_flows": int(suspicious_flows),
        "active_threat_level": active_threat_level,
        "protocol_breakdown": {
            "tcp": int(tcp_flows),
            "udp": int(udp_flows),
            "icmp": int(icmp_flows)
        },
        "top_attacked_ports": top_attacked_ports,
        "timestamp": time.time()
    }


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
        lat, lon = (geo.get("lat"), geo.get("lon")) if isinstance(geo, dict) else (50.1109, 8.6821)
        if lat is None or lon is None:
            lat, lon = 50.1109, 8.6821
        points.append({
            "src_ip": src_ip, "lat": lat, "lon": lon,
            "severity": alert.severity,
            "threat_category": alert.threat_category,
            "risk_score": alert.risk_score
        })
    return {"points": points}


@router.get("/api/v1/dashboard/weekly-report")
def weekly_report(
    week_offset: int = Query(0, ge=0, le=52),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user)
):
    from datetime import datetime, timedelta
    now_ts = time.time()
    end_ts = now_ts - (week_offset * 7 * 86400)
    start_ts = end_ts - (7 * 86400)

    total_packets = (
        db.query(func.sum(FlowORM.packet_count))
        .filter(FlowORM.start_ts >= start_ts, FlowORM.start_ts <= end_ts)
        .scalar() or 0
    )

    alerts_query = (
        db.query(AlertORM, FlowORM.src_ip)
        .join(FlowORM, AlertORM.flow_id == FlowORM.flow_id)
        .filter(AlertORM.created_ts >= start_ts, AlertORM.created_ts <= end_ts)
    )
    all_alerts = alerts_query.all()
    total_alerts = len(all_alerts)

    critical_count = sum(1 for a, _ in all_alerts if a.severity == "Critical")
    high_count = sum(1 for a, _ in all_alerts if a.severity == "High")
    medium_count = sum(1 for a, _ in all_alerts if a.severity == "Medium")
    low_count = sum(1 for a, _ in all_alerts if a.severity == "Low")

    unique_ips = len(set(src_ip for _, src_ip in all_alerts if src_ip))

    cat_counts = {}
    for a, _ in all_alerts:
        cat_counts[a.threat_category] = cat_counts.get(a.threat_category, 0) + 1
    top_threat_category = max(cat_counts.items(), key=lambda x: x[1])[0] if cat_counts else "None"

    days_labels = []
    day_buckets = {}
    start_day_ts = end_ts - (6 * 86400)
    for i in range(7):
        day_date = (datetime.utcfromtimestamp(start_day_ts) + timedelta(days=i)).strftime("%Y-%m-%d")
        days_labels.append(day_date)
        day_buckets[day_date] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}

    for a, _ in all_alerts:
        day_key = datetime.utcfromtimestamp(a.created_ts).strftime("%Y-%m-%d")
        if day_key in day_buckets:
            day_buckets[day_key][a.severity] = day_buckets[day_key].get(a.severity, 0) + 1

    daily_breakdown = {
        "labels": days_labels,
        "critical": [day_buckets[d]["Critical"] for d in days_labels],
        "high": [day_buckets[d]["High"] for d in days_labels],
        "medium": [day_buckets[d]["Medium"] for d in days_labels],
        "low": [day_buckets[d]["Low"] for d in days_labels],
    }

    category_breakdown = {
        "labels": list(cat_counts.keys()),
        "counts": list(cat_counts.values())
    }

    ip_stats = {}
    severity_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    for a, src_ip in all_alerts:
        if not src_ip:
            continue
        if src_ip not in ip_stats:
            ip_stats[src_ip] = {"alert_count": 0, "highest_severity": a.severity}
        ip_stats[src_ip]["alert_count"] += 1
        if severity_rank.get(a.severity, 0) > severity_rank.get(ip_stats[src_ip]["highest_severity"], 0):
            ip_stats[src_ip]["highest_severity"] = a.severity

    sorted_attackers = sorted(ip_stats.items(), key=lambda x: x[1]["alert_count"], reverse=True)[:10]
    top_attackers = [
        {"src_ip": ip, "alert_count": data["alert_count"], "highest_severity": data["highest_severity"]}
        for ip, data in sorted_attackers
    ]

    paginated_alerts = alerts_query.order_by(AlertORM.created_ts.desc()).offset(offset).limit(limit).all()
    full_alert_log_items = [
        {
            "alert_id": a.alert_id,
            "created_ts": a.created_ts,
            "src_ip": src_ip,
            "threat_category": a.threat_category,
            "risk_score": a.risk_score,
            "severity": a.severity,
            "status": "Active"
        }
        for a, src_ip in paginated_alerts
    ]

    return {
        "week_offset": week_offset,
        "start_date": datetime.utcfromtimestamp(start_ts).strftime("%Y-%m-%d"),
        "end_date": datetime.utcfromtimestamp(end_ts).strftime("%Y-%m-%d"),
        "summary": {
            "total_packets": int(total_packets),
            "total_alerts": total_alerts,
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": medium_count,
            "low_count": low_count,
            "unique_attacker_ips": unique_ips,
            "top_threat_category": top_threat_category,
            "false_positive_rate": 0.0
        },
        "daily_breakdown": daily_breakdown,
        "category_breakdown": category_breakdown,
        "top_attackers": top_attackers,
        "full_alert_log": {
            "total": total_alerts,
            "limit": limit,
            "offset": offset,
            "alerts": full_alert_log_items
        }
    }
