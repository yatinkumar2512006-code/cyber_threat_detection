import time
from typing import Dict, Any, List
from fastapi import APIRouter, Depends
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
