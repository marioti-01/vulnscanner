"""
WebSocket — VulnScanner v8
Notificações em tempo real para o dashboard via Socket.IO.
Emite eventos quando scans agendados terminam, chains são detectadas, etc.
"""

from flask_socketio import SocketIO, emit, join_room, leave_room
from flask import request
from flask_login import current_user

socketio = SocketIO(
    cors_allowed_origins="*",
    async_mode="eventlet",
    logger=False,
    engineio_logger=False,
)


def init_socketio(app):
    socketio.init_app(app)
    return socketio


# ── Eventos do cliente ────────────────────────────────────────────────────────

@socketio.on("connect")
def on_connect():
    """Cliente conecta — entra na sala do usuário."""
    if current_user.is_authenticated:
        room = f"user_{current_user.id}"
        join_room(room)
        emit("connected", {"status": "ok", "room": room})


@socketio.on("disconnect")
def on_disconnect():
    if current_user.is_authenticated:
        leave_room(f"user_{current_user.id}")


@socketio.on("subscribe_scan")
def on_subscribe_scan(data):
    """Cliente subscreve a um scan específico."""
    scan_id = data.get("scan_id", "")
    if scan_id:
        join_room(f"scan_{scan_id}")
        emit("subscribed", {"scan_id": scan_id})


@socketio.on("unsubscribe_scan")
def on_unsubscribe_scan(data):
    scan_id = data.get("scan_id", "")
    if scan_id:
        leave_room(f"scan_{scan_id}")


# ── Emissores (chamados pelo backend) ─────────────────────────────────────────

def notify_scan_complete(user_id: str, scan_data: dict):
    """Notifica o dashboard que um scan terminou."""
    socketio.emit(
        "scan_complete",
        {
            "type":    "scan_complete",
            "scan_id": scan_data.get("scan_id"),
            "url":     scan_data.get("url"),
            "score":   scan_data.get("score"),
            "counts":  scan_data.get("counts", {}),
            "elapsed": scan_data.get("elapsed"),
            "message": f"Scan de {scan_data.get('url','')} concluído — Score: {scan_data.get('score',0)}/100",
        },
        room=f"user_{user_id}",
    )


def notify_scan_progress(scan_id: str, module_name: str, progress: int,
                         critical: int = 0, high: int = 0):
    """Emite progresso de um scan em andamento."""
    socketio.emit(
        "scan_progress",
        {
            "scan_id":     scan_id,
            "module":      module_name,
            "progress":    progress,
            "critical":    critical,
            "high":        high,
        },
        room=f"scan_{scan_id}",
    )


def notify_chain_detected(user_id: str, chain: dict, scan_id: str):
    """Notificação especial quando uma attack chain crítica é detectada."""
    if chain.get("severity") != "critical":
        return
    socketio.emit(
        "chain_detected",
        {
            "type":    "chain_detected",
            "scan_id": scan_id,
            "title":   chain.get("title", ""),
            "cvss":    chain.get("cvss_estimate", ""),
            "message": f"⛓ Attack Chain detectada: {chain.get('title','')}",
        },
        room=f"user_{user_id}",
    )


def notify_scheduled_scan_done(user_id: str, url: str, score: int,
                               counts: dict, scan_id: str):
    """Notifica que um scan agendado terminou."""
    critical = counts.get("critical", 0)
    level    = "critical" if critical > 0 else "warning" if counts.get("high", 0) > 0 else "info"
    socketio.emit(
        "scheduled_scan_done",
        {
            "type":    "scheduled_scan_done",
            "scan_id": scan_id,
            "url":     url,
            "score":   score,
            "counts":  counts,
            "level":   level,
            "message": (
                f"Scan agendado de {url} — Score: {score}/100"
                + (f" | {critical} CRÍTICO(S)" if critical > 0 else "")
            ),
        },
        room=f"user_{user_id}",
    )


def broadcast_system_message(message: str, level: str = "info"):
    """Mensagem de sistema para todos os usuários conectados (apenas admin)."""
    socketio.emit(
        "system_message",
        {"type": "system", "message": message, "level": level},
    )
