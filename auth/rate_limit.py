"""
Rate Limiting de API — VulnScanner v7
Controla quantas requisições/scans cada usuário pode fazer.
"""

import time
import threading
from collections import defaultdict, deque
from flask import request, jsonify, g
from functools import wraps


# ── Limites por role ──────────────────────────────────────────────────────────
ROLE_LIMITS = {
    "admin": {
        "scans_per_day": 9999,
        "requests_per_minute": 300,
        "concurrent_scans": 10,
    },
    "user": {
        "scans_per_day": 20,
        "requests_per_minute": 60,
        "concurrent_scans": 2,
    },
}

# Estado em memória (em produção real, usar Redis)
_request_windows: dict = defaultdict(deque)   # user_id → timestamps de requests
_scan_counts: dict = defaultdict(list)         # user_id → timestamps de scans hoje
_active_scans: dict = defaultdict(int)         # user_id → scans ativos agora
_lock = threading.Lock()


def _get_limits(user) -> dict:
    role = getattr(user, "role", "user")
    return ROLE_LIMITS.get(role, ROLE_LIMITS["user"])


def check_rate_limit(user) -> tuple[bool, str, dict]:
    """
    Verifica se o usuário pode fazer mais requests.
    Retorna (allowed, reason, headers).
    """
    if not user:
        return False, "Não autenticado", {}

    limits = _get_limits(user)
    user_id = str(user.id)
    now = time.monotonic()

    with _lock:
        # Sliding window — requests por minuto
        window = _request_windows[user_id]
        cutoff = now - 60.0
        while window and window[0] < cutoff:
            window.popleft()

        rpm = len(window)
        max_rpm = limits["requests_per_minute"]

        if rpm >= max_rpm:
            retry_after = int(60 - (now - window[0])) + 1
            return False, f"Rate limit excedido: {rpm}/{max_rpm} req/min", {
                "X-RateLimit-Limit": str(max_rpm),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(int(time.time()) + retry_after),
                "Retry-After": str(retry_after),
            }

        window.append(now)
        remaining = max_rpm - len(window)

    return True, "", {
        "X-RateLimit-Limit": str(max_rpm),
        "X-RateLimit-Remaining": str(remaining),
        "X-RateLimit-Reset": str(int(time.time()) + 60),
    }


def check_scan_quota(user) -> tuple[bool, str]:
    """Verifica se o usuário pode iniciar mais um scan."""
    if not user:
        return False, "Não autenticado"

    limits = _get_limits(user)
    user_id = str(user.id)
    now = time.time()
    day_start = now - 86400  # últimas 24h

    with _lock:
        # Scans nas últimas 24h
        scans_today = _scan_counts[user_id]
        _scan_counts[user_id] = [t for t in scans_today if t > day_start]
        daily_count = len(_scan_counts[user_id])

        if daily_count >= limits["scans_per_day"]:
            return False, (
                f"Limite diário de scans atingido: {daily_count}/{limits['scans_per_day']}. "
                f"Resets em 24h."
            )

        # Scans simultâneos
        active = _active_scans[user_id]
        if active >= limits["concurrent_scans"]:
            return False, (
                f"Limite de scans simultâneos: {active}/{limits['concurrent_scans']} ativos. "
                f"Aguarde um scan terminar."
            )

    return True, ""


def register_scan_start(user):
    """Registra início de um scan."""
    if not user:
        return
    user_id = str(user.id)
    with _lock:
        _scan_counts[user_id].append(time.time())
        _active_scans[user_id] += 1


def register_scan_end(user):
    """Registra fim de um scan."""
    if not user:
        return
    user_id = str(user.id)
    with _lock:
        if _active_scans[user_id] > 0:
            _active_scans[user_id] -= 1


def get_quota_status(user) -> dict:
    """Retorna status de quota do usuário."""
    if not user:
        return {}
    limits = _get_limits(user)
    user_id = str(user.id)
    now = time.time()
    day_start = now - 86400

    with _lock:
        scans_today = len([t for t in _scan_counts[user_id] if t > day_start])
        active = _active_scans[user_id]

    return {
        "scans_today": scans_today,
        "scans_limit": limits["scans_per_day"],
        "scans_remaining": max(0, limits["scans_per_day"] - scans_today),
        "concurrent_active": active,
        "concurrent_limit": limits["concurrent_scans"],
        "requests_per_minute": limits["requests_per_minute"],
    }


# ── Decorators ────────────────────────────────────────────────────────────────

def rate_limited(f):
    """Aplica rate limiting de requests por minuto."""
    @wraps(f)
    def decorated(*args, **kwargs):
        from auth.middleware import get_current_user
        user = get_current_user()
        allowed, reason, headers = check_rate_limit(user)

        if not allowed:
            resp = jsonify({"error": reason, "code": 429})
            resp.status_code = 429
            for k, v in headers.items():
                resp.headers[k] = v
            return resp

        response = f(*args, **kwargs)

        # Adiciona headers de rate limit na resposta
        if hasattr(response, "headers"):
            for k, v in headers.items():
                response.headers[k] = v
        return response
    return decorated


def scan_quota_required(f):
    """Verifica quota de scans antes de iniciar."""
    @wraps(f)
    def decorated(*args, **kwargs):
        from auth.middleware import get_current_user
        user = get_current_user()
        allowed, reason = check_scan_quota(user)
        if not allowed:
            return jsonify({"error": reason, "code": 429}), 429
        return f(*args, **kwargs)
    return decorated
