"""
Auth System — VulnScanner v6
Login por sessão (web) e API keys (CI/CD e integrações).
"""

import datetime
import functools
from flask import request, jsonify, session, redirect, url_for, g
from flask_login import LoginManager, current_user
from database.models import db, User, ApiKey

login_manager = LoginManager()


def init_auth(app):
    login_manager.init_app(app)
    login_manager.login_view = "auth_bp.login_page"
    login_manager.login_message = "Faça login para continuar."


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


# ── API Key middleware ────────────────────────────────────────────────────────
def resolve_api_key(key_str: str):
    """Valida API key e retorna o usuário associado."""
    if not key_str or not key_str.startswith("vs_"):
        return None
    api_key = ApiKey.query.filter_by(key=key_str, is_active=True).first()
    if not api_key:
        return None
    # Atualiza last_used
    api_key.last_used = datetime.datetime.utcnow()
    api_key.scans_used += 1
    db.session.commit()
    return User.query.get(api_key.user_id)


def require_auth(f):
    """
    Decorator que aceita tanto sessão de usuário logado
    quanto API key via header X-API-Key ou Bearer token.
    """
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        # 1. Sessão web
        if current_user.is_authenticated:
            g.current_user = current_user
            return f(*args, **kwargs)

        # 2. API Key via header
        api_key = (
            request.headers.get("X-API-Key") or
            request.headers.get("Authorization", "").replace("Bearer ", "")
        )
        if api_key:
            user = resolve_api_key(api_key)
            if user and user.is_active:
                g.current_user = user
                return f(*args, **kwargs)

        # 3. Não autenticado
        if request.is_json or request.path.startswith("/api/"):
            return jsonify({"error": "Autenticação necessária", "code": 401}), 401
        return redirect(url_for("auth_bp.login_page"))

    return decorated


def require_admin(f):
    """Decorator que exige role admin."""
    @functools.wraps(f)
    @require_auth
    def decorated(*args, **kwargs):
        user = getattr(g, "current_user", current_user)
        if user.role != "admin":
            if request.is_json:
                return jsonify({"error": "Acesso negado — requer admin"}), 403
            return redirect(url_for("dashboard_bp.index"))
        return f(*args, **kwargs)
    return decorated


def get_current_user():
    """Retorna o usuário atual (sessão ou API key)."""
    return getattr(g, "current_user", current_user if current_user.is_authenticated else None)
