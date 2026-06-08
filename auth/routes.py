"""
Auth Routes — VulnScanner v6
Blueprint com rotas de login, registro, logout e gestão de API keys.
"""

import datetime
from flask import Blueprint, render_template, request, jsonify, redirect, url_for, flash, session
from flask_login import login_user, logout_user, current_user
from database.models import db, User, ApiKey
from auth.middleware import get_current_user, require_auth

auth_bp = Blueprint("auth_bp", __name__, url_prefix="/auth")


@auth_bp.route("/login", methods=["GET"])
def login_page():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard_bp.index"))
    return render_template("auth/login.html")


@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json() or request.form
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Username e senha obrigatórios"}), 400

    user = User.query.filter(
        (User.username == username) | (User.email == username)
    ).first()

    if not user or not user.check_password(password):
        return jsonify({"error": "Credenciais inválidas"}), 401

    if not user.is_active:
        return jsonify({"error": "Conta desativada"}), 403

    login_user(user, remember=True)
    user.last_login = datetime.datetime.utcnow()
    db.session.commit()

    return jsonify({"success": True, "redirect": url_for("dashboard_bp.index")})


@auth_bp.route("/register", methods=["GET"])
def register_page():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard_bp.index"))
    # Só permite registro se não existir nenhum usuário (first-run) ou admin logado
    user_count = User.query.count()
    return render_template("auth/register.html", first_run=(user_count == 0))


@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.get_json() or request.form
    username = data.get("username", "").strip()
    email    = data.get("email", "").strip()
    password = data.get("password", "")

    if not username or not email or not password:
        return jsonify({"error": "Todos os campos são obrigatórios"}), 400
    if len(password) < 8:
        return jsonify({"error": "Senha deve ter no mínimo 8 caracteres"}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username já em uso"}), 409
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email já cadastrado"}), 409

    # Primeiro usuário é admin automaticamente
    role = "admin" if User.query.count() == 0 else "user"
    user = User(username=username, email=email, role=role)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    login_user(user)
    return jsonify({"success": True, "redirect": url_for("dashboard_bp.index")})


@auth_bp.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("auth_bp.login_page"))


# ── API Keys ──────────────────────────────────────────────────────────────────

@auth_bp.route("/api-keys", methods=["GET"])
@require_auth
def list_api_keys():
    user = get_current_user()
    keys = ApiKey.query.filter_by(user_id=user.id).order_by(ApiKey.created_at.desc()).all()
    return jsonify([{
        "id": k.id,
        "name": k.name,
        "key_preview": k.key[:10] + "..." + k.key[-4:],
        "created_at": k.created_at.isoformat(),
        "last_used": k.last_used.isoformat() if k.last_used else None,
        "scans_used": k.scans_used,
        "is_active": k.is_active,
    } for k in keys])


@auth_bp.route("/api-keys", methods=["POST"])
@require_auth
def create_api_key():
    user = get_current_user()
    data = request.get_json()
    name = data.get("name", "").strip()
    if not name:
        return jsonify({"error": "Nome da API key é obrigatório"}), 400
    if ApiKey.query.filter_by(user_id=user.id).count() >= 10:
        return jsonify({"error": "Máximo de 10 API keys por usuário"}), 400

    key = ApiKey(user_id=user.id, name=name)
    db.session.add(key)
    db.session.commit()

    # Retorna a key completa apenas uma vez
    return jsonify({
        "id": key.id,
        "name": key.name,
        "key": key.key,  # Mostrar só aqui — depois só preview
        "created_at": key.created_at.isoformat(),
    }), 201


@auth_bp.route("/api-keys/<key_id>", methods=["DELETE"])
@require_auth
def delete_api_key(key_id):
    user = get_current_user()
    key = ApiKey.query.filter_by(id=key_id, user_id=user.id).first_or_404()
    db.session.delete(key)
    db.session.commit()
    return jsonify({"success": True})


@auth_bp.route("/profile", methods=["GET"])
@require_auth
def profile():
    user = get_current_user()
    return jsonify(user.to_dict())


@auth_bp.route("/profile", methods=["PUT"])
@require_auth
def update_profile():
    user = get_current_user()
    data = request.get_json()

    if "email" in data:
        existing = User.query.filter_by(email=data["email"]).first()
        if existing and existing.id != user.id:
            return jsonify({"error": "Email já em uso"}), 409
        user.email = data["email"]

    if "password" in data:
        if len(data["password"]) < 8:
            return jsonify({"error": "Senha deve ter no mínimo 8 caracteres"}), 400
        if not user.check_password(data.get("current_password", "")):
            return jsonify({"error": "Senha atual incorreta"}), 401
        user.set_password(data["password"])

    db.session.commit()
    return jsonify({"success": True})
