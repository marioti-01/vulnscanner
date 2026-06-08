"""
Database Models — VulnScanner v6
SQLAlchemy ORM para todos os dados persistentes.
"""

import uuid
import secrets
import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import UserMixin

db = SQLAlchemy()
bcrypt = Bcrypt()


def generate_uuid():
    return str(uuid.uuid4())


def generate_api_key():
    return "vs_" + secrets.token_hex(32)


# ── User ─────────────────────────────────────────────────────────────────────
class User(UserMixin, db.Model):
    __tablename__ = "users"

    id           = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    username     = db.Column(db.String(80), unique=True, nullable=False)
    email        = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role         = db.Column(db.String(20), default="user")  # admin | user
    created_at   = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    last_login   = db.Column(db.DateTime)
    is_active    = db.Column(db.Boolean, default=True)

    projects  = db.relationship("Project", backref="owner", lazy=True, cascade="all, delete")
    api_keys  = db.relationship("ApiKey", backref="user", lazy=True, cascade="all, delete")

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode("utf-8")

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "created_at": self.created_at.isoformat(),
        }


# ── ApiKey ────────────────────────────────────────────────────────────────────
class ApiKey(db.Model):
    __tablename__ = "api_keys"

    id         = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    user_id    = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False)
    key        = db.Column(db.String(80), unique=True, default=generate_api_key)
    name       = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    last_used  = db.Column(db.DateTime)
    is_active  = db.Column(db.Boolean, default=True)
    scans_used = db.Column(db.Integer, default=0)


# ── Project ───────────────────────────────────────────────────────────────────
class Project(db.Model):
    __tablename__ = "projects"

    id          = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    user_id     = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False)
    name        = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, default="")
    color       = db.Column(db.String(7), default="#FF4757")
    created_at  = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at  = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    scans           = db.relationship("Scan", backref="project", lazy=True, cascade="all, delete")
    scheduled_scans = db.relationship("ScheduledScan", backref="project", lazy=True, cascade="all, delete")

    def latest_scan(self):
        return Scan.query.filter_by(project_id=self.id).order_by(Scan.created_at.desc()).first()

    def scan_count(self):
        return Scan.query.filter_by(project_id=self.id).count()

    def to_dict(self):
        latest = self.latest_scan()
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "color": self.color,
            "created_at": self.created_at.isoformat(),
            "scan_count": self.scan_count(),
            "latest_score": latest.score if latest else None,
            "latest_url": latest.url if latest else None,
            "latest_scan_date": latest.created_at.isoformat() if latest else None,
        }


# ── Scan ──────────────────────────────────────────────────────────────────────
class Scan(db.Model):
    __tablename__ = "scans"

    id           = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    scan_id      = db.Column(db.String(8), unique=True, nullable=False)
    project_id   = db.Column(db.String(36), db.ForeignKey("projects.id"), nullable=True)
    user_id      = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False)
    url          = db.Column(db.String(500), nullable=False)
    status       = db.Column(db.String(20), default="running")  # running | done | error
    score        = db.Column(db.Integer, default=0)
    elapsed      = db.Column(db.Float, default=0.0)
    rate_profile = db.Column(db.String(20), default="normal")
    created_at   = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    completed_at = db.Column(db.DateTime)

    # Contadores de severidade
    count_critical = db.Column(db.Integer, default=0)
    count_high     = db.Column(db.Integer, default=0)
    count_medium   = db.Column(db.Integer, default=0)
    count_low      = db.Column(db.Integer, default=0)
    count_info     = db.Column(db.Integer, default=0)

    # Dados completos em JSON
    report_json  = db.Column(db.Text)  # JSON completo do relatório

    def get_report(self):
        import json
        if self.report_json:
            return json.loads(self.report_json)
        return {}

    def set_report(self, report_dict):
        import json
        self.report_json = json.dumps(report_dict, ensure_ascii=False, default=str)

    def to_dict(self, include_report=False):
        d = {
            "id": self.id,
            "scan_id": self.scan_id,
            "project_id": self.project_id,
            "url": self.url,
            "status": self.status,
            "score": self.score,
            "elapsed": self.elapsed,
            "rate_profile": self.rate_profile,
            "created_at": self.created_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "counts": {
                "critical": self.count_critical,
                "high": self.count_high,
                "medium": self.count_medium,
                "low": self.count_low,
                "info": self.count_info,
            },
        }
        if include_report:
            d["report"] = self.get_report()
        return d


# ── ScheduledScan ─────────────────────────────────────────────────────────────
class ScheduledScan(db.Model):
    __tablename__ = "scheduled_scans"

    id           = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    project_id   = db.Column(db.String(36), db.ForeignKey("projects.id"), nullable=False)
    user_id      = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False)
    url          = db.Column(db.String(500), nullable=False)
    frequency    = db.Column(db.String(20), nullable=False)  # daily | weekly | monthly
    rate_profile = db.Column(db.String(20), default="normal")
    notify_email = db.Column(db.String(200), default="")
    notify_on    = db.Column(db.String(50), default="always")  # always | degradation | critical
    is_active    = db.Column(db.Boolean, default=True)
    created_at   = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    last_run     = db.Column(db.DateTime)
    next_run     = db.Column(db.DateTime)
    run_count    = db.Column(db.Integer, default=0)

    def to_dict(self):
        return {
            "id": self.id,
            "project_id": self.project_id,
            "url": self.url,
            "frequency": self.frequency,
            "rate_profile": self.rate_profile,
            "notify_email": self.notify_email,
            "notify_on": self.notify_on,
            "is_active": self.is_active,
            "last_run": self.last_run.isoformat() if self.last_run else None,
            "next_run": self.next_run.isoformat() if self.next_run else None,
            "run_count": self.run_count,
        }


# ── Plugin ────────────────────────────────────────────────────────────────────
class Plugin(db.Model):
    __tablename__ = "plugins"

    id          = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    user_id     = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False)
    name        = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, default="")
    version     = db.Column(db.String(20), default="1.0.0")
    code        = db.Column(db.Text, nullable=False)  # Python code do plugin
    is_active   = db.Column(db.Boolean, default=True)
    created_at  = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    run_count   = db.Column(db.Integer, default=0)
    last_run    = db.Column(db.DateTime)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat(),
            "run_count": self.run_count,
        }
