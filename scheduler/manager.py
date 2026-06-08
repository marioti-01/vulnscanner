"""
Scheduler — VulnScanner v6
Gerencia scans agendados (diário, semanal, mensal).
Usa APScheduler + notificação por email via SMTP.
"""

import datetime
import smtplib
import uuid
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

logger = logging.getLogger(__name__)

_scheduler = BackgroundScheduler(timezone="UTC")
_app_ref = None  # Flask app reference


def init_scheduler(app):
    """Inicializa o scheduler com referência ao app Flask."""
    global _app_ref
    _app_ref = app
    _scheduler.start()
    _load_jobs_from_db()
    logger.info("Scheduler iniciado.")


def _load_jobs_from_db():
    """Carrega todos os scans agendados ativos do banco."""
    if not _app_ref:
        return
    with _app_ref.app_context():
        from database.models import ScheduledScan
        jobs = ScheduledScan.query.filter_by(is_active=True).all()
        for job in jobs:
            _add_job(job)
        logger.info(f"Scheduler: {len(jobs)} job(s) carregado(s).")


def _get_cron_trigger(frequency: str) -> CronTrigger:
    """Converte frequência em CronTrigger."""
    triggers = {
        "daily":   CronTrigger(hour=3, minute=0),           # Todo dia às 03:00 UTC
        "weekly":  CronTrigger(day_of_week="mon", hour=3),  # Toda segunda às 03:00 UTC
        "monthly": CronTrigger(day=1, hour=3),               # Dia 1 de cada mês às 03:00 UTC
    }
    return triggers.get(frequency, CronTrigger(hour=3))


def _add_job(scheduled_scan):
    """Adiciona ou atualiza um job no scheduler."""
    job_id = f"scan_{scheduled_scan.id}"
    trigger = _get_cron_trigger(scheduled_scan.frequency)

    if _scheduler.get_job(job_id):
        _scheduler.remove_job(job_id)

    _scheduler.add_job(
        func=_run_scheduled_scan,
        trigger=trigger,
        id=job_id,
        args=[scheduled_scan.id],
        replace_existing=True,
        misfire_grace_time=3600,  # 1h de tolerância
    )


def _run_scheduled_scan(scheduled_scan_id: str):
    """Executa um scan agendado."""
    if not _app_ref:
        return

    with _app_ref.app_context():
        from database.models import db, ScheduledScan, Scan, Project
        from modules.circuit_breaker import safe_run_module

        scheduled = ScheduledScan.query.get(scheduled_scan_id)
        if not scheduled or not scheduled.is_active:
            return

        logger.info(f"Scheduler: executando scan de {scheduled.url}")

        # Importa o runner principal
        try:
            from app import _run_scan, score_findings, count_by_severity, SEVERITY_COLORS
            import json

            scan_id = str(uuid.uuid4())[:8]
            start = datetime.datetime.utcnow()

            auth = {}  # Scans agendados sem auth por ora
            results = _run_scan(scheduled.url, auth, scheduled.rate_profile)

            elapsed = (datetime.datetime.utcnow() - start).total_seconds()
            score = score_findings(results)
            counts = count_by_severity(results)

            from modules.executive_report import generate_executive_report
            executive = generate_executive_report(
                url=scheduled.url, scan_id=scan_id, elapsed=elapsed,
                score=score, counts=counts, modules_results=results,
            )

            report = {
                "scan_id": scan_id,
                "url": scheduled.url,
                "elapsed": round(elapsed, 1),
                "score": score,
                "counts": counts,
                "modules": results,
                "severity_colors": SEVERITY_COLORS,
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "executive": executive,
                "scheduled": True,
            }

            scan = Scan(
                scan_id=scan_id,
                project_id=scheduled.project_id,
                user_id=scheduled.user_id,
                url=scheduled.url,
                status="done",
                score=score,
                elapsed=round(elapsed, 1),
                rate_profile=scheduled.rate_profile,
                completed_at=datetime.datetime.utcnow(),
                count_critical=counts.get("critical", 0),
                count_high=counts.get("high", 0),
                count_medium=counts.get("medium", 0),
                count_low=counts.get("low", 0),
                count_info=counts.get("info", 0),
            )
            scan.set_report(report)
            db.session.add(scan)

            scheduled.last_run = datetime.datetime.utcnow()
            scheduled.run_count += 1
            db.session.commit()

            # Notificação por email
            _maybe_notify(scheduled, scan, report)

        except Exception as e:
            logger.error(f"Scheduler: erro no scan de {scheduled.url}: {e}")

            scheduled.last_run = datetime.datetime.utcnow()
            db.session.commit()


def _maybe_notify(scheduled, scan, report):
    """Envia notificação por email se configurado."""
    if not scheduled.notify_email:
        return

    notify_on = scheduled.notify_on
    counts = report.get("counts", {})
    score = report.get("score", 100)

    should_notify = False
    if notify_on == "always":
        should_notify = True
    elif notify_on == "critical" and counts.get("critical", 0) > 0:
        should_notify = True
    elif notify_on == "degradation":
        # Verifica se score piorou (comparando com scan anterior)
        should_notify = score < 70  # Simplificado

    if should_notify:
        _send_email_notification(scheduled.notify_email, scan, report)


def _send_email_notification(to_email: str, scan, report: dict):
    """Envia email de notificação de scan."""
    import os
    smtp_host = os.getenv("SMTP_HOST", "")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER", "")
    smtp_pass = os.getenv("SMTP_PASS", "")

    if not smtp_host or not smtp_user:
        logger.warning("SMTP não configurado — notificação ignorada.")
        return

    counts = report.get("counts", {})
    score = report.get("score", 0)
    url = scan.url

    subject = f"[VulnScanner] Scan de {url} — Score: {score}/100"
    if counts.get("critical", 0) > 0:
        subject = f"🚨 {subject} — {counts['critical']} CRÍTICO(S)"
    elif counts.get("high", 0) > 0:
        subject = f"⚠️ {subject} — {counts['high']} ALTO(S)"

    body = f"""
VulnScanner — Resultado do Scan Agendado
=========================================

Alvo: {url}
Score: {score}/100
Data: {datetime.datetime.utcnow().strftime('%d/%m/%Y %H:%M UTC')}
ID: {scan.scan_id}

Resumo:
  Critical: {counts.get('critical', 0)}
  High:     {counts.get('high', 0)}
  Medium:   {counts.get('medium', 0)}
  Low:      {counts.get('low', 0)}

Avaliação:
{report.get('executive', {}).get('executive', {}).get('summary', 'N/A')}

Acesse o relatório completo em:
http://localhost:5000/report/{scan.scan_id}

---
VulnScanner v6 — Use apenas em sistemas autorizados.
"""

    try:
        msg = MIMEMultipart()
        msg["From"] = smtp_user
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain", "utf-8"))

        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)

        logger.info(f"Email enviado para {to_email}")
    except Exception as e:
        logger.error(f"Erro ao enviar email: {e}")


# ── API pública do scheduler ──────────────────────────────────────────────────

def add_scheduled_scan(scheduled_scan) -> bool:
    """Adiciona um novo scan agendado."""
    try:
        _add_job(scheduled_scan)
        return True
    except Exception as e:
        logger.error(f"Erro ao adicionar job: {e}")
        return False


def remove_scheduled_scan(scheduled_scan_id: str):
    """Remove um scan agendado."""
    job_id = f"scan_{scheduled_scan_id}"
    if _scheduler.get_job(job_id):
        _scheduler.remove_job(job_id)


def pause_scheduled_scan(scheduled_scan_id: str):
    """Pausa um scan agendado."""
    job_id = f"scan_{scheduled_scan_id}"
    job = _scheduler.get_job(job_id)
    if job:
        job.pause()


def resume_scheduled_scan(scheduled_scan_id: str):
    """Retoma um scan pausado."""
    job_id = f"scan_{scheduled_scan_id}"
    job = _scheduler.get_job(job_id)
    if job:
        job.resume()


def get_scheduler_status() -> dict:
    """Retorna status geral do scheduler."""
    jobs = _scheduler.get_jobs()
    return {
        "running": _scheduler.running,
        "jobs_count": len(jobs),
        "jobs": [
            {
                "id": j.id,
                "next_run": j.next_run_time.isoformat() if j.next_run_time else None,
            }
            for j in jobs
        ],
    }
