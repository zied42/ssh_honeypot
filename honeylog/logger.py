"""Structured JSON Lines Logging module for SSH Honeypot"""

import json
import logging
import os
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from config.settings import LOG_DIR, AUDIT_LOG, CMD_LOG, ALERT_LOG, LOG_MAX_BYTES, LOG_BACKUP_COUNT

os.makedirs(LOG_DIR, exist_ok=True)


class JSONFormatter(logging.Formatter):
    """Format record payload into single-line JSON string safely sanitizing bytes and objects"""
    def format(self, record):
        if isinstance(record.msg, dict):
            payload = record.msg.copy()
        else:
            payload = {"event": "raw_message", "message": record.getMessage()}

        if "timestamp" not in payload:
            payload["timestamp"] = datetime.now(timezone.utc).isoformat()

        def sanitize(obj):
            if isinstance(obj, bytes):
                return obj.decode("utf-8", errors="ignore")
            if isinstance(obj, dict):
                return {k: sanitize(v) for k, v in obj.items()}
            if isinstance(obj, (list, tuple)):
                return [sanitize(i) for i in obj]
            return obj

        return json.dumps(sanitize(payload), ensure_ascii=False)


def build_logger(name, filename, level=logging.INFO):
    """Build a logger with RotatingFileHandler emitting JSON lines"""
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.propagate = False

    if not logger.handlers:
        log_path = os.path.join(LOG_DIR, filename)
        handler = RotatingFileHandler(
            log_path,
            maxBytes=LOG_MAX_BYTES,
            backupCount=LOG_BACKUP_COUNT,
            encoding="utf-8"
        )
        handler.setFormatter(JSONFormatter())
        logger.addHandler(handler)

    return logger


funnel_logger = build_logger("FunnelLogger", AUDIT_LOG, logging.INFO)
cmd_logger = build_logger("CmdLogger", CMD_LOG, logging.INFO)
alert_logger = build_logger("AlertLogger", ALERT_LOG, logging.WARNING)


def log_event(logger, event_type, session_id=None, src_ip=None, src_port=None, username=None, **kwargs):
    """Helper to emit structured log event"""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event_type,
        "session_id": session_id,
        "src_ip": src_ip,
        "src_port": src_port,
        "username": username,
    }
    for k, v in kwargs.items():
        if v is not None:
            entry[k] = v

    logger.info(entry)
    return entry


def log_alert(session_id, src_ip, username, severity, hits, command, category=None, mitre_attack=None, iocs=None, **kwargs):
    """Helper to emit alert log event"""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": "alert",
        "session_id": session_id,
        "src_ip": src_ip,
        "username": username,
        "severity": severity,
        "hits": hits,
        "category": category,
        "mitre_attack": mitre_attack,
        "command": command,
        "iocs": iocs or {},
    }
    for k, v in kwargs.items():
        if v is not None:
            entry[k] = v

    alert_logger.warning(entry)
    return entry
