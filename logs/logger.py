"""Logging module for honeypot"""

import logging
from logging.handlers import RotatingFileHandler
import os
from config.settings import LOG_DIR, LOG_MAX_BYTES, LOG_BACKUP_COUNT

# Create logs directory if it doesn't exist
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

FORMAT = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)


def build_logger(name, level, filename):
    """Build a logger with rotating file handler"""
    logger = logging.getLogger(name)
    logger.setLevel(level)

    if not logger.handlers:
        log_path = os.path.join(LOG_DIR, filename)
        handler = RotatingFileHandler(
            log_path, 
            maxBytes=LOG_MAX_BYTES, 
            backupCount=LOG_BACKUP_COUNT
        )
        handler.setFormatter(FORMAT)
        logger.addHandler(handler)

    return logger


# Global logger instances
funnel_logger = build_logger("FunnelLogger", logging.INFO, "audits.log")
cmd_logger = build_logger("CmdLogger", logging.INFO, "cmd_audits.log")
alert_logger = build_logger("AlertLogger", logging.WARNING, "alerts.log")