# app/logger.py
import logging
import re
from datetime import datetime
from .config import Config

# Configure logging
logging.basicConfig(
    filename=Config.LOG_FILE,
    level=getattr(logging, Config.LOG_LEVEL),
    encoding="utf-8",
    filemode="a",
    format="{asctime} - {levelname} - {message}",
    style="{",
    datefmt="%Y-%m-%d %H:%M:%S",
)

logger = logging.getLogger(__name__)

def mask_sensitive_data(data):
    """
    Enmascara información sensible en los logs
    """
    if isinstance(data, dict):
        masked_data = {}
        for key, value in data.items():
            if key.lower() in ['password', 'token', 'pin', 'secret', 'key']:
                masked_data[key] = "****"
            elif key.lower() in ['email']:
                # Mask email partially: user@domain.com -> u***@d***.com
                if isinstance(value, str) and '@' in value:
                    parts = value.split('@')
                    if len(parts) == 2:
                        username = parts[0]
                        domain = parts[1]
                        masked_username = username[0] + '*' * (len(username) - 1) if len(username) > 1 else username
                        masked_domain = domain[0] + '*' * (len(domain) - 1) if len(domain) > 1 else domain
                        masked_data[key] = f"{masked_username}@{masked_domain}"
                    else:
                        masked_data[key] = "***"
                else:
                    masked_data[key] = "***"
            elif key.lower() in ['account_number', 'card_number']:
                # Mask all but last 4 digits
                if isinstance(value, (str, int)):
                    str_value = str(value)
                    if len(str_value) > 4:
                        masked_data[key] = '*' * (len(str_value) - 4) + str_value[-4:]
                    else:
                        masked_data[key] = "****"
                else:
                    masked_data[key] = "****"
            elif isinstance(value, dict):
                masked_data[key] = mask_sensitive_data(value)
            elif isinstance(value, list):
                masked_data[key] = [mask_sensitive_data(item) if isinstance(item, dict) else item for item in value]
            else:
                masked_data[key] = value
        return masked_data
    elif isinstance(data, str):
        # Mask potential sensitive patterns in strings
        # Mask credit card numbers (16 digits)
        data = re.sub(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b', 
                     lambda m: '*' * (len(m.group()) - 4) + m.group()[-4:], data)
        # Mask potential tokens (long alphanumeric strings)
        data = re.sub(r'\b[A-Za-z0-9]{20,}\b', '****', data)
        return data
    else:
        return data

def log_action(action, user_id=None, details=None, level="INFO", **kwargs):
    """
    Registra una acción en el log con enmascaramiento de datos sensibles
    """
    timestamp = datetime.now().isoformat()
    
    log_entry = {
        "timestamp": timestamp,
        "action": action,
        "user_id": user_id,
        "details": details
    }
    
    # Add any additional data
    for key, value in kwargs.items():
        log_entry[key] = value
    
    # Mask sensitive data
    masked_entry = mask_sensitive_data(log_entry)
    
    # Format log message
    log_message = f"Action: {masked_entry['action']}"
    if masked_entry.get('user_id'):
        log_message += f" | User ID: {masked_entry['user_id']}"
    if masked_entry.get('details'):
        log_message += f" | Details: {masked_entry['details']}"
    
    # Add any additional masked data
    for key, value in masked_entry.items():
        if key not in ['timestamp', 'action', 'user_id', 'details']:
            log_message += f" | {key}: {value}"
    
    # Log with appropriate level
    if level.upper() == "DEBUG":
        logger.debug(log_message)
    elif level.upper() == "WARNING":
        logger.warning(log_message)
    elif level.upper() == "ERROR":
        logger.error(log_message)
    else:
        logger.info(log_message)
