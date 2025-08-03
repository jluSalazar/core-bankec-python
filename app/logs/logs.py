from datetime import datetime
from app.db import get_connection

def log_event(log_type, remote_ip=None, username=None, action=None, http_code=None):
    """
    Inserta un registro de log en la tabla bank.logs.
    - log_type: 'INFO', 'DEBUG', 'WARNING', 'ERROR'
    - remote_ip: dirección IP remota (opcional)
    - username: nombre de usuario (opcional)
    - action: acción/mensaje/opción accedida (opcional)
    - http_code: código HTTP de respuesta (opcional)
    """
    conn = get_connection()
    cur = conn.cursor()
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]  # AAAA-MM-DD HH:MM:SS.sss
    cur.execute(
        """
        INSERT INTO bank.logs (log_time, log_type, remote_ip, username, action, http_code)
        VALUES (%s, %s, %s, %s, %s, %s)
        """,
        (now, log_type, remote_ip, username, action, http_code)
    )
    conn.commit()
    cur.close()
    conn.close()
