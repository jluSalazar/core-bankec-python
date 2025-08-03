import jwt
import os
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import request, g
from flask_restx import abort

# Clave secreta para JWT (en producción debería estar en variables de entorno)
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY')
JWT_ALGORITHM = 'HS256'
JWT_EXPIRATION_HOURS = 24

def generate_jwt_token(user_data):
    """
    Genera un token JWT con los datos del usuario
    """
    payload = {
        'user_id': user_data['id'],
        'username': user_data['username'],
        'role': user_data['role'],
        'full_name': user_data['full_name'],
        'email': user_data['email'],
        'exp': datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS),
        'iat': datetime.now(timezone.utc)
    }
    
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return token

def decode_jwt_token(token):
    """
    Decodifica y valida un token JWT
    """
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def mask_sensitive_data(data_str, mask_char='*'):
    """
    Enmascara información sensible para logs
    """
    if not data_str or len(data_str) <= 4:
        return mask_char * len(data_str) if data_str else None
    
    # Mostrar solo los primeros 4 caracteres y enmascarar el resto
    return data_str[:4] + mask_char * (len(data_str) - 4)

def jwt_required(f):
    """
    Decorator que requiere un token JWT válido
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            abort(401, "Authorization header missing or invalid")
        
        token = auth_header.split(" ")[1]
        
        # Decodificar el token JWT
        payload = decode_jwt_token(token)
        if not payload:
            abort(401, "Invalid or expired JWT token")
        
        # Establecer los datos del usuario en g
        g.user = {
            "id": payload['user_id'],
            "username": payload['username'],
            "role": payload['role'],
            "full_name": payload['full_name'],
            "email": payload['email']
        }
        
        return f(*args, **kwargs)
    
    return decorated