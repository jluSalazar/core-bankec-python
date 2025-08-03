# app/auth.py
import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask import request, g
from flask_restx import abort
from .config import Config
from .db import get_connection
from .logger import log_action
import re

class JWTAuth:
    @staticmethod
    def generate_token(user_data):
        """
        Genera un token JWT para el usuario autenticado
        """
        payload = {
            'user_id': user_data['id'],
            'username': user_data['username'],
            'role': user_data['role'],
            'exp': datetime.utcnow() + Config.JWT_ACCESS_TOKEN_EXPIRES,
            'iat': datetime.utcnow()
        }
        
        token = jwt.encode(
            payload,
            Config.JWT_SECRET_KEY,
            algorithm=Config.JWT_ALGORITHM
        )
        
        log_action(
            action="TOKEN_GENERATED",
            user_id=user_data['id'],
            details=f"Token generated for user {user_data['username']}"
        )
        
        return token
    
    @staticmethod
    def decode_token(token):
        """
        Decodifica y valida un token JWT
        """
        try:
            payload = jwt.decode(
                token,
                Config.JWT_SECRET_KEY,
                algorithms=[Config.JWT_ALGORITHM]
            )
            return payload
        except jwt.ExpiredSignatureError:
            log_action(
                action="TOKEN_EXPIRED",
                details="Attempted to use expired token"
            )
            return None
        except jwt.InvalidTokenError:
            log_action(
                action="TOKEN_INVALID",
                details="Attempted to use invalid token"
            )
            return None
    
    @staticmethod
    def get_user_from_token(token):
        """
        Obtiene la información del usuario desde un token JWT
        """
        payload = JWTAuth.decode_token(token)
        if not payload:
            return None
        
        conn = get_connection()
        cur = conn.cursor()
        
        try:
            cur.execute("""
                SELECT id, username, role, full_name, email 
                FROM bank.users 
                WHERE id = %s
            """, (payload['user_id'],))
            
            user = cur.fetchone()
            if user:
                return {
                    "id": user[0],
                    "username": user[1],
                    "role": user[2],
                    "full_name": user[3],
                    "email": user[4]
                }
            return None
        finally:
            cur.close()
            conn.close()

def jwt_required(f):
    """
    Decorador que requiere autenticación JWT válida
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        
        if not auth_header:
            log_action(
                action="AUTH_FAILED",
                details="Missing Authorization header"
            )
            abort(401, "Authorization header is required")
        
        if not auth_header.startswith("Bearer "):
            log_action(
                action="AUTH_FAILED",
                details="Invalid Authorization header format"
            )
            abort(401, "Authorization header must start with 'Bearer '")
        
        token = auth_header.split(" ")[1]
        
        # Validate token format
        if not token or not re.match(r'^[A-Za-z0-9\-_.]+$', token):
            log_action(
                action="AUTH_FAILED",
                details="Invalid token format"
            )
            abort(401, "Invalid token format")
        
        user = JWTAuth.get_user_from_token(token)
        if not user:
            log_action(
                action="AUTH_FAILED",
                details="Invalid or expired token"
            )
            abort(401, "Invalid or expired token")
        
        g.user = user
        log_action(
            action="AUTH_SUCCESS",
            user_id=user['id'],
            details=f"User {user['username']} authenticated successfully"
        )
        
        return f(*args, **kwargs)
    return decorated

def role_required(required_roles):
    """
    Decorador que requiere roles específicos
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not hasattr(g, 'user'):
                abort(401, "Authentication required")
            
            if g.user['role'] not in required_roles:
                log_action(
                    action="AUTHORIZATION_FAILED",
                    user_id=g.user['id'],
                    details=f"User {g.user['username']} attempted to access resource requiring roles {required_roles} but has role {g.user['role']}"
                )
                abort(403, "Insufficient permissions")
            
            return f(*args, **kwargs)
        return decorated
    return decorator
