import secrets
from flask import Flask, request, g
from flask_restx import Api, Resource, fields # type: ignore
from functools import wraps
from app.db import get_connection, init_db
from app.logs.logs import log_event
from app.jwt_config import generate_jwt_token, jwt_required, mask_sensitive_data
import logging
import random
from datetime import datetime, timedelta

# SQL constantes
UPDATE_BANK_ACCOUNTS_SQL = "UPDATE bank.accounts SET balance = balance - %s WHERE user_id = %s"

#log = logging.getLogger(__name__)
logging.basicConfig(
     filename="app.log",
     level=logging.DEBUG,
     encoding="utf-8",
     filemode="a",
     format="{asctime} - {levelname} - {message}",
     style="{",
     datefmt="%Y-%m-%d %H:%M",
)

# Configure Swagger security scheme for Bearer tokens
authorizations = {
    'Bearer': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'Authorization',
        'description': "Enter your JWT token in the format **Bearer <jwt_token>**"
    }
}

app = Flask(__name__)
api = Api(
    app,
    version='1.0',
    title='Core Bancario API',
    description='API para operaciones bancarias con autenticación JWT, incluyendo autenticación y operaciones de cuenta.',
    doc='/swagger',  # Swagger UI endpoint
    authorizations=authorizations,
    security='Bearer'
)

# Create namespaces for authentication and bank operations
auth_ns = api.namespace('auth', description='Operaciones de autenticación JWT')
bank_ns = api.namespace('bank', description='Operaciones bancarias')

# Define the expected payload models for Swagger
login_model = auth_ns.model('Login', {
    'username': fields.String(required=True, description='Nombre de usuario', example='user1'),
    'password': fields.String(required=True, description='Contraseña', example='pass1')
})

deposit_model = bank_ns.model('Deposit', {
    'account_number': fields.Integer(required=True, description='Número de cuenta', example=123),
    'amount': fields.Float(required=True, description='Monto a depositar', example=100)
})

withdraw_model = bank_ns.model('Withdraw', {
    'amount': fields.Float(required=True, description='Monto a retirar', example=100)
})

credit_payment_model = bank_ns.model('CreditPayment', {
    'amount': fields.Float(required=True, description='Monto de la compra a crédito', example=100)
})

pay_credit_balance_model = bank_ns.model('PayCreditBalance', {
    'amount': fields.Float(required=True, description='Monto a abonar a la deuda de la tarjeta', example=50)
})

transfer_register_model = bank_ns.model('TransferRegister', {
    'target_username': fields.String(required=True, description='Usuario destino', example='user2'),
    'amount': fields.Float(required=True, description='Monto a transferir', example=100)
})

transfer_confirm_model = bank_ns.model('TransferConfirm', {
    'otp_code': fields.String(required=True, description='Código OTP de 6 dígitos', example='123456')
})

# ---------------- Authentication Endpoints ----------------

@auth_ns.route('/login')
class Login(Resource):
    @auth_ns.expect(login_model, validate=True)
    @auth_ns.doc('login')
    def post(self):
        """Inicia sesión y devuelve un token JWT de autenticación."""
        data = api.payload
        username = data.get("username")
        password = data.get("password")
        
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, username, password, role, full_name, email FROM bank.users WHERE username = %s", (username,))
        user = cur.fetchone()
        if user and user[2] == password:
            # Crear datos del usuario para el JWT
            user_data = {
                'id': user[0],
                'username': user[1],
                'role': user[3],
                'full_name': user[4],
                'email': user[5]
            }
            
            # Generar token JWT
            jwt_token = generate_jwt_token(user_data)
            
            cur.close()
            conn.close()
            
            log_event(
                log_type="INFO",
                remote_ip=request.remote_addr,
                username=username,
                action="Login exitoso con JWT",
                http_code=200
            )
            return {
                "message": "Login successful", 
                "token": jwt_token,
                "token_type": "JWT",
                "expires_in": "24 hours"
            }, 200
        else:  # credenciales invalidas
            cur.close()
            conn.close()
            log_event(
                log_type="WARNING",
                remote_ip=request.remote_addr,
                username=mask_sensitive_data(username),
                action="Intento de login fallido",
                http_code=401
            )
            api.abort(401, "Invalid credentials")

@auth_ns.route('/logout')
class Logout(Resource):
    @auth_ns.doc('logout', security='Bearer')
    @jwt_required
    def post(self):
        """Invalida la sesión actual (con JWT no se puede invalidar el token hasta que expire)."""
        log_event(
            log_type="INFO",
            remote_ip=request.remote_addr,
            username=g.user['username'],
            action="Logout exitoso",
            http_code=200
        )
        return {
            "message": "Logout successful",
            "note": "JWT token will remain valid until expiration. Consider implementing a blacklist for production."
        }, 200

# ---------------- Banking Operation Endpoints ----------------

@bank_ns.route('/deposit')
class Deposit(Resource):
    @bank_ns.expect(deposit_model, validate=True)
    @bank_ns.doc('deposit', security='Bearer')
    @jwt_required
    def post(self):
        """
        Realiza un depósito en la cuenta especificada.
        Se requiere el número de cuenta y el monto a depositar.
        """
        data = api.payload
        account_number = data.get("account_number")
        amount = data.get("amount", 0)
        
        # validar amount
        if amount <= 0:
            log_event(
                log_type="WARNING",
                remote_ip=request.remote_addr,
                username=g.user['username'],
                action="Intento de depósito con monto inválido",
                http_code=400
            )
            api.abort(400, "Amount must be greater than zero")
        
        conn = get_connection()
        cur = conn.cursor()
        # actualizar account balance
        cur.execute(
            "UPDATE bank.accounts SET balance = balance + %s WHERE id = %s RETURNING balance",
            (amount, account_number)
        )
        result = cur.fetchone()
        if not result:
            conn.rollback()
            cur.close()
            conn.close()
            log_event(
                log_type="ERROR",
                remote_ip=request.remote_addr,
                username=g.user['username'],
                action=f"Depósito fallido: cuenta {mask_sensitive_data(str(account_number))} no encontrada",
                http_code=404
            )
            api.abort(404, "Account not found")
        nuevo_balance = float(result[0])
        conn.commit()
        cur.close()
        conn.close()
        log_event(
            log_type="INFO",
            remote_ip=request.remote_addr,
            username=g.user['username'],
            action=f"Depósito exitoso en cuenta {mask_sensitive_data(str(account_number))} por {amount}",
            http_code=200
        )
        return {"message": "Deposit successful", "new_balance": nuevo_balance}, 200

@bank_ns.route('/withdraw')
class Withdraw(Resource):
    @bank_ns.expect(withdraw_model, validate=True)
    @bank_ns.doc('withdraw', security='Bearer')
    @jwt_required
    def post(self):
        """Realiza un retiro de la cuenta del usuario autenticado."""
        data = api.payload
        amount = data.get("amount", 0)
        if amount <= 0:
            log_event(
                log_type="WARNING",
                remote_ip=request.remote_addr,
                username=g.user['username'],
                action="Intento de retiro con monto inválido",
                http_code=400
            )
            api.abort(400, "Amount must be greater than zero")
        user_id = g.user['id']
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (user_id,))
        row = cur.fetchone()
        if not row:
            cur.close()
            conn.close()
            log_event(
                log_type="ERROR",
                remote_ip=request.remote_addr,
                username=g.user['username'],
                action="Retiro fallido: cuenta no encontrada",
                http_code=404
            )
            api.abort(404, "Account not found")
        current_balance = float(row[0]) 
        if current_balance < amount:  
            cur.close()
            conn.close()
            log_event(
                log_type="WARNING",
                remote_ip=request.remote_addr,
                username=g.user['username'],
                action="Retiro fallido: fondos insuficientes",
                http_code=400
            )
            api.abort(400, "Insufficient funds")
        cur.execute("UPDATE bank.accounts SET balance = balance - %s WHERE user_id = %s RETURNING balance", (amount, user_id))
        new_balance = float(cur.fetchone()[0])
        conn.commit()
        cur.close()
        conn.close()
        log_event(
            log_type="INFO",
            remote_ip=request.remote_addr,
            username=g.user['username'],
            action=f"Retiro exitoso de {amount}",
            http_code=200
        )
        return {"message": "Withdrawal successful", "new_balance": new_balance}, 200


@bank_ns.route('/credit-payment')
class CreditPayment(Resource):
    @bank_ns.expect(credit_payment_model, validate=True)
    @bank_ns.doc('credit_payment', security='Bearer')
    @jwt_required
    def post(self):
        """Realiza una compra a crédito."""
        data = api.payload
        amount = data.get("amount", 0)
        if amount <= 0:
            log_event(
                log_type="WARNING",
                remote_ip=request.remote_addr,
                username=g.user['username'],
                action="Intento de compra a crédito con monto inválido",
                http_code=400
            )
            api.abort(400, "Amount must be greater than zero")
        user_id = g.user['id']
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (user_id,))
        row = cur.fetchone()
        if not row:
            cur.close()
            conn.close()
            log_event(
                log_type="ERROR",
                remote_ip=request.remote_addr,
                username=g.user['username'],
                action="Compra a crédito fallida: cuenta no encontrada",
                http_code=404
            )
            api.abort(404, "Account not found")
        account_balance = float(row[0])
        if account_balance < amount:
            cur.close()
            conn.close()
            log_event(
                log_type="WARNING",
                remote_ip=request.remote_addr,
                username=g.user['username'],
                action="Compra a crédito fallida: fondos insuficientes",
                http_code=400
            )
            api.abort(400, "Insufficient funds in account")
        try:
            # debitar en la otra cuenta el monto 
            cur.execute(UPDATE_BANK_ACCOUNTS_SQL, (amount, user_id))
            cur.execute("UPDATE bank.credit_cards SET balance = balance + %s WHERE user_id = %s", (amount, user_id))
            cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (user_id,))
            new_account_balance = float(cur.fetchone()[0])
            cur.execute("SELECT balance FROM bank.credit_cards WHERE user_id = %s", (user_id,))
            new_credit_balance = float(cur.fetchone()[0])
            conn.commit()
        except Exception as e:
            conn.rollback()
            cur.close()
            conn.close()
            log_event(
                log_type="ERROR",
                remote_ip=request.remote_addr,
                username=g.user['username'],
                action=f"Error en compra a crédito: {mask_sensitive_data(str(e))}",
                http_code=500
            )
            api.abort(500, f"Error processing credit card purchase: {str(e)}")
        cur.close()
        conn.close()
        log_event(
            log_type="INFO",
            remote_ip=request.remote_addr,
            username=g.user['username'],
            action=f"Compra a crédito exitosa por {amount}",
            http_code=200
        )
        return {
            "message": "Credit card purchase successful",
            "account_balance": new_account_balance,
            "credit_card_debt": new_credit_balance
        }, 200

@bank_ns.route('/pay-credit-balance')
class PayCreditBalance(Resource):
    @bank_ns.expect(pay_credit_balance_model, validate=True)
    @bank_ns.doc('pay_credit_balance', security='Bearer')
    @jwt_required
    def post(self):
        """Realiza un abono al saldo de la tarjeta de crédito."""
        data = api.payload
        amount = data.get("amount", 0)
        if amount <= 0:
            log_event(
                log_type="WARNING",
                remote_ip=request.remote_addr,
                username=g.user['username'],
                action="Intento de abono a crédito con monto inválido",
                http_code=400
            )
            api.abort(400, "Amount must be greater than zero")
        user_id = g.user['id']
        conn = get_connection()
        cur = conn.cursor()
        # Check account funds
        cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (user_id,))
        row = cur.fetchone()
        if not row:
            cur.close()
            conn.close()
            log_event(
                log_type="ERROR",
                remote_ip=request.remote_addr,
                username=g.user['username'],
                action="Abono a crédito fallido: cuenta no encontrada",
                http_code=404
            )
            api.abort(404, "Account not found")
        account_balance = float(row[0])
        if account_balance < amount:
            cur.close()
            conn.close()
            log_event(
                log_type="WARNING",
                remote_ip=request.remote_addr,
                username=g.user['username'],
                action="Abono a crédito fallido: fondos insuficientes",
                http_code=400
            )
            api.abort(400, "Insufficient funds in account")
        # Get current credit card debt
        cur.execute("SELECT balance FROM bank.credit_cards WHERE user_id = %s", (user_id,))
        row = cur.fetchone()
        if not row:
            cur.close()
            conn.close()
            log_event(
                log_type="ERROR",
                remote_ip=request.remote_addr,
                username=g.user['username'],
                action="Abono a crédito fallido: tarjeta no encontrada",
                http_code=404
            )
            api.abort(404, "Credit card not found")
        credit_debt = float(row[0])
        payment = min(amount, credit_debt)
        try:
            cur.execute(UPDATE_BANK_ACCOUNTS_SQL, (payment, user_id))
            cur.execute("UPDATE bank.credit_cards SET balance = balance - %s WHERE user_id = %s", (payment, user_id))
            cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (user_id,))
            new_account_balance = float(cur.fetchone()[0])
            cur.execute("SELECT balance FROM bank.credit_cards WHERE user_id = %s", (user_id,))
            new_credit_debt = float(cur.fetchone()[0])
            conn.commit()
        except Exception as e:
            conn.rollback()
            cur.close()
            conn.close()
            log_event(
                log_type="ERROR",
                remote_ip=request.remote_addr,
                username=g.user['username'],
                action=f"Error en abono a crédito: {mask_sensitive_data(str(e))}",
                http_code=500
            )
            api.abort(500, f"Error processing credit balance payment: {str(e)}")
        cur.close()
        conn.close()
        log_event(
            log_type="INFO",
            remote_ip=request.remote_addr,
            username=g.user['username'],
            action=f"Abono a crédito exitoso por {payment}",
            http_code=200
        )
        return {
            "message": "Credit card debt payment successful",
            "account_balance": new_account_balance,
            "credit_card_debt": new_credit_debt
        }, 200

# Endpoint para consultar logs
@api.route('/logs')
class Logs(Resource):
    @api.doc('logs', security='Bearer')
    @jwt_required
    def get(self):
        """Devuelve los logs del sistema (máximo 1000 registros, ordenados por fecha descendente)."""
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT log_time, log_type, remote_ip, username, action, http_code
            FROM bank.logs
            ORDER BY log_time DESC
            LIMIT 1000
        """)
        logs = [
            {
                "log_time": str(row[0]),
                "log_type": row[1],
                "remote_ip": row[2],
                "username": row[3],
                "action": row[4],
                "http_code": row[5]
            }
            for row in cur.fetchall()
        ]
        cur.close()
        conn.close()
        log_event(
            log_type="INFO",
            remote_ip=request.remote_addr,
            username=g.user['username'],
            action="Consulta de logs del sistema",
            http_code=200
        )
        return {"logs": logs}, 200

@bank_ns.route('/transfer/register')
class TransferRegister(Resource):
    @bank_ns.expect(transfer_register_model, validate=True)
    @bank_ns.doc('transfer_register', security='Bearer')
    @jwt_required
    def post(self):
        """Registra una transferencia y genera un código OTP para confirmación."""
        data = api.payload
        target_username = data.get("target_username")
        amount = data.get("amount", 0)
        
        # validacion basica
        if not target_username or amount <= 0:
            log_event(
                log_type="WARNING",
                remote_ip=request.remote_addr,
                username=g.user['username'],
                action="Intento de registro de transferencia con datos inválidos",
                http_code=400
            )
            api.abort(400, "Invalid data")
        
        if target_username == g.user['username']:
            log_event(
                log_type="WARNING",
                remote_ip=request.remote_addr,
                username=g.user['username'],
                action="Intento de transferencia a sí mismo (register)",
                http_code=400
            )
            api.abort(400, "Cannot transfer to the same account")
        
        conn = get_connection()
        cur = conn.cursor()
        
        # verificar balance del sender - CRITICO: no permitir transferencia sin fondos
        cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (g.user['id'],))
        row = cur.fetchone()
        if not row:
            log_event(
                log_type="WARNING",
                remote_ip=request.remote_addr,
                username=g.user['username'],
                action="Intento de registro de transferencia sin cuenta de origen",
                http_code=404
            )
            cur.close()
            conn.close()
            api.abort(404, "Sender account not found")
        
        sender_balance = float(row[0])
        if sender_balance < amount:  # insufficient funds check - MANDATORY
            log_event(
                log_type="WARNING",
                remote_ip=request.remote_addr,
                username=g.user['username'],
                action="Intento de registro de transferencia con fondos insuficientes",
                http_code=400
            )
            cur.close()
            conn.close()
            api.abort(400, "Fondos insuficientes")
        
        # Check if target user exists in same bank
        cur.execute("SELECT id FROM bank.users WHERE username = %s", (target_username,))
        target_user = cur.fetchone()
        if not target_user:
            log_event(
                log_type="WARNING",
                remote_ip=request.remote_addr,
                username=g.user['username'],
                action=f"Intento de registro de transferencia a usuario no encontrado: {mask_sensitive_data(target_username)}",
                http_code=404
            )
            cur.close()
            conn.close()
            api.abort(404, "Target user not found in this bank. Only transfers between clients of the same bank are allowed.")
        
        try:
            target_user_id = target_user[0]
            
            # INVALIDAR transferencias pendientes anteriores del mismo usuario
            cur.execute("""
                UPDATE bank.transfers_pending 
                SET status = 'cancelled'
                WHERE sender_user_id = %s AND status = 'pending'
            """, (g.user['id'],))
            
            # generate OTP code
            otp_code = str(random.randint(100000, 999999))
            
            # calcular expiration time
            expires_at = datetime.now() + timedelta(minutes=15)
            
            # insert pending transfer
            cur.execute("""
                INSERT INTO bank.transfers_pending 
                (sender_user_id, target_username, target_user_id, amount, otp_code, expires_at)
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING id
            """, (g.user['id'], target_username, target_user_id, amount, otp_code, expires_at))
            
            transfer_id = cur.fetchone()[0]
            conn.commit()
            
            log_event(
                log_type="INFO",
                remote_ip=request.remote_addr,
                username=g.user['username'],
                action=f"Transferencia registrada (id={transfer_id}) a {mask_sensitive_data(target_username)} por {amount} OTP:{mask_sensitive_data(otp_code)}",
                http_code=200
            )

            return {
                "message": "Transfer registered successfully.",
                "transfer_id": transfer_id,
                "otp_code": otp_code,
                "expires_at": expires_at.isoformat(),
                "note": "Use this OTP code to confirm the transfer with /transfer/confirm"
            }, 200
            
        except Exception as e:
            conn.rollback()
            raise RuntimeError(f"Error registering transfer: {str(e)}")
        finally:
            cur.close()
            conn.close()

@bank_ns.route('/transfer/confirm')
class TransferConfirm(Resource):
    @bank_ns.expect(transfer_confirm_model, validate=True)
    @bank_ns.doc('transfer_confirm', security='Bearer')
    @jwt_required
    def post(self):
        """Confirma una transferencia previamente registrada usando el código OTP."""
        data = api.payload
        otp_code = data.get("otp_code")
        
        # validate OTP
        if not otp_code or len(otp_code) != 6:
            log_event(
                log_type="WARNING",
                remote_ip=request.remote_addr,
                username=g.user['username'],
                action="Intento de confirmación de transferencia con OTP inválido",
                http_code=400
            )
            api.abort(400, "Invalid OTP code")
        
        conn = get_connection()
        cur = conn.cursor()
        
        # buscar transferencia con OTP valido
        cur.execute("""
            SELECT id, target_user_id, amount, target_username
            FROM bank.transfers_pending 
            WHERE sender_user_id = %s AND otp_code = %s 
            AND status = 'pending' AND expires_at > NOW()
            LIMIT 1
        """, (g.user['id'], otp_code))
        
        transfer_data = cur.fetchone()
        
        if not transfer_data:  # OTP invalid or expired
            log_event(
                log_type="WARNING",
                remote_ip=request.remote_addr,
                username=g.user['username'],
                action=f"Intento de confirmación de transferencia con OTP inválido o expirado: {mask_sensitive_data(otp_code)}",
                http_code=400
            )
            cur.close()
            conn.close()
            api.abort(400, "Código de verificación de la transacción inválido o expirado")

        try:
          
            transfer_id, target_user_id, amount, target_username = transfer_data
            amount = float(amount)
            
            # Check balance again before transfer
            cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (g.user['id'],))
            row = cur.fetchone()
            if not row:
                log_event(
                    log_type="WARNING",
                    remote_ip=request.remote_addr,
                    username=g.user['username'],
                    action="Intento de ejecución de transferencia sin cuenta de origen",
                    http_code=404
                )
                api.abort(404, "Sender account not found")
            
            sender_balance = float(row[0])
            if sender_balance < amount:  # balance verification
                log_event(
                    log_type="WARNING",
                    remote_ip=request.remote_addr,
                    username=g.user['username'],
                    action="Intento de ejecución de transferencia con fondos insuficientes",
                    http_code=400
                )
                api.abort(400, "Insufficient funds for this transfer")
            
            # ejecutar la transferencia
            cur.execute(UPDATE_BANK_ACCOUNTS_SQL, 
                       (amount, g.user['id']))
            cur.execute("UPDATE bank.accounts SET balance = balance + %s WHERE user_id = %s", 
                       (amount, target_user_id))
            
            # mark transfer as completed
            cur.execute("UPDATE bank.transfers_pending SET status = 'completed' WHERE id = %s", 
                       (transfer_id,))
            
            # get new balance
            cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (g.user['id'],))
            new_balance = float(cur.fetchone()[0])
            
            conn.commit()
            log_event(
                log_type="INFO",
                remote_ip=request.remote_addr,
                username=g.user['username'],
                action=f"Transferencia confirmada (id={transfer_id}) a {mask_sensitive_data(target_username)} por {amount}",
                http_code=200
            )
            return {
                "message": "Transfer executed successfully",
                "transfer_id": transfer_id,
                "target_username": target_username,
                "amount": amount,
                "new_balance": new_balance
            }, 200
            
        except Exception as e:
            conn.rollback()
            log_event(
                log_type="ERROR",
                remote_ip=request.remote_addr,
                username=g.user['username'],
                action=f"Error ejecutando transferencia: {mask_sensitive_data(str(e))}",
                http_code=500
            )
            api.abort(500, f"Error executing transfers: {str(e)}")
        finally:
            cur.close()
            conn.close()

@bank_ns.route('/transfer/pending')
class PendingTransfers(Resource):
    @bank_ns.doc('pending_transfers', security='Bearer')
    @jwt_required
    def get(self):
        """Obtiene las transferencias pendientes del usuario autenticado."""
        conn = get_connection()
        cur = conn.cursor()
        
        try:
            # buscar pending transfers
            cur.execute("""
                SELECT id, target_username, amount, created_at, expires_at
                FROM bank.transfers_pending 
                WHERE sender_user_id = %s AND status = 'pending' AND expires_at > NOW()
                ORDER BY created_at
            """, (g.user['id'],))
            
            transfers = cur.fetchall()
            
            pending_list = []  # lista de transferencias pendientes
            for transfer in transfers:
                pending_list.append({
                    "transfer_id": transfer[0],
                    "target_username": transfer[1],
                    "amount": float(transfer[2]),
                    "created_at": transfer[3].isoformat(),
                    "expires_at": transfer[4].isoformat()
                })
            
            total_amt = sum(t["amount"] for t in pending_list)  # variable con nombre corto
            log_event(
                log_type="INFO",
                remote_ip=request.remote_addr,
                username=g.user['username'],
                action=f"Consulta de transferencias pendientes. Total: {len(pending_list)}",
                http_code=200
            )
            return {
                "pending_transfers": pending_list,
                "total_amount": total_amt
            }, 200
            
        finally:
            cur.close()
            conn.close()

@app.before_first_request
def initialize_db():
    init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)