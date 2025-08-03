import secrets
from flask import Flask, request, g
from flask_restx import Api, Resource, fields # type: ignore
from functools import wraps
from .db import get_connection, init_db
from .config import Config
from .auth import JWTAuth, jwt_required, role_required
from .validators import (
    LoginSchema, DepositSchema, WithdrawSchema, 
    TransferSchema, CreditPaymentSchema, PayCreditBalanceSchema,
    validate_request_data
)
from .logger import log_action
import logging

# Define a simple in-memory token store (deprecated - now using JWT)
tokens = {}

# Configure logging using the new logger module
logger = logging.getLogger(__name__)

# Configure Swagger security scheme for Bearer tokens
authorizations = {
    'Bearer': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'Authorization',
        'description': "Enter your token in the format **Bearer <token>**"
    }
}

app = Flask(__name__)
api = Api(
    app,
    version='1.0',
    title='Core Bancario API',
    description='API para operaciones bancarias, incluyendo autenticación y operaciones de cuenta.',
    doc='/swagger',  # Swagger UI endpoint
    authorizations=authorizations,
    security='Bearer'
)

# Create namespaces for authentication and bank operations
auth_ns = api.namespace('auth', description='Operaciones de autenticación')
bank_ns = api.namespace('bank', description='Operaciones bancarias')

# Define the expected payload models for Swagger
login_model = auth_ns.model('Login', {
    'username': fields.String(required=True, description='Nombre de usuario (mínimo 3 caracteres)', example='user1'),
    'password': fields.String(required=True, description='Contraseña (mínimo 6 caracteres)', example='pass1')
})

deposit_model = bank_ns.model('Deposit', {
    'account_number': fields.Integer(required=True, description='Número de cuenta válido', example=123),
    'amount': fields.Float(required=True, description='Monto a depositar (mayor a 0, máximo 2 decimales)', example=100.50)
})

withdraw_model = bank_ns.model('Withdraw', {
    'amount': fields.Float(required=True, description='Monto a retirar (mayor a 0, máximo 2 decimales)', example=100.50)
})

transfer_model = bank_ns.model('Transfer', {
    'target_username': fields.String(required=True, description='Usuario destino válido', example='user2'),
    'amount': fields.Float(required=True, description='Monto a transferir (mayor a 0, máximo 2 decimales)', example=100.50)
})

credit_payment_model = bank_ns.model('CreditPayment', {
    'amount': fields.Float(required=True, description='Monto de la compra a crédito (mayor a 0, máximo 2 decimales)', example=100.50)
})

pay_credit_balance_model = bank_ns.model('PayCreditBalance', {
    'amount': fields.Float(required=True, description='Monto a abonar a la deuda (mayor a 0, máximo 2 decimales)', example=50.25)
})

# Response models for better documentation
token_response_model = auth_ns.model('TokenResponse', {
    'message': fields.String(description='Mensaje de respuesta'),
    'token': fields.String(description='Token JWT de autenticación'),
    'expires_in': fields.String(description='Tiempo de expiración del token')
})

balance_response_model = bank_ns.model('BalanceResponse', {
    'message': fields.String(description='Mensaje de respuesta'),
    'new_balance': fields.Float(description='Nuevo saldo de la cuenta')
})

transfer_response_model = bank_ns.model('TransferResponse', {
    'message': fields.String(description='Mensaje de respuesta'),
    'new_balance': fields.Float(description='Nuevo saldo de la cuenta origen')
})

credit_response_model = bank_ns.model('CreditResponse', {
    'message': fields.String(description='Mensaje de respuesta'),
    'account_balance': fields.Float(description='Saldo de la cuenta'),
    'credit_card_debt': fields.Float(description='Deuda de la tarjeta de crédito')
})

# ---------------- Authentication Endpoints ----------------

@auth_ns.route('/login')
class Login(Resource):
    @auth_ns.expect(login_model, validate=True)
    @auth_ns.doc('login')
    @auth_ns.response(200, 'Login exitoso', token_response_model)
    @auth_ns.response(400, 'Datos de entrada inválidos')
    @auth_ns.response(401, 'Credenciales inválidas')
    def post(self):
        """Inicia sesión y devuelve un token JWT de autenticación."""
        try:
            # Validar datos de entrada
            validated_data, errors = validate_request_data(LoginSchema, api.payload)
            if errors:
                log_action(
                    action="LOGIN_VALIDATION_ERROR",
                    details=f"Validation errors: {errors}",
                    request_data=api.payload
                )
                api.abort(400, f"Validation errors: {errors}")
            
            username = validated_data["username"]
            password = validated_data["password"]
            
            log_action(
                action="LOGIN_ATTEMPT",
                details=f"User {username} attempting to login",
                username=username
            )
            
            conn = get_connection()
            cur = conn.cursor()
            
            try:
                cur.execute(
                    "SELECT id, username, password, role, full_name, email FROM bank.users WHERE username = %s", 
                    (username,)
                )
                user = cur.fetchone()
                
                if user and user[2] == password:  # Simple password check - in production use bcrypt
                    user_data = {
                        "id": user[0],
                        "username": user[1],
                        "role": user[3],
                        "full_name": user[4],
                        "email": user[5]
                    }
                    
                    # Generate JWT token
                    token = JWTAuth.generate_token(user_data)
                    
                    log_action(
                        action="LOGIN_SUCCESS",
                        user_id=user[0],
                        details=f"User {username} logged in successfully"
                    )
                    
                    return {
                        "message": "Login successful", 
                        "token": token,
                        "expires_in": str(Config.JWT_ACCESS_TOKEN_EXPIRES)
                    }, 200
                else:
                    log_action(
                        action="LOGIN_FAILED",
                        details=f"Invalid credentials for user {username}",
                        username=username,
                        level="WARNING"
                    )
                    api.abort(401, "Invalid credentials")
                    
            finally:
                cur.close()
                conn.close()
                
        except Exception as e:
            log_action(
                action="LOGIN_ERROR",
                details=f"Unexpected error during login: {str(e)}",
                level="ERROR"
            )
            api.abort(500, "Internal server error")
            conn.close()
            api.abort(401, "Invalid credentials")

@auth_ns.route('/logout')
class Logout(Resource):
    @auth_ns.doc('logout', security='Bearer')
    @auth_ns.response(200, 'Logout exitoso')
    @auth_ns.response(401, 'Token inválido o no proporcionado')
    @jwt_required
    def post(self):
        """Invalida el token JWT de autenticación."""
        try:
            log_action(
                action="LOGOUT_SUCCESS",
                user_id=g.user['id'],
                details=f"User {g.user['username']} logged out successfully"
            )
            
            # Note: With JWT, we can't really "invalidate" a token on the server side
            # unless we maintain a blacklist. For now, we'll just log the logout.
            # In a production system, you might want to implement a token blacklist.
            
            return {"message": "Logout successful"}, 200
            
        except Exception as e:
            log_action(
                action="LOGOUT_ERROR",
                user_id=g.user.get('id') if hasattr(g, 'user') else None,
                details=f"Error during logout: {str(e)}",
                level="ERROR"
            )
            api.abort(500, "Internal server error")

# ---------------- Token-Required Decorator (Deprecated - now using JWT) ----------------

# The old token_required decorator is replaced by jwt_required from auth.py

# ---------------- Banking Operation Endpoints ----------------

@bank_ns.route('/deposit')
class Deposit(Resource):
    @bank_ns.expect(deposit_model, validate=True)
    @bank_ns.doc('deposit', security='Bearer')
    @bank_ns.response(200, 'Depósito exitoso', balance_response_model)
    @bank_ns.response(400, 'Datos inválidos o monto incorrecto')
    @bank_ns.response(401, 'Token inválido o no proporcionado')
    @bank_ns.response(404, 'Cuenta no encontrada')
    @jwt_required
    @role_required(['cajero', 'admin'])
    def post(self):
        """
        Realiza un depósito en la cuenta especificada.
        Se requiere el número de cuenta y el monto a depositar.
        Requiere rol de cajero o administrador.
        """
        try:
            # Validar datos de entrada
            validated_data, errors = validate_request_data(DepositSchema, api.payload)
            if errors:
                log_action(
                    action="DEPOSIT_VALIDATION_ERROR",
                    user_id=g.user['id'],
                    details=f"Validation errors: {errors}",
                    request_data=api.payload
                )
                api.abort(400, f"Validation errors: {errors}")
            
            account_number = validated_data["account_number"]
            amount = validated_data["amount"]
            
            log_action(
                action="DEPOSIT_ATTEMPT",
                user_id=g.user['id'],
                details=f"User {g.user['username']} attempting to deposit {amount} to account {account_number}",
                account_number=account_number,
                amount=amount
            )
            
            conn = get_connection()
            cur = conn.cursor()
            
            try:
                # Update the specified account using its account number (primary key)
                cur.execute(
                    "UPDATE bank.accounts SET balance = balance + %s WHERE id = %s RETURNING balance",
                    (amount, account_number)
                )
                result = cur.fetchone()
                
                if not result:
                    log_action(
                        action="DEPOSIT_FAILED",
                        user_id=g.user['id'],
                        details=f"Account {account_number} not found",
                        account_number=account_number,
                        level="WARNING"
                    )
                    api.abort(404, "Account not found")
                
                new_balance = float(result[0])
                conn.commit()
                
                log_action(
                    action="DEPOSIT_SUCCESS",
                    user_id=g.user['id'],
                    details=f"Successfully deposited {amount} to account {account_number}. New balance: {new_balance}",
                    account_number=account_number,
                    amount=amount,
                    new_balance=new_balance
                )
                
                return {"message": "Deposit successful", "new_balance": new_balance}, 200
                
            finally:
                cur.close()
                conn.close()
                
        except Exception as e:
            log_action(
                action="DEPOSIT_ERROR",
                user_id=g.user['id'],
                details=f"Unexpected error during deposit: {str(e)}",
                level="ERROR"
            )
            api.abort(500, "Internal server error")

@bank_ns.route('/withdraw')
class Withdraw(Resource):
    @bank_ns.expect(withdraw_model, validate=True)
    @bank_ns.doc('withdraw', security='Bearer')
    @bank_ns.response(200, 'Retiro exitoso', balance_response_model)
    @bank_ns.response(400, 'Datos inválidos, monto incorrecto o fondos insuficientes')
    @bank_ns.response(401, 'Token inválido o no proporcionado')
    @bank_ns.response(404, 'Cuenta no encontrada')
    @jwt_required
    def post(self):
        """Realiza un retiro de la cuenta del usuario autenticado."""
        try:
            # Validar datos de entrada
            validated_data, errors = validate_request_data(WithdrawSchema, api.payload)
            if errors:
                log_action(
                    action="WITHDRAW_VALIDATION_ERROR",
                    user_id=g.user['id'],
                    details=f"Validation errors: {errors}",
                    request_data=api.payload
                )
                api.abort(400, f"Validation errors: {errors}")
            
            amount = validated_data["amount"]
            user_id = g.user['id']
            
            log_action(
                action="WITHDRAW_ATTEMPT",
                user_id=user_id,
                details=f"User {g.user['username']} attempting to withdraw {amount}",
                amount=amount
            )
            
            conn = get_connection()
            cur = conn.cursor()
            
            try:
                cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (user_id,))
                row = cur.fetchone()
                
                if not row:
                    log_action(
                        action="WITHDRAW_FAILED",
                        user_id=user_id,
                        details="Account not found",
                        level="WARNING"
                    )
                    api.abort(404, "Account not found")
                
                current_balance = float(row[0])
                
                if current_balance < amount:
                    log_action(
                        action="WITHDRAW_FAILED",
                        user_id=user_id,
                        details=f"Insufficient funds. Current balance: {current_balance}, requested: {amount}",
                        current_balance=current_balance,
                        requested_amount=amount,
                        level="WARNING"
                    )
                    api.abort(400, "Insufficient funds")
                
                cur.execute("UPDATE bank.accounts SET balance = balance - %s WHERE user_id = %s RETURNING balance", 
                           (amount, user_id))
                new_balance = float(cur.fetchone()[0])
                conn.commit()
                
                log_action(
                    action="WITHDRAW_SUCCESS",
                    user_id=user_id,
                    details=f"Successfully withdrew {amount}. New balance: {new_balance}",
                    amount=amount,
                    new_balance=new_balance
                )
                
                return {"message": "Withdrawal successful", "new_balance": new_balance}, 200
                
            finally:
                cur.close()
                conn.close()
                
        except Exception as e:
            log_action(
                action="WITHDRAW_ERROR",
                user_id=g.user['id'],
                details=f"Unexpected error during withdrawal: {str(e)}",
                level="ERROR"
            )
            api.abort(500, "Internal server error")

@bank_ns.route('/transfer')
class Transfer(Resource):
    @bank_ns.expect(transfer_model, validate=True)
    @bank_ns.doc('transfer', security='Bearer')
    @bank_ns.response(200, 'Transferencia exitosa', transfer_response_model)
    @bank_ns.response(400, 'Datos inválidos, fondos insuficientes o transferencia a la misma cuenta')
    @bank_ns.response(401, 'Token inválido o no proporcionado')
    @bank_ns.response(404, 'Cuenta origen o destino no encontrada')
    @jwt_required
    def post(self):
        """Transfiere fondos desde la cuenta del usuario autenticado a otra cuenta."""
        try:
            # Validar datos de entrada
            validated_data, errors = validate_request_data(TransferSchema, api.payload)
            if errors:
                log_action(
                    action="TRANSFER_VALIDATION_ERROR",
                    user_id=g.user['id'],
                    details=f"Validation errors: {errors}",
                    request_data=api.payload
                )
                api.abort(400, f"Validation errors: {errors}")
            
            target_username = validated_data["target_username"]
            amount = validated_data["amount"]
            
            if target_username == g.user['username']:
                log_action(
                    action="TRANSFER_FAILED",
                    user_id=g.user['id'],
                    details="Cannot transfer to the same account",
                    level="WARNING"
                )
                api.abort(400, "Cannot transfer to the same account")
            
            log_action(
                action="TRANSFER_ATTEMPT",
                user_id=g.user['id'],
                details=f"User {g.user['username']} attempting to transfer {amount} to {target_username}",
                target_username=target_username,
                amount=amount
            )
            
            conn = get_connection()
            cur = conn.cursor()
            
            try:
                # Check sender's balance
                cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (g.user['id'],))
                row = cur.fetchone()
                
                if not row:
                    log_action(
                        action="TRANSFER_FAILED",
                        user_id=g.user['id'],
                        details="Sender account not found",
                        level="ERROR"
                    )
                    api.abort(404, "Sender account not found")
                
                sender_balance = float(row[0])
                
                if sender_balance < amount:
                    log_action(
                        action="TRANSFER_FAILED",
                        user_id=g.user['id'],
                        details=f"Insufficient funds. Balance: {sender_balance}, requested: {amount}",
                        current_balance=sender_balance,
                        requested_amount=amount,
                        level="WARNING"
                    )
                    api.abort(400, "Insufficient funds")
                
                # Find target user
                cur.execute("SELECT id FROM bank.users WHERE username = %s", (target_username,))
                target_user = cur.fetchone()
                
                if not target_user:
                    log_action(
                        action="TRANSFER_FAILED",
                        user_id=g.user['id'],
                        details=f"Target user {target_username} not found",
                        target_username=target_username,
                        level="WARNING"
                    )
                    api.abort(404, "Target user not found")
                
                target_user_id = target_user[0]
                
                # Perform the transfer
                cur.execute("UPDATE bank.accounts SET balance = balance - %s WHERE user_id = %s", 
                           (amount, g.user['id']))
                cur.execute("UPDATE bank.accounts SET balance = balance + %s WHERE user_id = %s", 
                           (amount, target_user_id))
                cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (g.user['id'],))
                new_balance = float(cur.fetchone()[0])
                
                conn.commit()
                
                log_action(
                    action="TRANSFER_SUCCESS",
                    user_id=g.user['id'],
                    details=f"Successfully transferred {amount} to {target_username}. New balance: {new_balance}",
                    target_username=target_username,
                    amount=amount,
                    new_balance=new_balance
                )
                
                return {"message": "Transfer successful", "new_balance": new_balance}, 200
                
            except Exception as e:
                conn.rollback()
                log_action(
                    action="TRANSFER_ERROR",
                    user_id=g.user['id'],
                    details=f"Database error during transfer: {str(e)}",
                    level="ERROR"
                )
                api.abort(500, f"Error during transfer: {str(e)}")
            finally:
                cur.close()
                conn.close()
                
        except Exception as e:
            log_action(
                action="TRANSFER_ERROR",
                user_id=g.user['id'],
                details=f"Unexpected error during transfer: {str(e)}",
                level="ERROR"
            )
            api.abort(500, "Internal server error")

@bank_ns.route('/credit-payment')
class CreditPayment(Resource):
    @bank_ns.expect(credit_payment_model, validate=True)
    @bank_ns.doc('credit_payment', security='Bearer')
    @bank_ns.response(200, 'Compra a crédito exitosa', credit_response_model)
    @bank_ns.response(400, 'Datos inválidos o fondos insuficientes')
    @bank_ns.response(401, 'Token inválido o no proporcionado')
    @bank_ns.response(404, 'Cuenta o tarjeta de crédito no encontrada')
    @jwt_required
    def post(self):
        """
        Realiza una compra a crédito:
        - Descuenta el monto de la cuenta.
        - Aumenta la deuda de la tarjeta de crédito.
        """
        try:
            # Validar datos de entrada
            validated_data, errors = validate_request_data(CreditPaymentSchema, api.payload)
            if errors:
                log_action(
                    action="CREDIT_PAYMENT_VALIDATION_ERROR",
                    user_id=g.user['id'],
                    details=f"Validation errors: {errors}",
                    request_data=api.payload
                )
                api.abort(400, f"Validation errors: {errors}")
            
            amount = validated_data["amount"]
            user_id = g.user['id']
            
            log_action(
                action="CREDIT_PAYMENT_ATTEMPT",
                user_id=user_id,
                details=f"User {g.user['username']} attempting credit purchase of {amount}",
                amount=amount
            )
            
            conn = get_connection()
            cur = conn.cursor()
            
            try:
                cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (user_id,))
                row = cur.fetchone()
                
                if not row:
                    log_action(
                        action="CREDIT_PAYMENT_FAILED",
                        user_id=user_id,
                        details="Account not found",
                        level="ERROR"
                    )
                    api.abort(404, "Account not found")
                
                account_balance = float(row[0])
                
                if account_balance < amount:
                    log_action(
                        action="CREDIT_PAYMENT_FAILED",
                        user_id=user_id,
                        details=f"Insufficient funds in account. Balance: {account_balance}, required: {amount}",
                        account_balance=account_balance,
                        required_amount=amount,
                        level="WARNING"
                    )
                    api.abort(400, "Insufficient funds in account")
                
                # Perform the credit card purchase
                cur.execute("UPDATE bank.accounts SET balance = balance - %s WHERE user_id = %s", 
                           (amount, user_id))
                cur.execute("UPDATE bank.credit_cards SET balance = balance + %s WHERE user_id = %s", 
                           (amount, user_id))
                
                cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (user_id,))
                new_account_balance = float(cur.fetchone()[0])
                
                cur.execute("SELECT balance FROM bank.credit_cards WHERE user_id = %s", (user_id,))
                new_credit_balance = float(cur.fetchone()[0])
                
                conn.commit()
                
                log_action(
                    action="CREDIT_PAYMENT_SUCCESS",
                    user_id=user_id,
                    details=f"Credit purchase of {amount} successful. Account balance: {new_account_balance}, Credit debt: {new_credit_balance}",
                    amount=amount,
                    account_balance=new_account_balance,
                    credit_debt=new_credit_balance
                )
                
                return {
                    "message": "Credit card purchase successful",
                    "account_balance": new_account_balance,
                    "credit_card_debt": new_credit_balance
                }, 200
                
            except Exception as e:
                conn.rollback()
                log_action(
                    action="CREDIT_PAYMENT_ERROR",
                    user_id=user_id,
                    details=f"Database error processing credit card purchase: {str(e)}",
                    level="ERROR"
                )
                api.abort(500, f"Error processing credit card purchase: {str(e)}")
            finally:
                cur.close()
                conn.close()
                
        except Exception as e:
            log_action(
                action="CREDIT_PAYMENT_ERROR",
                user_id=g.user['id'],
                details=f"Unexpected error during credit payment: {str(e)}",
                level="ERROR"
            )
            api.abort(500, "Internal server error")

@bank_ns.route('/pay-credit-balance')
class PayCreditBalance(Resource):
    @bank_ns.expect(pay_credit_balance_model, validate=True)
    @bank_ns.doc('pay_credit_balance', security='Bearer')
    @bank_ns.response(200, 'Pago de deuda exitoso', credit_response_model)
    @bank_ns.response(400, 'Datos inválidos o fondos insuficientes')
    @bank_ns.response(401, 'Token inválido o no proporcionado')
    @bank_ns.response(404, 'Cuenta o tarjeta de crédito no encontrada')
    @jwt_required
    def post(self):
        """
        Realiza un abono a la deuda de la tarjeta:
        - Descuenta el monto (o el máximo posible) de la cuenta.
        - Reduce la deuda de la tarjeta de crédito.
        """
        try:
            # Validar datos de entrada
            validated_data, errors = validate_request_data(PayCreditBalanceSchema, api.payload)
            if errors:
                log_action(
                    action="PAY_CREDIT_VALIDATION_ERROR",
                    user_id=g.user['id'],
                    details=f"Validation errors: {errors}",
                    request_data=api.payload
                )
                api.abort(400, f"Validation errors: {errors}")
            
            amount = validated_data["amount"]
            user_id = g.user['id']
            
            log_action(
                action="PAY_CREDIT_ATTEMPT",
                user_id=user_id,
                details=f"User {g.user['username']} attempting to pay credit debt of {amount}",
                amount=amount
            )
            
            conn = get_connection()
            cur = conn.cursor()
            
            try:
                # Check account funds
                cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (user_id,))
                row = cur.fetchone()
                
                if not row:
                    log_action(
                        action="PAY_CREDIT_FAILED",
                        user_id=user_id,
                        details="Account not found",
                        level="ERROR"
                    )
                    api.abort(404, "Account not found")
                
                account_balance = float(row[0])
                
                if account_balance < amount:
                    log_action(
                        action="PAY_CREDIT_FAILED",
                        user_id=user_id,
                        details=f"Insufficient funds in account. Balance: {account_balance}, required: {amount}",
                        account_balance=account_balance,
                        required_amount=amount,
                        level="WARNING"
                    )
                    api.abort(400, "Insufficient funds in account")
                
                # Get current credit card debt
                cur.execute("SELECT balance FROM bank.credit_cards WHERE user_id = %s", (user_id,))
                row = cur.fetchone()
                
                if not row:
                    log_action(
                        action="PAY_CREDIT_FAILED",
                        user_id=user_id,
                        details="Credit card not found",
                        level="ERROR"
                    )
                    api.abort(404, "Credit card not found")
                
                credit_debt = float(row[0])
                payment = min(amount, credit_debt)
                
                # Perform the payment
                cur.execute("UPDATE bank.accounts SET balance = balance - %s WHERE user_id = %s", 
                           (payment, user_id))
                cur.execute("UPDATE bank.credit_cards SET balance = balance - %s WHERE user_id = %s", 
                           (payment, user_id))
                
                cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (user_id,))
                new_account_balance = float(cur.fetchone()[0])
                
                cur.execute("SELECT balance FROM bank.credit_cards WHERE user_id = %s", (user_id,))
                new_credit_debt = float(cur.fetchone()[0])
                
                conn.commit()
                
                log_action(
                    action="PAY_CREDIT_SUCCESS",
                    user_id=user_id,
                    details=f"Credit debt payment of {payment} successful. Account balance: {new_account_balance}, Credit debt: {new_credit_debt}",
                    payment_amount=payment,
                    account_balance=new_account_balance,
                    credit_debt=new_credit_debt
                )
                
                return {
                    "message": "Credit card debt payment successful",
                    "account_balance": new_account_balance,
                    "credit_card_debt": new_credit_debt
                }, 200
                
            except Exception as e:
                conn.rollback()
                log_action(
                    action="PAY_CREDIT_ERROR",
                    user_id=user_id,
                    details=f"Database error processing credit balance payment: {str(e)}",
                    level="ERROR"
                )
                api.abort(500, f"Error processing credit balance payment: {str(e)}")
            finally:
                cur.close()
                conn.close()
                
        except Exception as e:
            log_action(
                action="PAY_CREDIT_ERROR",
                user_id=g.user['id'],
                details=f"Unexpected error during credit payment: {str(e)}",
                level="ERROR"
            )
            api.abort(500, "Internal server error")

# ---------------- Additional Banking Endpoints ----------------

@bank_ns.route('/balance')
class Balance(Resource):
    @bank_ns.doc('get_balance', security='Bearer')
    @bank_ns.response(200, 'Consulta de saldo exitosa')
    @bank_ns.response(401, 'Token inválido o no proporcionado')
    @bank_ns.response(404, 'Cuenta no encontrada')
    @jwt_required
    def get(self):
        """Consulta el saldo de la cuenta del usuario autenticado."""
        try:
            user_id = g.user['id']
            
            log_action(
                action="BALANCE_INQUIRY",
                user_id=user_id,
                details=f"User {g.user['username']} requesting balance information"
            )
            
            conn = get_connection()
            cur = conn.cursor()
            
            try:
                # Get account balance
                cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (user_id,))
                account_row = cur.fetchone()
                
                if not account_row:
                    log_action(
                        action="BALANCE_INQUIRY_FAILED",
                        user_id=user_id,
                        details="Account not found",
                        level="ERROR"
                    )
                    api.abort(404, "Account not found")
                
                # Get credit card balance
                cur.execute("SELECT balance, limit_credit FROM bank.credit_cards WHERE user_id = %s", (user_id,))
                credit_row = cur.fetchone()
                
                account_balance = float(account_row[0])
                credit_debt = float(credit_row[0]) if credit_row else 0
                credit_limit = float(credit_row[1]) if credit_row else 0
                
                log_action(
                    action="BALANCE_INQUIRY_SUCCESS",
                    user_id=user_id,
                    details=f"Balance inquiry successful for user {g.user['username']}",
                    account_balance=account_balance,
                    credit_debt=credit_debt
                )
                
                return {
                    "message": "Balance inquiry successful",
                    "account_balance": account_balance,
                    "credit_card_debt": credit_debt,
                    "credit_limit": credit_limit,
                    "available_credit": credit_limit - credit_debt
                }, 200
                
            finally:
                cur.close()
                conn.close()
                
        except Exception as e:
            log_action(
                action="BALANCE_INQUIRY_ERROR",
                user_id=g.user['id'],
                details=f"Unexpected error during balance inquiry: {str(e)}",
                level="ERROR"
            )
            api.abort(500, "Internal server error")

@app.before_first_request
def initialize_db():
    try:
        init_db()
        log_action(
            action="DATABASE_INITIALIZED",
            details="Database tables initialized successfully"
        )
    except Exception as e:
        log_action(
            action="DATABASE_INIT_ERROR",
            details=f"Failed to initialize database: {str(e)}",
            level="ERROR"
        )

if __name__ == "__main__":
    log_action(
        action="APPLICATION_START",
        details="Core Banking API application starting"
    )
    app.run(host="0.0.0.0", port=8000, debug=True)

