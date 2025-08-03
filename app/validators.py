# app/validators.py
from marshmallow import Schema, fields, validate, ValidationError
from email_validator import validate_email, EmailNotValidError
import re

def validate_username(value):
    """Valida el formato del nombre de usuario"""
    if not value or len(value) < 3:
        raise ValidationError("Username must be at least 3 characters long")
    if len(value) > 50:
        raise ValidationError("Username must be less than 50 characters")
    if not re.match(r'^[a-zA-Z0-9_]+$', value):
        raise ValidationError("Username can only contain letters, numbers, and underscores")
    return value

def validate_password(value):
    """Valida el formato de la contraseña"""
    if not value or len(value) < 6:
        raise ValidationError("Password must be at least 6 characters long")
    if len(value) > 100:
        raise ValidationError("Password must be less than 100 characters")
    return value

def validate_amount(value):
    """Valida los montos monetarios"""
    if value is None:
        raise ValidationError("Amount is required")
    if not isinstance(value, (int, float)):
        raise ValidationError("Amount must be a number")
    if value <= 0:
        raise ValidationError("Amount must be greater than zero")
    if value > 1000000:  # Límite máximo de $1,000,000
        raise ValidationError("Amount exceeds maximum allowed limit")
    # Validar que no tenga más de 2 decimales
    if isinstance(value, float) and len(str(value).split('.')[-1]) > 2:
        raise ValidationError("Amount cannot have more than 2 decimal places")
    return value

def validate_account_number(value):
    """Valida el número de cuenta"""
    if value is None:
        raise ValidationError("Account number is required")
    if not isinstance(value, int):
        raise ValidationError("Account number must be an integer")
    if value <= 0:
        raise ValidationError("Account number must be greater than zero")
    return value

def validate_email_format(value):
    """Valida el formato del email"""
    if not value:
        raise ValidationError("Email is required")
    try:
        valid = validate_email(value)
        return valid.email
    except EmailNotValidError:
        raise ValidationError("Invalid email format")

# Esquemas de validación para los endpoints

class LoginSchema(Schema):
    username = fields.Str(required=True, validate=validate_username)
    password = fields.Str(required=True, validate=validate_password)

class DepositSchema(Schema):
    account_number = fields.Integer(required=True, validate=validate_account_number)
    amount = fields.Float(required=True, validate=validate_amount)

class WithdrawSchema(Schema):
    amount = fields.Float(required=True, validate=validate_amount)

class TransferSchema(Schema):
    target_username = fields.Str(required=True, validate=validate_username)
    amount = fields.Float(required=True, validate=validate_amount)

class CreditPaymentSchema(Schema):
    amount = fields.Float(required=True, validate=validate_amount)

class PayCreditBalanceSchema(Schema):
    amount = fields.Float(required=True, validate=validate_amount)

class UserRegistrationSchema(Schema):
    username = fields.Str(required=True, validate=validate_username)
    password = fields.Str(required=True, validate=validate_password)
    full_name = fields.Str(required=True, validate=validate.Length(min=2, max=100))
    email = fields.Str(required=True, validate=validate_email_format)
    role = fields.Str(required=True, validate=validate.OneOf(['cliente', 'cajero', 'admin']))

def validate_request_data(schema_class, data):
    """
    Valida los datos de entrada usando el esquema especificado
    """
    schema = schema_class()
    try:
        validated_data = schema.load(data)
        return validated_data, None
    except ValidationError as err:
        return None, err.messages
