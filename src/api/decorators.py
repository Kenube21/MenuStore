
from functools import wraps

from flask import jsonify
from flask_jwt_extended import get_jwt

def admin_required(func):

    @wraps(func)
    def wrapper(*args, **kwargs):
        jwt = get_jwt()
        role = jwt.get("role")

        if role != "admin":
            return jsonify({
                "error": "Rol sin Autorizacion"
            }), 403

        return func(*args, **kwargs)

    return wrapper