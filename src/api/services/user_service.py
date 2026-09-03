
from api.utils import APIException

from werkzeug.security import (
    generate_password_hash
)

from api.models import (
    db,
    User
)

def valid_content(value, field):

    if not value or not value.strip():
        raise APIException(f"El {field} es obligatorio")


    if field == "password" and len(value) < 6:
        raise APIException("La contraseña debe tener al menos 6 caracteres", 411)
    


def create_user(data):

    if not data:
        raise APIException("No enviaste datos",400)

    name = data.get("name")
    email = data.get("email")
    password = data.get("password")

    valid_content(name, "name")
    valid_content(email, "email")
    valid_content(password, "password")

    existing_user = db.session.scalar(
        db.select(User).where(User.email == email)
    )

    if existing_user:
        raise APIException("Usuario ya existe", 409)

    hashed_password = generate_password_hash(password)

    new_user = User(
        name = name,
        email = email,
        password = hashed_password
    )

    try:
        db.session.add(new_user)
        db.session.commit()

        return new_user

    except Exception as error:
        db.session.rollback()

        print("ERROR USUARIO:", error)

        raise APIException("Error al crear Usuario", 500)