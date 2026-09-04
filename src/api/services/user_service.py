
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
        raise APIException(
            "La contraseña debe tener al menos 6 caracteres", 411)


def create_user(data):

    if not data:
        raise APIException("No enviaste datos", 400)

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
        name=name,
        email=email,
        password=hashed_password
    )

    try:
        db.session.add(new_user)
        db.session.commit()

        
    except Exception as error:
        db.session.rollback()

        print("ERROR USUARIO:", error)

        raise APIException("Error al crear Usuario", 500)

    return new_user


def update_user(user_id, data):

    if not data:
        raise APIException("No enviaste datos", 400)

    user = db.session.get(User, user_id)

    if user is None:
        raise APIException("Usuario no existe", 404)

    if "image" in data:
        user.image = data["image"]

    if "name" in data:
        new_name = data["name"]

        valid_content(new_name, "name")

        user.name = new_name.strip()

    if "email" in data:
        new_email = data["email"]

        valid_content(new_email, "email")

        clean_email = new_email.strip().lower()

        existing_email = db.session.scalar(
            db.select(User).where(
                User.email == clean_email,
                User.id != user_id
            )
        )

        if existing_email:
            raise APIException("Ya existe un usuario con ese correo", 409)

        user.email = clean_email

    if "password" in data:
        new_password = data["password"]

        valid_content(new_password, "password")

        user.password = generate_password_hash(new_password)

    try:
        db.session.commit()

    except Exception as error:
        db.session.rollback()

        print("ERROR CAMBIO USUARIO:", error)

        raise APIException("Error al cambiar Usuario", 500)

    return user

    
