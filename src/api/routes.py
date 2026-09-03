"""
This module takes care of starting the API Server,
Loading the DB and Adding the endpoints.
"""

from api.decorators import admin_required
from api.services.checkout_service import process_checkout
from api.services.user_service import create_user as create_user_service

from flask import request, jsonify, Blueprint
from flask_cors import CORS

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)


from flask_jwt_extended import (
    create_access_token,
    jwt_required,
    get_jwt_identity
)

from api.models import (
    db,
    User,
    Store,
    Category,
    Product,
    Cart,
    Cart_Items,
    Favorite,
    Order,
    Order_Items
)


api = Blueprint("api", __name__)

# Permitir solicitudes CORS a esta API
CORS(api)


@api.route("/admin/users", methods=["GET"])
@jwt_required()
@admin_required
def get_users():
    statement = db.select(User)
    result = db.session.execute(statement)

    users = result.unique().scalars().all()

    return jsonify(
        [user.serialize() for user in users]
    ), 200


# =========================================================
# USUARIOS
# =========================================================


@api.route("/user", methods=["POST"])
def create_user():
    
    data = request.get_json()

    user = create_user_service(data)

    return jsonify({
                "message": "Usuario registrado correctamente",
                "user": user.serialize()
            }), 201

        

    


# =========================================================
# LOGIN DEL CLIENTE CON JWT
# =========================================================

@api.route("/user/login", methods=["POST"])
def login_client():
    data = request.get_json()

    if not data:
        return jsonify({
            "error": "No enviaste datos"
        }), 400

    email = data.get("email")
    password = data.get("password")

    if not email or not email.strip():
        return jsonify({
            "error": "El correo electrónico es obligatorio"
        }), 400

    if not password:
        return jsonify({
            "error": "La contraseña es obligatoria"
        }), 400

    clean_email = email.strip().lower()

    user = db.session.scalar(
        db.select(User).filter_by(email=clean_email)
    )

    if user is None:
        return jsonify({
            "error": "Correo o contraseña incorrectos"
        }), 401

    if not user.is_active:
        return jsonify({
            "error": "La cuenta está desactivada"
        }), 403

    if user.role not in ("client", "admin"):
        return jsonify({
            "error": "Esta cuenta no corresponde a un cliente ni administrador"
        }), 403

    if not check_password_hash(user.password, password):
        return jsonify({
            "error": "Correo o contraseña incorrectos"
        }), 401

    access_token = create_access_token(
        identity=str(user.id),
        additional_claims={
            "role": user.role
        }
    )

    return jsonify({
        "message": "Inicio de sesión exitoso",
        "token": access_token,
        "user": user.serialize()
    }), 200


@api.route("/user/private", methods=["GET"])
@jwt_required()
def private_user():
    user_id = get_jwt_identity()

    user = db.session.get(User, int(user_id))

    if user is None:
        return jsonify({
            "error": "Usuario no encontrado"
        }), 404

    return jsonify({
        "message": "Token válido",
        "user": user.serialize()
    }), 200


@api.route("/user/<int:user_id>", methods=["PUT"])
@jwt_required()
def update_user(user_id):
    current_user_id = int(get_jwt_identity())

    if current_user_id != user_id:
        return jsonify({
            "error": "No autorizado"
        }), 403

    data = request.get_json()

    if not data:
        return jsonify({
            "error": "No enviaste datos"
        }), 400

    user = db.session.get(User, user_id)

    if user is None:
        return jsonify({
            "error": "Usuario no encontrado"
        }), 404

    if "image" in data:
        user.image = data["image"]

    if "name" in data:
        new_name = data["name"]

        if not new_name or not new_name.strip():
            return jsonify({
                "error": "El nombre no puede estar vacío"
            }), 400

        user.name = new_name.strip()

    if "email" in data:
        new_email = data["email"]

        if not new_email or not new_email.strip():
            return jsonify({
                "error": "El correo electrónico no puede estar vacío"
            }), 400

        clean_email = new_email.strip().lower()

        existing_user = db.session.scalar(
            db.select(User).where(
                User.email == clean_email,
                User.id != user_id
            )
        )

        if existing_user:
            return jsonify({
                "error": "Ya existe otro usuario con ese correo electrónico"
            }), 409

        user.email = clean_email

    if "password" in data:
        new_password = data["password"]

        if not new_password:
            return jsonify({
                "error": "La contraseña no puede estar vacía"
            }), 400

        if len(new_password) < 6:
            return jsonify({
                "error": "La contraseña debe tener al menos 6 caracteres"
            }), 400

        user.password = generate_password_hash(new_password)

    try:
        db.session.commit()

    except Exception as error:
        db.session.rollback()

        print("Error al actualizar usuario:", error)

        return jsonify({
            "error": "Error al actualizar el usuario"
        }), 500

    return jsonify(user.serialize()), 200


@api.route("/user/<int:user_id>", methods=["DELETE"])
@jwt_required()
def delete_user(user_id):
    current_user_id = int(get_jwt_identity())

    if current_user_id != user_id:
        return jsonify({
            "error": "No autorizado"
        }), 403

    user = db.session.get(User, user_id)

    if user is None:
        return jsonify({
            "error": "Usuario no encontrado"
        }), 404

    try:
        db.session.delete(user)
        db.session.commit()

    except Exception as error:
        db.session.rollback()

        print("Error al eliminar usuario:", error)

        return jsonify({
            "error": "Error al eliminar el usuario"
        }), 500

    return jsonify({
        "message": "Usuario eliminado correctamente"
    }), 200


# =========================================================
# CARRITO
# =========================================================

@api.route("/user/cart/<int:user_id>", methods=["GET"])
@jwt_required()
def get_user_cart(user_id):
    current_user_id = int(get_jwt_identity())

    if current_user_id != user_id:
        return jsonify({
            "error": "No autorizado"
        }), 403

    user = db.session.get(User, user_id)

    if user is None:
        return jsonify({
            "error": "Usuario no encontrado"
        }), 404

    cart = user.cart

    if cart is None:
        return jsonify({
            "id": None,
            "user_id": user.id,
            "cart_items": []
        }), 200

    return jsonify(cart.serialize()), 200


@api.route("/cart/add", methods=["POST"])
@jwt_required()
def add_product_to_cart():
    data = request.get_json()

    if not data:
        return jsonify({
            "error": "Datos no enviados"
        }), 400

    user_id = int(get_jwt_identity())
    product_id = data.get("productId")

    if not product_id:
        return jsonify({
            "error": "Falta productId"
        }), 400

    user = db.session.get(User, user_id)

    if user is None:
        return jsonify({
            "error": "Usuario no encontrado"
        }), 404

    product = db.session.get(Product, product_id)

    if product is None:
        return jsonify({
            "error": "Producto no encontrado"
        }), 404

    cart = (
        db.session.execute(
            db.select(Cart).filter_by(user_id=user_id)
        )
        .unique()
        .scalar_one_or_none()
    )

    if cart is None:
        cart = Cart(user_id=user_id)
        db.session.add(cart)
        db.session.flush()

    cart_item = db.session.scalar(
        db.select(Cart_Items).filter_by(
            cart_id=cart.id,
            product_id=product_id
        )
    )

    if cart_item:
        cart_item.quantity += 1
    else:
        cart_item = Cart_Items(
            cart_id=cart.id,
            product_id=product_id,
            quantity=1
        )
        db.session.add(cart_item)

    try:
        db.session.commit()

        return jsonify({
            "message": "Producto agregado al carrito correctamente",
            "cart": cart.serialize()
        }), 200

    except Exception as error:
        db.session.rollback()
        print("Error al agregar producto al carrito:", error)

        return jsonify({
            "error": "Error al agregar el producto al carrito"
        }), 500


@api.route("/cart/update-quantity", methods=["PUT"])
@jwt_required()
def update_cart_item_quantity():
    data = request.get_json()

    product_id = data.get("productId")
    quantity = data.get("quantity")

    if product_id is None:
        return jsonify({
            "error": "Falta productId"
        }), 400

    if quantity is None:
        return jsonify({
            "error": "Falta quantity"
        }), 400

    try:
        quantity = int(quantity)
    except (TypeError, ValueError):
        return jsonify({
            "error": "La cantidad debe ser un número entero"
        }), 400

    user_id = int(get_jwt_identity())

    cart = db.session.scalar(
        db.select(Cart).filter_by(user_id=user_id)
    )

    if cart is None:
        return jsonify({
            "error": "Carrito no encontrado"
        }), 404

    cart_item = db.session.scalar(
        db.select(Cart_Items).filter_by(
            cart_id=cart.id,
            product_id=product_id
        )
    )

    if cart_item is None:
        return jsonify({
            "error": "Producto no encontrado en el carrito"
        }), 404

    # Si llega 0, elimina solamente este producto
    if quantity == 0:
        db.session.delete(cart_item)
        db.session.commit()

        return jsonify({
            "message": "Producto eliminado del carrito"
        }), 200

    # Solo rechaza números negativos
    if quantity < 0:
        return jsonify({
            "error": "La cantidad no puede ser negativa"
        }), 400

    cart_item.quantity = quantity
    db.session.commit()

    return jsonify({
        "message": "Cantidad actualizada",
        "cart_item": cart_item.serialize()
    }), 200


@api.route("/cart/clear", methods=["DELETE"])
@jwt_required()
def clear_cart():

    user_id = int(get_jwt_identity())

    cart = db.session.scalar(
        db.select(Cart).filter_by(user_id=user_id)
    )

    if cart is None:
        return jsonify({
            "error": "Carrito no encontrado para el usuario"
        }), 404

    try:
        db.session.execute(
            db.delete(Cart_Items).where(
                Cart_Items.cart_id == cart.id
            )
        )

        db.session.commit()

        return jsonify({
            "message": "Carrito vaciado correctamente"
        }), 200

    except Exception as error:
        db.session.rollback()

        print("Error al vaciar carrito:", error)

        return jsonify({
            "error": "Error al vaciar el carrito"
        }), 500

# =========================================================
# PAGO DE CARRITO
# =========================================================


@api.route("/checkout", methods=["POST"])
@jwt_required()
def checkout():

    user_id = int(get_jwt_identity())

    order = process_checkout(user_id)

    return jsonify({
        "message": "Compra realizada correctamente",
        "order": order.serialize()
    }), 201

    

# =========================================================
# TIENDA
# =========================================================


@api.route("/store", methods=["GET"])
def get_store():
    store = db.session.scalar(
        db.select(Store)
    )

    if store is None:
        return jsonify({
            "message": "No existe ninguna tienda todavía."
        }), 404

    return jsonify(store.serialize()), 200


@api.route("/store", methods=["POST"])
def create_store():
    data = request.get_json()

    if not data:
        return jsonify({
            "error": "No enviaste datos"
        }), 400

    name = data.get("name")
    logo = data.get("logo")
    description = data.get("description")

    if not name or not name.strip():
        return jsonify({
            "error": "El nombre de la tienda es obligatorio"
        }), 400

    existing_store = db.session.scalar(
        db.select(Store)
    )

    if existing_store:
        return jsonify({
            "error": "Ya existe una tienda"
        }), 400

    new_store = Store(
        name=name.strip(),
        logo=logo,
        description=description
    )

    try:
        db.session.add(new_store)
        db.session.commit()

    except Exception as error:
        db.session.rollback()

        print("Error al crear tienda:", error)

        return jsonify({
            "error": "Error al crear la tienda"
        }), 500

    return jsonify(new_store.serialize()), 201


@api.route("/store", methods=["PUT"])
def update_store():
    data = request.get_json()

    if not data:
        return jsonify({
            "error": "No enviaste datos"
        }), 400

    store = db.session.scalar(
        db.select(Store)
    )

    if store is None:
        return jsonify({
            "error": "No existe ninguna tienda todavía"
        }), 404

    if "name" in data:
        name = data["name"]

        if not name or not name.strip():
            return jsonify({
                "error": "El nombre de la tienda no puede estar vacío"
            }), 400

        store.name = name.strip()

    if "logo" in data:
        store.logo = data["logo"]

    if "description" in data:
        store.description = data["description"]

    try:
        db.session.commit()

    except Exception as error:
        db.session.rollback()

        print("Error al actualizar tienda:", error)

        return jsonify({
            "error": "Error al actualizar la tienda"
        }), 500

    return jsonify(store.serialize()), 200


# =========================================================
# ORDENES TIENDA
# =========================================================

@api.route("/store/orders", methods=["GET"])
@jwt_required()
def get_orders():
    current_user_id = int(get_jwt_identity())
    current_user = db.session.get(User, current_user_id)

    if current_user is None:
        return jsonify({
            "error": "Usuario no encontrado"
        }), 404

    if current_user.role != "admin":
        return jsonify({
            "error": "No autorizado"
        }), 403

    orders = (
        db.session.execute(
            db.select(Order)
            .order_by(Order.date.desc())
        )
        .unique()
        .scalars()
        .all()
    )

    return jsonify([
        order.serialize()
        for order in orders
    ]), 200


@api.route("/store/orders/<int:order_id>", methods=["PUT"])
@jwt_required()
def update_store_order(order_id):
    current_user_id = int(get_jwt_identity())
    current_user = db.session.get(User, current_user_id)

    if current_user is None:
        return jsonify({
            "error": "Usuario no encontrado"
        }), 404

    if current_user.role != "admin":
        return jsonify({
            "error": "No autorizado"
        }), 403

    data = request.get_json()

    if not data:
        return jsonify({
            "error": "No enviaste datos"
        }), 400

    order = db.session.get(Order, order_id)

    if order is None:
        return jsonify({
            "error": "Pedido no encontrado"
        }), 404

    new_status = data.get("status")

    if new_status not in {"pending", "completed", "cancelled"}:
        return jsonify({
            "error": "Estado de pedido inválido"
        }), 400

    order.status = new_status

    try:
        db.session.commit()
    except Exception as error:
        db.session.rollback()
        print("Error al actualizar pedido:", error)
        return jsonify({
            "error": "No se pudo actualizar el pedido"
        }), 500

    return jsonify(order.serialize()), 200


# =========================================================
# CATEGORÍAS
# =========================================================

@api.route("/categories", methods=["GET"])
def get_categories():
    categories = db.session.scalars(
        db.select(Category)
    ).all()

    return jsonify(
        [category.serialize() for category in categories]
    ), 200


@api.route("/categories", methods=["POST"])
def create_category():
    data = request.get_json()

    if not data:
        return jsonify({
            "error": "No enviaste datos"
        }), 400

    name = data.get("name")

    if not name or not name.strip():
        return jsonify({
            "error": "El nombre de la categoría es obligatorio"
        }), 400

    clean_name = name.strip().lower()

    existing_category = db.session.scalar(
        db.select(Category).where(
            db.func.lower(Category.name) == clean_name
        )
    )

    if existing_category:
        return jsonify({
            "error": "Esa categoría ya existe"
        }), 409

    new_category = Category(
        name=clean_name
    )

    try:
        db.session.add(new_category)
        db.session.commit()

    except Exception as error:
        db.session.rollback()

        print("Error al crear categoría:", error)

        return jsonify({
            "error": "Error al crear la categoría"
        }), 500

    return jsonify(new_category.serialize()), 201


@api.route("/categories/<int:category_id>", methods=["DELETE"])
def delete_category(category_id):
    category = db.session.get(Category, category_id)

    if category is None:
        return jsonify({
            "error": "Categoría no encontrada"
        }), 404

    try:
        db.session.delete(category)
        db.session.commit()

    except Exception as error:
        db.session.rollback()

        print("Error al eliminar categoría:", error)

        return jsonify({
            "error": "Error al eliminar la categoría"
        }), 500

    return jsonify({
        "message": "Categoría eliminada correctamente"
    }), 200


# =========================================================
# PRODUCTOS
# =========================================================

@api.route(
    "/products/category/<int:category_id>",
    methods=["GET"]
)
def get_products_by_category(category_id):
    category = db.session.get(Category, category_id)

    if category is None:
        return jsonify({
            "error": "Categoría no encontrada"
        }), 404

    statement = db.select(Product).filter_by(
        category_id=category_id
    )

    result = db.session.execute(statement)

    products = result.unique().scalars().all()

    return jsonify(
        [product.serialize() for product in products]
    ), 200


@api.route("/products", methods=["POST"])
def create_product():
    data = request.get_json()

    if not data:
        return jsonify({
            "error": "No enviaste datos"
        }), 400

    name = data.get("name")
    price = data.get("price")
    description = data.get("description")
    image = data.get("image")
    category_id = data.get("category_id")

    if not name or not name.strip():
        return jsonify({
            "error": "El nombre del producto es obligatorio"
        }), 400

    if price is None:
        return jsonify({
            "error": "El precio del producto es obligatorio"
        }), 400

    try:
        price = float(price)

    except (TypeError, ValueError):
        return jsonify({
            "error": "El precio debe ser un número válido"
        }), 400

    if price < 0:
        return jsonify({
            "error": "El precio no puede ser negativo"
        }), 400

    if not category_id:
        return jsonify({
            "error": "La categoría es obligatoria"
        }), 400

    category = db.session.get(Category, category_id)

    if category is None:
        return jsonify({
            "error": "Categoría no encontrada"
        }), 404

    new_product = Product(
        name=name.strip(),
        price=price,
        description=description,
        image=image,
        category_id=category_id
    )

    try:
        db.session.add(new_product)
        db.session.commit()

    except Exception as error:
        db.session.rollback()

        print("Error al crear producto:", error)

        return jsonify({
            "error": "Error al crear el producto"
        }), 500

    return jsonify(new_product.serialize()), 201


@api.route("/products/<int:product_id>", methods=["PUT"])
def update_product(product_id):
    data = request.get_json()

    if not data:
        return jsonify({
            "error": "No enviaste datos"
        }), 400

    product = db.session.get(Product, product_id)

    if product is None:
        return jsonify({
            "error": "Producto no encontrado"
        }), 404

    if "name" in data:
        name = data["name"]

        if not name or not name.strip():
            return jsonify({
                "error": "El nombre del producto no puede estar vacío"
            }), 400

        product.name = name.strip()

    if "price" in data:
        try:
            new_price = float(data["price"])

        except (TypeError, ValueError):
            return jsonify({
                "error": "El precio debe ser un número válido"
            }), 400

        if new_price < 0:
            return jsonify({
                "error": "El precio no puede ser negativo"
            }), 400

        product.price = new_price

    if "description" in data:
        product.description = data["description"]

    if "image" in data:
        product.image = data["image"]

    if "category_id" in data:
        category = db.session.get(
            Category,
            data["category_id"]
        )

        if category is None:
            return jsonify({
                "error": "Categoría no encontrada"
            }), 404

        product.category_id = data["category_id"]

    try:
        db.session.commit()

    except Exception as error:
        db.session.rollback()

        print("Error al actualizar producto:", error)

        return jsonify({
            "error": "Error al actualizar el producto"
        }), 500

    return jsonify(product.serialize()), 200


@api.route("/products/<int:product_id>", methods=["DELETE"])
def delete_product(product_id):
    product = db.session.get(Product, product_id)

    if product is None:
        return jsonify({
            "error": "Producto no encontrado"
        }), 404

    try:
        db.session.delete(product)
        db.session.commit()

    except Exception as error:
        db.session.rollback()

        print("Error al eliminar producto:", error)

        return jsonify({
            "error": "Error al eliminar el producto"
        }), 500

    return jsonify({
        "message": "Producto eliminado correctamente"
    }), 200


# =========================================================
# FAVORITOS
# =========================================================

@api.route(
    "/favorites/user/<int:user_id>",
    methods=["GET"]
)
@jwt_required()
def get_user_favorites(user_id):

    current_user = int(get_jwt_identity())

    if current_user != user_id:
        return jsonify({
            "error": "No autorizado"
        }), 403

    user = db.session.get(User, user_id)

    if user is None:
        return jsonify({
            "error": "Usuario no encontrado"
        }), 404

    statement = db.select(Favorite).filter_by(
        user_id=user_id
    )

    result = db.session.execute(statement)

    favorites = result.unique().scalars().all()

    return jsonify(
        [favorite.serialize() for favorite in favorites]
    ), 200


@api.route("/favorites", methods=["POST"])
@jwt_required()
def add_favorite():
    data = request.get_json()

    if not data:
        return jsonify({
            "error": "No enviaste datos"
        }), 400

    current_user_id = int(get_jwt_identity())
    user_id = data.get("user_id")
    product_id = data.get("product_id")

    if not user_id or not product_id:
        return jsonify({
            "error": "user_id y product_id son obligatorios"
        }), 400

    if current_user_id != int(user_id):
        return jsonify({
            "error": "No autorizado"
        }), 403

    user = db.session.get(User, user_id)

    if user is None:
        return jsonify({
            "error": "Usuario no encontrado"
        }), 404

    product = db.session.get(Product, product_id)

    if product is None:
        return jsonify({
            "error": "Producto no encontrado"
        }), 404

    existing_favorite = db.session.scalar(
        db.select(Favorite).filter_by(
            user_id=user_id,
            product_id=product_id
        )
    )

    if existing_favorite:
        return jsonify({
            "error": "El producto ya está en favoritos"
        }), 409

    new_favorite = Favorite(
        user_id=user_id,
        product_id=product_id
    )

    try:
        db.session.add(new_favorite)
        db.session.commit()

    except Exception as error:
        db.session.rollback()
        print("Error agregando favorito:", error)

        return jsonify({
            "error": "Error al agregar favorito"
        }), 500

    return jsonify(new_favorite.serialize()), 201


@api.route(
    "/favorites/user/<int:user_id>/product/<int:product_id>",
    methods=["DELETE"]
)
@jwt_required()
def delete_favorite(user_id, product_id):
    current_user_id = int(get_jwt_identity())

    if current_user_id != user_id:
        return jsonify({
            "error": "No autorizado"
        }), 403

    favorite = db.session.scalar(
        db.select(Favorite).filter_by(
            user_id=user_id,
            product_id=product_id
        )
    )

    if favorite is None:
        return jsonify({
            "error": "Favorito no encontrado"
        }), 404

    try:
        db.session.delete(favorite)
        db.session.commit()

    except Exception as error:
        db.session.rollback()
        print("Error eliminando favorito:", error)

        return jsonify({
            "error": "Error al eliminar favorito"
        }), 500

    return jsonify({
        "message": "Favorito eliminado correctamente"
    }), 200


# =========================================================
# HISTORIAL PEDIDOS
# =========================================================
@api.route("/orders", methods=["GET"])
@jwt_required()
def get_user_orders():
    user_id = int(get_jwt_identity())

    orders = (
        db.session.execute(
            db.select(Order)
            .where(Order.user_id == user_id)
            .order_by(Order.date.desc())
        )
        .unique()
        .scalars()
        .all()
    )

    return jsonify([
        order.serialize()
        for order in orders
    ]), 200


@api.route("/orders/<int:order_id>", methods=["GET"])
@jwt_required()
def get_user_order(order_id):
    user_id = int(get_jwt_identity())

    order = (
        db.session.execute(
            db.select(Order).where(
                Order.id == order_id,
                Order.user_id == user_id
            )
        )
        .unique()
        .scalar_one_or_none()
    )

    if order is None:
        return jsonify({
            "error": "Pedido no encontrado"
        }), 404

    return jsonify(order.serialize()), 200
