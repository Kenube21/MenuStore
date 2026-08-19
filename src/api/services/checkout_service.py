
from api.utils import APIException

from api.models import (
    db,
    Cart,
    Cart_Items,
    Order,
    Order_Items
)


def process_checkout(user_id):

    cart = db.session.execute(
        db.select(Cart).where(Cart.user_id == user_id)
    ).scalar_one_or_none()

    if cart is None:
        raise APIException(
            "Carrito no encontrado", 404
        )

    cart_items = db.session.execute(
        db.select(Cart_Items).where(Cart_Items.cart_id == cart.id)
    ).unique().scalars().all()

    if not cart_items:
        raise APIException(
            "Carrito vacío", 400
        )

    total_amount = sum(
        cart_item.quantity * float(cart_item.product.price)
        for cart_item in cart_items
    )

    new_order = Order(
        user_id=user_id,
        total_amount=total_amount,
        status="pending"
    )

    try:
        db.session.add(new_order)
        db.session.flush()

        for cart_item in cart_items:
            order_item = Order_Items(
                order_id=new_order.id,
                product_id=cart_item.product_id,
                quantity=cart_item.quantity,
                historic_price=float(cart_item.product.price)
            )

            db.session.add(order_item)

        for cart_item in cart_items:
            db.session.delete(cart_item)

        db.session.commit()

        return new_order

    except Exception as error:
        db.session.rollback()

        print("ERROR CHECKOUT:", error)

        raise APIException(
            "No se pudo completar la compra", 500
        )
