# app.py
import os
import uuid
import requests
import importlib.util
from functools import wraps
from datetime import datetime, timedelta

from flask import Flask, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from sqlalchemy import or_, func

# ---------- Optional external FCM config import ----------
GLOBAL_FCM_SERVER_KEY = None
try:
    spec = importlib.util.find_spec("fcm_config")
    if spec is not None:
        fcm_config = importlib.import_module("fcm_config")
        GLOBAL_FCM_SERVER_KEY = getattr(fcm_config, "FCM_SERVER_KEY", None)
except Exception:
    GLOBAL_FCM_SERVER_KEY = None

# ---------- Config ----------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(BASE_DIR, "app.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY", "change-this-secret")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

db = SQLAlchemy(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)

# ---------- Models ----------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    name = db.Column(db.String(80))
    surname = db.Column(db.String(80))
    phone = db.Column(db.String(50))
    address = db.Column(db.Text, nullable=True)
    role = db.Column(db.String(20), default="user")  # 'user' or 'admin'
    fcm_server_key = db.Column(db.Text, nullable=True)  # admin can store server key
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    device_tokens = db.relationship("DeviceToken", backref="user", lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class DeviceToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(512), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Float, nullable=False)
    stock = db.Column(db.Integer, default=0)
    image_filename = db.Column(db.String(256), nullable=True)
    category_id = db.Column(db.Integer, db.ForeignKey("category.id"), nullable=True)
    discount_percent = db.Column(db.Float, default=0.0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    category = db.relationship("Category")

    @property
    def price_after_discount(self):
        if self.discount_percent and self.discount_percent > 0:
            return round(self.price * (1 - self.discount_percent / 100), 2)
        return self.price

class CartItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey("product.id"), nullable=False)
    quantity = db.Column(db.Integer, default=1)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    product = db.relationship("Product")

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    total_amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(50), default="new")  # new, processing, shipped, completed
    payment_method = db.Column(db.String(50), default="kapida_nakit")  # kapida_kart or kapida_nakit
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    items = db.relationship("OrderItem", backref="order", lazy=True)

class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey("order.id"), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey("product.id"), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    unit_price = db.Column(db.Float, nullable=False)
    product = db.relationship("Product")

# ---------- Helpers ----------
def admin_required(fn):
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        current = get_jwt_identity()
        user = User.query.filter_by(username=current).first()
        if not user or user.role != "admin":
            return jsonify({"msg": "Admin yetkisi gerekli"}), 403
        return fn(*args, **kwargs)
    return wrapper

def send_fcm_notification(server_key, tokens, title, body, data=None):
    """
    server_key: FCM server key string (legacy). If None, function returns error.
    tokens: list of device tokens
    """
    if not tokens:
        return {"success": False, "error": "Recipient token yok"}
    sk = server_key or GLOBAL_FCM_SERVER_KEY
    if not sk:
        return {"success": False, "error": "FCM server key yok (hem admin hem global)"}
    url = "https://fcm.googleapis.com/fcm/send"
    headers = {
        "Authorization": "key=" + sk,
        "Content-Type": "application/json",
    }
    payload = {
        "registration_ids": tokens,
        "notification": {"title": title, "body": body},
        "data": data or {}
    }
    try:
        r = requests.post(url, json=payload, headers=headers, timeout=8)
        return {"success": True, "status_code": r.status_code, "response": r.json()}
    except Exception as e:
        return {"success": False, "error": str(e)}

def save_image_file(file_storage):
    ext = os.path.splitext(file_storage.filename)[1]
    filename = f"{uuid.uuid4().hex}{ext}"
    path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    file_storage.save(path)
    return filename

# ---------- Routes ----------
@app.route("/health")
def health():
    return jsonify({"status": "ok"})

# --- Auth ---
@app.route("/auth/register_admin", methods=["POST"])
def register_admin():
    data = request.json or {}
    required = ("name", "surname", "email", "phone", "username", "password")
    if not all(k in data for k in required):
        return jsonify({"msg": "Eksik alan"}), 400
    if User.query.filter_by(username=data["username"]).first():
        return jsonify({"msg": "Kullanıcı adı zaten var"}), 400
    user = User(
        username=data["username"],
        email=data["email"],
        name=data["name"],
        surname=data["surname"],
        phone=data["phone"],
        role="admin"
    )
    user.set_password(data["password"])
    if "fcm_server_key" in data:
        user.fcm_server_key = data["fcm_server_key"]
    db.session.add(user)
    db.session.commit()
    return jsonify({"msg": "Admin oluşturuldu", "admin_id": user.id})

@app.route("/auth/register", methods=["POST"])
def register_user():
    data = request.json or {}
    required = ("name", "surname", "email", "phone", "address", "username", "password")
    if not all(k in data for k in required):
        return jsonify({"msg": "Eksik alan"}), 400
    if User.query.filter_by(username=data["username"]).first():
        return jsonify({"msg": "Kullanıcı adı zaten var"}), 400
    user = User(
        username=data["username"],
        email=data["email"],
        name=data["name"],
        surname=data["surname"],
        phone=data["phone"],
        address=data["address"],
        role="user"
    )
    user.set_password(data["password"])
    db.session.add(user)
    db.session.commit()
    return jsonify({"msg": "Kullanıcı oluşturuldu", "user_id": user.id})

@app.route("/auth/login", methods=["POST"])
def login():
    data = request.json or {}
    if "username" not in data or "password" not in data:
        return jsonify({"msg": "username ve password gerekli"}), 400
    user = User.query.filter_by(username=data["username"]).first()
    if not user or not user.check_password(data["password"]):
        return jsonify({"msg": "Kullanıcı adı veya şifre hatalı"}), 401
    expires = timedelta(days=7)
    token = create_access_token(identity=user.username, expires_delta=expires)
    return jsonify({"access_token": token, "user": {"id": user.id, "username": user.username, "role": user.role}})

# --- Device token registration for FCM ---
@app.route("/auth/device/register", methods=["POST"])
@jwt_required()
def register_device():
    data = request.json or {}
    if "token" not in data:
        return jsonify({"msg": "token gerekli"}), 400
    current = get_jwt_identity()
    user = User.query.filter_by(username=current).first()
    dt = DeviceToken(token=data["token"], user_id=user.id)
    db.session.add(dt)
    db.session.commit()
    return jsonify({"msg": "Device token kaydedildi"})

# --- Category management ---
@app.route("/admin/categories", methods=["POST"])
@admin_required
def create_category():
    data = request.json or {}
    if "name" not in data:
        return jsonify({"msg": "name gerekli"}), 400
    if Category.query.filter(func.lower(Category.name) == data["name"].lower()).first():
        return jsonify({"msg": "Kategori zaten var"}), 400
    c = Category(name=data["name"])
    db.session.add(c)
    db.session.commit()
    return jsonify({"msg": "Kategori oluşturuldu", "category_id": c.id})

@app.route("/categories", methods=["GET"])
def list_categories():
    cats = Category.query.order_by(Category.name.asc()).all()
    return jsonify([{"id": c.id, "name": c.name} for c in cats])

# --- Product management ---
@app.route("/admin/products", methods=["POST"])
@admin_required
def create_product():
    title = request.form.get("title")
    price = request.form.get("price")
    stock = request.form.get("stock", 0)
    description = request.form.get("description", "")
    category_id = request.form.get("category_id")
    if not title or not price:
        return jsonify({"msg": "title ve price gerekli"}), 400
    try:
        price = float(price)
        stock = int(stock)
    except:
        return jsonify({"msg": "price/stock format hatası"}), 400
    p = Product(title=title, price=price, stock=stock, description=description)
    if category_id:
        try:
            p.category_id = int(category_id)
        except:
            pass
    if "image" in request.files:
        file = request.files["image"]
        filename = save_image_file(file)
        p.image_filename = filename
    db.session.add(p)
    db.session.commit()
    return jsonify({"msg": "Ürün oluşturuldu", "product_id": p.id})

@app.route("/uploads/<path:filename>")
def uploads(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

@app.route("/admin/products/<int:product_id>", methods=["PUT"])
@admin_required
def update_product(product_id):
    p = Product.query.get_or_404(product_id)
    data = request.form or {}
    if "title" in data: p.title = data["title"]
    if "price" in data:
        try: p.price = float(data["price"])
        except: pass
    if "stock" in data:
        try: p.stock = int(data["stock"])
        except: pass
    if "description" in data: p.description = data["description"]
    if "category_id" in data:
        try: p.category_id = int(data["category_id"])
        except: pass
    if "discount_percent" in data:
        try: p.discount_percent = float(data["discount_percent"])
        except: p.discount_percent = 0.0
    if "image" in request.files:
        file = request.files["image"]
        filename = save_image_file(file)
        p.image_filename = filename
    db.session.commit()
    return jsonify({"msg": "Ürün güncellendi"})

@app.route("/admin/products/<int:product_id>", methods=["DELETE"])
@admin_required
def delete_product(product_id):
    p = Product.query.get_or_404(product_id)
    db.session.delete(p)
    db.session.commit()
    return jsonify({"msg": "Ürün silindi"})

@app.route("/admin/products/<int:product_id>/discount", methods=["POST"])
@admin_required
def set_discount(product_id):
    p = Product.query.get_or_404(product_id)
    data = request.json or {}
    if "discount_percent" not in data:
        return jsonify({"msg": "discount_percent gerekli"}), 400
    try:
        p.discount_percent = float(data["discount_percent"])
    except:
        return jsonify({"msg": "discount_percent format hatası"}), 400
    db.session.commit()
    return jsonify({"msg": "İndirim uygulandı", "discount_percent": p.discount_percent})

# --- Search / List products with filters, pagination, sorting ---
@app.route("/products", methods=["GET"])
def list_products():
    q_text = request.args.get("q", type=str)
    category_name = request.args.get("category", type=str)
    category_id = request.args.get("category_id", type=int)
    min_price = request.args.get("min_price", type=float)
    max_price = request.args.get("max_price", type=float)
    sort_by = request.args.get("sort_by", type=str)
    page = request.args.get("page", default=1, type=int)
    per_page = request.args.get("per_page", default=20, type=int)
    if per_page > 100:
        per_page = 100

    q = Product.query.outerjoin(Category)

    if q_text:
        like_expr = f"%{q_text}%"
        q = q.filter(or_(Product.title.ilike(like_expr), Product.description.ilike(like_expr)))

    if category_id:
        q = q.filter(Product.category_id == category_id)
    elif category_name:
        cat = Category.query.filter(func.lower(Category.name) == category_name.lower()).first()
        if cat:
            q = q.filter(Product.category_id == cat.id)
        else:
            return jsonify({"total": 0, "page": page, "per_page": per_page, "total_pages": 0, "products": []})

    if min_price is not None:
        q = q.filter(Product.price >= min_price)
    if max_price is not None:
        q = q.filter(Product.price <= max_price)

    if sort_by == "price_asc":
        q = q.order_by(Product.price.asc())
    elif sort_by == "price_desc":
        q = q.order_by(Product.price.desc())
    elif sort_by == "newest":
        q = q.order_by(Product.created_at.desc())
    else:
        q = q.order_by(Product.id.asc())

    total = q.count()
    total_pages = (total + per_page - 1) // per_page if per_page else 1
    items = q.offset((page - 1) * per_page).limit(per_page).all()

    out = []
    for p in items:
        out.append({
            "id": p.id,
            "title": p.title,
            "description": p.description,
            "price": p.price,
            "price_after_discount": p.price_after_discount,
            "stock": p.stock,
            "image_url": (request.host_url.rstrip("/") + "/uploads/" + p.image_filename) if p.image_filename else None,
            "category": p.category.name if p.category else None,
            "discount_percent": p.discount_percent
        })

    return jsonify({
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": total_pages,
        "products": out
    })

# --- Cart endpoints ---
@app.route("/cart", methods=["GET"])
@jwt_required()
def get_cart():
    current = get_jwt_identity()
    user = User.query.filter_by(username=current).first()
    items = CartItem.query.filter_by(user_id=user.id).all()
    out = []
    for it in items:
        out.append({
            "id": it.id,
            "product": {"id": it.product.id, "title": it.product.title, "price": it.product.price_after_discount},
            "quantity": it.quantity
        })
    return jsonify(out)

@app.route("/cart", methods=["POST"])
@jwt_required()
def add_to_cart():
    data = request.json or {}
    if "product_id" not in data or "quantity" not in data:
        return jsonify({"msg": "product_id ve quantity gerekli"}), 400
    current = get_jwt_identity()
    user = User.query.filter_by(username=current).first()
    product = Product.query.get_or_404(data["product_id"])
    qty = int(data["quantity"])
    if product.stock < qty:
        return jsonify({"msg": "Yeterli stok yok"}), 400
    item = CartItem.query.filter_by(user_id=user.id, product_id=product.id).first()
    if item:
        item.quantity += qty
    else:
        item = CartItem(user_id=user.id, product_id=product.id, quantity=qty)
        db.session.add(item)
    db.session.commit()
    return jsonify({"msg": "Sepete eklendi"})

@app.route("/cart/remove", methods=["POST"])
@jwt_required()
def remove_cart_item():
    data = request.json or {}
    if "cart_item_id" not in data:
        return jsonify({"msg": "cart_item_id gerekli"}), 400
    item = CartItem.query.get_or_404(data["cart_item_id"])
    db.session.delete(item)
    db.session.commit()
    return jsonify({"msg": "Silindi"})

# --- Checkout / create order ---
@app.route("/cart/checkout", methods=["POST"])
@jwt_required()
def checkout():
    data = request.json or {}
    payment_method = data.get("payment_method", "kapida_nakit")
    if payment_method in ("card_on_delivery", "kapida_kart"):
        payment_method = "kapida_kart"
    else:
        payment_method = "kapida_nakit"

    current = get_jwt_identity()
    user = User.query.filter_by(username=current).first()
    items = CartItem.query.filter_by(user_id=user.id).all()
    if not items:
        return jsonify({"msg": "Sepet boş"}), 400
    total = 0.0
    for it in items:
        if it.product.stock < it.quantity:
            return jsonify({"msg": f"{it.product.title} için yeterli stok yok"}), 400
        total += it.product.price_after_discount * it.quantity

    order = Order(user_id=user.id, total_amount=round(total,2), payment_method=payment_method)
    db.session.add(order)
    db.session.commit()
    for it in items:
        oi = OrderItem(order_id=order.id, product_id=it.product.id, quantity=it.quantity, unit_price=it.product.price_after_discount)
        db.session.add(oi)
        it.product.stock -= it.quantity
        db.session.delete(it)
    db.session.commit()

    admins = User.query.filter_by(role="admin").all()
    for admin in admins:
        tokens = [dt.token for dt in admin.device_tokens]
        server_key_to_use = admin.fcm_server_key or GLOBAL_FCM_SERVER_KEY
        if tokens and server_key_to_use:
            title = "Yeni Sipariş"
            body = f"#{order.id} numaralı sipariş oluşturuldu. Tutar: {order.total_amount} TL. Ödeme: {order.payment_method}"
            send_fcm_notification(server_key_to_use, tokens, title, body, data={"order_id": order.id})
    return jsonify({"msg": "Sipariş oluştu", "order_id": order.id, "payment_method": order.payment_method})

# --- Admin view orders ---
@app.route("/admin/orders", methods=["GET"])
@admin_required
def admin_orders():
    orders = Order.query.order_by(Order.created_at.desc()).all()
    out = []
    for o in orders:
        out.append({
            "id": o.id,
            "user_id": o.user_id,
            "total_amount": o.total_amount,
            "status": o.status,
            "payment_method": o.payment_method,
            "created_at": o.created_at.isoformat(),
            "items": [{"product_id": it.product_id, "title": it.product.title, "quantity": it.quantity, "unit_price": it.unit_price} for it in o.items]
        })
    return jsonify(out)

# --- Admin announcement via their FCM key (or global fallback) ---
@app.route("/admin/announce", methods=["POST"])
@admin_required
def admin_announce():
    data = request.json or {}
    if "title" not in data or "body" not in data:
        return jsonify({"msg": "title ve body gerekli"}), 400
    current = get_jwt_identity()
    admin = User.query.filter_by(username=current).first()
    if "tokens" in data and isinstance(data["tokens"], list) and data["tokens"]:
        tokens = data["tokens"]
    else:
        tokens = [dt.token for u in User.query.filter_by(role="user").all() for dt in u.device_tokens]
    server_key_to_use = admin.fcm_server_key or GLOBAL_FCM_SERVER_KEY
    if not server_key_to_use:
        return jsonify({"msg": "Admin için FCM server key tanımlı değil ve global fallback yok"}), 400
    res = send_fcm_notification(server_key_to_use, tokens, data["title"], data["body"], data.get("data"))
    return jsonify(res)

@app.route("/admin/fcm_key", methods=["POST"])
@admin_required
def set_admin_fcm_key():
    data = request.json or {}
    if "fcm_server_key" not in data:
        return jsonify({"msg": "fcm_server_key gerekli"}), 400
    current = get_jwt_identity()
    admin = User.query.filter_by(username=current).first()
    admin.fcm_server_key = data["fcm_server_key"]
    db.session.commit()
    return jsonify({"msg": "FCM server key kaydedildi"})

@app.route("/admin/summary", methods=["GET"])
@admin_required
def admin_summary():
    total_products = Product.query.count()
    total_orders = Order.query.count()
    total_users = User.query.filter_by(role="user").count()
    total_income = db.session.query(func.sum(Order.total_amount)).scalar() or 0.0
    return jsonify({
        "total_products": total_products,
        "total_orders": total_orders,
        "total_users": total_users,
        "total_income": float(total_income)
    })

# --- Kullanıcı kendi profilini görüntüleme / güncelleme ---
@app.route("/me", methods=["GET"])
@jwt_required()
def get_me():
    current = get_jwt_identity()
    user = User.query.filter_by(username=current).first_or_404()
    return jsonify({
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "name": user.name,
        "surname": user.surname,
        "phone": user.phone,
        "address": user.address,
        "role": user.role,
        "created_at": user.created_at.isoformat()
    })

@app.route("/me", methods=["PUT"])
@jwt_required()
def update_me():
    data = request.json or {}
    current_identity = get_jwt_identity()
    user = User.query.filter_by(username=current_identity).first_or_404()

    original_username = user.username

    if "username" in data and data["username"] and data["username"] != user.username:
        if User.query.filter_by(username=data["username"]).first():
            return jsonify({"msg": "Bu kullanıcı adı zaten alınmış"}), 400
        user.username = data["username"]

    if "email" in data and data["email"] and data["email"] != user.email:
        if User.query.filter(User.email == data["email"], User.id != user.id).first():
            return jsonify({"msg": "Bu e-posta başka bir hesapta kullanılıyor"}), 400
        user.email = data["email"]

    for field in ("name", "surname", "phone", "address"):
        if field in data:
            setattr(user, field, data[field])

    if "new_password" in data:
        if "current_password" not in data or not user.check_password(data["current_password"]):
            return jsonify({"msg": "Mevcut şifre yanlış veya sağlanmadı"}), 400
        user.set_password(data["new_password"])

    db.session.commit()

    response = {"msg": "Profil güncellendi", "user": {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "name": user.name,
        "surname": user.surname,
        "phone": user.phone,
        "address": user.address
    }}
    if original_username != user.username:
        expires = timedelta(days=7)
        new_token = create_access_token(identity=user.username, expires_delta=expires)
        response["new_token"] = new_token

    return jsonify(response)

# ---------- Run ----------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=8000, debug=True)
