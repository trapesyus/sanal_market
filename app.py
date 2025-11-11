# app.py
import os
import uuid
import base64
import requests
import importlib.util
from functools import wraps
from datetime import datetime, timedelta

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from sqlalchemy import or_, func, cast, Float

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

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(BASE_DIR, "app.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY", "change-this-secret")

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
    # price and discount stored as strings (as requested)
    price = db.Column(db.String(64), nullable=False)
    stock = db.Column(db.Integer, default=0)           # stored as integer internally
    image_base64 = db.Column(db.Text, nullable=True)
    image_mime = db.Column(db.String(80), nullable=True)
    category_id = db.Column(db.Integer, db.ForeignKey("category.id"), nullable=True)
    discount_percent = db.Column(db.String(64), default="0")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    category = db.relationship("Category")

    def _price_float(self):
        try:
            return float(self.price.replace(",", ".")) if isinstance(self.price, str) else float(self.price)
        except Exception:
            return 0.0

    def _discount_float(self):
        try:
            return float(self.discount_percent.replace(",", ".")) if isinstance(self.discount_percent, str) else float(self.discount_percent)
        except Exception:
            return 0.0

    @property
    def price_after_discount(self):
        p = self._price_float()
        d = self._discount_float()
        if d and d > 0:
            val = round(p * (1 - d / 100), 2)
        else:
            val = round(p, 2)
        # return as string per requirement
        return f"{val:.2f}"

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
    total_amount = db.Column(db.String(64), nullable=False)
    status = db.Column(db.String(50), default="new")
    payment_method = db.Column(db.String(50), default="kapida_nakit")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    items = db.relationship("OrderItem", backref="order", lazy=True)

class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey("order.id"), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey("product.id"), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    unit_price = db.Column(db.String(64), nullable=False)
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
    server_key: FCM legacy server key
    tokens: list of device tokens
    """
    if not tokens:
        return {"success": False, "error": "Recipient token yok"}
    if not server_key:
        return {"success": False, "error": "FCM server key yok"}
    url = "https://fcm.googleapis.com/fcm/send"
    headers = {
        "Authorization": "key=" + server_key,
        "Content-Type": "application/json",
    }
    payload = {
        "registration_ids": tokens,
        "notification": {"title": title, "body": body},
        "data": data or {}
    }
    try:
        r = requests.post(url, json=payload, headers=headers, timeout=10)
        try:
            resp_json = r.json()
        except Exception:
            resp_json = r.text
        return {"success": True, "status_code": r.status_code, "response": resp_json}
    except Exception as e:
        return {"success": False, "error": str(e)}

def _file_storage_to_base64(file_storage):
    data = file_storage.read()
    try:
        file_storage.stream.seek(0)
    except Exception:
        pass
    b64 = base64.b64encode(data).decode("utf-8")
    filename = getattr(file_storage, "filename", "") or ""
    mime = None
    if "." in filename:
        ext = filename.rsplit(".", 1)[1].lower()
        if ext in ("jpg", "jpeg"):
            mime = "image/jpeg"
        elif ext == "png":
            mime = "image/png"
        elif ext == "gif":
            mime = "image/gif"
    return b64, mime

def _is_numeric_string(s):
    try:
        float(str(s).replace(",", "."))
        return True
    except Exception:
        return False

def _parse_stock_value(s):
    """
    Accept stock provided as string (e.g. "10" or "10.0" or 10) and
    return integer value. Raises ValueError on invalid.
    """
    if s is None or s == "":
        return 0
    if isinstance(s, int):
        return s
    try:
        # allow "10", "10.0", "10,0"
        val = float(str(s).replace(",", "."))
        return int(val)
    except Exception:
        raise ValueError("stock integer formatında olmalı (örn. '10')")

def notify_users_about_discount(product: Product, triggered_by_admin_username: str = None):
    """
    Send FCM notifications to all users about a discount on `product`.
    """
    title = f"{product.title} için {product.discount_percent}% indirim!"
    body = f"{product.title} ürününde {product.discount_percent}% indirim başladı. Yeni fiyat: {product.price_after_discount} TL"

    users = User.query.filter_by(role="user").all()
    tokens = [dt.token for u in users for dt in u.device_tokens]

    result = {"total_user_tokens": len(tokens), "fcm_sends": []}

    if not tokens:
        result["note"] = "Kayıtlı device token yok"
        return result

    # Prefer global key
    if GLOBAL_FCM_SERVER_KEY:
        res = send_fcm_notification(GLOBAL_FCM_SERVER_KEY, tokens, title, body, data={"product_id": product.id})
        result["fcm_sends"].append({"key": "GLOBAL", "result": res})
        return result

    # If no global key, try all admins' keys (avoid duplicates)
    admin_keys = set()
    admins = User.query.filter_by(role="admin").all()
    for admin in admins:
        if admin.fcm_server_key:
            admin_keys.add(admin.fcm_server_key)

    if not admin_keys:
        result["note"] = "FCM server key bulunamadı (global yok, adminlerin keyleri yok)"
        return result

    for key in admin_keys:
        res = send_fcm_notification(key, tokens, title, body, data={"product_id": product.id})
        result["fcm_sends"].append({"key_hash": key[:12] + "...", "result": res})

    return result

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

    # döndürülecek user objesi: kayıt sırasında girilen tüm bilgiler
    user_info = {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "name": user.name,
        "surname": user.surname,
        "phone": user.phone,
        "address": user.address,
        "role": user.role,
        "created_at": user.created_at.isoformat(),
        "device_tokens": [dt.token for dt in user.device_tokens]
    }

    return jsonify({"access_token": token, "user": user_info})

# --- Device token registration for FCM ---
@app.route("/auth/device/register", methods=["POST"])
@jwt_required()
def register_device():
    data = request.json or {}
    if "token" not in data:
        return jsonify({"msg": "token gerekli"}), 400
    current = get_jwt_identity()
    user = User.query.filter_by(username=current).first()
    # prevent duplicate tokens
    if DeviceToken.query.filter_by(token=data["token"], user_id=user.id).first():
        return jsonify({"msg": "Token zaten kayıtlı"})
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

@app.route("/admin/categories/<int:category_id>", methods=["DELETE"])
@admin_required
def delete_category(category_id):
    cat = Category.query.get_or_404(category_id)
    related_count = Product.query.filter_by(category_id=cat.id).count()
    force = request.args.get("force", "false").lower() in ("1", "true", "yes")

    if related_count > 0 and not force:
        return jsonify({
            "msg": "Bu kategoride ürün(ler) mevcut. Kategori silinemez.",
            "category_id": cat.id,
            "products_count": related_count,
            "hint": "Eğer tüm ürünlerin kategorisini kaldırmak istiyorsan ?force=true ekleyerek talep gönder."
        }), 400

    if related_count > 0 and force:
        Product.query.filter_by(category_id=cat.id).update({"category_id": None})
        db.session.commit()

    db.session.delete(cat)
    db.session.commit()
    return jsonify({"msg": "Kategori silindi", "category_id": category_id})

# --- Product management ---
@app.route("/admin/products", methods=["POST"])
@admin_required
def create_product():
    if request.is_json:
        data = request.get_json()
        title = data.get("title")
        price_str = data.get("price")
        stock_in = data.get("stock", "0")   # expecting string
        description = data.get("description", "")
        category_id = data.get("category_id")
        image_base64 = data.get("image_base64")
        image_mime = data.get("image_mime")
        discount_percent_str = data.get("discount_percent", "0")
    else:
        title = request.form.get("title")
        price_str = request.form.get("price")
        stock_in = request.form.get("stock", "0")
        description = request.form.get("description", "")
        category_id = request.form.get("category_id")
        image_base64 = None
        image_mime = None
        discount_percent_str = request.form.get("discount_percent", "0")
        if "image" in request.files:
            file = request.files["image"]
            image_base64, image_mime = _file_storage_to_base64(file)

    if not title or price_str is None:
        return jsonify({"msg": "title ve price gerekli"}), 400

    if not _is_numeric_string(price_str):
        return jsonify({"msg": "price numeric string formatında olmalı (örn. '4999' veya '4999.00')"}), 400
    if discount_percent_str is None:
        discount_percent_str = "0"
    if not _is_numeric_string(discount_percent_str):
        return jsonify({"msg": "discount_percent numeric string formatında olmalı (örn. '5' veya '5.0')"}), 400

    try:
        stock_val = _parse_stock_value(stock_in)
    except ValueError as e:
        return jsonify({"msg": str(e)}), 400

    p = Product(
        title=title,
        price=str(price_str),
        stock=stock_val,
        description=description,
        discount_percent=str(discount_percent_str)
    )
    if category_id:
        try:
            p.category_id = int(category_id)
        except Exception:
            pass
    if image_base64:
        p.image_base64 = image_base64
        p.image_mime = image_mime
    db.session.add(p)
    db.session.commit()

    # If initial discount > 0, notify users (FCM only)
    try:
        if float(p.discount_percent.replace(",", ".")) > 0:
            current = get_jwt_identity()
            notify_users_about_discount(p, triggered_by_admin_username=current)
    except Exception:
        pass

    return jsonify({"msg": "Ürün oluşturuldu", "product_id": p.id})

@app.route("/admin/products/<int:product_id>", methods=["PUT"])
@admin_required
def update_product(product_id):
    p = Product.query.get_or_404(product_id)
    old_discount = str(p.discount_percent)

    if request.is_json:
        data = request.get_json()
        if "title" in data: p.title = data.get("title")
        if "price" in data:
            price_str = data.get("price")
            if price_str is not None:
                if not _is_numeric_string(price_str):
                    return jsonify({"msg": "price numeric string formatında olmalı"}), 400
                p.price = str(price_str)
        if "stock" in data:
            try:
                p.stock = _parse_stock_value(data.get("stock"))
            except ValueError as e:
                return jsonify({"msg": str(e)}), 400
        if "description" in data: p.description = data.get("description")
        if "category_id" in data:
            try: p.category_id = int(data.get("category_id"))
            except: pass
        if "discount_percent" in data:
            dp = data.get("discount_percent")
            if dp is not None:
                if not _is_numeric_string(dp):
                    return jsonify({"msg": "discount_percent numeric string formatında olmalı"}), 400
                p.discount_percent = str(dp)
        if "image_base64" in data:
            p.image_base64 = data.get("image_base64")
            p.image_mime = data.get("image_mime")
    else:
        data = request.form or {}
        if "title" in data: p.title = data["title"]
        if "price" in data:
            price_str = data["price"]
            if not _is_numeric_string(price_str):
                return jsonify({"msg": "price numeric string formatında olmalı"}), 400
            p.price = str(price_str)
        if "stock" in data:
            try:
                p.stock = _parse_stock_value(data["stock"])
            except ValueError as e:
                return jsonify({"msg": str(e)}), 400
        if "description" in data: p.description = data["description"]
        if "category_id" in data:
            try: p.category_id = int(data["category_id"])
            except: pass
        if "discount_percent" in data:
            dp = data["discount_percent"]
            if not _is_numeric_string(dp):
                return jsonify({"msg": "discount_percent numeric string formatında olmalı"}), 400
            p.discount_percent = str(dp)
        if "image" in request.files:
            file = request.files["image"]
            b64, mime = _file_storage_to_base64(file)
            p.image_base64 = b64
            p.image_mime = mime

    db.session.commit()

    # If discount changed and >0, notify users (FCM only)
    try:
        if old_discount != str(p.discount_percent):
            if float(str(p.discount_percent).replace(",", ".")) > 0:
                current = get_jwt_identity()
                notify_users_about_discount(p, triggered_by_admin_username=current)
    except Exception:
        pass

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
    dp = data.get("discount_percent")
    if dp is None or not _is_numeric_string(dp):
        return jsonify({"msg": "discount_percent numeric string formatında olmalı"}), 400
    p.discount_percent = str(dp)
    db.session.commit()

    # Notify users about discount (FCM only)
    current = get_jwt_identity()
    notify_result = notify_users_about_discount(p, triggered_by_admin_username=current)
    return jsonify({"msg": "İndirim uygulandı", "discount_percent": p.discount_percent, "notify_result": notify_result})

# --- Search / List products ---
@app.route("/products", methods=["GET"])
def list_products():
    q_text = request.args.get("q", type=str)
    category_name = request.args.get("category", type=str)
    category_id = request.args.get("category_id", type=int)
    min_price = request.args.get("min_price", type=str)
    max_price = request.args.get("max_price", type=str)
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

    if min_price is not None and _is_numeric_string(min_price):
        q = q.filter(cast(Product.price, Float) >= float(min_price.replace(",", ".")))
    if max_price is not None and _is_numeric_string(max_price):
        q = q.filter(cast(Product.price, Float) <= float(max_price.replace(",", ".")))

    if sort_by == "price_asc":
        q = q.order_by(cast(Product.price, Float).asc())
    elif sort_by == "price_desc":
        q = q.order_by(cast(Product.price, Float).desc())
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
            "price": str(p.price),
            "price_after_discount": p.price_after_discount,
            "stock": str(p.stock),          # RETURN AS STRING
            "image_base64": p.image_base64,
            "image_mime": p.image_mime,
            "category": p.category.name if p.category else None,
            "discount_percent": str(p.discount_percent)
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
            "product": {
                "id": it.product.id,
                "title": it.product.title,
                "price": str(it.product.price),
                "price_after_discount": it.product.price_after_discount,
                "stock": str(it.product.stock),   # RETURN AS STRING
                "image_base64": it.product.image_base64,
                "image_mime": it.product.image_mime
            },
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
    try:
        qty = int(data["quantity"])
    except Exception:
        return jsonify({"msg": "quantity integer olmalı"}), 400
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

# --- NEW: Update cart item quantity (PATCH + PUT supported) ---
@app.route("/cart/<int:cart_item_id>", methods=["PATCH", "PUT"])
@jwt_required()
def update_cart_item(cart_item_id):
    data = request.json or {}
    if "quantity" not in data:
        return jsonify({"msg": "quantity gerekli"}), 400

    # parse quantity (int)
    try:
        qty = int(data["quantity"])
    except Exception:
        return jsonify({"msg": "quantity integer olmalı"}), 400

    if qty < 0:
        return jsonify({"msg": "quantity negatif olamaz"}), 400

    current = get_jwt_identity()
    user = User.query.filter_by(username=current).first_or_404()

    item = CartItem.query.get_or_404(cart_item_id)

    # sadece öğeyi ekleyen kullanıcı değiştirebilir
    if item.user_id != user.id:
        return jsonify({"msg": "Bu sepet öğesini değiştirme yetkiniz yok"}), 403

    # qty == 0 ise öğeyi sil
    if qty == 0:
        db.session.delete(item)
        db.session.commit()
        return jsonify({"msg": "Sepet öğesi silindi", "cart_item_id": cart_item_id})

    # stok kontrolü
    product = item.product
    if product.stock < qty:
        return jsonify({"msg": "Yeterli stok yok", "available_stock": str(product.stock)}), 400

    # güncelle
    item.quantity = qty
    db.session.commit()

    out = {
        "id": item.id,
        "product": {
            "id": product.id,
            "title": product.title,
            "price": str(product.price),
            "price_after_discount": product.price_after_discount,
            "stock": str(product.stock),
            "image_base64": product.image_base64,
            "image_mime": product.image_mime
        },
        "quantity": item.quantity
    }
    return jsonify({"msg": "Sepet güncellendi", "cart_item": out})

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
        try:
            unit = float(it.product.price_after_discount.replace(",", "."))
        except Exception:
            unit = 0.0
        total += unit * it.quantity

    total_rounded = round(total, 2)
    order = Order(user_id=user.id, total_amount=f"{total_rounded:.2f}", payment_method=payment_method)
    db.session.add(order)
    db.session.commit()
    for it in items:
        unit_price_str = it.product.price_after_discount
        oi = OrderItem(order_id=order.id, product_id=it.product.id, quantity=it.quantity, unit_price=str(unit_price_str))
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
    return jsonify({"msg": "Sipariş oluştu", "order_id": order.id, "payment_method": order.payment_method, "total_amount": order.total_amount})

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
            "total_amount": str(o.total_amount),
            "status": o.status,
            "payment_method": o.payment_method,
            "created_at": o.created_at.isoformat(),
            "items": [{"product_id": it.product_id, "title": it.product.title, "quantity": it.quantity, "unit_price": str(it.unit_price)} for it in o.items]
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
    total_income_val = 0.0
    for o in Order.query.all():
        try:
            total_income_val += float(str(o.total_amount).replace(",", "."))
        except Exception:
            pass
    total_income_str = f"{round(total_income_val,2):.2f}"
    return jsonify({
        "total_products": total_products,
        "total_orders": total_orders,
        "total_users": total_users,
        "total_income": total_income_str
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
        "created_at": user.created_at.isoformat(),
        "device_tokens": [dt.token for dt in user.device_tokens]
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
