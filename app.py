# app.py
import os
import uuid
import base64
import json
import logging
import requests
import importlib.util
from functools import wraps
from datetime import datetime, timedelta

from flask import Flask, request, jsonify, send_from_directory, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from sqlalchemy import or_, func, cast, Float, text

# Try optional DuckDB-related imports to give earlier warning if missing
DUCKDB_AVAILABLE = True
try:
    import duckdb  # noqa: F401
    import duckdb_engine  # noqa: F401
except Exception:
    DUCKDB_AVAILABLE = False

# ---------- Config ----------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
IMAGE_FOLDER = os.path.join(UPLOAD_FOLDER, "images")
os.makedirs(IMAGE_FOLDER, exist_ok=True)

app = Flask(__name__)

# ---------- Choose DuckDB as backend ----------
# We will use a file-based DuckDB database at BASE_DIR/app.duckdb.
DB_FILE = os.path.join(BASE_DIR, "app.duckdb")

# Minimum order amount configuration
MINIMUM_ORDER_AMOUNT = 300.0  # Default minimum order amount


def _make_duckdb_uri(path):
    # If absolute path -> use duckdb://// + stripped leading slash
    if os.path.isabs(path):
        return "duckdb:////" + path.lstrip("/")
    # relative -> duckdb:///relative/path
    return "duckdb:///" + path


app.config["SQLALCHEMY_DATABASE_URI"] = _make_duckdb_uri(DB_FILE)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY", "change-this-secret")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["IMAGE_FOLDER"] = IMAGE_FOLDER

db = SQLAlchemy(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)

# If duckdb packages weren't available, warn in logs (app exists now).
if not DUCKDB_AVAILABLE:
    if not os.path.exists("logs"):
        os.makedirs("logs", exist_ok=True)
    lh = logging.getLogger()
    lh.setLevel(logging.INFO)
    fh = logging.FileHandler("logs/app.log")
    fh.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s'))
    lh.addHandler(fh)
    lh.warning("duckdb veya duckdb-engine yüklü değil. Lütfen `pip install duckdb duckdb-engine` ile yükleyin. Uygulama yine de başlatılmaya çalışılacak ancak DB sürücüsü eksikse hata alınır.")

# ---------- Logging ----------
if not os.path.exists("logs"):
    os.makedirs("logs")
file_handler = logging.FileHandler("logs/app.log")
file_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s'))
file_handler.setLevel(logging.INFO)
app.logger.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.addHandler(logging.StreamHandler())


# ---------- Database Setup (DUCKDB Uyumlu) ----------
def setup_database():
    """
    DuckDB uyumlu tablo kurucusu.
    - DuckDB kullanılıyorsa SQLAlchemy'nin ürettiği SERIAL tip hatasını atlamak için
      elle CREATE SEQUENCE + CREATE TABLE IF NOT EXISTS (id INTEGER DEFAULT nextval(...)) kullanır.
    - Veriler kaybolsa sakınca yoksa, DB dosyasını silip sıfırdan başlatabilirsiniz.
    """
    try:
        with app.app_context():
            engine_uri = app.config.get("SQLALCHEMY_DATABASE_URI", "") or ""
            is_duckdb = engine_uri.startswith("duckdb:")
            conn = db.engine.connect()

            if is_duckdb:
                app.logger.info("DuckDB detected — elle tablolar/sequence'ler oluşturuluyor.")

                # Önce varsa tablo/sequence drop etmeye çalış (hata olursa devam)
                try:
                    conn.execute(text("DROP TABLE IF EXISTS order_item"))
                    conn.execute(text("DROP TABLE IF EXISTS \"order\""))
                    conn.execute(text("DROP TABLE IF EXISTS cart_item"))
                    conn.execute(text("DROP TABLE IF EXISTS product"))
                    conn.execute(text("DROP TABLE IF EXISTS category"))
                    conn.execute(text("DROP TABLE IF EXISTS device_token"))
                    conn.execute(text("DROP TABLE IF EXISTS announcement"))
                    conn.execute(text("DROP TABLE IF EXISTS app_config"))
                    conn.execute(text("DROP TABLE IF EXISTS \"user\""))
                except Exception as e:
                    app.logger.warning(f"drop table sırasında uyarı: {e}")

                # Drop sequences if exist (sessizce devam et)
                seqs = [
                    "seq_user", "seq_device_token", "seq_category", "seq_product",
                    "seq_cart_item", "seq_order", "seq_order_item", "seq_announcement", "seq_app_config"
                ]
                for s in seqs:
                    try:
                        conn.execute(text(f"DROP SEQUENCE IF EXISTS {s}"))
                    except Exception:
                        pass

                # Create sequences
                try:
                    conn.execute(text("CREATE SEQUENCE IF NOT EXISTS seq_user START 1"))
                    conn.execute(text("CREATE SEQUENCE IF NOT EXISTS seq_device_token START 1"))
                    conn.execute(text("CREATE SEQUENCE IF NOT EXISTS seq_category START 1"))
                    conn.execute(text("CREATE SEQUENCE IF NOT EXISTS seq_product START 1"))
                    conn.execute(text("CREATE SEQUENCE IF NOT EXISTS seq_cart_item START 1"))
                    conn.execute(text("CREATE SEQUENCE IF NOT EXISTS seq_order START 1"))
                    conn.execute(text("CREATE SEQUENCE IF NOT EXISTS seq_order_item START 1"))
                    conn.execute(text("CREATE SEQUENCE IF NOT EXISTS seq_announcement START 1"))
                    conn.execute(text("CREATE SEQUENCE IF NOT EXISTS seq_app_config START 1"))
                except Exception as e:
                    app.logger.warning(f"sequence oluşturma sırasında uyarı: {e}")

                # CREATE TABLEs (DuckDB uyumlu)
                conn.execute(text("""
                CREATE TABLE IF NOT EXISTS "user" (
                    id INTEGER PRIMARY KEY DEFAULT nextval('seq_user'),
                    username VARCHAR(80) NOT NULL UNIQUE,
                    password_hash VARCHAR(256) NOT NULL,
                    email VARCHAR(120) NOT NULL,
                    name VARCHAR(80),
                    surname VARCHAR(80),
                    phone VARCHAR(50),
                    address TEXT,
                    role VARCHAR(20),
                    fcm_server_key TEXT,
                    created_at TIMESTAMP
                )
                """))

                conn.execute(text("""
                CREATE TABLE IF NOT EXISTS device_token (
                    id INTEGER PRIMARY KEY DEFAULT nextval('seq_device_token'),
                    token VARCHAR(512) NOT NULL,
                    user_id INTEGER NOT NULL,
                    created_at TIMESTAMP,
                    FOREIGN KEY(user_id) REFERENCES "user"(id)
                )
                """))

                conn.execute(text("""
                CREATE TABLE IF NOT EXISTS category (
                    id INTEGER PRIMARY KEY DEFAULT nextval('seq_category'),
                    name VARCHAR(80) UNIQUE NOT NULL
                )
                """))

                conn.execute(text("""
                CREATE TABLE IF NOT EXISTS product (
                    id INTEGER PRIMARY KEY DEFAULT nextval('seq_product'),
                    title VARCHAR(200) NOT NULL,
                    description TEXT,
                    price VARCHAR(64) NOT NULL,
                    stock INTEGER DEFAULT 0,
                    image_filename VARCHAR(255),
                    category_id INTEGER,
                    discount_percent VARCHAR(64) DEFAULT '0',
                    created_at TIMESTAMP,
                    FOREIGN KEY(category_id) REFERENCES category(id)
                )
                """))

                conn.execute(text("""
                CREATE TABLE IF NOT EXISTS cart_item (
                    id INTEGER PRIMARY KEY DEFAULT nextval('seq_cart_item'),
                    user_id INTEGER NOT NULL,
                    product_id INTEGER NOT NULL,
                    quantity INTEGER DEFAULT 1,
                    created_at TIMESTAMP,
                    FOREIGN KEY(user_id) REFERENCES "user"(id),
                    FOREIGN KEY(product_id) REFERENCES product(id)
                )
                """))

                conn.execute(text("""
                CREATE TABLE IF NOT EXISTS "order" (
                    id INTEGER PRIMARY KEY DEFAULT nextval('seq_order'),
                    user_id INTEGER NOT NULL,
                    total_amount VARCHAR(64) NOT NULL,
                    status VARCHAR(50) DEFAULT 'new',
                    payment_method VARCHAR(50) DEFAULT 'kapida_nakit',
                    delivery_address TEXT,
                    note TEXT,
                    created_at TIMESTAMP,
                    updated_at TIMESTAMP,
                    FOREIGN KEY(user_id) REFERENCES "user"(id)
                )
                """))

                conn.execute(text("""
                CREATE TABLE IF NOT EXISTS order_item (
                    id INTEGER PRIMARY KEY DEFAULT nextval('seq_order_item'),
                    order_id INTEGER NOT NULL,
                    product_id INTEGER NOT NULL,
                    quantity INTEGER NOT NULL,
                    unit_price VARCHAR(64) NOT NULL,
                    FOREIGN KEY(order_id) REFERENCES "order"(id),
                    FOREIGN KEY(product_id) REFERENCES product(id)
                )
                """))

                conn.execute(text("""
                CREATE TABLE IF NOT EXISTS announcement (
                    id INTEGER PRIMARY KEY DEFAULT nextval('seq_announcement'),
                    title VARCHAR(200) NOT NULL,
                    body TEXT NOT NULL,
                    admin_id INTEGER NOT NULL,
                    created_at TIMESTAMP,
                    FOREIGN KEY(admin_id) REFERENCES "user"(id)
                )
                """))

                # App config table for minimum order amount
                conn.execute(text("""
                CREATE TABLE IF NOT EXISTS app_config (
                    id INTEGER PRIMARY KEY DEFAULT nextval('seq_app_config'),
                    config_key VARCHAR(100) UNIQUE NOT NULL,
                    config_value TEXT,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """))

                # Insert default minimum order amount
                try:
                    conn.execute(text("""
                    INSERT INTO app_config (config_key, config_value) 
                    VALUES ('minimum_order_amount', '300.0')
                    ON CONFLICT (config_key) DO NOTHING
                    """))
                except Exception as e:
                    app.logger.warning(f"Default config eklenirken hata: {e}")

                conn.commit()
                app.logger.info("DuckDB tabloları oluşturuldu/varsa korundu.")
            else:
                # fallback: normal SQLAlchemy create_all() (ör. sqlite)
                try:
                    db.drop_all()
                except Exception as e:
                    app.logger.warning(f"drop_all sırasında uyarı (non-duckdb): {e}")
                db.create_all()
                
                # Insert default minimum order amount for non-duckdb
                try:
                    config = AppConfig.query.filter_by(config_key='minimum_order_amount').first()
                    if not config:
                        default_config = AppConfig(config_key='minimum_order_amount', config_value='300.0')
                        db.session.add(default_config)
                        db.session.commit()
                except Exception as e:
                    app.logger.warning(f"Default config eklenirken hata (non-duckdb): {e}")
                
                app.logger.info("SQLAlchemy create_all() çalıştırıldı (non-duckdb).")

            conn.close()

    except Exception as e:
        app.logger.exception(f"Veritabanı kurulum hatası: {e}")


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
    fcm_server_key = db.Column(db.Text, nullable=True)  # legacy HTTP server key (optional)
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
    price = db.Column(db.String(64), nullable=False)  # string per requirement
    stock = db.Column(db.Integer, default=0)  # stored as int internally
    image_filename = db.Column(db.String(255), nullable=True)  # Resim dosya adı
    category_id = db.Column(db.Integer, db.ForeignKey("category.id"), nullable=True)
    discount_percent = db.Column(db.String(64), default="0")  # string percent
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    category = db.relationship("Category")

    def _price_float(self):
        try:
            return float(self.price.replace(",", ".")) if isinstance(self.price, str) else float(self.price)
        except Exception:
            return 0.0

    def _discount_float(self):
        try:
            return float(self.discount_percent.replace(",", ".")) if isinstance(self.discount_percent, str) else float(
                self.discount_percent)
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
        return f"{val:.2f}"

    @property
    def image_url(self):
        if self.image_filename:
            return url_for('get_image', filename=self.image_filename, _external=True)
        return None


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
    total_amount = db.Column(db.String(64), nullable=False)  # string
    status = db.Column(db.String(50), default="new")  # new, yolda, teslim_edildi, teslim_edilemedi
    payment_method = db.Column(db.String(50), default="kapida_nakit")
    delivery_address = db.Column(db.Text, nullable=True)  # Teslimat adresi
    note = db.Column(db.Text, nullable=True)  # Sipariş notu
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    items = db.relationship("OrderItem", backref="order", lazy=True)
    user = db.relationship("User", backref="orders")


class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey("order.id"), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey("product.id"), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    unit_price = db.Column(db.String(64), nullable=False)
    product = db.relationship("Product")


class Announcement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    body = db.Column(db.Text, nullable=False)
    admin_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    admin = db.relationship("User")


class AppConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    config_key = db.Column(db.String(100), unique=True, nullable=False)
    config_value = db.Column(db.Text, nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


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


def save_base64_image(base64_data, filename=None):
    """Base64 verisini dosyaya kaydeder ve dosya adını döndürür"""
    try:
        # Base64 başlığını kaldır (eğer varsa)
        if ',' in base64_data:
            base64_data = base64_data.split(',', 1)[1]
        
        # Base64 verisini decode et
        image_data = base64.b64decode(base64_data)
        
        # Dosya adını oluştur
        if not filename:
            file_ext = '.jpg'  # Varsayılan uzantı
            # MIME type'a göre uzantı belirle (opsiyonel)
            if base64_data.startswith('/9j') or base64_data.startswith('iV'):
                file_ext = '.jpg'
            elif base64_data.startswith('iVBOR'):
                file_ext = '.png'
            elif base64_data.startswith('R0lGOD'):
                file_ext = '.gif'
            filename = f"{uuid.uuid4().hex}{file_ext}"
        
        filepath = os.path.join(app.config['IMAGE_FOLDER'], filename)
        
        # Dosyayı kaydet
        with open(filepath, 'wb') as f:
            f.write(image_data)
        
        return filename
    except Exception as e:
        app.logger.error(f"Resim kaydetme hatası: {e}")
        return None


def save_uploaded_file(file_storage, filename=None):
    """Yüklenen dosyayı kaydeder ve dosya adını döndürür"""
    try:
        if not filename:
            # Orijinal dosya adından uzantıyı al
            original_name = file_storage.filename
            if original_name and '.' in original_name:
                file_ext = '.' + original_name.rsplit('.', 1)[1].lower()
            else:
                file_ext = '.jpg'  # Varsayılan uzantı
            
            filename = f"{uuid.uuid4().hex}{file_ext}"
        
        filepath = os.path.join(app.config['IMAGE_FOLDER'], filename)
        file_storage.save(filepath)
        return filename
    except Exception as e:
        app.logger.error(f"Dosya kaydetme hatası: {e}")
        return None


def _is_numeric_string(s):
    try:
        float(str(s).replace(",", "."))
        return True
    except Exception:
        return False


def _parse_stock_value(s):
    if s is None or s == "":
        return 0
    if isinstance(s, int):
        return s
    try:
        val = float(str(s).replace(",", "."))
        return int(val)
    except Exception:
        raise ValueError("stock integer formatında olmalı (örn. '10')")


def get_minimum_order_amount():
    """Get minimum order amount from database"""
    try:
        config = AppConfig.query.filter_by(config_key='minimum_order_amount').first()
        if config and config.config_value:
            return float(config.config_value)
        else:
            # Default value if not set
            return MINIMUM_ORDER_AMOUNT
    except Exception as e:
        app.logger.error(f"Minimum order amount alınırken hata: {e}")
        return MINIMUM_ORDER_AMOUNT


def set_minimum_order_amount(amount):
    """Set minimum order amount in database"""
    try:
        config = AppConfig.query.filter_by(config_key='minimum_order_amount').first()
        if config:
            config.config_value = str(amount)
        else:
            config = AppConfig(config_key='minimum_order_amount', config_value=str(amount))
            db.session.add(config)
        db.session.commit()
        return True
    except Exception as e:
        app.logger.error(f"Minimum order amount ayarlanırken hata: {e}")
        return False


# ---------- Firebase / FCM Setup ----------
SERVICE_ACCOUNT_PATH = "/root/perem-sa-new.json"  # as requested
firebase_app = None

if DUCKDB_AVAILABLE is None:
    DUCKDB_AVAILABLE = False

try:
    import firebase_admin
    from firebase_admin import credentials, messaging
    from firebase_admin.exceptions import FirebaseError

    FIREBASE_AVAILABLE = True
except Exception:
    FIREBASE_AVAILABLE = False

if FIREBASE_AVAILABLE:
    try:
        if os.path.exists(SERVICE_ACCOUNT_PATH):
            with open(SERVICE_ACCOUNT_PATH, "r", encoding="utf-8") as f:
                key_data = json.load(f)
            # fix newline escape if present
            if "private_key" in key_data and "\\n" in key_data["private_key"]:
                key_data["private_key"] = key_data["private_key"].replace("\\n", "\n")
            required = ["type", "project_id", "private_key_id", "private_key", "client_email"]
            missing = [r for r in required if r not in key_data]
            if missing:
                app.logger.error(f"Service account eksik alanlar: {missing} — Firebase devre dışı")
                firebase_app = None
            elif key_data.get("type") != "service_account":
                app.logger.error(f"Service account tipi beklenmiyor: {key_data.get('type')} — Firebase devre dışı")
                firebase_app = None
            else:
                cred = credentials.Certificate(key_data)
                firebase_app = firebase_admin.initialize_app(cred)
                app.logger.info("Firebase Admin SDK başarıyla başlatıldı.")
        else:
            app.logger.warning(f"Firebase service account bulunamadı: {SERVICE_ACCOUNT_PATH} — Firebase devre dışı")
            firebase_app = None
    except Exception as e:
        app.logger.exception(f"Firebase init hatası: {e}")
        firebase_app = None
else:
    app.logger.warning("firebase_admin yüklü değil — Firebase FCM devre dışı")


# helper chunk
def _chunks(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


def cleanup_invalid_fcm_token(token):
    try:
        dts = DeviceToken.query.filter_by(token=token).all()
        for dt in dts:
            db.session.delete(dt)
        db.session.commit()
        app.logger.info(f"Geçersiz token temizlendi: {token[:20]}...")
    except Exception as e:
        app.logger.exception(f"cleanup_invalid_fcm_token hata: {e}")


def send_fcm_via_firebase(tokens, title, body, data=None):
    if not firebase_app:
        return {"success": False, "error": "firebase_app yok"}
    if not tokens:
        return {"success": False, "error": "no tokens"}
    data = data or {}
    summary = {"total_tokens": len(tokens), "success_count": 0, "failure_count": 0, "responses": []}
    try:
        for batch in _chunks(tokens, 500):
            message = messaging.MulticastMessage(
                tokens=batch,
                notification=messaging.Notification(title=title, body=body),
                data={k: str(v) for k, v in (data or {}).items()},
                android=messaging.AndroidConfig(priority="high",
                                                notification=messaging.AndroidNotification(sound="default",
                                                                                           click_action="FLUTTER_NOTIFICATION_CLICK")),
                apns=messaging.APNSConfig(payload=messaging.APNSPayload(aps=messaging.Aps(sound="default", badge=1)))
            )
            resp = messaging.send_each_for_multicast(message)
            summary["success_count"] += resp.success_count
            summary["failure_count"] += resp.failure_count
            for i, r in enumerate(resp.responses):
                if r.success:
                    summary["responses"].append({"index": i, "message_id": r.message_id})
                else:
                    err = str(r.exception) if r.exception else "unknown"
                    summary["responses"].append({"index": i, "error": err})
                    s = err.lower()
                    if any(x in s for x in ["unregistered", "not-found", "notregistered", "invalid-argument"]):
                        try:
                            cleanup_invalid_fcm_token(batch[i])
                        except Exception:
                            pass
        return {"success": True, "summary": summary}
    except Exception as e:
        app.logger.exception(f"send_fcm_via_firebase hata: {e}")
        return {"success": False, "error": str(e)}


def send_fcm_legacy(server_key, tokens, title, body, data=None):
    if not server_key:
        return {"success": False, "error": "no server_key"}
    if not tokens:
        return {"success": False, "error": "no tokens"}
    url = "https://fcm.googleapis.com/fcm/send"
    headers = {"Authorization": "key=" + server_key, "Content-Type": "application/json"}
    payload = {"registration_ids": tokens, "notification": {"title": title, "body": body}, "data": data or {}}
    try:
        r = requests.post(url, json=payload, headers=headers, timeout=10)
        try:
            resp_json = r.json()
        except Exception:
            resp_json = r.text
        return {"success": True, "status_code": r.status_code, "response": resp_json}
    except Exception as e:
        app.logger.exception(f"send_fcm_legacy hata: {e}")
        return {"success": False, "error": str(e)}


def send_fcm_notification(tokens, title, body, data=None, fallback_server_keys=None):
    if not tokens:
        return {"success": False, "error": "no tokens provided"}

    app.logger.info(f"FCM gönderiliyor: {len(tokens)} token, başlık: {title}")

    # try firebase_admin first
    if firebase_app:
        res = send_fcm_via_firebase(tokens, title, body, data or {})
        if res.get("success"):
            app.logger.info(f"Firebase Admin ile gönderim başarılı: {res.get('summary', {})}")
            return res
        else:
            app.logger.warning(f"Firebase Admin ile gönderim başarısız: {res.get('error')}")

    # fallback with provided keys
    if fallback_server_keys:
        for sk in fallback_server_keys:
            if not sk:
                continue
            res = send_fcm_legacy(sk, tokens, title, body, data or {})
            if res.get("success"):
                app.logger.info(f"Legacy FCM ile gönderim başarılı: {res.get('status_code')}")
                return res

    # try global env key
    env_key = os.environ.get("GLOBAL_LEGACY_FCM_SERVER_KEY")
    if env_key:
        res = send_fcm_legacy(env_key, tokens, title, body, data or {})
        if res.get("success"):
            return res

    app.logger.error("Hiçbir FCM yöntemi çalışmadı")
    return {"success": False, "error": "No working FCM method available"}


def validate_fcm_token(fcm_token):
    if not fcm_token:
        app.logger.warning("validate_fcm_token: Token boş")
        return False

    # Firebase başlatılmamışsa basit bir format kontrolü yap
    if not firebase_app:
        app.logger.warning("validate_fcm_token: Firebase başlatılmamış, basit kontrol yapılıyor")
        # FCM token formatı: genellikle 2 nokta ile ayrılmış 2 kısım
        if ':' in fcm_token and len(fcm_token) > 50:
            return True
        else:
            app.logger.warning(f"validate_fcm_token: Token formatı uygun değil: {fcm_token[:50]}...")
            return False

    # Firebase başlatılmışsa dry-run ile test et
    try:
        msg = messaging.Message(
            token=fcm_token,
            data={"validation": "test"}
        )
        messaging.send(msg, dry_run=True)
        app.logger.info(f"validate_fcm_token: Token geçerli: {fcm_token[:20]}...")
        return True
    except FirebaseError as e:
        error_str = str(e).lower()
        app.logger.warning(f"validate_fcm_token FirebaseError: {error_str}")

        # Geçersiz token hataları
        if any(x in error_str for x in ["unregistered", "not-found", "notregistered", "invalid-argument", "invalid"]):
            app.logger.error(f"validate_fcm_token: Geçersiz token - {error_str}")
            return False
        else:
            # Diğer hatalarda (network vs.) token'ı kabul et
            app.logger.warning(f"validate_fcm_token: Diğer hata, token kabul ediliyor: {error_str}")
            return True
    except Exception as e:
        app.logger.exception(f"validate_fcm_token beklenmeyen hata: {e}")
        # Beklenmeyen hatalarda token'ı kabul et
        return True


def format_order_response(order):
    """Sipariş nesnesini JSON formatında döndür"""
    return {
        "id": order.id,
        "user_id": order.user_id,
        "user_name": f"{order.user.name} {order.user.surname}",
        "user_phone": order.user.phone,
        "user_email": order.user.email,
        "total_amount": str(order.total_amount),
        "status": order.status,
        "payment_method": order.payment_method,
        "delivery_address": order.delivery_address or order.user.address,
        "note": order.note,  # Sipariş notu eklendi
        "created_at": order.created_at.isoformat(),
        "updated_at": order.updated_at.isoformat() if order.updated_at else order.created_at.isoformat(),
        "items": [{
            "id": it.id,
            "product_id": it.product_id,
            "product_title": it.product.title,
            "product_image_url": it.product.image_url,
            "quantity": it.quantity,
            "unit_price": str(it.unit_price),
            "subtotal": f"{float(str(it.unit_price).replace(',', '.')) * it.quantity:.2f}"
        } for it in order.items]
    }


# ---------- Routes ----------
@app.route("/health")
def health():
    return jsonify({"status": "ok"})


# Resim sunan endpoint
@app.route("/images/<filename>")
def get_image(filename):
    """Resim dosyalarını sunar"""
    return send_from_directory(app.config["IMAGE_FOLDER"], filename)


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


# Device token registration
@app.route("/auth/device/register", methods=["POST"])
@jwt_required()
def register_device():
    data = request.json or {}
    if "token" not in data:
        return jsonify({"msg": "token gerekli"}), 400

    token = data["token"]
    app.logger.info(f"Device token kaydı için gelen token: {token[:50]}...")

    # Token validation'ı daha esnek hale getir
    if not token or len(token) < 10:
        return jsonify({"msg": "Token çok kısa veya boş"}), 400

    current = get_jwt_identity()
    user = User.query.filter_by(username=current).first()
    if not user:
        return jsonify({"msg": "Kullanıcı bulunamadı"}), 404

    # Aynı token zaten var mı kontrol et
    existing_token = DeviceToken.query.filter_by(token=token, user_id=user.id).first()
    if existing_token:
        return jsonify({"msg": "Token zaten kayıtlı"})

    # Token'ı kaydet
    dt = DeviceToken(token=token, user_id=user.id)
    db.session.add(dt)
    db.session.commit()

    app.logger.info(f"Device token başarıyla kaydedildi: {token[:50]}...")
    return jsonify({"msg": "Device token kaydedildi"})


# Categories
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


# Product management
@app.route("/admin/products", methods=["POST"])
@admin_required
def create_product():
    if request.is_json:
        data = request.get_json()
        title = data.get("title")
        price_str = data.get("price")
        stock_in = data.get("stock", "0")
        description = data.get("description", "")
        category_id = data.get("category_id")
        image_base64 = data.get("image_base64")
        discount_percent_str = data.get("discount_percent", "0")
    else:
        title = request.form.get("title")
        price_str = request.form.get("price")
        stock_in = request.form.get("stock", "0")
        description = request.form.get("description", "")
        category_id = request.form.get("category_id")
        image_base64 = None
        discount_percent_str = request.form.get("discount_percent", "0")
        if "image" in request.files:
            file = request.files["image"]
            image_base64 = file  # Burada artık base64 değil, dosya var

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

    # Resim işleme
    if image_base64:
        if request.is_json:
            # Base64 string olarak geldi
            filename = save_base64_image(image_base64)
            if filename:
                p.image_filename = filename
        else:
            # Dosya olarak geldi
            filename = save_uploaded_file(image_base64)
            if filename:
                p.image_filename = filename

    db.session.add(p)
    db.session.commit()

    # notify if discount > 0
    try:
        if float(p.discount_percent.replace(",", ".")) > 0:
            notify_result = notify_users_about_discount(p)
            app.logger.info(f"Discount notify result: {notify_result}")
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
        if "title" in data: 
            p.title = data.get("title")
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
        if "description" in data: 
            p.description = data.get("description")
        if "category_id" in data:
            try:
                p.category_id = int(data.get("category_id"))
            except:
                p.category_id = None
        if "discount_percent" in data:
            dp = data.get("discount_percent")
            if dp is not None:
                if not _is_numeric_string(dp):
                    return jsonify({"msg": "discount_percent numeric stringında olmalı"}), 400
                p.discount_percent = str(dp)
        
        # Resim güncelleme - artık zorunlu değil
        if "image_base64" in data:
            image_data = data.get("image_base64")
            if image_data is not None and image_data != "":
                # Yeni resim var, kaydet
                filename = save_base64_image(image_data)
                if filename:
                    # Eski resmi sil
                    if p.image_filename:
                        try:
                            old_path = os.path.join(app.config['IMAGE_FOLDER'], p.image_filename)
                            if os.path.exists(old_path):
                                os.remove(old_path)
                        except Exception as e:
                            app.logger.warning(f"Eski resim silinemedi: {e}")
                    p.image_filename = filename
            else:
                # Boş string veya null geldiyse, resmi kaldır
                if p.image_filename:
                    try:
                        old_path = os.path.join(app.config['IMAGE_FOLDER'], p.image_filename)
                        if os.path.exists(old_path):
                            os.remove(old_path)
                    except Exception as e:
                        app.logger.warning(f"Eski resim silinemedi: {e}")
                p.image_filename = None

    else:
        data = request.form or {}
        if "title" in data: 
            p.title = data["title"]
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
        if "description" in data: 
            p.description = data["description"]
        if "category_id" in data:
            try:
                p.category_id = int(data["category_id"])
            except:
                p.category_id = None
        if "discount_percent" in data:
            dp = data["discount_percent"]
            if not _is_numeric_string(dp):
                return jsonify({"msg": "discount_percent numeric stringında olmalı"}), 400
            p.discount_percent = str(dp)
        
        # Resim güncelleme - artık zorunlu değil
        if "image" in request.files:
            file = request.files["image"]
            if file and file.filename:  # Dosya var ve boş değilse
                filename = save_uploaded_file(file)
                if filename:
                    # Eski resmi sil
                    if p.image_filename:
                        try:
                            old_path = os.path.join(app.config['IMAGE_FOLDER'], p.image_filename)
                            if os.path.exists(old_path):
                                os.remove(old_path)
                        except Exception as e:
                            app.logger.warning(f"Eski resim silinemedi: {e}")
                    p.image_filename = filename

    db.session.commit()

    # If discount changed and >0, notify users
    try:
        if old_discount != str(p.discount_percent):
            if float(str(p.discount_percent).replace(",", ".")) > 0:
                notify_result = notify_users_about_discount(p)
                app.logger.info(f"Discount notify result: {notify_result}")
    except Exception:
        pass

    return jsonify({"msg": "Ürün güncellendi"})


@app.route("/admin/products/<int:product_id>", methods=["DELETE"])
@admin_required
def delete_product(product_id):
    p = Product.query.get_or_404(product_id)
    # Resmi de sil
    if p.image_filename:
        try:
            image_path = os.path.join(app.config['IMAGE_FOLDER'], p.image_filename)
            if os.path.exists(image_path):
                os.remove(image_path)
        except Exception as e:
            app.logger.warning(f"Resim dosyası silinemedi: {e}")
    
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
        return jsonify({"msg": "discount_percent numeric stringında olmalı"}), 400
    p.discount_percent = str(dp)
    db.session.commit()

    notify_result = notify_users_about_discount(p)
    return jsonify({"msg": "İndirim uygulandı", "discount_percent": p.discount_percent, "notify_result": notify_result})


# Products listing/search
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
            "stock": str(p.stock),
            "image_url": p.image_url,
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


# Cart operations
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
                "stock": str(it.product.stock),
                "image_url": it.product.image_url,
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


# Update cart item quantity (PATCH & PUT)
@app.route("/cart/<int:cart_item_id>", methods=["PATCH", "PUT"])
@jwt_required()
def update_cart_item(cart_item_id):
    data = request.json or {}
    if "quantity" not in data:
        return jsonify({"msg": "quantity gerekli"}), 400

    try:
        qty = int(data["quantity"])
    except Exception:
        return jsonify({"msg": "quantity integer olmalı"}), 400

    if qty < 0:
        return jsonify({"msg": "quantity negatif olamaz"}), 400

    current = get_jwt_identity()
    user = User.query.filter_by(username=current).first_or_404()
    item = CartItem.query.get_or_404(cart_item_id)

    if item.user_id != user.id:
        return jsonify({"msg": "Bu sepet öğesini değiştirme yetkiniz yok"}), 403

    if qty == 0:
        db.session.delete(item)
        db.session.commit()
        return jsonify({"msg": "Sepet öğesi silindi", "cart_item_id": cart_item_id})

    product = item.product
    if product.stock < qty:
        return jsonify({"msg": "Yeterli stok yok", "available_stock": str(product.stock)}), 400

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
            "image_url": product.image_url,
        },
        "quantity": item.quantity
    }
    return jsonify({"msg": "Sepet güncellendi", "cart_item": out})


# Checkout
@app.route("/cart/checkout", methods=["POST"])
@jwt_required()
def checkout():
    data = request.json or {}
    payment_method = data.get("payment_method", "kapida_nakit")
    delivery_address = data.get("delivery_address")  # Özel teslimat adresi
    note = data.get("note", "")  # Sipariş notu

    if payment_method in ("card_on_delivery", "kapida_kart"):
        payment_method = "kapida_kart"
    else:
        payment_method = "kapida_nakit"

    current = get_jwt_identity()
    user = User.query.filter_by(username=current).first()
    items = CartItem.query.filter_by(user_id=user.id).all()
    if not items:
        return jsonify({"msg": "Sepet boş"}), 400

    # Stok kontrolü
    for it in items:
        if it.product.stock < it.quantity:
            return jsonify({"msg": f"{it.product.title} için yeterli stok yok"}), 400

    # Toplam tutarı hesapla
    total = 0.0
    for it in items:
        try:
            unit = float(it.product.price_after_discount.replace(",", "."))
        except Exception:
            unit = 0.0
        total += unit * it.quantity

    total_rounded = round(total, 2)

    # Minimum sipariş tutarı kontrolü
    minimum_order_amount = get_minimum_order_amount()
    if total_rounded < minimum_order_amount:
        return jsonify({
            "msg": f"Minimum sipariş tutarı {minimum_order_amount} TL'dir. Sipariş tutarınız: {total_rounded} TL"
        }), 400

    # Teslimat adresini belirle (gönderilmişse özel adresi kullan, yoksa kullanıcı adresini)
    final_address = delivery_address if delivery_address else user.address

    # Sipariş oluştur
    order = Order(
        user_id=user.id,
        total_amount=f"{total_rounded:.2f}",
        payment_method=payment_method,
        delivery_address=final_address,
        note=note  # Sipariş notu eklendi
    )
    db.session.add(order)
    db.session.commit()

    # Sipariş öğelerini oluştur ve stokları güncelle
    for it in items:
        unit_price_str = it.product.price_after_discount
        oi = OrderItem(order_id=order.id, product_id=it.product.id, quantity=it.quantity,
                       unit_price=str(unit_price_str))
        db.session.add(oi)
        it.product.stock -= it.quantity
        db.session.delete(it)
    db.session.commit()

    # Admin'lere bildirim gönder
    admins = User.query.filter_by(role="admin").all()
    admin_tokens = [dt.token for a in admins for dt in a.device_tokens]
    admin_keys = [a.fcm_server_key for a in admins if a.fcm_server_key]

    app.logger.info(f"Sipariş #{order.id} oluşturuldu. Admin bildirim gönderiliyor...")

    if admin_tokens:
        title = "Yeni Sipariş"
        body = f"#{order.id} numaralı sipariş oluşturuldu. Tutar: {order.total_amount} TL. Ödeme: {order.payment_method}"

        order_data = {
            "order_id": str(order.id),
            "total_amount": order.total_amount,
            "payment_method": order.payment_method,
            "user_name": f"{user.name} {user.surname}",
            "type": "new_order"
        }

        notify_result = send_fcm_notification(
            admin_tokens,
            title,
            body,
            data=order_data,
            fallback_server_keys=admin_keys
        )
        app.logger.info(f"Admin bildirim sonucu: {notify_result}")
    else:
        app.logger.warning("Admin token bulunamadığı için bildirim gönderilmedi")

    return jsonify({
        "msg": "Sipariş oluştu",
        "order_id": order.id,
        "payment_method": order.payment_method,
        "total_amount": order.total_amount,
        "delivery_address": final_address,
        "note": note
    })


# ========== MINIMUM ORDER AMOUNT ENDPOINTS ==========
@app.route("/admin/minimum_order_amount", methods=["GET"])
@admin_required
def get_minimum_order_amount_api():
    """Admin için minimum sipariş tutarını getirir"""
    amount = get_minimum_order_amount()
    return jsonify({"minimum_order_amount": amount})


@app.route("/admin/minimum_order_amount", methods=["POST"])
@admin_required
def set_minimum_order_amount_api():
    """Admin için minimum sipariş tutarını ayarlar"""
    data = request.json or {}
    if "amount" not in data:
        return jsonify({"msg": "amount gerekli"}), 400
    
    try:
        amount = float(data["amount"])
        if amount < 0:
            return jsonify({"msg": "Minimum sipariş tutarı negatif olamaz"}), 400
    except (ValueError, TypeError):
        return jsonify({"msg": "Geçerli bir sayısal değer giriniz"}), 400

    success = set_minimum_order_amount(amount)
    if success:
        return jsonify({
            "msg": "Minimum sipariş tutarı güncellendi", 
            "minimum_order_amount": amount
        })
    else:
        return jsonify({"msg": "Minimum sipariş tutarı güncellenemedi"}), 500


@app.route("/minimum_order_amount", methods=["GET"])
def get_minimum_order_amount_public():
    """Herkes için minimum sipariş tutarını getirir (genel bilgi)"""
    amount = get_minimum_order_amount()
    return jsonify({"minimum_order_amount": amount})


# ========== YENİ: KULLANICI SİPARİŞLERİ ==========
@app.route("/orders/my", methods=["GET"])
@jwt_required()
def get_my_orders():
    """Kullanıcın kendi siparişlerini listeler"""
    current = get_jwt_identity()
    user = User.query.filter_by(username=current).first_or_404()

    # Filtreleme parametreleri
    status = request.args.get("status")  # new, yolda, teslim_edildi, teslim_edilemedi
    page = request.args.get("page", default=1, type=int)
    per_page = request.args.get("per_page", default=20, type=int)

    if per_page > 100:
        per_page = 100

    # Sorgu oluştur
    query = Order.query.filter_by(user_id=user.id)

    if status:
        query = query.filter_by(status=status)

    query = query.order_by(Order.created_at.desc())

    # Sayfalama
    total = query.count()
    total_pages = (total + per_page - 1) // per_page if per_page else 1
    orders = query.offset((page - 1) * per_page).limit(per_page).all()

    return jsonify({
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": total_pages,
        "orders": [format_order_response(o) for o in orders]
    })


@app.route("/orders/my/<int:order_id>", methods=["GET"])
@jwt_required()
def get_my_order_detail(order_id):
    """Kullanıcın belirli bir siparişinin detayını getirir"""
    current = get_jwt_identity()
    user = User.query.filter_by(username=current).first_or_404()

    order = Order.query.get_or_404(order_id)

    # Kullanıcı sadece kendi siparişlerini görebilir
    if order.user_id != user.id:
        return jsonify({"msg": "Bu siparişi görüntüleme yetkiniz yok"}), 403

    return jsonify(format_order_response(order))


# ========== YENİ: SİPARİŞ DURUM GÜNCELLEMESİ (TOKENSIZ) ==========
@app.route("/admin/orders/<int:order_id>/status", methods=["PATCH", "PUT"])
def update_order_status(order_id):
    """Bu endpoint artık **tokensız** — siparişin durumunu günceller (new -> yolda -> teslim_edildi/teslim_edilemedi)"""
    data = request.json or {}

    if "status" not in data:
        return jsonify({"msg": "status gerekli"}), 400

    new_status = data["status"]
    valid_statuses = ["new", "yolda", "teslim_edildi", "teslim_edilemedi"]

    if new_status not in valid_statuses:
        return jsonify({
            "msg": f"Geçersiz status. Geçerli değerler: {', '.join(valid_statuses)}"
        }), 400

    order = Order.query.get_or_404(order_id)
    old_status = order.status
    order.status = new_status
    order.updated_at = datetime.utcnow()
    db.session.commit()

    # Kullanıcıya bildirim gönder
    user = order.user
    user_tokens = [dt.token for dt in user.device_tokens]

    if user_tokens:
        status_messages = {
            "yolda": "Siparişiniz yola çıktı",
            "teslim_edildi": "Siparişiniz teslim edildi",
            "teslim_edilemedi": "Siparişiniz teslim edilemedi"
        }

        if new_status in status_messages:
            title = status_messages[new_status]
            body = f"#{order.id} numaralı siparişiniz {new_status} durumuna geçti."

            order_data = {
                "order_id": str(order.id),
                "status": new_status,
                "type": "order_status_update"
            }

            admin_keys = [a.fcm_server_key for a in User.query.filter_by(role="admin").all() if a.fcm_server_key]

            notify_result = send_fcm_notification(
                user_tokens,
                title,
                body,
                data=order_data,
                fallback_server_keys=admin_keys
            )
            app.logger.info(f"Sipariş #{order_id} durum bildirimi gönderildi: {notify_result}")

    app.logger.info(f"Sipariş #{order_id} durumu güncellendi: {old_status} -> {new_status}")

    return jsonify({
        "msg": "Sipariş durumu güncellendi",
        "order": format_order_response(order)
    })


# ========== HARICI API İÇİN SİPARİŞ DURUM GÜNCELLEMESİ ==========
@app.route("/api/orders/<int:order_id>/status", methods=["PATCH", "PUT"])
def external_update_order_status(order_id):
    """
    Harici API'den sipariş durumu güncellemesi için endpoint
    Basit API key authentication kullanır
    """
    # API key kontrolü
    api_key = request.headers.get("X-API-Key") or request.args.get("api_key")
    expected_key = os.environ.get("EXTERNAL_API_KEY", "your-secret-api-key-here")

    if not api_key or api_key != expected_key:
        return jsonify({"msg": "Geçersiz veya eksik API key"}), 401

    data = request.json or {}

    if "status" not in data:
        return jsonify({"msg": "status gerekli"}), 400

    new_status = data["status"]
    valid_statuses = ["new", "yolda", "teslim_edildi", "teslim_edilemedi"]

    if new_status not in valid_statuses:
        return jsonify({
            "msg": f"Geçersiz status. Geçerli değerler: {', '.join(valid_statuses)}"
        }), 400

    order = Order.query.get_or_404(order_id)
    old_status = order.status
    order.status = new_status
    order.updated_at = datetime.utcnow()
    db.session.commit()

    # Kullanıcıya bildirim gönder
    user = order.user
    user_tokens = [dt.token for dt in user.device_tokens]

    # Admin'e de bildirim gönderelim
    admins = User.query.filter_by(role="admin").all()
    admin_tokens = [dt.token for a in admins for dt in a.device_tokens]
    admin_keys = [a.fcm_server_key for a in admins if a.fcm_server_key]

    if user_tokens:
        status_messages = {
            "yolda": "Siparişiniz yola çıktı",
            "teslim_edildi": "Siparişiniz teslim edildi",
            "teslim_edilemedi": "Siparişiniz teslim edilemedi"
        }

        if new_status in status_messages:
            title = status_messages[new_status]
            body = f"#{order.id} numaralı siparişiniz {new_status} durumuna geçti."

            order_data = {
                "order_id": str(order.id),
                "status": new_status,
                "type": "order_status_update"
            }

            notify_result = send_fcm_notification(
                user_tokens,
                title,
                body,
                data=order_data,
                fallback_server_keys=admin_keys
            )
            app.logger.info(f"[EXTERNAL API] Sipariş #{order_id} durum bildirimi gönderildi: {notify_result}")

    # Admin'lere bilgi bildirimi
    if admin_tokens and new_status in ["teslim_edildi", "teslim_edilemedi"]:
        admin_title = f"Sipariş #{order.id} - {new_status.replace('_', ' ').title()}"
        admin_body = f"{user.name} {user.surname}'in siparişi {new_status} olarak işaretlendi."

        send_fcm_notification(
            admin_tokens,
            admin_title,
            admin_body,
            data={"order_id": str(order.id), "status": new_status, "type": "order_status_update"},
            fallback_server_keys=admin_keys
        )

    app.logger.info(f"[EXTERNAL API] Sipariş #{order_id} durumu güncellendi: {old_status} -> {new_status}")

    return jsonify({
        "success": True,
        "msg": "Sipariş durumu güncellendi",
        "order": format_order_response(order)
    })


# Admin orders (Mevcut + Geliştirilmiş)
@app.route("/admin/orders", methods=["GET"])
@admin_required
def admin_orders():
    """Admin tüm siparişleri listeler"""
    status = request.args.get("status")  # Filtreleme için
    page = request.args.get("page", default=1, type=int)
    per_page = request.args.get("per_page", default=50, type=int)

    if per_page > 100:
        per_page = 100

    query = Order.query

    if status:
        query = query.filter_by(status=status)

    query = query.order_by(Order.created_at.desc())

    total = query.count()
    total_pages = (total + per_page - 1) // per_page if per_page else 1
    orders = query.offset((page - 1) * per_page).limit(per_page).all()

    return jsonify({
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": total_pages,
        "orders": [format_order_response(o) for o in orders]
    })


@app.route("/admin/orders/<int:order_id>", methods=["GET"])
@admin_required
def admin_order_detail(order_id):
    """Admin belirli bir siparişin detayını görüntüler"""
    order = Order.query.get_or_404(order_id)
    return jsonify(format_order_response(order))


# ========== YENİ: DUYURULAR İÇİN GELİŞTİRİLMİŞ ENDPOINT'LER ==========
@app.route("/announcements", methods=["GET"])
@jwt_required()
def get_announcements():
    """Hem admin hem de kullanıcılar için duyuruları listeler"""
    page = request.args.get("page", default=1, type=int)
    per_page = request.args.get("per_page", default=20, type=int)

    announcements = Announcement.query.order_by(Announcement.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    out = []
    for ann in announcements.items:
        out.append({
            "id": ann.id,
            "title": ann.title,
            "body": ann.body,
            "admin_name": f"{ann.admin.name} {ann.admin.surname}",
            "created_at": ann.created_at.isoformat()
        })

    return jsonify({
        "announcements": out,
        "total": announcements.total,
        "page": page,
        "per_page": per_page,
        "total_pages": announcements.pages
    })


@app.route("/announcements/<int:announcement_id>", methods=["GET"])
@jwt_required()
def get_announcement(announcement_id):
    """Belirli bir duyurunun detayını getirir"""
    announcement = Announcement.query.get_or_404(announcement_id)

    return jsonify({
        "id": announcement.id,
        "title": announcement.title,
        "body": announcement.body,
        "admin_name": f"{announcement.admin.name} {announcement.admin.surname}",
        "admin_email": announcement.admin.email,
        "created_at": announcement.created_at.isoformat()
    })


@app.route("/admin/announcements/<int:announcement_id>", methods=["DELETE"])
@admin_required
def delete_announcement(announcement_id):
    """Admin duyuru silme"""
    announcement = Announcement.query.get_or_404(announcement_id)

    # Mevcut kullanıcının admin olduğunu kontrol et (zaten admin_required decorator var)
    current = get_jwt_identity()
    admin = User.query.filter_by(username=current).first()

    # Duyuruyu sil
    db.session.delete(announcement)
    db.session.commit()

    app.logger.info(f"Admin #{admin.id} duyuru #{announcement_id} sildi")

    return jsonify({
        "msg": "Duyuru silindi",
        "announcement_id": announcement_id
    })


@app.route("/admin/announcements", methods=["GET"])
@admin_required
def admin_get_announcements():
    """Admin için duyuruları listeler (tüm duyurular)"""
    page = request.args.get("page", default=1, type=int)
    per_page = request.args.get("per_page", default=50, type=int)

    announcements = Announcement.query.order_by(Announcement.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    out = []
    for ann in announcements.items:
        out.append({
            "id": ann.id,
            "title": ann.title,
            "body": ann.body,
            "admin_id": ann.admin_id,
            "admin_name": f"{ann.admin.name} {ann.admin.surname}",
            "admin_email": ann.admin.email,
            "created_at": ann.created_at.isoformat()
        })

    return jsonify({
        "announcements": out,
        "total": announcements.total,
        "page": page,
        "per_page": per_page,
        "total_pages": announcements.pages
    })


# Admin announce
@app.route("/admin/announce", methods=["POST"])
@admin_required
def admin_announce():
    data = request.json or {}
    if "title" not in data or "body" not in data:
        return jsonify({"msg": "title ve body gerekli"}), 400

    current = get_jwt_identity()
    admin = User.query.filter_by(username=current).first()

    # Duyuruyu veritabanına kaydet
    announcement = Announcement(
        title=data["title"],
        body=data["body"],
        admin_id=admin.id
    )
    db.session.add(announcement)
    db.session.commit()

    # Hangi token'lara gönderilecek
    if "tokens" in data and isinstance(data["tokens"], list) and data["tokens"]:
        tokens = data["tokens"]
        app.logger.info(f"Manuel token listesi ile duyuru: {len(tokens)} token")
    else:
        # Tüm kullanıcılara gönder
        users = User.query.filter_by(role="user").all()
        tokens = [dt.token for u in users for dt in u.device_tokens]
        app.logger.info(f"Tüm kullanıcılara duyuru: {len(users)} kullanıcı, {len(tokens)} token")

    admin_keys = [a.fcm_server_key for a in User.query.filter_by(role="admin").all() if a.fcm_server_key]
    server_keys = admin_keys if admin_keys else None

    app.logger.info(f"Duyuru gönderiliyor: {data['title']} - {len(tokens)} token")

    res = send_fcm_notification(
        tokens,
        data["title"],
        data["body"],
        data.get("data"),
        fallback_server_keys=server_keys
    )

    # Yanıta duyuru ID'sini de ekle
    res["announcement_id"] = announcement.id

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
    total_announcements = Announcement.query.count()

    # Durum bazlı sipariş sayıları
    orders_new = Order.query.filter_by(status="new").count()
    orders_yolda = Order.query.filter_by(status="yolda").count()
    orders_teslim_edildi = Order.query.filter_by(status="teslim_edildi").count()
    orders_teslim_edilemedi = Order.query.filter_by(status="teslim_edilemedi").count()

    total_income_val = 0.0
    for o in Order.query.filter_by(status="teslim_edildi").all():
        try:
            total_income_val += float(str(o.total_amount).replace(",", "."))
        except Exception:
            pass
    total_income_str = f"{round(total_income_val, 2):.2f}"

    # Minimum sipariş tutarı
    minimum_order_amount = get_minimum_order_amount()

    return jsonify({
        "total_products": total_products,
        "total_orders": total_orders,
        "total_users": total_users,
        "total_announcements": total_announcements,
        "total_income": total_income_str,
        "minimum_order_amount": minimum_order_amount,
        "order_status": {
            "new": orders_new,
            "yolda": orders_yolda,
            "teslim_edildi": orders_teslim_edildi,
            "teslim_edilemedi": orders_teslim_edilemedi
        }
    })


# User profile
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


@app.route("/me", methods=["PATCH"])
@jwt_required()
def patch_me():
    data = request.json or {}
    current_identity = get_jwt_identity()
    user = User.query.filter_by(username=current_identity).first_or_404()

    original_username = user.username

    # Sadece gönderilen alanları güncelle
    if "username" in data and data["username"] and data["username"] != user.username:
        if User.query.filter_by(username=data["username"]).first():
            return jsonify({"msg": "Bu kullanıcı adı zaten alınmış"}), 400
        user.username = data["username"]

    if "email" in data and data["email"] and data["email"] != user.email:
        if User.query.filter(User.email == data["email"], User.id != user.id).first():
            return jsonify({"msg": "Bu e-posta başka bir hesapta kullanılıyor"}), 400
        user.email = data["email"]

    # İsteğe bağlı alanlar
    optional_fields = ["name", "surname", "phone", "address"]
    for field in optional_fields:
        if field in data:
            setattr(user, field, data[field])

    # Şifre güncelleme
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


@app.route("/admin/me", methods=["PATCH"])
@admin_required
def patch_admin_me():
    data = request.json or {}
    current_identity = get_jwt_identity()
    admin = User.query.filter_by(username=current_identity).first_or_404()

    original_username = admin.username

    # Sadece gönderilen alanları güncelle
    if "username" in data and data["username"] and data["username"] != admin.username:
        if User.query.filter_by(username=data["username"]).first():
            return jsonify({"msg": "Bu kullanıcı adı zaten alınmış"}), 400
        admin.username = data["username"]

    if "email" in data and data["email"] and data["email"] != admin.email:
        if User.query.filter(User.email == data["email"], User.id != admin.id).first():
            return jsonify({"msg": "Bu e-posta başka bir hesapta kullanılıyor"}), 400
        admin.email = data["email"]

    # İsteğe bağlı alanlar (admin için phone ve name, surname)
    optional_fields = ["name", "surname", "phone"]
    for field in optional_fields:
        if field in data:
            setattr(admin, field, data[field])

    # Şifre güncelleme
    if "new_password" in data:
        if "current_password" not in data or not admin.check_password(data["current_password"]):
            return jsonify({"msg": "Mevcut şifre yanlış veya sağlanmadı"}), 400
        admin.set_password(data["new_password"])

    db.session.commit()

    response = {"msg": "Admin profili güncellendi", "admin": {
        "id": admin.id,
        "username": admin.username,
        "email": admin.email,
        "name": admin.name,
        "surname": admin.surname,
        "phone": admin.phone
    }}
    if original_username != admin.username:
        expires = timedelta(days=7)
        new_token = create_access_token(identity=admin.username, expires_delta=expires)
        response["new_token"] = new_token

    return jsonify(response)


# ---------- Helpers used earlier: notify discount ----------
def notify_users_about_discount(product: Product):
    title = f"{product.title} için {product.discount_percent}% indirim!"
    body = f"{product.title} ürününde {product.discount_percent}% indirim başladı. Yeni fiyat: {product.price_after_discount} TL"

    users = User.query.filter_by(role="user").all()
    tokens = [dt.token for u in users for dt in u.device_tokens]
    admin_keys = [a.fcm_server_key for a in User.query.filter_by(role="admin").all() if a.fcm_server_key]

    app.logger.info(f"İndirim bildirimi: {len(tokens)} kullanıcı token'ı bulundu")

    res = send_fcm_notification(
        tokens,
        title,
        body,
        data={"product_id": str(product.id), "type": "discount"},
        fallback_server_keys=admin_keys
    )
    return res


# ---------- Teardown + Run ----------
@app.teardown_appcontext
def shutdown_session(exception=None):
    try:
        db.session.remove()
        db.engine.dispose()
    except Exception:
        pass


if __name__ == "__main__":
    # Veritabanını kur
    setup_database()
    # reloader'ı kapattık — development sırasında çift process oluşmasını engeller
    app.run(host="0.0.0.0", port=8000, debug=False, use_reloader=False)
