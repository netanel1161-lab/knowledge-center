import logging
import os
import uuid
import secrets
import smtplib
from email.message import EmailMessage
from functools import wraps
from typing import Optional

from bson import ObjectId
from flask import (
    Flask,
    jsonify,
    redirect,
    render_template_string,
    request,
    send_from_directory,
    url_for,
)
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_wtf import CSRFProtect
from flask_wtf.csrf import generate_csrf
from pydantic import BaseModel, Field, ValidationError, model_validator
from pymongo import MongoClient
from pymongo.server_api import ServerApi
from bson.json_util import dumps
from authlib.integrations.flask_client import OAuth

from chroma_repository import ChromaRepository
from config import get_settings
from models import KnowledgeItemModel, UserModel
from werkzeug.security import generate_password_hash
from utils import extract_text_from_html

# -------------------------------------------------
# Configuration & Logging
# -------------------------------------------------
settings = get_settings()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("app")

app = Flask(__name__, static_folder=".", static_url_path="/")
app.secret_key = settings.session_secret_key
app.config.update(
    SESSION_COOKIE_SECURE=settings.flask_env != "development",
    SESSION_COOKIE_SAMESITE="Lax",
)

CORS(app, origins=settings.allowed_origins, supports_credentials=True)
csrf = CSRFProtect(app)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per hour", "50 per minute"],
    storage_uri="memory://",
)

login_manager = LoginManager(app)
login_manager.login_view = "login"

# -------------------------------------------------
# Database & Models
# -------------------------------------------------
mongo_client = MongoClient(settings.mongo_uri, server_api=ServerApi("1"), serverSelectionTimeoutMS=4000)
mongo_db = mongo_client[settings.mongo_db_name]
knowledge_items_collection = mongo_db.knowledge_items
users_collection = mongo_db.users

knowledge_item_model = KnowledgeItemModel(knowledge_items_collection)
user_model = UserModel(users_collection)

# Bootstrap / upsert default admin if configured
if settings.admin_default_user and settings.admin_default_password:
    admin_username = settings.admin_default_user
    password_hash = generate_password_hash(settings.admin_default_password)
    users_collection.update_one(
        {"username": admin_username},
        {
            "$set": {
                "username": admin_username,
                "password_hash": password_hash,
                "role": settings.admin_default_role or "admin",
            }
        },
        upsert=True,
    )
    logger.info("Upserted default admin user '%s'", admin_username)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
VIEWS_DIR = os.path.join(BASE_DIR, "views")
MENU_FILE = "תפריט ראשי2.HTML"
LOGIN_LANDING_FILE = "עמוד כניסה.HTML"

chroma_repo = ChromaRepository(persist_directory=settings.chroma_persist_dir)

# OAuth setup (Google)
oauth = OAuth(app)
if settings.google_client_id and settings.google_client_secret:
    oauth.register(
        name="google",
        client_id=settings.google_client_id,
        client_secret=settings.google_client_secret,
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"},
    )

# -------------------------------------------------
# Auth / Roles
# -------------------------------------------------


class User(UserMixin):
    def __init__(self, user_doc: dict):
        self.id = str(user_doc["_id"])
        self.username = user_doc.get("username")
        self.role = user_doc.get("role", "viewer")


@login_manager.user_loader
def load_user(user_id: str) -> Optional[User]:
    user_doc = users_collection.find_one({"_id": ObjectId(user_id)})
    return User(user_doc) if user_doc else None


@login_manager.unauthorized_handler
def unauthorized():
    if request.path.startswith("/api"):
        return jsonify({"error": "Unauthorized"}), 401
    return redirect(url_for("login"))


def role_required(*roles):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for("login"))
            if current_user.role not in roles:
                return jsonify({"error": "Forbidden"}), 403
            return fn(*args, **kwargs)

        return wrapper

    return decorator


# -------------------------------------------------
# Validation Models
# -------------------------------------------------
ALLOWED_ITEM_TYPES = [
    "strategy",
    "finance",
    "hr",
    "ops",
    "infra",
    "archive",
    "document",
    "template",
    "policy",
    "marketing_asset",
    "supplier",
    "timeline_item",
]


class KnowledgeItemPayload(BaseModel):
    item_type: str
    title: str
    content: str
    metadata: dict = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_item(self):
        if self.metadata is None:
            self.metadata = {}
        if self.item_type not in ALLOWED_ITEM_TYPES:
            raise ValueError(f"item_type must be one of {ALLOWED_ITEM_TYPES}")
        return self


class KnowledgeItemUpdate(BaseModel):
    item_type: Optional[str]
    title: Optional[str]
    content: Optional[str]
    metadata: Optional[dict]

    @model_validator(mode="after")
    def validate_item(self):
        if self.item_type and self.item_type not in ALLOWED_ITEM_TYPES:
            raise ValueError(f"item_type must be one of {ALLOWED_ITEM_TYPES}")
        return self


# -------------------------------------------------
# Error Handling
# -------------------------------------------------


class APIError(Exception):
    def __init__(self, message: str, status_code: int = 400, details: Optional[dict] = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.details = details or {}


@app.errorhandler(APIError)
def handle_api_error(err: APIError):
    logger.error("API error: %s", err.message, extra={"details": err.details})
    return jsonify({"error": err.message, "details": err.details}), err.status_code


@app.errorhandler(ValidationError)
def handle_validation_error(err: ValidationError):
    logger.error("Validation error: %s", err.json())
    return jsonify({"error": "Validation failed", "details": err.errors()}), 400


@app.errorhandler(404)
def handle_404(_):
    if request.path.startswith("/api"):
        return jsonify({"error": "Not found"}), 404
    return "Not found", 404


@app.errorhandler(500)
def handle_500(err):
    logger.exception("Unhandled server error: %s", err)
    if request.path.startswith("/api"):
        return jsonify({"error": "Internal server error"}), 500
    return "Internal server error", 500


@app.before_request
def log_request():
    logger.info(
        "REQ %s %s user=%s",
        request.method,
        request.path,
        getattr(current_user, "username", "anon"),
    )


# -------------------------------------------------
# Helpers
# -------------------------------------------------


def parse_pagination():
    try:
        page = max(int(request.args.get("page", 1)), 1)
    except ValueError:
        raise APIError("Invalid page parameter", 400)
    try:
        page_size = min(max(int(request.args.get("page_size", 20)), 1), 100)
    except ValueError:
        raise APIError("Invalid page_size parameter", 400)
    return page, page_size


# -------------------------------------------------
# Healthcheck
# -------------------------------------------------


@app.route("/health", methods=["GET"])
@limiter.exempt
def health():
    mongo_ok = False
    chroma_ok = False
    try:
        mongo_client.admin.command("ping")
        mongo_ok = True
    except Exception as exc:  # noqa: BLE001
        logger.error("MongoDB ping failed: %s", exc)

    try:
        _ = chroma_repo.get_collection_count()
        chroma_ok = True
    except Exception as exc:  # noqa: BLE001
        logger.error("Chroma check failed: %s", exc)

    status = 200 if mongo_ok and chroma_ok else 503
    return jsonify({"mongo": mongo_ok, "chroma": chroma_ok, "status": status}), status


# -------------------------------------------------
# Auth Routes
# -------------------------------------------------


@app.route("/login", methods=["GET"])
@limiter.limit("20 per minute")
def login_page():
    token = generate_csrf()
    html = f"""
    <!DOCTYPE html>
    <html lang="he" dir="rtl">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>התחברות</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="min-h-screen flex items-center justify-center bg-gray-100">
        <form method="POST" action="/login" class="bg-white p-8 rounded-xl shadow-md w-full max-w-sm space-y-4">
            <h1 class="text-2xl font-bold text-center">התחברות</h1>
            <input type="hidden" name="csrf_token" value="{token}">
            <div>
                <label class="block text-sm font-medium text-gray-700">שם משתמש</label>
                <input required name="username" class="mt-1 w-full border rounded-md p-2" />
            </div>
            <div>
                <label class="block text-sm font-medium text-gray-700">סיסמה</label>
                <input required type="password" name="password" class="mt-1 w-full border rounded-md p-2" />
            </div>
            <button class="w-full bg-blue-600 text-white py-2 rounded-md">התחבר</button>
        </form>
    </body>
    </html>
    """
    return render_template_string(html)


@app.route("/login", methods=["POST"])
@limiter.limit("20 per minute")
def login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    if not username or not password:
        return jsonify({"error": "Missing credentials"}), 400
    user_doc = user_model.verify_user(username, password)
    if not user_doc:
        return jsonify({"error": "Invalid credentials"}), 401
    if user_doc.get("email") and not user_doc.get("email_verified", False):
        return jsonify({"error": "Email not verified"}), 403
    login_user(User(user_doc))
    redirect_to = request.args.get("next") or url_for("menu_page")
    return jsonify({"message": "Logged in", "role": user_doc.get("role", "viewer"), "next": redirect_to})


@app.route("/logout", methods=["POST"])
@limiter.limit("20 per minute")
@login_required
@csrf.exempt
def logout():
    logout_user()
    return jsonify({"message": "Logged out"})


def send_verification_email(to_email: str, token: str):
    if not (settings.smtp_host and settings.smtp_port and settings.smtp_username and settings.smtp_password and settings.email_from):
        logger.warning("SMTP not configured; verification token for %s: %s", to_email, token)
        return
    msg = EmailMessage()
    msg["Subject"] = "Verify your account"
    msg["From"] = settings.email_from
    msg["To"] = to_email
    verify_link = url_for("verify_email", token=token, _external=True)
    msg.set_content(f"Click to verify your account: {verify_link}")
    with smtplib.SMTP(settings.smtp_host, settings.smtp_port) as server:
        if settings.smtp_use_tls:
            server.starttls()
        server.login(settings.smtp_username, settings.smtp_password)
        server.send_message(msg)


@app.route("/signup", methods=["POST"])
@csrf.exempt
@limiter.limit("20 per minute")
def signup():
    payload = request.get_json() or {}
    email = (payload.get("email") or "").strip().lower()
    username = (payload.get("username") or "").strip()
    password = (payload.get("password") or "").strip()
    if not email or not username or not password:
        return jsonify({"error": "Missing email, username or password"}), 400
    existing_email = user_model.get_user_by_email(email)
    if existing_email:
        return jsonify({"error": "Email already registered"}), 409
    created = user_model.create_user(username=username, password=password, role="viewer", email=email)
    if not created:
        return jsonify({"error": "Username already exists"}), 409
    token = secrets.token_urlsafe(32)
    user_model.set_email_verification_token(created["_id"], token)
    send_verification_email(email, token)
    return jsonify({"message": "Signup successful. Check email to verify your account."}), 201


@app.route("/verify-email", methods=["GET"])
def verify_email():
    token = request.args.get("token")
    if not token:
        return jsonify({"error": "Missing token"}), 400
    ok = user_model.verify_email_token(token)
    if not ok:
        return jsonify({"error": "Invalid or expired token"}), 400
    return jsonify({"message": "Email verified"}), 200


@app.route("/auth/google/login")
def google_login():
    if "google" not in oauth._registry:
        return jsonify({"error": "Google OAuth not configured"}), 501
    redirect_uri = settings.oauth_redirect_uri or url_for("google_callback", _external=True)
    return oauth.google.authorize_redirect(redirect_uri)


@app.route("/auth/google/callback")
def google_callback():
    if "google" not in oauth._registry:
        return jsonify({"error": "Google OAuth not configured"}), 501
    token = oauth.google.authorize_access_token()
    user_info = oauth.google.parse_id_token(token)
    if not user_info:
        return jsonify({"error": "Failed to fetch Google user info"}), 400
    google_id = user_info.get("sub")
    email = (user_info.get("email") or "").lower()
    name = user_info.get("name") or email
    user_doc = user_model.get_user_by_google_id(google_id)
    if not user_doc:
        existing_email = user_model.get_user_by_email(email)
        if existing_email:
            user_model.attach_google_id(existing_email["_id"], google_id)
            user_doc = user_model.get_user_by_google_id(google_id)
        else:
            user_doc = user_model.create_user_from_google(google_id=google_id, email=email, name=name)
    login_user(User(user_doc))
    return redirect(url_for("menu_page"))


# -------------------------------------------------
# Static/Admin Routes
# -------------------------------------------------


@app.route("/")
def index():
    landing_path = os.path.join(BASE_DIR, LOGIN_LANDING_FILE)
    if os.path.exists(landing_path):
        return send_from_directory(BASE_DIR, LOGIN_LANDING_FILE)
    if os.path.exists(os.path.join(BASE_DIR, "QE.html")):
        return send_from_directory(BASE_DIR, "QE.html")
    if os.path.exists(os.path.join(VIEWS_DIR, "QE.html")):
        return send_from_directory(VIEWS_DIR, "QE.html")
    return "<h1>Server is running</h1>"


@app.route("/admin")
@login_required
@role_required("editor", "admin", "viewer")
@limiter.limit("60 per minute")
def admin_dashboard():
    return send_from_directory(VIEWS_DIR, "admin.html")


@app.route("/admin/add")
@login_required
@role_required("editor", "admin")
@limiter.limit("60 per minute")
def admin_add_item():
    return send_from_directory(VIEWS_DIR, "admin_add_edit.html")


@app.route("/admin/edit/<item_id>")
@login_required
@role_required("editor", "admin")
@limiter.limit("60 per minute")
def admin_edit_item(item_id):
    return send_from_directory(VIEWS_DIR, "admin_add_edit.html")


@app.route("/admin/list")
@login_required
@role_required("editor", "admin", "viewer")
@limiter.limit("60 per minute")
def admin_list_items():
    return send_from_directory(VIEWS_DIR, "admin_list.html")


@app.route("/admin/knowledge")
@login_required
@role_required("editor", "admin", "viewer")
@limiter.limit("60 per minute")
def admin_knowledge():
    return send_from_directory(VIEWS_DIR, "admin_knowledge.html")


@app.route("/menu")
def menu_page():
    menu_path = os.path.join(BASE_DIR, MENU_FILE)
    if os.path.exists(menu_path):
        return send_from_directory(BASE_DIR, MENU_FILE)
    return "Menu page not found", 404


@app.route("/<path:filename>")
def serve_static(filename):
    if os.path.exists(os.path.join(BASE_DIR, filename)):
        return send_from_directory(BASE_DIR, filename)
    if os.path.exists(os.path.join(VIEWS_DIR, filename)):
        return send_from_directory(VIEWS_DIR, filename)
    return "File not found", 404


# -------------------------------------------------
# API Routes
# -------------------------------------------------


@app.route("/api/knowledge_items", methods=["POST"])
@csrf.exempt
@login_required
@role_required("editor", "admin")
@limiter.limit("30 per minute")
def create_knowledge_item():
    payload = request.get_json() or {}
    data = KnowledgeItemPayload(**payload)
    plain_text_content = (
        extract_text_from_html(data.content) if "<" in data.content and ">" in data.content else data.content
    )
    chroma_id = str(uuid.uuid4())
    try:
        chroma_repo.add_document(doc_id=chroma_id, document=plain_text_content, metadata=data.metadata)
    except Exception as exc:  # noqa: BLE001
        raise APIError(f"Failed to add to ChromaDB: {exc}", 500)

    new_item_data = knowledge_item_model.create_item(
        item_type=data.item_type,
        title=data.title,
        content=data.content,
        metadata=data.metadata,
        embedding_id=chroma_id,
    )
    return jsonify(knowledge_item_model.to_dict(new_item_data)), 201


@app.route("/api/knowledge_items", methods=["GET"])
@csrf.exempt
@login_required
@role_required("viewer", "editor", "admin")
@limiter.limit("60 per minute")
def get_all_knowledge_items():
    item_type = request.args.get("item_type")
    query = request.args.get("q")
    page, page_size = parse_pagination()

    criteria = {}
    if item_type:
        if item_type not in ALLOWED_ITEM_TYPES:
            raise APIError("Invalid item_type filter", 400)
        criteria["item_type"] = item_type

    if query:
        criteria["$or"] = [
            {"title": {"$regex": query, "$options": "i"}},
            {"content": {"$regex": query, "$options": "i"}},
        ]

    items, total = knowledge_item_model.search_items(criteria, page, page_size)
    return (
        jsonify(
            {
                "items": [knowledge_item_model.to_dict(item) for item in items],
                "page": page,
                "page_size": page_size,
                "total": total,
            }
        ),
        200,
    )


@app.route("/api/knowledge_items/<item_id>", methods=["GET"])
@csrf.exempt
@login_required
@role_required("viewer", "editor", "admin")
@limiter.limit("60 per minute")
def get_knowledge_item(item_id):
    if not ObjectId.is_valid(item_id):
        raise APIError("Invalid item ID format", 400)
    item = knowledge_item_model.get_item_by_id(item_id)
    if not item:
        raise APIError("Knowledge item not found", 404)
    return jsonify(knowledge_item_model.to_dict(item)), 200


@app.route("/api/knowledge_items/<item_id>", methods=["PUT"])
@csrf.exempt
@login_required
@role_required("editor", "admin")
@limiter.limit("30 per minute")
def update_knowledge_item(item_id):
    if not ObjectId.is_valid(item_id):
        raise APIError("Invalid item ID format", 400)

    payload = request.get_json() or {}
    data = KnowledgeItemUpdate(**payload)
    original_item = knowledge_item_model.get_item_by_id(item_id)
    if not original_item:
        raise APIError("Knowledge item not found", 404)

    updates = {k: v for k, v in data.dict().items() if v is not None}
    if not updates:
        raise APIError("No valid fields to update", 400)

    if "content" in updates and updates["content"] != original_item.get("content"):
        plain_text_content = (
            extract_text_from_html(updates["content"])
            if "<" in updates["content"] and ">" in updates["content"]
            else updates["content"]
        )
        try:
            chroma_repo.update_document(
                doc_id=original_item["embedding_id"],
                document=plain_text_content,
                metadata=updates.get("metadata", original_item.get("metadata")),
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to update ChromaDB: %s", exc)

    updated = knowledge_item_model.update_item(item_id, updates)
    if not updated:
        raise APIError("Failed to update knowledge item", 500)

    updated_item = knowledge_item_model.get_item_by_id(item_id)
    return jsonify(knowledge_item_model.to_dict(updated_item)), 200


@app.route("/api/knowledge_items/<item_id>", methods=["DELETE"])
@csrf.exempt
@login_required
@role_required("editor", "admin")
@limiter.limit("20 per minute")
def delete_knowledge_item(item_id):
    if not ObjectId.is_valid(item_id):
        raise APIError("Invalid item ID format", 400)

    item_to_delete = knowledge_item_model.get_item_by_id(item_id)
    if not item_to_delete:
        raise APIError("Knowledge item not found", 404)

    if "embedding_id" in item_to_delete and item_to_delete["embedding_id"]:
        try:
            chroma_repo.delete_document(doc_id=item_to_delete["embedding_id"])
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to delete from ChromaDB: %s", exc)

    deleted = knowledge_item_model.delete_item(item_id)
    if not deleted:
        raise APIError("Failed to delete knowledge item", 500)

    return jsonify({"message": "Knowledge item deleted successfully"}), 200


@app.route("/debug/admin_users", methods=["GET"])
def debug_admin_users():
    users = list(users_collection.find({}, {"_id": 0, "username": 1, "role": 1}))
    return jsonify(users)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=settings.port, debug=settings.flask_env == "development")
