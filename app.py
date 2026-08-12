import hmac
import os
import re
import secrets
import sqlite3
import time
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse
import uuid

from flask import Flask, abort, jsonify, make_response, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-only-change-this-secret-key")
app.config.update(
    MAX_CONTENT_LENGTH=16 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("FLASK_COOKIE_SECURE") == "1",
)

DB_PATH = Path(__file__).with_name("site.db")
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin")
ADMIN_PASSWORD_HASH = os.environ.get("ADMIN_PASSWORD_HASH")
ADMIN_PATH = "/st"
LEGACY_ADMIN_PATH = "/sk"

BRANCH_HOSTS = {
    "root": "khudoverdiev.ru",
    "it": "it.khudoverdiev.ru",
    "ph": "ph.khudoverdiev.ru",
}
WWW_HOST = f"www.{BRANCH_HOSTS['root']}"
PHOTO_CLIENT_BASE_URL = f"https://{BRANCH_HOSTS['ph']}"
PHOTO_REVIEW_URL = "https://vk.ru/reviews-190646738"
PHOTO_PORTFOLIO_IMAGE_ORDER = [
    38,
    39,
    40,
    41,
    98,
    99,
    100,
    101,
    89,
    88,
    92,
    93,
    95,
    96,
    97,
    1,
    11,
    20,
    18,
    19,
    55,
    107,
    106,
    123,
    122,
    120,
    121,
    57,
    56,
    108,
    109,
    110,
    111,
    112,
    58,
    59,
    60,
    61,
    62,
    102,
    103,
    104,
    105,
    25,
    23,
    21,
    24,
    26,
    22,
    14,
    7,
    9,
    8,
    12,
    13,
    16,
    17,
    2,
    5,
    4,
    6,
    3,
    10,
    15,
    28,
    29,
    30,
    31,
    32,
    33,
    34,
    35,
    36,
    37,
    45,
    46,
    48,
    49,
    50,
    52,
    53,
    54,
    69,
    68,
    70,
    71,
    72,
    73,
    74,
    75,
    76,
    77,
    78,
    79,
    80,
    81,
    82,
    83,
    84,
    85,
    86,
    87,
    90,
    91,
    94,
    27,
    43,
    44,
    47,
    51,
    63,
    64,
    65,
    66,
    67,
    113,
    117,
    118,
    119,
    114,
    115,
    116,
    124,
    125,
    126,
    42,
]
PHOTO_PORTFOLIO_IMAGES = [f"photo/portfolio/portfolio-{index:03}.jpg" for index in PHOTO_PORTFOLIO_IMAGE_ORDER]

ALLOWED_HOSTS = {
    "127.0.0.1",
    "localhost",
    "0.0.0.0",
    "::1",
    "it.localhost",
    "ph.localhost",
    WWW_HOST,
    *BRANCH_HOSTS.values(),
}
CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
SLUG_RE = re.compile(r"^[a-z0-9-]{1,80}$")
CLIENT_SLUG_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"
CLIENT_SLUG_LENGTH = 32
RATE_LIMITS = {}


SOCIAL_LINKS = [
    {"name": "vk", "label": "ВКонтакте", "url": "https://vk.com/khudoverdiev", "icon": "fa-vk"},
    {"name": "telegram", "label": "Telegram", "url": "https://t.me/khudoverdiev", "icon": "fa-telegram"},
    {"name": "tiktok", "label": "TikTok", "url": "https://www.tiktok.com/@khudoverdiev", "icon": "fa-tiktok"},
    {
        "name": "youtube",
        "label": "YouTube",
        "url": "https://www.youtube.com/channel/UCbfwSfsKLwgdGLoQUXMsv1g/videos",
        "icon": "fa-youtube",
    },
    {
        "name": "instagram",
        "label": "Instagram",
        "url": "https://instagram.com/khudoverdiev",
        "icon": "fa-instagram",
        "hint": "Используй VPN",
    },
]

DASHBOARD_SITE_SOURCES = [
    ("ph.khudoverdiev.ru", "ph.khudoverdiev"),
    ("khudoverdiev.ru", "khudoverdiev"),
    ("it.khudoverdiev.ru", "it.khudoverdiev"),
]


def normalize_host(host):
    host = (host or "").lower().strip()
    if host.startswith("[") and "]" in host:
        return host[1 : host.index("]")]
    return host.split(":", 1)[0]


def is_allowed_host():
    return normalize_host(request.host) in ALLOWED_HOSTS


def get_client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",", 1)[0].strip()


def check_rate_limit(scope, limit, window_seconds):
    key = f"{scope}:{get_client_ip()}:{request.headers.get('User-Agent', '')[:80]}"
    current_time = time.time()
    hits = [hit for hit in RATE_LIMITS.get(key, []) if current_time - hit < window_seconds]
    if len(hits) >= limit:
        RATE_LIMITS[key] = hits
        return False
    hits.append(current_time)
    RATE_LIMITS[key] = hits
    return True


def csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


app.jinja_env.globals["csrf_token"] = csrf_token


def validate_csrf():
    submitted = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    expected = session.get("_csrf_token")
    return bool(submitted and expected and hmac.compare_digest(submitted, expected))


def clean_text(value, max_length):
    value = CONTROL_CHARS_RE.sub("", (value or "").strip())
    return value[:max_length]


def clean_slug(value):
    value = CONTROL_CHARS_RE.sub("", (value or "").strip().lower())
    value = re.sub(r"[\s_]+", "-", value)
    value = re.sub(r"[^a-z0-9-]", "", value)
    value = re.sub(r"-{2,}", "-", value).strip("-")
    return value[:80]


def is_valid_slug(value):
    return bool(SLUG_RE.fullmatch(value or ""))


def generate_photo_client_slug():
    return "".join(secrets.choice(CLIENT_SLUG_ALPHABET) for _ in range(CLIENT_SLUG_LENGTH))


def generate_unique_photo_client_slug(db, max_attempts=20):
    for _ in range(max_attempts):
        slug = generate_photo_client_slug()
        exists = db.execute("SELECT 1 FROM photo_clients WHERE slug = ?", (slug,)).fetchone()
        if not exists:
            return slug
    raise RuntimeError("Could not generate a unique client link")


def photo_client_public_url(slug):
    return f"{PHOTO_CLIENT_BASE_URL}/client/{clean_slug(slug)}"


app.jinja_env.globals["photo_client_public_url"] = photo_client_public_url


def clean_external_url(value, max_length=500):
    value = clean_text(value, max_length)
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return ""
    return value


def verify_admin_password(password):
    if ADMIN_PASSWORD_HASH:
        return check_password_hash(ADMIN_PASSWORD_HASH, password or "")
    return hmac.compare_digest(password or "", ADMIN_PASSWORD)


def verify_admin_credentials(username, password):
    return hmac.compare_digest(username or "", ADMIN_USERNAME) and verify_admin_password(password)


@app.before_request
def security_gate():
    if not is_allowed_host():
        abort(400)
    if request.endpoint != "static" and request.method == "GET":
        csrf_token()


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    is_portfolio_pdf = request.path.startswith("/static/portfolio/") and request.path.endswith(".pdf")
    response.headers["X-Frame-Options"] = "SAMEORIGIN" if is_portfolio_pdf else "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    frame_ancestors = "'self'" if is_portfolio_pdf else "'none'"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' https://cdnjs.cloudflare.com 'unsafe-inline'; "
        "style-src 'self' https://cdnjs.cloudflare.com 'unsafe-inline'; "
        "font-src 'self' https://cdnjs.cloudflare.com data:; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-src https://vk.com https://vk.ru https://vkvideo.ru; "
        "base-uri 'self'; "
        "form-action 'self'; "
        f"frame-ancestors {frame_ancestors}"
    )
    if request.is_secure or os.environ.get("FORCE_HTTPS") == "1":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if request.path.startswith((ADMIN_PATH, LEGACY_ADMIN_PATH, "/admin")):
        response.headers["Cache-Control"] = "no-store, max-age=0"
    return response


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as db:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS visits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                site_source TEXT NOT NULL DEFAULT 'khudoverdiev.ru',
                ip TEXT,
                user_agent TEXT
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS clicks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                social TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                contact TEXT,
                text TEXT NOT NULL,
                message_type TEXT NOT NULL DEFAULT 'message',
                site_source TEXT NOT NULL DEFAULT 'khudoverdiev.ru',
                created_at TEXT NOT NULL
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS unique_visits (
                visitor_id TEXT PRIMARY KEY,
                first_seen_at TEXT NOT NULL,
                ip TEXT,
                user_agent TEXT
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS photo_clients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_name TEXT NOT NULL,
                slug TEXT NOT NULL UNIQUE,
                photo_link TEXT NOT NULL,
                review_link TEXT,
                discount_text TEXT,
                message_text TEXT,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        ensure_column(db, "visits", "site_source", "TEXT NOT NULL DEFAULT 'khudoverdiev.ru'")
        ensure_column(db, "messages", "message_type", "TEXT NOT NULL DEFAULT 'message'")
        ensure_column(db, "messages", "site_source", "TEXT NOT NULL DEFAULT 'khudoverdiev.ru'")


def ensure_column(db, table, column, definition):
    columns = {row["name"] for row in db.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in columns:
        db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def cutoff_30_days():
    return (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")


def social_by_name(name):
    return next((social for social in SOCIAL_LINKS if social["name"] == name), None)


def message_source_label():
    branch = get_site_branch()
    return BRANCH_HOSTS.get(branch, BRANCH_HOSTS["root"])


def dashboard_site_visit_stats(rows):
    counts = {}
    for row in rows:
        source = row["site_source"] or BRANCH_HOSTS["root"]
        counts[source] = counts.get(source, 0) + row["count"]

    stats = []
    for source, label in DASHBOARD_SITE_SOURCES:
        stats.append({"source": source, "label": label, "count": counts.pop(source, 0)})
    for source in sorted(counts):
        stats.append({"source": source, "label": source.removesuffix(".ru"), "count": counts[source]})
    return stats


def build_booking_message(form):
    shoot_type = clean_text(form.get("shoot_type"), 80)
    shoot_date = clean_text(form.get("shoot_date"), 40)
    shoot_location = clean_text(form.get("shoot_location"), 120)
    shoot_format = clean_text(form.get("shoot_format"), 80)
    people_count = clean_text(form.get("people_count"), 40)
    details = clean_text(form.get("details"), 600)

    lines = ["Заявка на съемку"]
    for label, value in (
        ("Направление", shoot_type),
        ("Дата или период", shoot_date),
        ("Город / локация", shoot_location),
        ("Формат", shoot_format),
        ("Количество участников", people_count),
    ):
        if value:
            lines.append(f"{label}: {value}")
    if details:
        lines.append(f"Комментарий: {details}")
    return clean_text("\n".join(lines), 1000)


def get_photo_client_by_slug(slug):
    init_db()
    with get_db() as db:
        return db.execute(
            """
            SELECT id, client_name, slug, photo_link, review_link, discount_text, message_text, is_active, created_at, updated_at
            FROM photo_clients
            WHERE slug = ?
            """,
            (slug,),
        ).fetchone()


def get_photo_clients():
    init_db()
    with get_db() as db:
        return db.execute(
            """
            SELECT id, client_name, slug, photo_link, review_link, discount_text, message_text, is_active, created_at, updated_at
            FROM photo_clients
            ORDER BY created_at DESC, id DESC
            """
        ).fetchall()


def build_photo_client_payload(form):
    photo_link = clean_external_url(form.get("photo_link"))
    review_link = clean_external_url(form.get("review_link")) if form.get("review_link") else ""
    has_discount = form.get("has_discount") == "1"
    payload = {
        "client_name": clean_text(form.get("client_name"), 120),
        "photo_link": photo_link,
        "review_link": review_link,
        "discount_text": clean_text(form.get("discount_text"), 160) if has_discount else "",
        "message_text": clean_text(form.get("message_text"), 700),
        "has_discount": 1 if has_discount else 0,
        "is_active": 1 if form.get("is_active") == "1" else 0,
    }
    errors = []
    if not payload["client_name"]:
        errors.append("Укажите имя клиента.")
    if not photo_link:
        errors.append("Укажите корректную внешнюю ссылку на фотографии.")
    if form.get("review_link") and not review_link:
        errors.append("Ссылка для отзыва должна начинаться с http:// или https://.")
    return payload, " ".join(errors)


def photo_client_form_defaults(payload=None):
    defaults = {
        "client_name": "",
        "photo_link": "",
        "review_link": "",
        "discount_text": "10%",
        "has_discount": 1,
        "message_text": "Мне было очень приятно работать с вами. Ниже вы найдете ссылку на готовые фотографии.",
        "is_active": 1,
    }
    if payload:
        defaults.update(payload)
    return defaults


def admin_dashboard_context(**extra):
    cutoff = cutoff_30_days()
    with get_db() as db:
        stats = {
            "visits": db.execute("SELECT COUNT(*) FROM visits WHERE created_at >= ?", (cutoff,)).fetchone()[0],
            "unique_visits": db.execute(
                "SELECT COUNT(*) FROM unique_visits WHERE first_seen_at >= ?",
                (cutoff,),
            ).fetchone()[0],
            "messages": db.execute("SELECT COUNT(*) FROM messages WHERE created_at >= ?", (cutoff,)).fetchone()[0],
            "bookings": db.execute(
                """
                SELECT COUNT(*)
                FROM messages
                WHERE created_at >= ?
                  AND (message_type = 'booking' OR text LIKE 'Заявка на съемку%')
                """,
                (cutoff,),
            ).fetchone()[0],
        }
        site_visit_rows = db.execute(
            """
            SELECT COALESCE(site_source, ?) AS site_source, COUNT(*) AS count
            FROM visits
            WHERE created_at >= ?
            GROUP BY COALESCE(site_source, ?)
            """,
            (BRANCH_HOSTS["root"], cutoff, BRANCH_HOSTS["root"]),
        ).fetchall()
        click_stats = db.execute(
            """
            SELECT social, COUNT(*) AS count
            FROM clicks
            WHERE created_at >= ?
            GROUP BY social
            ORDER BY count DESC
            """,
            (cutoff,),
        ).fetchall()

    context = {
        "authorized": True,
        "active_admin_tab": "dashboard",
        "stats": stats,
        "site_visit_stats": dashboard_site_visit_stats(site_visit_rows),
        "click_stats": click_stats,
        "period_label": "Последние 30 дней",
    }
    context.update(extra)
    return context


def admin_messages_context(**extra):
    cutoff = cutoff_30_days()
    with get_db() as db:
        source_count_rows = db.execute(
            """
            SELECT site_source, COUNT(*) AS count
            FROM messages
            WHERE created_at >= ?
            GROUP BY site_source
            ORDER BY
                CASE site_source
                    WHEN 'ph.khudoverdiev.ru' THEN 0
                    WHEN 'khudoverdiev.ru' THEN 1
                    WHEN 'it.khudoverdiev.ru' THEN 2
                    ELSE 3
                END,
                site_source
            """,
            (cutoff,),
        ).fetchall()
        messages = db.execute(
            """
            SELECT id, name, contact, text, site_source, created_at
            FROM messages
            WHERE created_at >= ?
            ORDER BY
                CASE site_source
                    WHEN 'ph.khudoverdiev.ru' THEN 0
                    WHEN 'khudoverdiev.ru' THEN 1
                    WHEN 'it.khudoverdiev.ru' THEN 2
                    ELSE 3
                END,
                site_source,
                id DESC
            """,
            (cutoff,),
        ).fetchall()

    fixed_sources = [source for source, _label in DASHBOARD_SITE_SOURCES]
    source_count_map = {row["site_source"]: row["count"] for row in source_count_rows}
    source_counts = [{"site_source": source, "count": source_count_map.get(source, 0)} for source in fixed_sources]
    extra_count_sources = sorted(set(source_count_map) - set(fixed_sources))
    source_counts.extend({"site_source": source, "count": source_count_map[source]} for source in extra_count_sources)

    messages_by_source = []
    for source in fixed_sources:
        source_messages = [message for message in messages if message["site_source"] == source]
        messages_by_source.append({"source": source, "messages": source_messages, "count": len(source_messages)})
    extra_sources = sorted({message["site_source"] for message in messages} - set(fixed_sources))
    for source in extra_sources:
        source_messages = [message for message in messages if message["site_source"] == source]
        messages_by_source.append({"source": source, "messages": source_messages, "count": len(source_messages)})

    context = {
        "authorized": True,
        "active_admin_tab": "messages",
        "messages_by_source": messages_by_source,
        "messages_total": len(messages),
        "message_source_counts": source_counts,
        "period_label": "Последние 30 дней",
    }
    context.update(extra)
    return context


def admin_clients_context(**extra):
    context = {
        "authorized": True,
        "active_admin_tab": "clients",
        "photo_clients": get_photo_clients(),
        "client_form": photo_client_form_defaults(),
    }
    context.update(extra)
    return context


def get_site_branch():
    host = normalize_host(request.host)
    if host.endswith(".localhost"):
        local_branch = host.split(".", 1)[0]
        if local_branch in BRANCH_HOSTS and local_branch != "root":
            return local_branch
    for branch, branch_host in BRANCH_HOSTS.items():
        if host == branch_host:
            return branch
    for branch, branch_host in BRANCH_HOSTS.items():
        if branch != "root" and host.endswith(f".{branch_host}"):
            return branch
    return "root"


def record_visit():
    """Record a page view and return the stable anonymous visitor id."""
    init_db()
    visitor_id = request.cookies.get("visitor_id") or uuid.uuid4().hex
    timestamp = now()
    site_source = message_source_label()
    with get_db() as db:
        db.execute(
            "INSERT INTO visits (created_at, site_source, ip, user_agent) VALUES (?, ?, ?, ?)",
            (timestamp, site_source, request.remote_addr, request.headers.get("User-Agent", "")),
        )
        db.execute(
            """
            INSERT OR IGNORE INTO unique_visits (visitor_id, first_seen_at, ip, user_agent)
            VALUES (?, ?, ?, ?)
            """,
            (visitor_id, timestamp, request.remote_addr, request.headers.get("User-Agent", "")),
        )
    return visitor_id


@app.route("/")
def index():
    visitor_id = record_visit()
    branch = get_site_branch()
    if branch == "it":
        response = make_response(render_template("it.html", socials=SOCIAL_LINKS))
    elif branch == "ph":
        response = make_response(render_template("photo.html"))
    else:
        response = make_response(
            render_template(
                "index.html",
                socials=SOCIAL_LINKS,
                sent=request.args.get("sent") == "1",
                site_branch=branch,
            )
        )
    response.set_cookie(
        "visitor_id",
        visitor_id,
        max_age=60 * 60 * 24 * 365,
        httponly=True,
        secure=app.config["SESSION_COOKIE_SECURE"],
        samesite="Lax",
    )
    return response


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/portfolio")
def photo_portfolio():
    visitor_id = record_visit()
    response = make_response(
        render_template(
            "photo_portfolio.html",
            photos=PHOTO_PORTFOLIO_IMAGES,
            source_album_url="https://vk.ru/ph.khudoverdiev?z=album-190646738_306357774",
        )
    )
    response.set_cookie(
        "visitor_id",
        visitor_id,
        max_age=60 * 60 * 24 * 365,
        httponly=True,
        secure=app.config["SESSION_COOKIE_SECURE"],
        samesite="Lax",
    )
    return response


@app.route("/go/<social_name>")
def go(social_name):
    init_db()
    social = social_by_name(social_name)
    if social is None:
        return redirect(url_for("index"))

    with get_db() as db:
        db.execute("INSERT INTO clicks (social, created_at) VALUES (?, ?)", (social["label"], now()))
    return redirect(social["url"])


@app.route("/client/<slug>")
def photo_client(slug):
    client = get_photo_client_by_slug(clean_slug(slug))
    if client is None or not client["is_active"]:
        return render_template("client_unavailable.html", direct_visit=False), 404
    photo_link = clean_external_url(client["photo_link"])
    if not photo_link:
        return render_template("client_unavailable.html", direct_visit=False), 404
    client_data = dict(client)
    client_data["photo_link"] = photo_link
    client_data["review_link"] = PHOTO_REVIEW_URL
    return render_template("client_photos.html", client=client_data)


@app.route("/message", methods=["POST"])
def message():
    init_db()
    if not validate_csrf():
        abort(400)
    if not check_rate_limit("message", limit=10, window_seconds=300):
        abort(429)

    name = clean_text(request.form.get("name"), 80) or "Гость"
    contact = clean_text(request.form.get("contact"), 120)
    message_type = "booking" if request.form.get("form_type") == "booking" else "message"
    if message_type == "booking":
        text = build_booking_message(request.form)
    else:
        text = clean_text(request.form.get("text"), 1000)

    if text:
        with get_db() as db:
            db.execute(
                """
                INSERT INTO messages (name, contact, text, message_type, site_source, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (name, contact, text, message_type, message_source_label(), now()),
            )

    if request.headers.get("X-Requested-With") == "fetch":
        return ("", 204)

    return redirect(url_for("index", sent=1))


@app.route(LEGACY_ADMIN_PATH)
def old_admin():
    return redirect(url_for("admin"))


@app.route("/admin")
def old_admin_alias():
    return redirect(url_for("admin"))


@app.route(ADMIN_PATH, methods=["GET", "POST"])
def admin():
    init_db()
    error = None

    if request.method == "POST":
        if not validate_csrf():
            abort(400)
        if not check_rate_limit("admin-login", limit=5, window_seconds=600):
            abort(429)
        if verify_admin_credentials(request.form.get("username"), request.form.get("password")):
            session.clear()
            session["admin"] = True
            session["_csrf_token"] = secrets.token_urlsafe(32)
            return redirect(url_for("admin"))
        error = "Неверный логин или пароль"

    if not session.get("admin"):
        return render_template("admin.html", authorized=False, error=error)

    return render_template("admin.html", **admin_dashboard_context())


@app.route(f"{ADMIN_PATH}/messages")
def admin_messages():
    init_db()
    if not session.get("admin"):
        return redirect(url_for("admin"))
    return render_template("admin.html", **admin_messages_context())


@app.route(f"{ADMIN_PATH}/clients", methods=["GET", "POST"])
def admin_clients():
    init_db()
    if not session.get("admin"):
        return redirect(url_for("admin"))
    if request.method == "GET":
        return render_template("admin.html", **admin_clients_context())
    if not validate_csrf():
        abort(400)

    payload, error = build_photo_client_payload(request.form)
    if error:
        return render_template(
            "admin.html",
            **admin_clients_context(client_form=photo_client_form_defaults(payload), client_error=error),
        ), 400

    timestamp = now()
    try:
        with get_db() as db:
            slug = generate_unique_photo_client_slug(db)
            db.execute(
                """
                INSERT INTO photo_clients (
                    client_name, slug, photo_link, review_link, discount_text, message_text, is_active, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload["client_name"],
                    slug,
                    payload["photo_link"],
                    payload["review_link"],
                    payload["discount_text"],
                    payload["message_text"],
                    payload["is_active"],
                    timestamp,
                    timestamp,
                ),
            )
    except sqlite3.IntegrityError:
        return render_template(
            "admin.html",
            **admin_clients_context(
                client_form=photo_client_form_defaults(payload),
                client_error="Такой адрес страницы уже занят.",
            ),
        ), 409

    return redirect(url_for("admin_clients"))


@app.route(f"{ADMIN_PATH}/clients/<int:client_id>", methods=["POST"])
def update_photo_client(client_id):
    init_db()
    if not session.get("admin"):
        return redirect(url_for("admin"))
    if not validate_csrf():
        abort(400)

    payload, error = build_photo_client_payload(request.form)
    if error:
        return render_template(
            "admin.html",
            **admin_clients_context(client_error=error),
        ), 400

    try:
        with get_db() as db:
            db.execute(
                """
                UPDATE photo_clients
                SET client_name = ?, photo_link = ?, review_link = ?, discount_text = ?,
                    message_text = ?, is_active = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    payload["client_name"],
                    payload["photo_link"],
                    payload["review_link"],
                    payload["discount_text"],
                    payload["message_text"],
                    payload["is_active"],
                    now(),
                    client_id,
                ),
            )
    except sqlite3.IntegrityError:
        return render_template(
            "admin.html",
            **admin_clients_context(client_error="Такой адрес страницы уже занят."),
        ), 409

    return redirect(url_for("admin_clients"))


@app.route(f"{ADMIN_PATH}/clients/<int:client_id>/delete", methods=["POST"])
def delete_photo_client(client_id):
    init_db()
    if not session.get("admin"):
        return redirect(url_for("admin"))
    if not validate_csrf():
        abort(400)

    with get_db() as db:
        db.execute("DELETE FROM photo_clients WHERE id = ?", (client_id,))
    return redirect(url_for("admin_clients"))


@app.route(f"{ADMIN_PATH}/clients/<int:client_id>/rotate-link", methods=["POST"])
def rotate_photo_client_link(client_id):
    init_db()
    if not session.get("admin"):
        return redirect(url_for("admin"))
    if not validate_csrf():
        abort(400)

    with get_db() as db:
        db.execute(
            "UPDATE photo_clients SET slug = ?, updated_at = ? WHERE id = ?",
            (generate_unique_photo_client_slug(db), now(), client_id),
        )
    return redirect(url_for("admin_clients"))


@app.route(f"{ADMIN_PATH}/messages/<int:message_id>/delete", methods=["POST"])
def delete_message(message_id):
    if not session.get("admin"):
        return redirect(url_for("admin"))
    if not validate_csrf():
        abort(400)

    init_db()
    with get_db() as db:
        db.execute("DELETE FROM messages WHERE id = ?", (message_id,))
    if request.headers.get("X-Requested-With") == "fetch":
        return ("", 204)
    return redirect(url_for("admin_messages"))


@app.route(f"{LEGACY_ADMIN_PATH}/messages/<int:message_id>/delete", methods=["POST"])
def legacy_delete_message(message_id):
    return delete_message(message_id)


@app.route(f"{ADMIN_PATH}/logout")
def admin_logout():
    session.pop("admin", None)
    return redirect(url_for("admin"))


@app.route(f"{LEGACY_ADMIN_PATH}/logout")
def legacy_admin_logout():
    return redirect(url_for("admin_logout"))


if __name__ == "__main__":
    init_db()
    app.run(
        debug=os.environ.get("FLASK_DEBUG") == "1",
        port=int(os.environ.get("FLASK_PORT", "5000")),
    )

