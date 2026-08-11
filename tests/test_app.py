import re
import sqlite3
from pathlib import Path

import pytest
from werkzeug.security import generate_password_hash

import app as site


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(site, "DB_PATH", tmp_path / "site.db")
    monkeypatch.setattr(site, "ADMIN_PASSWORD", "secret")
    monkeypatch.setattr(site, "ADMIN_PASSWORD_HASH", None)
    monkeypatch.setattr(site, "RATE_LIMITS", {})
    monkeypatch.delenv("FORCE_HTTPS", raising=False)
    site.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    with site.app.test_client() as client:
        yield client


def csrf_from(client, path="/", **kwargs):
    client.get(path, **kwargs)
    with client.session_transaction(**kwargs) as session:
        return session["_csrf_token"]


def db_rows(table):
    order_by = "visitor_id" if table == "unique_visits" else "id"
    with sqlite3.connect(site.DB_PATH) as db:
        db.row_factory = sqlite3.Row
        return db.execute(f"SELECT * FROM {table} ORDER BY {order_by}").fetchall()


def table_columns(table):
    with sqlite3.connect(site.DB_PATH) as db:
        db.row_factory = sqlite3.Row
        return {row["name"]: row for row in db.execute(f"PRAGMA table_info({table})").fetchall()}


def insert_message(
    name="Alice",
    contact="@alice",
    text="Hello",
    created_at="2099-01-02 03:04:05",
    site_source="khudoverdiev.ru",
):
    site.init_db()
    with sqlite3.connect(site.DB_PATH) as db:
        cursor = db.execute(
            "INSERT INTO messages (name, contact, text, site_source, created_at) VALUES (?, ?, ?, ?, ?)",
            (name, contact, text, site_source, created_at),
        )
        return cursor.lastrowid


def insert_photo_client(
    client_name="Иванова",
    slug="ivanova-2026",
    photo_link="https://drive.google.com/photos",
    review_link="https://reviews.example/ivanova",
    discount_text="10%",
    message_text="Ваши фотографии готовы.",
    is_active=1,
):
    site.init_db()
    with sqlite3.connect(site.DB_PATH) as db:
        cursor = db.execute(
            """
            INSERT INTO photo_clients (
                client_name, slug, photo_link, review_link, discount_text, message_text, is_active, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                client_name,
                slug,
                photo_link,
                review_link,
                discount_text,
                message_text,
                is_active,
                "2099-01-02 03:04:05",
                "2099-01-02 03:04:05",
            ),
        )
        return cursor.lastrowid


def login_as_admin(client):
    csrf = csrf_from(client, site.ADMIN_PATH)
    return client.post(site.ADMIN_PATH, data={"password": "secret", "csrf_token": csrf})


def test_index_records_visit_sets_stable_visitor_cookie_and_security_headers(client):
    response = client.get("/")

    assert response.status_code == 200
    assert "visitor_id=" in response.headers["Set-Cookie"]
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]
    assert len(db_rows("visits")) == 1
    assert len(db_rows("unique_visits")) == 1


def test_index_visitor_cookie_has_privacy_and_lifetime_attributes(client):
    response = client.get("/")
    cookie = response.headers["Set-Cookie"]

    assert "visitor_id=" in cookie
    assert "Max-Age=31536000" in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=Lax" in cookie


def test_index_records_remote_addr_and_user_agent_for_visit_audit(client):
    response = client.get("/", environ_base={"REMOTE_ADDR": "198.51.100.20"}, headers={"User-Agent": "qa-browser"})

    assert response.status_code == 200
    visit = db_rows("visits")[0]
    unique_visit = db_rows("unique_visits")[0]
    assert visit["ip"] == "198.51.100.20"
    assert visit["user_agent"] == "qa-browser"
    assert unique_visit["ip"] == "198.51.100.20"
    assert unique_visit["user_agent"] == "qa-browser"


def test_index_counts_returning_cookie_as_new_visit_but_not_new_unique_visitor(client):
    first = client.get("/")
    visitor_cookie = first.headers["Set-Cookie"].split("visitor_id=", 1)[1].split(";", 1)[0]

    response = client.get("/", headers={"Cookie": f"visitor_id={visitor_cookie}"})

    assert response.status_code == 200
    assert len(db_rows("visits")) == 2
    assert len(db_rows("unique_visits")) == 1


def test_static_assets_do_not_create_csrf_session_for_anonymous_users(client):
    response = client.get("/static/favicon.ico")

    assert response.status_code == 200
    assert "Set-Cookie" not in response.headers


@pytest.mark.parametrize(
    ("raw_host", "expected"),
    [
        ("KHUDOVERDIEV.RU:443", "khudoverdiev.ru"),
        ("[::1]:5000", "::1"),
        (" localhost ", "localhost"),
        ("it.khudoverdiev.ru", "it.khudoverdiev.ru"),
        ("it.localhost:5000", "it.localhost"),
    ],
)
def test_normalize_host_handles_case_ports_ipv6_and_whitespace(raw_host, expected):
    assert site.normalize_host(raw_host) == expected


def test_unknown_host_is_rejected_before_side_effects(client):
    response = client.get("/", base_url="http://evil.example")

    assert response.status_code == 400
    assert not site.DB_PATH.exists()


def test_allowed_host_with_port_is_accepted(client):
    response = client.get("/", base_url="http://localhost:5000")

    assert response.status_code == 200
    assert "Твой вдохновитель отправил новое сообщение".encode() in response.data
    assert "новый таплинк".encode() not in response.data
    assert len(db_rows("visits")) == 1


def test_nested_branch_host_is_rejected_by_public_allowlist(client):
    response = client.get("/", base_url="http://preview.it.khudoverdiev.ru")

    assert response.status_code == 400
    assert not site.DB_PATH.exists()


def test_force_https_env_adds_hsts_header(client, monkeypatch):
    monkeypatch.setenv("FORCE_HTTPS", "1")

    response = client.get("/")

    assert response.headers["Strict-Transport-Security"] == "max-age=31536000; includeSubDomains"


def test_secure_cookie_flag_is_applied_to_visitor_cookie_when_enabled(client, monkeypatch):
    monkeypatch.setitem(site.app.config, "SESSION_COOKIE_SECURE", True)

    response = client.get("/")

    assert "visitor_id=" in response.headers["Set-Cookie"]
    assert "Secure" in response.headers["Set-Cookie"]


def test_large_message_payload_is_rejected_before_persisting_body(client):
    csrf = csrf_from(client)

    response = client.post("/message", data={"csrf_token": csrf, "text": "A" * (17 * 1024)})

    assert response.status_code == 413
    assert db_rows("messages") == []


@pytest.mark.parametrize(
    ("base_url", "expected_branch"),
    [
        ("http://khudoverdiev.ru", "root"),
        ("http://it.khudoverdiev.ru", "it"),
        ("http://it.localhost", "it"),
        ("http://ph.khudoverdiev.ru", "ph"),
        ("http://phh.khudoverdiev.ru", "phh"),
    ],
)
def test_site_branch_is_selected_from_allowed_host(base_url, expected_branch):
    with site.app.test_request_context("/", base_url=base_url):
        assert site.get_site_branch() == expected_branch


def test_nested_branch_hostname_maps_to_own_branch_when_explicitly_reached():
    with site.app.test_request_context("/", base_url="http://preview.it.khudoverdiev.ru"):
        assert site.get_site_branch() == "it"


def test_it_subdomain_renders_developer_portfolio_without_replacing_root_taplink(client):
    portfolio = client.get("/", base_url="http://it.khudoverdiev.ru")
    taplink = client.get("/", base_url="http://khudoverdiev.ru")

    assert portfolio.status_code == 200
    assert "IT | Владимир Худовердиев".encode() in portfolio.data
    assert b"portfolio/vh-favicon.svg" in portfolio.data
    assert b"vh-favicon.svg?v=7" in portfolio.data
    assert b"css/it.css?v=69" in portfolio.data
    assert b"portfolio/vladimir-avatar-favicon.png" not in portfolio.data
    assert b"portfolio/vladimir-user-cutout.png" in portfolio.data
    assert b"class=\"portrait-photo\"" in portfolio.data
    assert b"portrait-word" not in portfolio.data
    assert b">WEB<" not in portfolio.data
    assert b">DEVELOPER<" not in portfolio.data
    assert b"portfolio/vladimir-cutout-tight.png" not in portfolio.data
    assert "CRM «Передача»".encode() in portfolio.data
    assert "CRM Shans".encode() in portfolio.data
    assert "Два продукта: чистая логика, сильный интерфейс и понятный результат.".encode() not in portfolio.data
    css = Path("static/css/it.css").read_text(encoding="utf-8")
    favicon = Path("static/portfolio/vh-favicon.svg").read_text(encoding="utf-8")
    assert 'font-size="23"' in favicon
    assert ">IT</text>" in favicon
    assert ">VH</text>" not in favicon
    assert 'cx="45.5"' in favicon
    assert ".project-actions > button.media-button:first-child" not in css
    assert "--desktop-width: 1320px;" in css
    assert "orbit-breathe" not in css
    assert ".portrait-photo {\n    position: absolute;\n    z-index: 2;\n    inset: 68px;" in css
    assert "clip-path: circle(50% at 50% 50%);" in css
    assert "--portrait-subject-offset: 24px;" in css
    assert "left: calc(50% - var(--portrait-subject-offset));" in css
    assert ".portrait-photo img {\n        left: 50%;" not in css
    assert "transform-origin: 50% 100%;" in css
    assert "bottom: -78px;" in css
    assert "height: 540px;" in css
    portrait_hover = re.search(r"\.portrait-wrap:hover \.portrait-photo img \{(?P<body>.*?)\n\}", css, re.S)
    assert portrait_hover is not None
    assert "translateY(" not in portrait_hover.group("body")
    assert "@media (min-width: 901px)" in css
    assert "@media (max-width: 900px)" in css
    width_media_queries = re.findall(r"@media\s*\((?:min|max)-width:[^)]+\)", css)
    assert width_media_queries == ["@media (min-width: 901px)", "@media (max-width: 900px)"]
    assert "body {\n        min-width: 0;\n        overflow-x: hidden;" in css
    assert "/* Mobile polish: one deliberate layout, not a squeezed desktop. */" in css
    assert ".hero {\n        min-height: 100svh;" in css
    assert "grid-template-columns: minmax(0, 1fr) 118px;" in css
    assert ".hero-copy {\n        display: contents;" in css
    assert ".hero h1 {\n        grid-column: 1;\n        grid-row: 3;" in css
    assert ".portrait-wrap {\n        grid-column: 2;\n        grid-row: 3 / span 2;" in css
    assert ".portrait-photo {\n        inset: 8px;\n        --portrait-subject-offset: 0px;" in css
    assert ".about-copy > p {\n        max-width: 330px;\n        margin-top: 2px;\n        padding: 0;" in css
    assert "scroll-snap-type: x mandatory;" in css
    assert ".media-button {\n        min-height: 54px;\n        padding: 0 12px 0 17px;\n        border-radius: 999px;" in css
    assert ".contact-circle:hover" in css
    assert "background:\n        linear-gradient(90deg, rgba(255, 255, 255, 0.98), rgba(255, 255, 255, 0.9)),\n        #fff;" in css
    assert "radial-gradient(circle at 18% 26%" not in css
    assert b"class=\"project-showcase\"" in portfolio.data
    assert b"class=\"project-text-case\"" not in portfolio.data
    assert b"class=\"project-visual\"" not in portfolio.data
    assert b"portfolio/slides/peredacha/slide-1.png" in portfolio.data
    assert b"portfolio/shans-case.png" not in portfolio.data
    assert b"portfolio/peredacha-title.png" not in portfolio.data
    assert b"portfolio/peredacha.pdf" in portfolio.data
    assert b"portfolio/shans.mp4" in portfolio.data
    assert portfolio.data.count(b'class="page-scroll-cue"') == 1
    assert b'class="section-next' not in portfolio.data
    assert b"data-direction=\"down\"" in portfolio.data
    assert b"pageScrollCue.dataset.direction === 'up'" in portfolio.data
    assert b"contact.getBoundingClientRect().top <= window.innerHeight * 0.58" in portfolio.data
    assert b"id=\"site-footer\"" in portfolio.data
    assert "Наверх".encode() not in portfolio.data
    for target in (b'href="#about"', b'href="#projects"', b'href="#contact"'):
        assert target in portfolio.data
    for social_name in ("vk", "telegram", "tiktok", "youtube", "instagram"):
        assert f"/go/{social_name}".encode() not in portfolio.data
    assert b'class="taplink-body"' in taplink.data
    assert "CRM «Передача»".encode() not in taplink.data


def test_it_portfolio_keeps_security_headers_and_records_visit(client):
    response = client.get("/", base_url="http://it.khudoverdiev.ru")

    assert response.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]
    assert len(db_rows("visits")) == 1
    assert len(db_rows("unique_visits")) == 1


def test_ph_subdomain_renders_photographer_portfolio(client):
    response = client.get("/", base_url="http://ph.khudoverdiev.ru")

    assert response.status_code == 200
    assert b"css/photo.css" in response.data
    assert b"js/photo.js" in response.data
    assert "Архангельск, Северодвинск".encode() in response.data
    assert b"photo/ph-favicon.ico" in response.data
    assert b"photo/ph-favicon.svg" in response.data
    assert b"photo/ph-favicon.png" in response.data
    assert b"portfolio/vh-favicon.svg" not in response.data
    assert b">PH<span>.</span></a>" in response.data
    assert b">IT<span" not in response.data
    assert b"photo/portrait-cutout.png" in response.data
    assert b"class=\"ph-portrait-orbit\"" in response.data
    assert b"class=\"ph-hero-collage\"" not in response.data
    assert b"photo/portfolio/portfolio-078.jpg" in response.data
    assert b"photo/portfolio/portfolio-123.jpg" in response.data
    assert b"photo/mikhail-" not in response.data
    assert b"data-lightbox" in response.data
    assert b"data-photo-card" in response.data
    assert b"data-card-next" in response.data
    assert b'id="brands"' in response.data
    assert b'class="ph-scroll-cue"' in response.data
    assert b'id="ph-site-footer"' in response.data
    assert b"vk.com/ph.khudoverdiev" in response.data
    assert b'href="/portfolio"' in response.data
    assert b'href="#video"' in response.data
    assert "Видеосъемка".encode() in response.data
    assert "Стоимость съемок".encode() not in response.data
    assert b'data-booking-open' in response.data
    assert b'data-booking-form' in response.data
    assert b'name="form_type" value="booking"' in response.data
    assert b'name="shoot_type"' in response.data
    assert b'name="shoot_date"' in response.data
    assert b'name="shoot_location"' in response.data
    assert b'class="ph-contact-actions"' in response.data
    assert "Записаться на съемку".encode() in response.data
    assert "Написать во ВКонтакте".encode() in response.data
    assert response.data.count(b"data-booking-open") == 2
    assert "Работал с".encode() in response.data
    assert b"Ozon" in response.data
    assert b"Black Star Burger" in response.data
    assert "Яндекс Маркет".encode() in response.data
    assert "Руки Вверх! Бар".encode() in response.data
    assert "Фотостудия «Сюжетная Линия»".encode() in response.data
    assert "Выберите формат под задачу".encode() in response.data
    assert "актуального VK Market".encode() not in response.data
    assert "Ты, он и белое платье".encode() in response.data
    assert "Твоя фотосессия".encode() in response.data
    assert "Все сделаем за тебя".encode() in response.data
    assert "Фото+видео".encode() in response.data
    assert "Подарочный сертификат".encode() in response.data
    assert "от 4 000 ₽/час".encode() in response.data
    assert "от 13 000 ₽".encode() in response.data
    assert b"https://vk.ru/market-190646738?screen=group" not in response.data
    assert "Дополнительно можно заказать".encode() not in response.data
    assert b'id="video"' in response.data
    assert "Видеосъемка".encode() in response.data
    assert "с живым дыханием".encode() in response.data
    assert "Свадебный фильм".encode() in response.data
    assert "Главный эпизод".encode() in response.data
    assert "Творческий ролик".encode() in response.data
    assert "Контент для бренда".encode() in response.data
    assert "от 5 000 ₽/час".encode() in response.data
    assert "от 6 000 ₽/час".encode() in response.data
    assert b"https://vk.ru/v.khudoverdiev" not in response.data
    assert "Быстрый ответ во VK".encode() not in response.data
    assert "Открыть видеосъемку во VK".encode() not in response.data
    assert "Открыть полное портфолио".encode() in response.data
    assert "Владимир Худовердиев · Все права защищены".encode() in response.data
    assert b'href="#gallery"' not in response.data
    assert b'id="gallery"' not in response.data
    assert "Снимаю".encode() not in response.data
    assert "снимаю".encode() not in response.data
    assert "Фотограф | Архангельск".encode() not in response.data
    assert "Фотограф · Архангельск".encode() not in response.data
    assert "ГОРОДСКОЙ ПОРТРЕТ".encode() not in response.data
    assert "Фотограф<br>Архангельск".encode() not in response.data


def test_ph_full_portfolio_renders_local_album_page_and_records_visit(client):
    response = client.get("/portfolio", base_url="http://ph.khudoverdiev.ru")

    assert response.status_code == 200
    assert b"css/photo.css" in response.data
    assert b"js/photo.js" in response.data
    assert "Портфолио".encode() in response.data
    assert "126 фотографий".encode() not in response.data
    assert "Собрал сюда все снимки из альбома ВКонтакте".encode() not in response.data
    assert b"photo/portfolio/portfolio-001.jpg" in response.data
    assert b"photo/portfolio/portfolio-126.jpg" in response.data
    assert response.data.count(b'class="ph-full-photo"') == 126
    assert b"data-lightbox" in response.data
    assert b">PH<span>.</span></a>" in response.data
    assert b"vkuserphoto.ru" not in response.data
    assert "visitor_id=" in response.headers["Set-Cookie"]
    assert len(db_rows("visits")) == 1
    assert len(db_rows("unique_visits")) == 1


def test_ph_localhost_maps_to_photographer_branch(client):
    response = client.get("/", base_url="http://ph.localhost")

    assert response.status_code == 200
    assert b"css/photo.css" in response.data


def test_phh_root_shows_private_materials_entry_state(client):
    response = client.get("/", base_url="http://phh.khudoverdiev.ru")

    assert response.status_code == 200
    assert "Материалы недоступны".encode() in response.data
    assert "персональной ссылке".encode() in response.data


def test_taplink_socials_use_tracking_redirects(client):
    response = client.get("/", base_url="http://khudoverdiev.ru")

    for social_name in ("vk", "telegram", "tiktok", "youtube", "instagram"):
        assert f'href="/go/{social_name}"'.encode() in response.data
    assert b'href="https://www.tiktok.com/@khudoverdiev"' not in response.data


def test_it_portfolio_project_form_uses_protected_shared_message_endpoint(client):
    response = client.get("/", base_url="http://it.khudoverdiev.ru")

    assert b'id="project-form"' in response.data
    assert b'action="/message"' in response.data
    assert b'name="csrf_token"' in response.data
    assert b'data-open-contact' in response.data


def test_it_project_request_is_saved_and_visible_in_admin_reached_through_sk(client):
    csrf = csrf_from(client)
    sent = client.post(
        "/message",
        data={
            "csrf_token": csrf,
            "name": "IT client",
            "contact": "@it_client",
            "text": "Нужна CRM для отдела продаж",
        },
        headers={"X-Requested-With": "fetch"},
    )

    assert sent.status_code == 204
    assert client.get("/sk").headers["Location"] == "/st"
    login_as_admin(client)
    messages = client.get("/st/messages")
    assert b"IT client" in messages.data
    assert b"@it_client" in messages.data
    assert "Нужна CRM для отдела продаж".encode() in messages.data


def test_portfolio_pdf_can_be_framed_only_by_same_origin(client):
    response = client.get("/static/portfolio/peredacha.pdf", base_url="http://it.khudoverdiev.ru")

    assert response.status_code == 200
    assert response.headers["X-Frame-Options"] == "SAMEORIGIN"
    assert "frame-ancestors 'self'" in response.headers["Content-Security-Policy"]


def test_valid_social_redirect_records_click_by_display_label(client):
    response = client.get("/go/telegram")

    assert response.status_code == 302
    assert response.headers["Location"] == "https://t.me/khudoverdiev"
    clicks = db_rows("clicks")
    assert len(clicks) == 1
    assert clicks[0]["social"] == "Telegram"


def test_unknown_social_redirects_home_without_recording_click(client):
    response = client.get("/go/not-a-social")

    assert response.status_code == 302
    assert response.headers["Location"] == "/"
    assert db_rows("clicks") == []


def test_social_by_name_returns_public_social_contract_without_mutating_it():
    social = site.social_by_name("youtube")

    assert social == {
        "name": "youtube",
        "label": "YouTube",
        "url": "https://www.youtube.com/channel/UCbfwSfsKLwgdGLoQUXMsv1g/videos",
        "icon": "fa-youtube",
    }


def test_message_requires_csrf(client):
    response = client.post("/message", data={"text": "Hello"})

    assert response.status_code == 400
    assert db_rows("messages") == []


def test_message_rejects_mismatched_csrf_token_without_side_effects(client):
    csrf_from(client)

    response = client.post("/message", data={"csrf_token": "wrong-token", "text": "Should not save"})

    assert response.status_code == 400
    assert db_rows("messages") == []


def test_message_endpoint_rejects_get_requests(client):
    response = client.get("/message")

    assert response.status_code == 405
    assert not site.DB_PATH.exists()


def test_message_persists_cleaned_text_default_name_and_redirects(client):
    csrf = csrf_from(client)

    response = client.post(
        "/message",
        data={
            "csrf_token": csrf,
            "name": " \x00\x08 ",
            "contact": "  @alice\x7f  ",
            "text": "  Hello\x00 world  ",
        },
    )

    assert response.status_code == 302
    assert response.headers["Location"] == "/?sent=1"
    messages = db_rows("messages")
    assert len(messages) == 1
    assert messages[0]["name"] == "Гость"
    assert messages[0]["contact"] == "@alice"
    assert messages[0]["text"] == "Hello world"


def test_message_fetch_request_returns_no_content_after_saving(client):
    csrf = csrf_from(client)

    response = client.post(
        "/message",
        data={"csrf_token": csrf, "name": "Alice", "text": "Ping"},
        headers={"X-Requested-With": "fetch", "X-CSRF-Token": csrf},
    )

    assert response.status_code == 204
    assert len(db_rows("messages")) == 1


def test_booking_form_posts_structured_shoot_request_to_admin_messages(client):
    csrf = csrf_from(client, base_url="http://ph.khudoverdiev.ru")

    response = client.post(
        "/message",
        base_url="http://ph.khudoverdiev.ru",
        data={
            "csrf_token": csrf,
            "form_type": "booking",
            "name": "Мария",
            "contact": "@maria",
            "shoot_type": "Видеосъемка",
            "shoot_date": "24 августа",
            "shoot_location": "Северодвинск",
            "shoot_format": "2 часа",
            "people_count": "пара",
            "details": "Нужен ролик для свадьбы <script>alert(1)</script>",
        },
        headers={"X-Requested-With": "fetch", "X-CSRF-Token": csrf},
    )

    assert response.status_code == 204
    messages = db_rows("messages")
    assert len(messages) == 1
    assert messages[0]["name"] == "Мария"
    assert messages[0]["contact"] == "@maria"
    assert messages[0]["site_source"] == "ph.khudoverdiev.ru"
    assert "Заявка на съемку" in messages[0]["text"]
    assert "Направление: Видеосъемка" in messages[0]["text"]
    assert "Дата или период: 24 августа" in messages[0]["text"]
    assert "Город / локация: Северодвинск" in messages[0]["text"]
    assert "Формат: 2 часа" in messages[0]["text"]
    assert "Количество участников: пара" in messages[0]["text"]

    login_as_admin(client)
    admin_response = client.get(f"{site.ADMIN_PATH}/messages")

    assert admin_response.status_code == 200
    assert "Мария".encode() in admin_response.data
    assert "Заявка на съемку".encode() in admin_response.data
    assert b"<script>alert(1)</script>" not in admin_response.data


def test_message_stores_source_site_from_request_host(client):
    root_csrf = csrf_from(client)

    root_response = client.post(
        "/message",
        data={"csrf_token": root_csrf, "name": "Root", "text": "From root"},
    )
    it_csrf = csrf_from(client, path="/", base_url="http://it.khudoverdiev.ru")
    it_response = client.post(
        "/message",
        data={"csrf_token": it_csrf, "name": "IT", "text": "From it"},
        base_url="http://it.khudoverdiev.ru",
    )

    assert root_response.status_code == 302
    assert it_response.status_code == 302
    messages = db_rows("messages")
    assert messages[0]["site_source"] == "khudoverdiev.ru"
    assert messages[1]["site_source"] == "it.khudoverdiev.ru"


def test_message_accepts_csrf_from_header_for_fetch_clients(client):
    csrf = csrf_from(client)

    response = client.post(
        "/message",
        data={"name": "Header client", "text": "Saved through header token"},
        headers={"X-Requested-With": "fetch", "X-CSRF-Token": csrf},
    )

    assert response.status_code == 204
    assert db_rows("messages")[0]["name"] == "Header client"


def test_message_ignores_empty_text_after_cleaning(client):
    csrf = csrf_from(client)

    response = client.post("/message", data={"csrf_token": csrf, "name": "Alice", "text": "\x00  "})

    assert response.status_code == 302
    assert db_rows("messages") == []


def test_message_limits_stored_field_lengths(client):
    csrf = csrf_from(client)

    client.post(
        "/message",
        data={
            "csrf_token": csrf,
            "name": "A" * 120,
            "contact": "B" * 150,
            "text": "C" * 1200,
        },
    )

    message = db_rows("messages")[0]
    assert len(message["name"]) == 80
    assert len(message["contact"]) == 120
    assert len(message["text"]) == 1000


def test_message_rate_limit_blocks_excessive_posts(client):
    csrf = csrf_from(client)
    for index in range(10):
        response = client.post("/message", data={"csrf_token": csrf, "text": f"Message {index}"})
        assert response.status_code == 302

    blocked = client.post("/message", data={"csrf_token": csrf, "text": "Too much"})

    assert blocked.status_code == 429
    assert len(db_rows("messages")) == 10


def test_message_rate_limit_is_scoped_by_first_forwarded_ip_and_user_agent(client, monkeypatch):
    monkeypatch.setattr(site.time, "time", lambda: 1_000.0)
    csrf = csrf_from(client)
    throttled_headers = {"X-Forwarded-For": "203.0.113.10, 10.0.0.1", "User-Agent": "mobile-app"}
    other_ip_headers = {"X-Forwarded-For": "203.0.113.11, 10.0.0.1", "User-Agent": "mobile-app"}
    other_agent_headers = {"X-Forwarded-For": "203.0.113.10, 10.0.0.1", "User-Agent": "browser"}

    for index in range(10):
        response = client.post(
            "/message",
            data={"csrf_token": csrf, "text": f"Limited {index}"},
            headers=throttled_headers,
        )
        assert response.status_code == 302

    assert client.post("/message", data={"csrf_token": csrf, "text": "Blocked"}, headers=throttled_headers).status_code == 429
    assert client.post("/message", data={"csrf_token": csrf, "text": "Other IP"}, headers=other_ip_headers).status_code == 302
    assert client.post("/message", data={"csrf_token": csrf, "text": "Other agent"}, headers=other_agent_headers).status_code == 302


def test_message_rate_limit_window_expires_without_manual_reset(client, monkeypatch):
    current_time = [1_000.0]
    monkeypatch.setattr(site.time, "time", lambda: current_time[0])
    csrf = csrf_from(client)

    for index in range(10):
        assert client.post("/message", data={"csrf_token": csrf, "text": f"Before {index}"}).status_code == 302
    assert client.post("/message", data={"csrf_token": csrf, "text": "Blocked"}).status_code == 429

    current_time[0] += 301
    response = client.post("/message", data={"csrf_token": csrf, "text": "After window"})

    assert response.status_code == 302
    assert len(db_rows("messages")) == 11


def test_admin_login_page_is_no_store_and_contains_csrf(client):
    response = client.get(site.ADMIN_PATH)

    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store, max-age=0"
    assert b'name="csrf_token"' in response.data


def test_admin_aliases_are_no_store_even_when_redirecting(client):
    legacy = client.get(site.LEGACY_ADMIN_PATH)
    old_alias = client.get("/admin")

    assert legacy.status_code == 302
    assert old_alias.status_code == 302
    assert legacy.headers["Cache-Control"] == "no-store, max-age=0"
    assert old_alias.headers["Cache-Control"] == "no-store, max-age=0"


def test_admin_login_requires_csrf(client):
    response = client.post(site.ADMIN_PATH, data={"password": "secret"})

    assert response.status_code == 400


def test_admin_rejects_wrong_password_without_session(client):
    csrf = csrf_from(client, site.ADMIN_PATH)

    response = client.post(site.ADMIN_PATH, data={"password": "wrong", "csrf_token": csrf})

    assert response.status_code == 200
    with client.session_transaction() as session:
        assert "admin" not in session
    assert "Неверный пароль".encode() in response.data


def test_admin_accepts_plain_password_and_rotates_csrf(client):
    old_csrf = csrf_from(client, site.ADMIN_PATH)

    response = client.post(site.ADMIN_PATH, data={"password": "secret", "csrf_token": old_csrf})

    assert response.status_code == 302
    assert response.headers["Location"] == site.ADMIN_PATH
    with client.session_transaction() as session:
        assert session["admin"] is True
        assert session["_csrf_token"] != old_csrf


def test_admin_login_clears_preexisting_session_state_to_prevent_fixation(client):
    csrf = csrf_from(client, site.ADMIN_PATH)
    with client.session_transaction() as session:
        session["cart"] = "unexpected-state"
        session["next"] = "/malicious"

    response = client.post(site.ADMIN_PATH, data={"password": "secret", "csrf_token": csrf})

    assert response.status_code == 302
    with client.session_transaction() as session:
        assert session["admin"] is True
        assert "cart" not in session
        assert "next" not in session


def test_admin_accepts_configured_password_hash(client, monkeypatch):
    monkeypatch.setattr(site, "ADMIN_PASSWORD_HASH", generate_password_hash("hashed-secret"))
    csrf = csrf_from(client, site.ADMIN_PATH)

    response = client.post(site.ADMIN_PATH, data={"password": "hashed-secret", "csrf_token": csrf})

    assert response.status_code == 302
    with client.session_transaction() as session:
        assert session["admin"] is True


def test_admin_password_hash_rejects_plain_fallback_password(client, monkeypatch):
    monkeypatch.setattr(site, "ADMIN_PASSWORD_HASH", generate_password_hash("hashed-secret"))
    csrf = csrf_from(client, site.ADMIN_PATH)

    response = client.post(site.ADMIN_PATH, data={"password": "secret", "csrf_token": csrf})

    assert response.status_code == 200
    with client.session_transaction() as session:
        assert "admin" not in session


def test_admin_login_rate_limit_blocks_brute_force_attempts(client):
    csrf = csrf_from(client, site.ADMIN_PATH)
    for _ in range(5):
        response = client.post(site.ADMIN_PATH, data={"password": "bad", "csrf_token": csrf})
        assert response.status_code == 200

    blocked = client.post(site.ADMIN_PATH, data={"password": "bad", "csrf_token": csrf})

    assert blocked.status_code == 429


def test_admin_dashboard_counts_only_recent_activity_and_orders_clicks(client, monkeypatch):
    monkeypatch.setattr(site, "cutoff_30_days", lambda: "2026-01-01 00:00:00")
    site.init_db()
    with sqlite3.connect(site.DB_PATH) as db:
        db.executemany(
            "INSERT INTO visits (created_at, ip, user_agent) VALUES (?, ?, ?)",
            [
                ("2026-01-02 00:00:00", "1.1.1.1", "new"),
                ("2025-12-31 23:59:59", "2.2.2.2", "old"),
            ],
        )
        db.executemany(
            "INSERT INTO unique_visits (visitor_id, first_seen_at, ip, user_agent) VALUES (?, ?, ?, ?)",
            [
                ("new", "2026-01-02 00:00:00", "1.1.1.1", "new"),
                ("old", "2025-12-31 23:59:59", "2.2.2.2", "old"),
            ],
        )
        db.executemany(
            "INSERT INTO clicks (social, created_at) VALUES (?, ?)",
            [
                ("Telegram", "2026-01-02 00:00:00"),
                ("Telegram", "2026-01-02 00:00:00"),
                ("VK", "2026-01-02 00:00:00"),
                ("Old", "2025-12-31 23:59:59"),
            ],
        )
        db.executemany(
            "INSERT INTO messages (name, contact, text, created_at) VALUES (?, ?, ?, ?)",
            [
                ("Recent", "", "visible", "2026-01-02 00:00:00"),
                ("Old", "", "hidden", "2025-12-31 23:59:59"),
            ],
        )
    login_as_admin(client)

    response = client.get(site.ADMIN_PATH)

    assert response.status_code == 200
    assert b'data-admin-shell' in response.data
    assert b"loadAdminTab" in response.data
    assert b"<strong>1</strong>" in response.data
    assert b"Telegram" in response.data
    assert response.data.index(b"Telegram") < response.data.index(b"VK")
    assert 'href="/st/messages"'.encode() in response.data
    assert b"Recent" not in response.data
    assert b"Old" not in response.data


def test_admin_dashboard_empty_state_is_rendered_without_seed_data(client):
    login_as_admin(client)

    response = client.get(site.ADMIN_PATH)

    assert response.status_code == 200
    assert b"<strong>0</strong>" in response.data
    assert "Кликов пока нет.".encode() in response.data
    assert b'class="message-admin-card"' not in response.data
    assert 'href="/st/clients"'.encode() in response.data
    assert 'href="/st/messages"'.encode() in response.data
    assert "Страницы клиентов".encode() not in response.data
    assert b'name="photo_link"' not in response.data
    assert b'type="file"' not in response.data
    assert b'multipart/form-data' not in response.data


def test_admin_clients_tab_lists_photo_clients_and_creation_form_without_file_storage(client):
    insert_photo_client()
    login_as_admin(client)

    response = client.get(f"{site.ADMIN_PATH}/clients")

    assert response.status_code == 200
    assert "Страницы клиентов".encode() in response.data
    assert 'href="/st"'.encode() in response.data
    assert 'href="/st/clients"'.encode() in response.data
    assert b'name="photo_link"' in response.data
    assert b'name="slug"' not in response.data
    assert b"https://drive.google.com/photos" in response.data
    assert b"https://ph.khudoverdiev.ru/client/ivanova-2026" in response.data
    assert "Клиентские страницы пока не созданы.".encode() not in response.data
    assert b'type="file"' not in response.data
    assert b'multipart/form-data' not in response.data


def test_admin_clients_tab_requires_authorization_and_is_no_store(client):
    response = client.get(f"{site.ADMIN_PATH}/clients")

    assert response.status_code == 302
    assert response.headers["Location"] == site.ADMIN_PATH
    assert response.headers["Cache-Control"] == "no-store, max-age=0"


def test_admin_clients_tab_empty_state_is_separate_from_dashboard(client):
    login_as_admin(client)

    response = client.get(f"{site.ADMIN_PATH}/clients")

    assert response.status_code == 200
    assert "Клиентские страницы пока не созданы.".encode() in response.data
    assert "Клики по соцсетям".encode() not in response.data
    assert 'class="message-admin-card"'.encode() not in response.data


def test_admin_messages_tab_requires_authorization_and_is_no_store(client):
    response = client.get(f"{site.ADMIN_PATH}/messages")

    assert response.status_code == 302
    assert response.headers["Location"] == site.ADMIN_PATH
    assert response.headers["Cache-Control"] == "no-store, max-age=0"


def test_admin_messages_tab_groups_recent_messages_by_source(client, monkeypatch):
    monkeypatch.setattr(site, "cutoff_30_days", lambda: "2026-01-01 00:00:00")
    insert_message(name="Root lead", text="Taplink", created_at="2026-01-02 00:00:00", site_source="khudoverdiev.ru")
    insert_message(name="IT lead", text="CRM", created_at="2026-01-03 00:00:00", site_source="it.khudoverdiev.ru")
    insert_message(name="Old lead", text="Hidden", created_at="2025-12-31 23:59:59", site_source="it.khudoverdiev.ru")
    login_as_admin(client)

    response = client.get(f"{site.ADMIN_PATH}/messages")

    assert response.status_code == 200
    assert b'id="messages-count">2</strong>' in response.data
    assert b"khudoverdiev.ru" in response.data
    assert b"it.khudoverdiev.ru" in response.data
    assert b"Root lead" in response.data
    assert b"IT lead" in response.data
    assert b"Old lead" not in response.data


def test_photo_client_page_renders_personal_redirect_buttons_without_storing_photos(client):
    insert_photo_client(client_name="Алина", slug="wedding-alina-2026", discount_text="скидку 15%")

    response = client.get("/client/wedding-alina-2026", base_url="http://ph.khudoverdiev.ru")

    assert response.status_code == 200
    assert "Спасибо за съемку,".encode() in response.data
    assert "Алина!".encode() in response.data
    assert "скидку 15%".encode() in response.data
    assert b"photo/portrait-cutout.png" in response.data
    assert b"class=\"client-photo-stage\"" in response.data
    assert b"img/profile-new.jpg" not in response.data
    assert "Владимир Худовердиев</a>".encode() not in response.data
    assert "Фотограф".encode() in response.data
    assert "Владимир Худовердиев</strong>".encode() in response.data
    assert b"photo/ph-favicon.ico" in response.data
    assert b"photo/ph-favicon.svg" in response.data
    assert b"photo/ph-favicon.png" in response.data
    assert b"portfolio/vh-favicon.svg" not in response.data
    assert b"photo/mikhail-" not in response.data
    assert b'href="https://drive.google.com/photos"' in response.data
    assert b'href="https://reviews.example/ivanova"' in response.data
    assert b"<form" not in response.data
    assert b'type="file"' not in response.data


def test_old_phh_client_page_redirects_to_ph_client_url(client):
    insert_photo_client(slug="old-safe-link")

    response = client.get("/client/old-safe-link", base_url="http://phh.khudoverdiev.ru")

    assert response.status_code == 301
    assert response.headers["Location"] == "https://ph.khudoverdiev.ru/client/old-safe-link"


def test_inactive_or_missing_photo_client_shows_unavailable_state_without_links(client):
    insert_photo_client(slug="disabled-client", is_active=0)

    inactive = client.get("/client/disabled-client", base_url="http://ph.khudoverdiev.ru")
    missing = client.get("/client/missing-client", base_url="http://ph.khudoverdiev.ru")

    assert inactive.status_code == 404
    assert missing.status_code == 404
    assert "Материалы недоступны".encode() in inactive.data
    assert "Владимир Худовердиев</a>".encode() not in inactive.data
    assert b"photo/ph-favicon.ico" in inactive.data
    assert b"photo/ph-favicon.svg" in inactive.data
    assert b"photo/ph-favicon.png" in inactive.data
    assert b"portfolio/vh-favicon.svg" not in inactive.data
    assert b"https://drive.google.com/photos" not in inactive.data


def test_photo_client_page_rejects_unsafe_links_already_in_database(client):
    insert_photo_client(slug="unsafe-existing", photo_link="javascript:alert(1)")

    response = client.get("/client/unsafe-existing", base_url="http://ph.khudoverdiev.ru")

    assert response.status_code == 404
    assert b"javascript:alert(1)" not in response.data


def test_photo_client_admin_create_requires_authorization_and_csrf(client):
    unauthorized = client.post(f"{site.ADMIN_PATH}/clients", data={"client_name": "A"})
    login_as_admin(client)

    missing_csrf = client.post(
        f"{site.ADMIN_PATH}/clients",
        data={"client_name": "A", "slug": "a-client", "photo_link": "https://drive.google.com/a"},
    )

    assert unauthorized.status_code == 302
    assert unauthorized.headers["Location"] == site.ADMIN_PATH
    assert missing_csrf.status_code == 400


def test_photo_client_admin_creates_unique_external_redirect_page(client):
    login_as_admin(client)
    with client.session_transaction() as session:
        csrf = session["_csrf_token"]

    response = client.post(
        f"{site.ADMIN_PATH}/clients",
        data={
            "csrf_token": csrf,
            "client_name": "Ivanova",
            "slug": " Ivanova_2026 ",
            "photo_link": "https://disk.yandex.ru/d/client",
            "review_link": "https://example.com/review",
            "discount_text": "20%",
            "message_text": "Фотографии готовы.",
            "is_active": "1",
        },
    )

    assert response.status_code == 302
    rows = db_rows("photo_clients")
    assert len(rows) == 1
    generated_slug = rows[0]["slug"]
    assert generated_slug != "ivanova-2026"
    assert re.fullmatch(r"[a-z0-9]{32}", generated_slug)
    created = client.get(f"/client/{generated_slug}")
    assert created.status_code == 200
    assert b"https://disk.yandex.ru/d/client" in created.data
    assert client.get("/client/ivanova-2026").status_code == 404


def test_photo_client_admin_ignores_submitted_slug_and_rejects_unsafe_external_links(client):
    insert_photo_client(slug="ivanova-2026")
    login_as_admin(client)
    with client.session_transaction() as session:
        csrf = session["_csrf_token"]

    ignored_slug = client.post(
        f"{site.ADMIN_PATH}/clients",
        data={
            "csrf_token": csrf,
            "client_name": "Ignored",
            "slug": "ivanova-2026",
            "photo_link": "https://dropbox.com/s/client",
            "is_active": "1",
        },
    )
    unsafe = client.post(
        f"{site.ADMIN_PATH}/clients",
        data={
            "csrf_token": csrf,
            "client_name": "Unsafe",
            "slug": "unsafe-client",
            "photo_link": "javascript:alert(1)",
            "is_active": "1",
        },
    )

    assert ignored_slug.status_code == 302
    assert unsafe.status_code == 400
    rows = db_rows("photo_clients")
    assert len(rows) == 2
    assert rows[1]["slug"] != "ivanova-2026"
    assert re.fullmatch(r"[a-z0-9]{32}", rows[1]["slug"])


def test_photo_client_admin_updates_and_deletes_client_records(client):
    client_id = insert_photo_client(slug="old-slug")
    login_as_admin(client)
    with client.session_transaction() as session:
        csrf = session["_csrf_token"]

    updated = client.post(
        f"{site.ADMIN_PATH}/clients/{client_id}",
        data={
            "csrf_token": csrf,
            "client_name": "Updated",
            "slug": "new-slug",
            "photo_link": "https://dropbox.com/s/new",
            "review_link": "",
            "discount_text": "подарок",
            "message_text": "Новая ссылка готова.",
        },
    )
    unavailable = client.get("/client/new-slug")
    rows = db_rows("photo_clients")
    deleted = client.post(f"{site.ADMIN_PATH}/clients/{client_id}/delete", data={"csrf_token": csrf})

    assert updated.status_code == 302
    assert unavailable.status_code == 404
    assert rows[0]["slug"] == "old-slug"
    assert deleted.status_code == 302
    assert db_rows("photo_clients") == []


def test_photo_client_admin_can_rotate_existing_client_link(client):
    client_id = insert_photo_client(slug="ivanova-2026")
    login_as_admin(client)
    with client.session_transaction() as session:
        csrf = session["_csrf_token"]

    response = client.post(f"{site.ADMIN_PATH}/clients/{client_id}/rotate-link", data={"csrf_token": csrf})

    assert response.status_code == 302
    rows = db_rows("photo_clients")
    assert len(rows) == 1
    assert rows[0]["slug"] != "ivanova-2026"
    assert re.fullmatch(r"[a-z0-9]{32}", rows[0]["slug"])
    assert client.get("/client/ivanova-2026").status_code == 404
    assert client.get(f"/client/{rows[0]['slug']}").status_code == 200


def test_photo_client_rotate_link_requires_admin_and_csrf(client):
    client_id = insert_photo_client()

    unauthorized = client.post(f"{site.ADMIN_PATH}/clients/{client_id}/rotate-link")
    login_as_admin(client)
    missing_csrf = client.post(f"{site.ADMIN_PATH}/clients/{client_id}/rotate-link")

    assert unauthorized.status_code == 302
    assert missing_csrf.status_code == 400
    assert db_rows("photo_clients")[0]["slug"] == "ivanova-2026"


def test_photo_client_delete_requires_admin_and_csrf(client):
    client_id = insert_photo_client()

    unauthorized = client.post(f"{site.ADMIN_PATH}/clients/{client_id}/delete")
    login_as_admin(client)
    missing_csrf = client.post(f"{site.ADMIN_PATH}/clients/{client_id}/delete")

    assert unauthorized.status_code == 302
    assert missing_csrf.status_code == 400
    assert len(db_rows("photo_clients")) == 1


def test_admin_messages_can_render_empty_messages_state_after_ajax_delete(client):
    insert_message()
    login_as_admin(client)

    response = client.get(f"{site.ADMIN_PATH}/messages")

    assert b'id="message-list"' in response.data
    assert b"function renderEmptyMessagesState()" in response.data
    assert "messageList.outerHTML = '<p class=\"empty\" id=\"message-list\">Нет пока обращений.</p>';".encode() in response.data


def test_admin_messages_escapes_user_supplied_message_content(client, monkeypatch):
    monkeypatch.setattr(site, "cutoff_30_days", lambda: "2026-01-01 00:00:00")
    insert_message(name="<script>alert(1)</script>", contact="<b>contact</b>", text="<img src=x onerror=alert(1)>", created_at="2026-01-02 00:00:00")
    login_as_admin(client)

    response = client.get(f"{site.ADMIN_PATH}/messages")

    assert response.status_code == 200
    assert b"<script>alert(1)</script>" not in response.data
    assert b"&lt;script&gt;alert(1)&lt;/script&gt;" in response.data
    assert b"<img src=x onerror=alert(1)>" not in response.data
    assert b"&lt;img src=x onerror=alert(1)&gt;" in response.data


def test_init_db_is_idempotent_and_preserves_existing_data(client):
    message_id = insert_message()

    site.init_db()
    site.init_db()

    messages = db_rows("messages")
    assert len(messages) == 1
    assert messages[0]["id"] == message_id


def test_init_db_creates_expected_not_null_schema_contract(client):
    site.init_db()

    messages = table_columns("messages")
    visits = table_columns("visits")
    unique_visits = table_columns("unique_visits")
    photo_clients = table_columns("photo_clients")
    assert messages["name"]["notnull"] == 1
    assert messages["text"]["notnull"] == 1
    assert messages["site_source"]["notnull"] == 1
    assert messages["created_at"]["notnull"] == 1
    assert visits["created_at"]["notnull"] == 1
    assert unique_visits["visitor_id"]["pk"] == 1
    assert unique_visits["first_seen_at"]["notnull"] == 1
    assert photo_clients["client_name"]["notnull"] == 1
    assert photo_clients["slug"]["notnull"] == 1
    assert photo_clients["photo_link"]["notnull"] == 1
    assert photo_clients["is_active"]["notnull"] == 1


def test_unauthorized_delete_redirects_to_admin_without_deleting(client):
    message_id = insert_message()

    response = client.post(f"{site.ADMIN_PATH}/messages/{message_id}/delete")

    assert response.status_code == 302
    assert response.headers["Location"] == site.ADMIN_PATH
    assert len(db_rows("messages")) == 1


def test_authorized_delete_requires_csrf(client):
    message_id = insert_message()
    login_as_admin(client)

    response = client.post(f"{site.ADMIN_PATH}/messages/{message_id}/delete")

    assert response.status_code == 400
    assert len(db_rows("messages")) == 1


def test_delete_endpoint_rejects_get_requests_even_for_authorized_admin(client):
    message_id = insert_message()
    login_as_admin(client)

    response = client.get(f"{site.ADMIN_PATH}/messages/{message_id}/delete")

    assert response.status_code == 405
    assert len(db_rows("messages")) == 1


def test_authorized_delete_removes_message_and_redirects(client):
    message_id = insert_message()
    login_as_admin(client)
    with client.session_transaction() as session:
        csrf = session["_csrf_token"]

    response = client.post(f"{site.ADMIN_PATH}/messages/{message_id}/delete", data={"csrf_token": csrf})

    assert response.status_code == 302
    assert response.headers["Location"] == f"{site.ADMIN_PATH}/messages"
    assert db_rows("messages") == []


def test_fetch_delete_returns_no_content(client):
    message_id = insert_message()
    login_as_admin(client)
    with client.session_transaction() as session:
        csrf = session["_csrf_token"]

    response = client.post(
        f"{site.ADMIN_PATH}/messages/{message_id}/delete",
        headers={"X-Requested-With": "fetch", "X-CSRF-Token": csrf},
    )

    assert response.status_code == 204
    assert db_rows("messages") == []


def test_delete_missing_message_is_idempotent_for_authorized_admin(client):
    login_as_admin(client)
    with client.session_transaction() as session:
        csrf = session["_csrf_token"]

    response = client.post(f"{site.ADMIN_PATH}/messages/999999/delete", data={"csrf_token": csrf})

    assert response.status_code == 302
    assert response.headers["Location"] == f"{site.ADMIN_PATH}/messages"
    assert db_rows("messages") == []


def test_legacy_delete_path_preserves_post_semantics(client):
    message_id = insert_message()
    login_as_admin(client)
    with client.session_transaction() as session:
        csrf = session["_csrf_token"]

    response = client.post(f"{site.LEGACY_ADMIN_PATH}/messages/{message_id}/delete", data={"csrf_token": csrf})

    assert response.status_code == 302
    assert response.headers["Location"] == f"{site.ADMIN_PATH}/messages"
    assert db_rows("messages") == []


def test_logout_removes_only_admin_flag(client):
    login_as_admin(client)
    with client.session_transaction() as session:
        csrf = session["_csrf_token"]

    response = client.get(f"{site.ADMIN_PATH}/logout")

    assert response.status_code == 302
    with client.session_transaction() as session:
        assert "admin" not in session
        assert session["_csrf_token"] == csrf


def test_legacy_routes_redirect_to_current_admin_paths(client):
    assert client.get(site.LEGACY_ADMIN_PATH).headers["Location"] == site.ADMIN_PATH
    assert client.get("/admin").headers["Location"] == site.ADMIN_PATH
    assert client.get(f"{site.LEGACY_ADMIN_PATH}/logout").headers["Location"] == f"{site.ADMIN_PATH}/logout"


def test_health_endpoint_reports_ok(client):
    response = client.get("/health")

    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}
