import re
import sqlite3
from pathlib import Path

import pytest
from werkzeug.security import generate_password_hash

import app as site


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(site, "DB_PATH", tmp_path / "site.db")
    monkeypatch.setattr(site, "ADMIN_USERNAME", "admin")
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
    return client.post(site.ADMIN_PATH, data={"username": "admin", "password": "secret", "csrf_token": csrf})


def test_index_records_visit_sets_stable_visitor_cookie_and_security_headers(client):
    response = client.get("/")
    cookies = response.headers.getlist("Set-Cookie")

    assert response.status_code == 200
    assert any(cookie.startswith("visitor_id=") for cookie in cookies)
    assert any("root_message_device=" in cookie for cookie in response.headers.getlist("Set-Cookie"))
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]
    visits = db_rows("visits")
    assert len(visits) == 1
    assert visits[0]["site_source"] == "khudoverdiev.ru"
    assert len(db_rows("unique_visits")) == 1


def test_index_visitor_cookie_has_privacy_and_lifetime_attributes(client):
    response = client.get("/")
    cookies = response.headers.getlist("Set-Cookie")
    visitor_cookie = next(cookie for cookie in cookies if cookie.startswith("visitor_id="))
    message_cookie = next(cookie for cookie in cookies if cookie.startswith("root_message_device="))

    assert "Max-Age=31536000" in visitor_cookie
    assert "HttpOnly" in visitor_cookie
    assert "SameSite=Lax" in visitor_cookie
    assert "Max-Age=31536000" in message_cookie
    assert "HttpOnly" in message_cookie
    assert "SameSite=Lax" in message_cookie


def test_index_records_remote_addr_and_user_agent_for_visit_audit(client):
    response = client.get("/", environ_base={"REMOTE_ADDR": "198.51.100.20"}, headers={"User-Agent": "qa-browser"})

    assert response.status_code == 200
    visit = db_rows("visits")[0]
    unique_visit = db_rows("unique_visits")[0]
    assert visit["ip"] == "198.51.100.20"
    assert visit["user_agent"] == "qa-browser"
    assert visit["site_source"] == "khudoverdiev.ru"
    assert unique_visit["ip"] == "198.51.100.20"
    assert unique_visit["user_agent"] == "qa-browser"


def test_index_counts_returning_cookie_as_new_visit_but_not_new_unique_visitor(client):
    first = client.get("/")
    visitor_header = next(cookie for cookie in first.headers.getlist("Set-Cookie") if cookie.startswith("visitor_id="))
    visitor_cookie = visitor_header.split("visitor_id=", 1)[1].split(";", 1)[0]

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
    assert b"css/styles.css?v=5" in response.data
    assert b'id="message-form-error"' in response.data
    assert b"payload.error" in response.data
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
    visitor_cookie = next(cookie for cookie in response.headers.getlist("Set-Cookie") if cookie.startswith("visitor_id="))

    assert "Secure" in visitor_cookie


def test_large_message_payload_is_rejected_before_persisting_body(client):
    csrf = csrf_from(client)

    response = client.post("/message", data={"csrf_token": csrf, "text": "A" * (17 * 1024)})

    assert response.status_code == 413
    assert db_rows("messages") == []


@pytest.mark.parametrize(
    ("base_url", "expected_branch"),
    [
        ("http://khudoverdiev.ru", "root"),
        ("http://www.khudoverdiev.ru", "root"),
        ("http://it.khudoverdiev.ru", "it"),
        ("http://it.localhost", "it"),
        ("http://ph.khudoverdiev.ru", "ph"),
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
    assert b'content="width=device-width, initial-scale=1, viewport-fit=cover"' in portfolio.data
    assert b"css/it.css?v=97" in portfolio.data
    assert b'id="project-prompt"' in portfolio.data
    assert b'class="project-prompt-close"' in portfolio.data
    assert b'data-close-project-prompt' in portfolio.data
    assert b"data-project-prompt-contact" in portfolio.data
    assert b'name="form_type" value="project"' in portfolio.data
    assert any("project_lead_device=" in cookie for cookie in portfolio.headers.getlist("Set-Cookie"))
    assert "30 секунд на сайте".encode() not in portfolio.data
    assert b"class=\"desktop-scale-shell\"" in portfolio.data
    assert b"class=\"desktop-scale-stage\"" in portfolio.data
    assert b"class=\"rotate-lock\"" in portfolio.data
    assert "Поверните телефон обратно".encode() in portfolio.data
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
    assert b"class=\"ui-icon ui-icon-symbol ui-icon-arrow-up-right\"" in portfolio.data
    assert b"class=\"ui-icon ui-icon-symbol ui-icon-play\"" in portfolio.data
    assert b"class=\"ui-icon ui-icon-symbol ui-icon-arrow-down\"" in portfolio.data
    assert b"class=\"mobile-action-console\"" in portfolio.data
    assert b"class=\"mobile-console-bar\"" in portfolio.data
    assert b"class=\"mobile-console-status\"" in portfolio.data
    assert b"cases / launch.ts" in portfolio.data
    assert b"scroll.down.to_cases()" in portfolio.data
    assert b"class=\"about-mobile-line\"" in portfolio.data
    assert b"class=\"about-mobile-copy\"" in portfolio.data
    for symbol in ("↗︎", "↓", "←", "→", "▶︎", "✓"):
        assert symbol.encode() in portfolio.data
    css = Path("static/css/it.css").read_text(encoding="utf-8")
    favicon = Path("static/portfolio/vh-favicon.svg").read_text(encoding="utf-8")
    assert 'font-size="23"' in favicon
    assert ">IT</text>" in favicon
    assert ">VH</text>" not in favicon
    assert 'cx="45.5"' in favicon
    assert ".project-actions > button.media-button:first-child" not in css
    assert "--desktop-width: 1320px;" in css
    assert "--desktop-canvas-width: 1920px;" in css
    assert "--desktop-canvas-height: 1080px;" in css
    assert "--desktop-scale: 1;" in css
    assert "--mobile-hero-height: 720px;" in css
    assert "--mobile-hero-bg: #070907;" in css
    assert "--mobile-hero-bottom-space: calc(38px + env(safe-area-inset-bottom));" in css
    assert "--mobile-console-height: 320px;" in css
    assert ".desktop-scale-stage {\n        width: var(--desktop-canvas-width);" in css
    assert "zoom: var(--desktop-scale);" in css
    assert "translate: 0 -68px;" in css
    assert "min-width: var(--desktop-canvas-width);" not in css
    assert "overflow-x: auto;" not in css
    assert "min-height: var(--desktop-canvas-height);" in css
    assert "clamp(" not in css
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
    assert "@media (min-width: 500px)" in css
    assert "@media (max-width: 499px)" in css
    assert "@media (min-width: 901px)" not in css
    assert "@media (max-width: 900px)" not in css
    width_media_queries = re.findall(r"@media\s*\((?:min|max)-width:[^)]+\)", css)
    assert width_media_queries == [
        "@media (min-width: 500px)",
        "@media (max-width: 499px)",
    ]
    assert "body {\n        min-width: 0;\n        overflow-x: hidden;" in css
    portfolio_text = portfolio.get_data(as_text=True)
    assert "desktopCanvasWidth = 1920" in portfolio_text
    assert "window.matchMedia('(min-width: 500px)')" in portfolio_text
    assert "updateMobileViewport" not in portfolio_text
    assert "visualViewport" not in portfolio_text
    assert "visualViewport.addEventListener" not in portfolio_text
    assert "visualViewport.addEventListener('scroll', updateMobileViewport" not in portfolio_text
    assert "projectPromptDelay = 120000" in portfolio_text
    assert "window.setTimeout(showProjectPrompt, projectPromptDelay)" in portfolio_text
    assert "projectPromptContact.addEventListener('click', openContact)" in portfolio_text
    assert "const contactDialog = contactModal.querySelector('.contact-dialog');" in portfolio_text
    assert "const openedFromProjectPrompt = Boolean(event.currentTarget.closest('#project-prompt'));" in portfolio_text
    assert "contactDialog.focus({ preventScroll: true });" in portfolio_text
    assert "contactModal.querySelector('input[name=\"name\"]').focus()" not in portfolio_text
    assert "payload.error" in portfolio_text
    assert "project-prompt-backdrop" in css
    assert "backdrop-filter: blur(18px) saturate(0.86);" in css
    assert ".project-prompt-kicker" not in css
    assert ".project-prompt-close {\n    position: absolute;\n    z-index: 2;" in css
    assert ".project-prompt-close:hover,\n.project-prompt-close:focus-visible {" in css
    assert ".project-prompt-primary {\n    min-height: 58px;" in css
    assert "border-radius: 6px;\n    background: var(--ink);\n    color: #fff;" in css
    assert ".project-prompt-primary .ui-icon {\n    color: #fff;" in css
    assert ".contact-dialog {\n    position: relative;\n    width: 840px;\n    min-height: 520px;" in css
    assert "outline: none;" in css
    assert "width: min(390px, calc(100vw - 28px));" in css
    assert "min-height: 0;\n        max-height: min(680px, calc(100dvh - 48px));" in css
    assert "max-height: min(680px, calc(100dvh - 48px));" in css
    assert "getScaledOffsetTop(element)" in portfolio_text
    assert "scrollToScaledTarget(target || document.getElementById('site-footer'))" in portfolio_text
    assert "/* Mobile polish: one deliberate layout, not a squeezed desktop. */" in css
    assert "--mobile-viewport-height" not in css
    assert ".hero {\n        height: var(--mobile-hero-height);\n        min-height: 704px;" in css
    assert "background: var(--mobile-hero-bg);" in css
    assert ".hero::before {\n        display: none;" in css
    assert ".hero-grid {\n        position: relative;\n        z-index: 1;\n        height: var(--mobile-hero-height);\n        min-height: 704px;" in css
    assert "padding: 92px 0 calc(18px + env(safe-area-inset-bottom));" in css
    assert "transition:\n            background 180ms ease,\n            border-color 180ms ease,\n            box-shadow 180ms ease;" in css
    assert "@media (max-width: 499px) and (max-height: 820px)" not in css
    assert "grid-template-rows: auto auto auto auto minmax(152px, 1fr) auto;" not in css
    assert "padding-top: 96px;" not in css
    assert "height: min(320px, 40svh);" not in css
    assert "grid-template-rows: 26px repeat(8, minmax(18px, 1fr)) 26px;" not in css
    assert "html.is-mobile-compact-hero" not in css
    assert ".mobile-action-console {\n        width: 100%;\n        height: 260px;" in css
    assert "grid-template-rows: 24px repeat(8, minmax(20px, 1fr)) 24px;" in css
    assert "lockMobileHeroHeight" not in portfolio_text
    assert "resetMobileHeroState();" in portfolio_text
    assert "@media (orientation: landscape) and (max-height: 499px) and (pointer: coarse)" in css
    assert ".rotate-lock {\n        position: fixed;\n        z-index: 9999;" in css
    rotate_lock = re.search(r"\.rotate-lock \{(?P<body>.*?)\n    \}", css, re.S)
    assert rotate_lock is not None
    assert "width: 100dvw;" not in rotate_lock.group("body")
    assert "height: 100dvh;" not in rotate_lock.group("body")
    assert ".rotate-lock::before {\n        content: \"\";\n        position: fixed;" in css
    assert "max(24px, env(safe-area-inset-right))" in css
    assert ".desktop-scale-shell,\n    .page-scroll-cue,\n    .project-prompt-modal,\n    .media-modal,\n    .contact-modal {\n        visibility: hidden;" in css
    assert "grid-template-rows: auto auto auto auto auto auto;" in css
    assert "grid-template-rows: auto auto auto auto minmax(112px, 1fr) auto;" not in css
    assert "grid-template-columns: minmax(0, 1fr) 118px;" not in css
    assert ".hero-copy {\n        display: flex;\n        flex-direction: column;\n        width: 100%;" in css
    assert ".hero::after {\n        content: \"\";\n        position: absolute;\n        z-index: 0;" in css
    assert ".hero h1 {\n        max-width: 100%;" in css
    assert ".portrait-wrap {\n        display: none;" in css
    assert ".mobile-action-console {\n    display: none;" in css
    assert ".mobile-action-console {\n        width: 100%;" in css
    assert "height: var(--mobile-console-height);" not in css
    assert "height: calc(100% - 26px);" not in css
    assert "align-self: start;" in css
    assert "grid-template-rows: 30px repeat(8, minmax(29px, 1fr)) 30px;" not in css
    assert "grid-template-rows: 24px repeat(8, minmax(20px, 1fr)) 24px;" in css
    assert ".mobile-console-bar,\n    .mobile-console-status {" in css
    assert ".mobile-console-bar + .mobile-code-line {\n        border-top: 0;" in css
    assert "animation: console-in 800ms var(--ease-out) 120ms both;" in css
    assert ".hero-actions {\n        margin-top: 16px;" in css
    assert ".about-mobile-line,\n    .about h2 em {\n        display: block;" in css
    assert ".about-desktop-copy {\n        display: none;" in css
    assert ".about-mobile-copy {\n        display: inline;" in css
    assert ".about-code-highlight {\n        display: inline-flex;" in css
    assert ".about-copy > p {\n        max-width: 330px;\n        margin-top: 2px;\n        padding: 0;" in css
    assert ".principles {\n        display: grid;\n        grid-template-columns: 1fr;" in css
    principles_hover = re.search(r"\.principles article:hover \{(?P<body>.*?)\n\}", css, re.S)
    assert principles_hover is not None
    assert "background:" not in principles_hover.group("body")
    assert "background-color: #1d2418;" in principles_hover.group("body")
    assert ".ui-icon-symbol::before,\n.ui-icon-symbol::after {\n    display: none;" in css
    assert "flex: 0 0 248px" not in css
    assert "scroll-snap-type: x mandatory;" not in css
    assert ".media-button {\n        min-height: 54px;\n        padding: 0 12px 0 17px;\n        border-radius: 999px;" in css
    assert ".media-dialog {\n        width: calc(100vw - 20px);" in css
    assert ".media-stage {\n        grid-column: 1 / -1;\n        grid-row: 1;" in css
    assert "max-height: calc(100svh - 140px);" in css
    assert ".media-viewer {\n        display: grid;\n        grid-template-columns: 1fr 1fr;\n        grid-template-rows: auto 42px;" in css
    assert ".media-nav {\n        position: relative;\n        top: auto;" in css
    assert ".media-prev {\n        grid-column: 1;\n        grid-row: 2;" in css
    assert ".media-next {\n        grid-column: 2;\n        grid-row: 2;" in css
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


def test_it_mobile_hero_height_does_not_follow_browser_viewport(client):
    client.get("/", base_url="http://it.khudoverdiev.ru")
    css = Path("static/css/it.css").read_text(encoding="utf-8")
    portfolio_text = Path("templates/it.html").read_text(encoding="utf-8")

    mobile_css = re.search(r"@media \(max-width: 499px\) \{(?P<body>.*?)\n\}", css, re.S)
    assert mobile_css is not None
    assert "--mobile-viewport-height" not in css
    assert "visualViewport" not in portfolio_text
    assert "--mobile-hero-height: 720px;" in css
    assert "--mobile-console-height: 320px;" in css
    assert ".hero {\n        height: var(--mobile-hero-height);\n        min-height: 704px;" in css
    assert ".hero {\n        height: var(--mobile-hero-height);\n        min-height: 704px;\n        position: relative;\n        z-index: 1;\n        overflow: visible;" in css
    assert ".hero-grid {\n        position: relative;\n        z-index: 1;\n        height: var(--mobile-hero-height);\n        min-height: 704px;" in css
    assert "width: min(408px, calc(100% - 32px));" in css
    assert "padding: 92px 0 calc(18px + env(safe-area-inset-bottom));" in css
    assert "min-height: var(--mobile-viewport-height)" not in css
    assert "height: min(320px, 40svh);" not in css
    assert "@media (max-width: 499px) and (max-height:" not in css
    assert "html.is-mobile-compact-hero" not in css
    assert ".mobile-action-console {\n        width: 100%;\n        height: 260px;" in css
    assert "const height = Math.max(620, getInitialMobileViewportHeight());" not in portfolio_text
    assert "is-mobile-compact-hero" not in portfolio_text
    assert "visualViewport.addEventListener" not in portfolio_text
    assert "if (!force && mobileHeroHeightLocked && currentWidth === mobileHeroLockWidth) return;" not in portfolio_text
    assert "resetMobileHeroState();" in portfolio_text


def test_it_portfolio_keeps_security_headers_and_records_visit(client):
    response = client.get("/", base_url="http://it.khudoverdiev.ru")

    assert response.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]
    assert len(db_rows("visits")) == 1
    assert len(db_rows("unique_visits")) == 1


def test_ph_subdomain_renders_photographer_portfolio(client):
    response = client.get("/", base_url="http://ph.khudoverdiev.ru")

    assert response.status_code == 200
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]
    assert "frame-src https://vk.com https://vk.ru https://vkvideo.ru" in response.headers["Content-Security-Policy"]
    assert b"css/photo.css" in response.data
    assert b"photo.css?v=49" in response.data
    assert b"js/photo.js" in response.data
    assert b"photo.js?v=19" in response.data
    assert "Архангельск, Северодвинск".encode() in response.data
    assert b"photo/ph-favicon.ico" in response.data
    assert b"photo/ph-favicon.svg" in response.data
    assert b"photo/ph-favicon.png" in response.data
    assert b"portfolio/vh-favicon.svg" not in response.data
    assert b">PH<span>.</span></a>" in response.data
    assert b">IT<span" not in response.data
    assert '<a href="#services">Фото</a>'.encode() in response.data
    assert '<a href="#services">Съемки</a>'.encode() not in response.data
    assert '<a href="#reviews">Отзывы</a>'.encode() in response.data
    assert b"photo/portrait-cutout.png" in response.data
    assert b"class=\"ph-portrait-orbit\"" in response.data
    assert b"class=\"ph-portrait-orbit\" aria-hidden=\"true\"></div>" in response.data
    assert b"class=\"ph-hero-collage\"" not in response.data
    assert b"photo/portfolio/portfolio-100.jpg" in response.data
    assert b"photo/portfolio/portfolio-123.jpg" in response.data
    assert b"photo/portfolio/portfolio-113.jpg" in response.data
    assert b"photo/portfolio/portfolio-110.jpg" in response.data
    assert b"photo/portfolio/portfolio-058.jpg" in response.data
    assert b"photo/mikhail-" not in response.data
    assert '<a class="ph-button ph-button-primary" href="#portfolio">Фото'.encode() in response.data
    assert "Смотреть портфолио".encode() not in response.data
    assert b"data-lightbox" in response.data
    assert b"data-photo-card" not in response.data
    assert b"data-card-next" not in response.data
    assert b"data-card-prev" not in response.data
    assert b"data-card-counter" not in response.data
    assert response.data.count(b"class=\"ph-work-slide is-active\"") == 5
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
    assert b'id="booking-success"' in response.data
    assert b'class="ph-booking-success-card"' in response.data
    assert b'data-booking-nudge' in response.data
    assert b'data-booking-nudge-open' in response.data
    assert b'class="ph-booking-nudge-card"' in response.data
    assert b'class="ph-booking-nudge-close"' in response.data
    assert "Желаете записаться на съемку?".encode() in response.data
    assert "Оставьте короткую заявку".encode() in response.data
    assert "Подробнее".encode() in response.data
    assert "Заявка отправлена. Я свяжусь с вами.".encode() not in response.data
    assert "Заявка принята".encode() in response.data
    assert "Я скоро напишу вам, чтобы согласовать дату, формат и детали съемки.".encode() in response.data
    assert "data-booking-nudge-open>Записаться".encode() not in response.data
    assert "У вас есть проект?".encode() not in response.data
    assert "Связаться".encode() not in response.data
    assert "Узнать подробности".encode() not in response.data
    assert "Оставьте детали, чтобы я сразу понял".encode() not in response.data
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
    assert "Выберите формат под задачу".encode() not in response.data
    assert b"class=\"ph-services-lead\"" not in response.data
    assert "актуального VK Market".encode() not in response.data
    assert "Ты, он и белое платье".encode() in response.data
    assert "Твоя фотосессия".encode() in response.data
    assert "Все сделаем за тебя".encode() in response.data
    assert "Фото+видео".encode() in response.data
    assert "Подарочный сертификат".encode() in response.data
    assert "4 000 ₽/час при заказе от 4х часов".encode() in response.data
    assert "от 4 000 ₽/час".encode() not in response.data
    assert "от 13 000 ₽".encode() in response.data
    assert b"https://vk.ru/market-190646738?screen=group" not in response.data
    assert "Дополнительно можно заказать".encode() not in response.data
    assert b'id="video"' in response.data
    assert b'class="ph-video-showcase"' in response.data
    assert b"data-video-player" in response.data
    assert b"data-video-card" in response.data
    assert b"data-video-frame" in response.data
    assert b"https://vk.com/video_ext.php?oid=-229443984&amp;id=456239042&amp;hd=2" in response.data
    assert b"https://vk.com/video_ext.php?oid=-229443984&amp;id=456239046&amp;hd=2" in response.data
    assert b'data-video-embed="https://vk.com/video_ext.php?oid=-229443984&amp;id=' in response.data
    assert b"data-video-url" not in response.data
    assert b"data-video-play>" not in response.data
    assert b'target="_blank" rel="noopener noreferrer" data-video-play' not in response.data
    assert "откройте ее в VK Video".encode() not in response.data
    assert "Видеопортфолио".encode() in response.data
    assert "Николай &amp; Галина".encode() in response.data
    assert "Промоакция магазина «Пятёрочка»".encode() in response.data
    assert "VK Клип".encode() in response.data
    assert "Видеосъемка".encode() in response.data
    assert "с живым дыханием".encode() in response.data
    assert "Сохраняю движение, голос, атмосферу".encode() not in response.data
    assert "Свадебный фильм".encode() in response.data
    assert "Главный эпизод".encode() in response.data
    assert "Творческий ролик".encode() in response.data
    assert "Контент для бренда".encode() in response.data
    assert "от 5 000 ₽/час".encode() in response.data
    assert "от 6 000 ₽/час".encode() in response.data
    assert "4 000 ₽/час при заказе от 4х часов".encode() in response.data
    assert "4 000 ₽/час при заказе от 2 часов".encode() not in response.data
    assert "От 4х часов".encode() in response.data
    assert "От 2 часов".encode() not in response.data
    assert b"https://vk.ru/v.khudoverdiev" not in response.data
    assert "Быстрый ответ во VK".encode() not in response.data
    assert "Открыть видеосъемку во VK".encode() not in response.data
    assert b'id="reviews"' in response.data
    assert "05 / Отзывы".encode() in response.data
    assert "После съемки".encode() in response.data
    assert "остается доверие".encode() in response.data
    assert b'class="ph-review-feature"' in response.data
    assert b'class="ph-review-feature-accent" aria-hidden="true"' in response.data
    assert b'class="ph-review-top"' in response.data
    assert b'class="ph-review-person"' in response.data
    assert b'class="ph-review-avatar" aria-hidden="true"' in response.data
    assert "Ю</span>".encode() in response.data
    assert "Н</span>".encode() in response.data
    assert b'class="ph-review-rating"' in response.data
    assert b">VK</span>" not in response.data
    assert b"data-reviews-open" not in response.data
    assert b"data-reviews-modal" not in response.data
    assert b"data-reviews-close" not in response.data
    assert "Посмотреть все".encode() in response.data
    assert b'class="ph-review-all-button" href="https://vk.ru/reviews-190646738"' in response.data
    assert "Открыть отзывы во ВКонтакте".encode() not in response.data
    assert "Открыть VK".encode() not in response.data
    assert "Все отзывы".encode() not in response.data
    assert 'id="reviews-modal-title"'.encode() not in response.data
    assert "Фото и видео".encode() not in response.data
    assert "Юлия Митягина".encode() in response.data
    assert "Большое спасибо Владимиру за замечательную фотосессию!".encode() in response.data
    assert "Наталья Неверова".encode() in response.data
    assert "Людмила Головкова".encode() in response.data
    assert "Елена Коняева".encode() in response.data
    assert "Галина Перова".encode() in response.data
    assert "Рекомендую Владимира всем, кто ищет качество и душевный подход!".encode() in response.data
    assert "очень нравиться подход к детям".encode() in response.data
    assert "Обратились к Владимиру для видеосъемки на свадьбе.".encode() in response.data
    assert "Спасибо большое.".encode() in response.data
    assert "Алина и Дмитрий".encode() not in response.data
    assert "Организатор".encode() not in response.data
    assert "Маркетолог".encode() not in response.data
    assert "Модель".encode() not in response.data
    assert "Пара</small>".encode() not in response.data
    assert b"photo/portfolio/portfolio-003.jpg" not in response.data
    assert b"photo/portfolio/portfolio-012.jpg" not in response.data
    assert b"photo/portfolio/portfolio-038.jpg" not in response.data
    assert "25 сен 2025".encode() in response.data
    assert b"https://vk.ru/reviews-190646738" in response.data
    assert "06 / Контакты".encode() in response.data
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
    assert b"photo.css?v=48" in response.data
    assert b"js/photo.js" in response.data
    assert b"photo.js?v=16" in response.data
    assert "Портфолио".encode() in response.data
    assert "126 фотографий".encode() not in response.data
    assert "Собрал сюда все снимки из альбома ВКонтакте".encode() not in response.data
    assert b"photo/portfolio/portfolio-001.jpg" in response.data
    assert b"photo/portfolio/portfolio-126.jpg" in response.data
    assert response.data.count(b'class="ph-full-photo"') == 126
    assert len(site.PHOTO_PORTFOLIO_IMAGE_ORDER) == 126
    assert sorted(site.PHOTO_PORTFOLIO_IMAGE_ORDER) == list(range(1, 127))
    assert site.PHOTO_PORTFOLIO_IMAGE_ORDER[:8] == [38, 39, 40, 41, 98, 99, 100, 101]
    assert site.PHOTO_PORTFOLIO_IMAGE_ORDER[-1] == 42
    assert response.data.find(b"photo/portfolio/portfolio-038.jpg") < response.data.find(b"photo/portfolio/portfolio-001.jpg")
    assert response.data.find(b"photo/portfolio/portfolio-042.jpg") > response.data.find(b"photo/portfolio/portfolio-126.jpg")
    assert b"data-lightbox" in response.data
    assert b">PH<span>.</span></a>" in response.data
    assert '<a href="/#services">Фото</a>'.encode() in response.data
    assert '<a href="/#video">Видео</a>'.encode() in response.data
    assert '<a href="/#reviews">Отзывы</a>'.encode() in response.data
    assert '<a href="/#services">Съемки</a>'.encode() not in response.data
    assert b"vkuserphoto.ru" not in response.data
    assert "visitor_id=" in response.headers["Set-Cookie"]
    assert len(db_rows("visits")) == 1
    assert len(db_rows("unique_visits")) == 1

    css = Path("static/css/photo.css").read_text(encoding="utf-8")
    assert ".ph-hero {\n    position: relative;\n    box-sizing: border-box;" in css
    assert ".ph-trust {\n    position: relative;\n    box-sizing: border-box;" in css
    assert ".ph-hero-stage {\n        width: min(640px, 100%);\n        height: 640px;" in css
    assert ".ph-portrait-orbit::after" not in css
    assert ".ph-portrait-orbit i" not in css
    assert ".ph-person-plate {\n        inset: 64px;" in css
    assert ".ph-hero-person {\n        height: 700px;\n        bottom: -196px;" in css
    assert ".ph-hero-person {\n        height: 600px;\n        bottom: -164px;" in css
    assert ".ph-hero-person {\n        width: auto;\n        height: 460px;\n        max-width: none;\n        bottom: -158px;" in css
    assert ".ph-hero-person {\n        height: 385px;\n        bottom: -126px;" in css
    assert "height: 482px;" not in css
    assert "bottom: -64px;" not in css
    assert ".ph-booking-fields select {\n    appearance: none;" in css
    assert "padding-right: 48px;" in css
    assert ".ph-custom-select-trigger {\n    position: relative;\n    width: 100%;" in css
    assert ".ph-custom-select-list {\n    position: absolute;" in css
    assert ".ph-custom-select-option.is-selected {" in css
    assert ".ph-booking-nudge {\n    position: fixed;" in css
    assert "inset: 0;" in css
    assert "place-items: center;" in css
    assert "backdrop-filter: blur(18px) saturate(.9);" in css
    assert "body.ph-modal-open,\nbody.ph-nudge-open { overflow: hidden; }" in css
    assert "body.ph-nudge-open .ph-scroll-cue {" in css
    assert ".ph-booking-nudge-card {\n    position: relative;" in css
    assert "justify-items: center;" in css
    assert "text-align: center;" in css
    assert ".ph-booking-nudge-card > button:not(.ph-booking-nudge-close) {" in css
    assert ".ph-booking-nudge.is-visible {" in css
    assert ".ph-reviews {\n    position: relative;" in css
    assert ".ph-review-layout {\n    position: relative;" in css
    assert ".ph-review-feature {\n    min-height: 506px;" not in css
    assert "grid-template-rows: auto auto auto;" in css
    assert "gap: 4px;" in css
    assert "align-content: start;" in css
    assert "grid-template-rows: auto minmax(59px, 1fr) auto;" not in css
    assert "grid-template-rows: auto minmax(118px, 1fr) auto;" not in css
    assert ".ph-review-feature-accent {\n    position: relative;" in css
    assert ".ph-review-feature-accent span {\n    font-family: Georgia" in css
    assert "align-self: start;" in css
    assert "margin-top: -4px;" in css
    assert ".ph-review-grid {\n    position: relative;" in css
    assert ".ph-review-top {\n    position: relative;" in css
    assert "justify-content: space-between;" in css
    assert ".ph-review-avatar {\n    width: 46px;" in css
    assert ".ph-review-grid .ph-review-avatar {\n    width: 38px;" in css
    assert ".ph-review-rating {\n    flex: 0 0 auto;" in css
    assert ".ph-review-grid article > small" not in css
    assert ".ph-review-link" not in css
    assert ".ph-reviews-modal" not in css
    assert ".ph-reviews-list" not in css
    assert ".ph-booking-head p:last-child" not in css
    js = Path("static/js/photo.js").read_text(encoding="utf-8")
    assert "initCustomSelects" in js
    assert 'const videoFrame = document.querySelector("[data-video-frame]");' in js
    assert "button.dataset.videoEmbed" in js
    assert "videoFrame.src = videoEmbed;" in js
    assert "card.setAttribute(\"aria-pressed\", isActive ? \"true\" : \"false\");" in js
    assert "videoPlayButton" not in js
    assert 'value.className = "ph-custom-select-value";' in js
    assert "data-custom-select-option" in js
    assert "window.setTimeout(showBookingNudge, 120000);" in js
    assert 'const bookingSuccessModal = document.getElementById("booking-success");' in js
    assert "openBookingSuccess()" in js
    assert "closeBookingSuccess()" in js
    assert "data-booking-nudge-open" in js
    assert "document.body.classList.add(\"ph-nudge-open\")" in js
    assert "document.body.classList.remove(\"ph-nudge-open\")" in js
    assert ".ph-booking-head > p:not(.ph-section-index)" in js
    assert "bookingStatus.textContent = \"Заявка отправлена. Я свяжусь с вами.\";" not in js
    assert ".ph-about-copy {\n    position: relative;\n    z-index: 1;\n    align-self: start;" in css
    assert ".ph-hero,\n    .ph-about,\n    .ph-portfolio" not in css
    assert ".ph-about {\n        align-content: start;\n        padding-top: 112px;\n        padding-bottom: 48px;" in css
    assert ".ph-section-heading {\n    display: grid;\n    grid-template-columns: max-content minmax(320px, 390px);\n    justify-content: start;" in css
    assert ".ph-services > header {\n    display: grid;\n    grid-template-columns: minmax(0, 1fr);\n    align-items: start;\n    gap: 18px;" in css
    assert ".ph-video-heading {\n    position: relative;\n    z-index: 1;\n    display: grid;\n    grid-template-columns: minmax(0, 1fr);\n    align-items: start;\n    gap: 18px;" in css
    assert ".ph-contact {\n    min-height: 0;\n    display: grid;\n    grid-template-columns: minmax(0, 1fr) minmax(300px, 420px);\n    align-items: start;" in css
    assert ".ph-contact > div:not(.ph-contact-actions) {\n    grid-column: 1;" in css
    assert ".ph-contact-actions {\n    grid-column: 2;\n    grid-row: 1 / span 2;\n    width: 300px;\n    justify-self: end;" in css
    assert ".ph-contact-actions {\n        grid-column: 1;\n        grid-row: auto;\n        width: 100%;" in css
    assert ".ph-contact {\n        padding-top: 52px;\n        padding-bottom: 48px;" in css
    assert ".ph-contact {\n        padding-top: 42px;" not in css
    assert ".ph-contact .ph-section-index {\n    align-self: start;\n    margin: 0;" in css
    assert "min-height: calc(100svh - 150px);" in css
    assert ".ph-trust {\n        min-height: 150px;" in css
    assert ".ph-trust {\n        min-height: 0;\n        flex-direction: column;" in css
    assert ".ph-work-controls {\n    display: none;" in css
    assert "aspect-ratio: 1 / 1;" in css
    assert ".ph-full-gallery {\n    display: grid;" in css
    assert "grid-auto-flow: row;" in css
    assert "columns: 4 250px" not in css
    assert "break-inside: avoid" not in css
    js = Path("static/js/photo.js").read_text(encoding="utf-8")
    assert "portfolio-100.jpg" in js
    assert '"#reviews"' in js
    assert "openReviews" not in js
    assert "closeReviews" not in js
    assert "data-reviews-open" not in js
    assert 'link.textContent = "Фото";' in js


def test_ph_localhost_maps_to_photographer_branch(client):
    response = client.get("/", base_url="http://ph.localhost")

    assert response.status_code == 200
    assert b"css/photo.css" in response.data


def test_phh_host_is_not_part_of_project(client):
    response = client.get("/", base_url="http://phh.khudoverdiev.ru")

    assert response.status_code == 400

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
    assert b'aria-labelledby="contact-title" tabindex="-1"' in response.data


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


def test_portfolio_video_is_small_enough_to_ship_through_git_deploy():
    gitignore = Path(".gitignore").read_text(encoding="utf-8")
    video = Path("static/portfolio/peredacha.mp4")

    assert "static/portfolio/peredacha.mp4" not in gitignore
    assert video.exists()
    assert video.stat().st_size < 100 * 1024 * 1024


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
    assert messages[0]["message_type"] == "message"


def test_message_fetch_request_returns_no_content_after_saving(client):
    csrf = csrf_from(client)

    response = client.post(
        "/message",
        data={"csrf_token": csrf, "name": "Alice", "text": "Ping"},
        headers={"X-Requested-With": "fetch", "X-CSRF-Token": csrf},
    )

    assert response.status_code == 204
    assert len(db_rows("messages")) == 1


def test_root_message_daily_limit_blocks_second_submission_from_same_device(client, monkeypatch):
    monkeypatch.setattr(site, "current_day", lambda: "2026-08-12")
    csrf = csrf_from(client)
    headers = {
        "X-Requested-With": "fetch",
        "X-CSRF-Token": csrf,
        "User-Agent": "root-browser",
        "Accept-Language": "ru-RU",
    }
    environ_base = {"REMOTE_ADDR": "203.0.113.21"}

    first = client.post(
        "/message",
        data={"name": "Root", "contact": "@root", "text": "First root message"},
        headers=headers,
        environ_base=environ_base,
    )
    blocked = client.post(
        "/message",
        data={"name": "Root", "contact": "@root", "text": "Second root message"},
        headers=headers,
        environ_base=environ_base,
    )

    messages = db_rows("messages")
    quota_rows = db_rows("daily_submission_limits")
    assert first.status_code == 204
    assert blocked.status_code == 429
    assert "уже отправлено сообщение".encode() in blocked.data
    assert len(messages) == 1
    assert messages[0]["message_type"] == "message"
    assert messages[0]["site_source"] == "khudoverdiev.ru"
    assert len(quota_rows) == 2
    assert {row["count"] for row in quota_rows} == {1}
    assert all(row["scope"] == site.ROOT_MESSAGE_SCOPE for row in quota_rows)
    assert all(re.fullmatch(r"[a-f0-9]{64}", row["fingerprint"]) for row in quota_rows)


def test_root_message_daily_limit_also_blocks_plain_post_without_fetch_header(client, monkeypatch):
    monkeypatch.setattr(site, "current_day", lambda: "2026-08-12")
    csrf = csrf_from(client)
    environ_base = {"REMOTE_ADDR": "203.0.113.22"}
    headers = {"User-Agent": "plain-root-browser"}

    first = client.post(
        "/message",
        data={"csrf_token": csrf, "contact": "@root", "text": "Plain first"},
        headers=headers,
        environ_base=environ_base,
    )
    blocked = client.post(
        "/message",
        data={"csrf_token": csrf, "contact": "@root", "text": "Plain second"},
        headers=headers,
        environ_base=environ_base,
    )

    assert first.status_code == 302
    assert blocked.status_code == 429
    assert len(db_rows("messages")) == 1


def test_root_message_daily_limit_survives_cookie_reset_by_network_signature(client, monkeypatch):
    monkeypatch.setattr(site, "current_day", lambda: "2026-08-12")
    headers = {
        "X-Requested-With": "fetch",
        "User-Agent": "same-root-browser",
        "Accept-Language": "ru-RU",
    }
    environ_base = {"REMOTE_ADDR": "198.51.100.54"}
    csrf = csrf_from(client)

    first = client.post(
        "/message",
        data={"csrf_token": csrf, "contact": "@root", "text": "First root message"},
        headers=headers,
        environ_base=environ_base,
    )

    with site.app.test_client() as fresh_client:
        fresh_client.get("/", headers=headers, environ_base=environ_base)
        with fresh_client.session_transaction() as session:
            fresh_csrf = session["_csrf_token"]
        blocked = fresh_client.post(
            "/message",
            data={"csrf_token": fresh_csrf, "contact": "@root", "text": "Fresh cookie attempt"},
            headers=headers,
            environ_base=environ_base,
        )

    assert first.status_code == 204
    assert blocked.status_code == 429
    assert len(db_rows("messages")) == 1


def test_root_message_daily_limit_resets_on_next_day(client, monkeypatch):
    quota_day = ["2026-08-12"]
    monkeypatch.setattr(site, "current_day", lambda: quota_day[0])
    csrf = csrf_from(client)
    headers = {"X-Requested-With": "fetch", "X-CSRF-Token": csrf, "User-Agent": "root-browser"}
    environ_base = {"REMOTE_ADDR": "203.0.113.29"}

    first = client.post(
        "/message",
        data={"contact": "@root", "text": "First root message"},
        headers=headers,
        environ_base=environ_base,
    )

    quota_day[0] = "2026-08-13"
    second = client.post(
        "/message",
        data={"contact": "@root", "text": "Next day root message"},
        headers=headers,
        environ_base=environ_base,
    )

    assert first.status_code == 204
    assert second.status_code == 204
    assert len(db_rows("messages")) == 2


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
    assert messages[0]["message_type"] == "booking"
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
    csrf = csrf_from(client, base_url="http://ph.khudoverdiev.ru")
    for index in range(10):
        response = client.post(
            "/message",
            data={"csrf_token": csrf, "text": f"Message {index}"},
            base_url="http://ph.khudoverdiev.ru",
        )
        assert response.status_code == 302

    blocked = client.post(
        "/message",
        data={"csrf_token": csrf, "text": "Too much"},
        base_url="http://ph.khudoverdiev.ru",
    )

    assert blocked.status_code == 429
    assert len(db_rows("messages")) == 10


def test_message_rate_limit_is_scoped_by_first_forwarded_ip_and_user_agent(client, monkeypatch):
    monkeypatch.setattr(site.time, "time", lambda: 1_000.0)
    csrf = csrf_from(client, base_url="http://ph.khudoverdiev.ru")
    throttled_headers = {"X-Forwarded-For": "203.0.113.10, 10.0.0.1", "User-Agent": "mobile-app"}
    other_ip_headers = {"X-Forwarded-For": "203.0.113.11, 10.0.0.1", "User-Agent": "mobile-app"}
    other_agent_headers = {"X-Forwarded-For": "203.0.113.10, 10.0.0.1", "User-Agent": "browser"}

    for index in range(10):
        response = client.post(
            "/message",
            data={"csrf_token": csrf, "text": f"Limited {index}"},
            headers=throttled_headers,
            base_url="http://ph.khudoverdiev.ru",
        )
        assert response.status_code == 302

    assert (
        client.post(
            "/message",
            data={"csrf_token": csrf, "text": "Blocked"},
            headers=throttled_headers,
            base_url="http://ph.khudoverdiev.ru",
        ).status_code
        == 429
    )
    assert (
        client.post(
            "/message",
            data={"csrf_token": csrf, "text": "Other IP"},
            headers=other_ip_headers,
            base_url="http://ph.khudoverdiev.ru",
        ).status_code
        == 302
    )
    assert (
        client.post(
            "/message",
            data={"csrf_token": csrf, "text": "Other agent"},
            headers=other_agent_headers,
            base_url="http://ph.khudoverdiev.ru",
        ).status_code
        == 302
    )


def test_message_rate_limit_window_expires_without_manual_reset(client, monkeypatch):
    current_time = [1_000.0]
    monkeypatch.setattr(site.time, "time", lambda: current_time[0])
    csrf = csrf_from(client, base_url="http://ph.khudoverdiev.ru")

    for index in range(10):
        assert (
            client.post(
                "/message",
                data={"csrf_token": csrf, "text": f"Before {index}"},
                base_url="http://ph.khudoverdiev.ru",
            ).status_code
            == 302
        )
    assert (
        client.post(
            "/message",
            data={"csrf_token": csrf, "text": "Blocked"},
            base_url="http://ph.khudoverdiev.ru",
        ).status_code
        == 429
    )

    current_time[0] += 301
    response = client.post(
        "/message",
        data={"csrf_token": csrf, "text": "After window"},
        base_url="http://ph.khudoverdiev.ru",
    )

    assert response.status_code == 302
    assert len(db_rows("messages")) == 11


def test_it_project_lead_daily_limit_blocks_fourth_submission_from_same_device(client, monkeypatch):
    monkeypatch.setattr(site, "current_day", lambda: "2026-08-12")
    csrf = csrf_from(client, path="/", base_url="http://it.khudoverdiev.ru")
    headers = {
        "X-Requested-With": "fetch",
        "X-CSRF-Token": csrf,
        "User-Agent": "lead-browser",
        "Accept-Language": "ru-RU",
    }
    environ_base = {"REMOTE_ADDR": "203.0.113.77"}

    for index in range(3):
        response = client.post(
            "/message",
            data={"name": "Lead", "contact": "@lead", "text": f"Project {index}"},
            headers=headers,
            environ_base=environ_base,
            base_url="http://it.khudoverdiev.ru",
        )
        assert response.status_code == 204

    blocked = client.post(
        "/message",
        data={"name": "Lead", "contact": "@lead", "text": "Project 4"},
        headers=headers,
        environ_base=environ_base,
        base_url="http://it.khudoverdiev.ru",
    )

    messages = db_rows("messages")
    quota_rows = db_rows("daily_submission_limits")
    assert blocked.status_code == 429
    assert "3 заявки".encode() in blocked.data
    assert len(messages) == 3
    assert {message["message_type"] for message in messages} == {"project"}
    assert {message["site_source"] for message in messages} == {"it.khudoverdiev.ru"}
    assert len(quota_rows) == 2
    assert {row["count"] for row in quota_rows} == {3}
    assert all(row["scope"] == site.PROJECT_LEAD_SCOPE for row in quota_rows)
    assert all(re.fullmatch(r"[a-f0-9]{64}", row["fingerprint"]) for row in quota_rows)


def test_it_project_lead_daily_limit_survives_cookie_reset_by_network_signature(client, monkeypatch):
    monkeypatch.setattr(site, "current_day", lambda: "2026-08-12")
    headers = {
        "X-Requested-With": "fetch",
        "User-Agent": "same-computer-browser",
        "Accept-Language": "ru-RU",
    }
    environ_base = {"REMOTE_ADDR": "198.51.100.42"}
    csrf = csrf_from(client, path="/", base_url="http://it.khudoverdiev.ru")

    for index in range(3):
        response = client.post(
            "/message",
            data={"csrf_token": csrf, "contact": "@lead", "text": f"Project {index}"},
            headers=headers,
            environ_base=environ_base,
            base_url="http://it.khudoverdiev.ru",
        )
        assert response.status_code == 204

    with site.app.test_client() as fresh_client:
        fresh_client.get(
            "/",
            headers=headers,
            environ_base=environ_base,
            base_url="http://it.khudoverdiev.ru",
        )
        with fresh_client.session_transaction(base_url="http://it.khudoverdiev.ru") as session:
            fresh_csrf = session["_csrf_token"]
        blocked = fresh_client.post(
            "/message",
            data={"csrf_token": fresh_csrf, "contact": "@lead", "text": "Fresh cookie attempt"},
            headers=headers,
            environ_base=environ_base,
            base_url="http://it.khudoverdiev.ru",
        )

    assert blocked.status_code == 429
    assert len(db_rows("messages")) == 3


def test_it_project_lead_daily_limit_resets_on_next_day(client, monkeypatch):
    quota_day = ["2026-08-12"]
    monkeypatch.setattr(site, "current_day", lambda: quota_day[0])
    csrf = csrf_from(client, path="/", base_url="http://it.khudoverdiev.ru")
    headers = {"X-Requested-With": "fetch", "X-CSRF-Token": csrf, "User-Agent": "lead-browser"}
    environ_base = {"REMOTE_ADDR": "203.0.113.88"}

    for index in range(3):
        assert (
            client.post(
                "/message",
                data={"contact": "@lead", "text": f"Project {index}"},
                headers=headers,
                environ_base=environ_base,
                base_url="http://it.khudoverdiev.ru",
            ).status_code
            == 204
        )

    quota_day[0] = "2026-08-13"
    response = client.post(
        "/message",
        data={"contact": "@lead", "text": "Next day project"},
        headers=headers,
        environ_base=environ_base,
        base_url="http://it.khudoverdiev.ru",
    )

    assert response.status_code == 204
    assert len(db_rows("messages")) == 4


def test_admin_login_page_is_no_store_and_contains_csrf(client):
    response = client.get(site.ADMIN_PATH)

    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store, max-age=0"
    assert b'name="csrf_token"' in response.data
    assert b'name="username"' in response.data
    assert b'autocomplete="username"' in response.data
    assert b"css/styles.css?v=29" in response.data
    assert "<title>Админ-панель</title>".encode() in response.data
    assert "Админ-панель — KHUDOVERDIEV".encode() not in response.data
    assert "Фотография сохраняет тишину момента".encode() in response.data
    css = Path("static/css/styles.css").read_text(encoding="utf-8")
    assert "rgba(255, 255, 255, 0.74)" in css
    assert "height: min(720px, calc(100svh - 60px));" in css
    assert "height: min(920px, calc(100svh - 60px));" not in css
    assert "min-height: min(720px, calc(100svh - 60px));" in css
    assert ".admin-content {\n    display: grid;" in css
    assert "min-height: 0;" in css
    assert "overflow-y: auto;" in css
    assert ".admin-period.is-placeholder {\n    visibility: hidden;\n    pointer-events: none;" in css
    assert '.login-aesthetic-note blockquote::after {\n    content: none;' in css
    assert '.login-aesthetic-note p::after {\n    content: "\\00BB";' in css


def test_admin_dashboard_layout_keeps_shell_height_stable_and_scrolls_content():
    css = Path("static/css/styles.css").read_text(encoding="utf-8")

    assert ".admin-page {\n    min-height: 100svh;" in css
    assert "overflow: visible;" in css
    assert "grid-template-rows: auto auto minmax(0, 1fr);" in css
    assert ".click-list div {\n    display: flex;" in css
    assert "min-width: 0;" in css
    assert ".click-list strong {\n    flex: 0 0 auto;" in css
    assert ".click-list span {\n    min-width: 0;\n    overflow-wrap: anywhere;" in css


def test_admin_tabs_keep_same_vertical_anchor_across_sections(client):
    login_as_admin(client)

    dashboard = client.get(site.ADMIN_PATH)
    clients = client.get(f"{site.ADMIN_PATH}/clients")
    messages = client.get(f"{site.ADMIN_PATH}/messages")

    assert b'class="admin-period"' in dashboard.data
    assert b'class="admin-period is-placeholder" aria-hidden="true"' in clients.data
    assert b'class="admin-period"' in messages.data
    assert b'class="admin-period is-placeholder"' not in dashboard.data
    assert b'class="admin-period is-placeholder"' not in messages.data


def test_admin_aliases_are_no_store_even_when_redirecting(client):
    legacy = client.get(site.LEGACY_ADMIN_PATH)
    old_alias = client.get("/admin")

    assert legacy.status_code == 302
    assert old_alias.status_code == 302
    assert legacy.headers["Cache-Control"] == "no-store, max-age=0"
    assert old_alias.headers["Cache-Control"] == "no-store, max-age=0"


def test_admin_login_requires_csrf(client):
    response = client.post(site.ADMIN_PATH, data={"username": "admin", "password": "secret"})

    assert response.status_code == 400


def test_admin_rejects_wrong_password_without_session(client):
    csrf = csrf_from(client, site.ADMIN_PATH)

    response = client.post(site.ADMIN_PATH, data={"username": "admin", "password": "wrong", "csrf_token": csrf})

    assert response.status_code == 200
    with client.session_transaction() as session:
        assert "admin" not in session
    assert "Неверный логин или пароль".encode() in response.data


def test_admin_rejects_wrong_username_without_session(client):
    csrf = csrf_from(client, site.ADMIN_PATH)

    response = client.post(site.ADMIN_PATH, data={"username": "wrong", "password": "secret", "csrf_token": csrf})

    assert response.status_code == 200
    with client.session_transaction() as session:
        assert "admin" not in session
    assert "Неверный логин или пароль".encode() in response.data


def test_admin_accepts_plain_password_and_rotates_csrf(client):
    old_csrf = csrf_from(client, site.ADMIN_PATH)

    response = client.post(site.ADMIN_PATH, data={"username": "admin", "password": "secret", "csrf_token": old_csrf})

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

    response = client.post(site.ADMIN_PATH, data={"username": "admin", "password": "secret", "csrf_token": csrf})

    assert response.status_code == 302
    with client.session_transaction() as session:
        assert session["admin"] is True
        assert "cart" not in session
        assert "next" not in session


def test_admin_accepts_configured_password_hash(client, monkeypatch):
    monkeypatch.setattr(site, "ADMIN_PASSWORD_HASH", generate_password_hash("hashed-secret"))
    csrf = csrf_from(client, site.ADMIN_PATH)

    response = client.post(
        site.ADMIN_PATH,
        data={"username": "admin", "password": "hashed-secret", "csrf_token": csrf},
    )

    assert response.status_code == 302
    with client.session_transaction() as session:
        assert session["admin"] is True


def test_admin_password_hash_rejects_plain_fallback_password(client, monkeypatch):
    monkeypatch.setattr(site, "ADMIN_PASSWORD_HASH", generate_password_hash("hashed-secret"))
    csrf = csrf_from(client, site.ADMIN_PATH)

    response = client.post(site.ADMIN_PATH, data={"username": "admin", "password": "secret", "csrf_token": csrf})

    assert response.status_code == 200
    with client.session_transaction() as session:
        assert "admin" not in session


def test_admin_login_rate_limit_blocks_brute_force_attempts(client):
    csrf = csrf_from(client, site.ADMIN_PATH)
    for _ in range(5):
        response = client.post(site.ADMIN_PATH, data={"username": "admin", "password": "bad", "csrf_token": csrf})
        assert response.status_code == 200

    blocked = client.post(site.ADMIN_PATH, data={"username": "admin", "password": "bad", "csrf_token": csrf})

    assert blocked.status_code == 429


def test_admin_dashboard_counts_only_recent_activity_and_orders_clicks(client, monkeypatch):
    monkeypatch.setattr(site, "cutoff_30_days", lambda: "2026-01-01 00:00:00")
    site.init_db()
    with sqlite3.connect(site.DB_PATH) as db:
        db.executemany(
            "INSERT INTO visits (created_at, site_source, ip, user_agent) VALUES (?, ?, ?, ?)",
            [
                ("2026-01-02 00:00:00", "ph.khudoverdiev.ru", "1.1.1.1", "new"),
                ("2026-01-02 00:00:00", "ph.khudoverdiev.ru", "1.1.1.2", "new"),
                ("2026-01-02 00:00:00", "it.khudoverdiev.ru", "1.1.1.3", "new"),
                ("2026-01-02 00:00:00", "khudoverdiev.ru", "1.1.1.4", "new"),
                ("2025-12-31 23:59:59", "it.khudoverdiev.ru", "2.2.2.2", "old"),
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
            "INSERT INTO messages (name, contact, text, message_type, created_at) VALUES (?, ?, ?, ?, ?)",
            [
                ("Recent", "", "visible", "message", "2026-01-02 00:00:00"),
                ("Booking", "", "Заявка на съемку", "booking", "2026-01-02 00:00:00"),
                ("Old", "", "hidden", "message", "2025-12-31 23:59:59"),
            ],
        )
    login_as_admin(client)

    response = client.get(site.ADMIN_PATH)

    assert response.status_code == 200
    assert b'data-admin-shell' in response.data
    assert b'data-admin-content' in response.data
    assert response.data.count(b'class="admin-tab-icon" aria-hidden="true"') == 3
    assert response.data.count(b'class="admin-tab-label"') == 3
    assert "Админ-панель".encode() in response.data
    assert "KHUDOVERDIEV</p>".encode() not in response.data
    assert b"loadAdminTab" in response.data
    assert b"window.scrollTo" not in response.data
    assert "Посещения сайтов".encode() in response.data
    assert "ph.khudoverdiev".encode() in response.data
    assert "khudoverdiev".encode() in response.data
    assert "it.khudoverdiev".encode() in response.data
    assert response.data.index(b"<span>ph.khudoverdiev</span>") < response.data.index(b"<span>khudoverdiev</span>")
    assert response.data.index(b"<span>khudoverdiev</span>") < response.data.index(b"<span>it.khudoverdiev</span>")
    assert "Заявки".encode() in response.data
    assert b"<strong>4</strong>" in response.data
    assert b"<strong>2</strong>" in response.data
    assert b"<strong>1</strong>" in response.data
    assert "Клики по ссылкам".encode() in response.data
    assert "Переходы с khudoverdiev.ru".encode() in response.data
    assert b"<small>khudoverdiev.ru</small>" in response.data
    assert b"Telegram" in response.data
    assert response.data.index(b'<span class="click-item-main">Telegram') < response.data.index(
        b'<span class="click-item-main">VK'
    )
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
    assert "Страницы клиентов".encode() not in response.data
    assert "Создавайте персональные ссылки без хранения фотографий на сайте.".encode() not in response.data
    assert "Заполните только рабочие ссылки и текст. Безопасный публичный адрес создастся автоматически.".encode() not in response.data
    assert "Клиенты".encode() in response.data
    assert b'class="client-subtabs"' in response.data
    assert b'data-client-subtab="create"' in response.data
    assert b'data-client-subtab="links"' in response.data
    assert b'data-client-subtab="archive"' in response.data
    assert b'id="client-panel-create"' in response.data
    assert b'id="client-panel-links"' in response.data
    assert b'id="client-panel-archive"' in response.data
    assert "Создание".encode() in response.data
    assert "Все ссылки".encode() in response.data
    assert 'href="/st"'.encode() in response.data
    assert 'href="/st/clients"'.encode() in response.data
    assert b'name="photo_link"' in response.data
    assert b'name="review_link"' not in response.data
    assert b'name="has_discount"' in response.data
    assert "Дать скидку".encode() in response.data
    assert b"class=\"client-create-visual\"" not in response.data
    assert b"class=\"client-url-field\"" in response.data
    assert b"<i aria-hidden=\"true\"></i>" not in response.data
    assert b'name="slug"' not in response.data
    assert b"https://drive.google.com/photos" in response.data
    assert b"https://ph.khudoverdiev.ru/client/ivanova-2026" in response.data
    assert "Безопасная ссылка".encode() not in response.data
    assert "Ссылка".encode() in response.data
    assert "Ссылка для отзыва".encode() not in response.data
    assert b"data-client-summary-link" in response.data
    assert b"data-client-url" in response.data
    assert b"data-copy-client-link" in response.data
    assert b"data-rotate-client-link" in response.data
    assert "Скопировать ссылку".encode() in response.data
    assert "Сменить</button>".encode() in response.data
    assert "Сменить ссылку".encode() not in response.data
    assert "Открыть</a>".encode() not in response.data
    assert "Удалить клиента".encode() not in response.data
    assert "Удалить</button>".encode() in response.data
    assert b"data-client-delete-form" in response.data
    assert b"data-client-delete-trigger" in response.data
    assert "Архив".encode() in response.data
    assert "Архив пока пуст.".encode() in response.data
    assert b'<div class="client-list">' in response.data
    assert b'type="file"' not in response.data
    assert b'multipart/form-data' not in response.data


def test_admin_client_form_layout_removes_decorative_icons_and_keeps_fields_stable():
    css = Path("static/css/styles.css").read_text(encoding="utf-8")

    assert '.client-link-note {\n    display: grid;\n    grid-template-columns: minmax(0, 1fr);\n    grid-template-areas:\n        "title"\n        "url";' in css
    assert ".client-link-note span {\n    grid-area: title;" in css
    assert ".client-link-note p {\n    grid-area: url;" in css
    assert ".client-create-panel {\n    display: grid;\n    grid-template-columns: 250px minmax(0, 1fr);" in css
    assert ".client-create-visual" not in css
    assert ".client-url-field {\n    display: block;" in css
    assert ".client-url-field i {" not in css
    assert ".client-url-field i::before" not in css
    assert ".client-url-field input {\n    border-radius: 14px;" in css
    assert ".client-form textarea {\n    min-height: 96px;" in css
    assert ".client-form textarea {\n        min-height: 112px;" in css
    assert "@media (max-width: 900px) {\n    .client-form {\n        grid-template-columns: 1fr;" in css
    assert ".client-discount-controls,\n    .client-create-actions {\n        grid-template-columns: 1fr;" in css


def test_admin_tabs_use_inline_icons_without_dot_markers():
    css = Path("static/css/styles.css").read_text(encoding="utf-8")

    assert ".admin-tab-icon {\n    width: 28px;" in css
    assert ".admin-tab-icon svg {\n    width: 17px;" in css
    assert ".admin-tabs a {\n        padding: 0 4px;\n        font-size: 11px;" in css
    assert ".admin-tab-icon {\n        width: 24px;\n        height: 24px;" in css
    assert ".admin-tabs a.is-active .admin-tab-icon {" in css
    assert ".admin-tabs a::before" not in css


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
    assert "Клики по ссылкам".encode() not in response.data
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
    assert b"ph.khudoverdiev.ru" in response.data
    assert b"khudoverdiev.ru" in response.data
    assert b"it.khudoverdiev.ru" in response.data
    assert response.data.index(b"<h3>ph.khudoverdiev.ru</h3>") < response.data.index(b"<h3>khudoverdiev.ru</h3>")
    assert response.data.index(b"<h3>khudoverdiev.ru</h3>") < response.data.index(b"<h3>it.khudoverdiev.ru</h3>")
    assert b"<span data-group-count>0</span>" in response.data
    assert "Нет пока обращений.".encode() in response.data
    assert b"Root lead" in response.data
    assert b"IT lead" in response.data
    assert b"Old lead" not in response.data


def test_photo_client_page_renders_personal_redirect_buttons_without_storing_photos(client):
    insert_photo_client(client_name="Алина", slug="wedding-alina-2026", discount_text="скидку 15%")

    response = client.get("/client/wedding-alina-2026", base_url="http://ph.khudoverdiev.ru")

    assert response.status_code == 200
    assert "Спасибо за съемку,".encode() in response.data
    assert "Алина!".encode() in response.data
    assert "Запечатленные моменты".encode() in response.data
    assert "Готовая серия".encode() not in response.data
    assert "скидку 15%".encode() in response.data
    assert b"css/styles.css?v=19" in response.data
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
    assert b'href="https://vk.ru/reviews-190646738"' in response.data
    assert b'href="https://ph.khudoverdiev.ru"' in response.data
    assert "Страница фотографа".encode() in response.data
    assert b"class=\"client-header-link\"" in response.data
    assert b"https://reviews.example/ivanova" not in response.data
    assert b"<form" not in response.data
    assert b'type="file"' not in response.data


def test_photo_client_page_hides_discount_when_admin_disables_it(client):
    insert_photo_client(slug="no-discount-client", discount_text="")

    response = client.get("/client/no-discount-client", base_url="http://ph.khudoverdiev.ru")

    assert response.status_code == 200
    assert "Благодарность".encode() not in response.data
    assert "на следующую съемку".encode() not in response.data
    assert b'class="client-discount"' not in response.data


def test_old_phh_client_page_is_not_part_of_project(client):
    insert_photo_client(slug="old-safe-link")

    response = client.get("/client/old-safe-link", base_url="http://phh.khudoverdiev.ru")

    assert response.status_code == 400

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
            "has_discount": "1",
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


def test_photo_client_admin_can_create_page_without_discount(client):
    login_as_admin(client)
    with client.session_transaction() as session:
        csrf = session["_csrf_token"]

    response = client.post(
        f"{site.ADMIN_PATH}/clients",
        data={
            "csrf_token": csrf,
            "client_name": "No Discount",
            "photo_link": "https://disk.yandex.ru/d/no-discount",
            "review_link": "",
            "discount_text": "10%",
            "message_text": "Фотографии готовы.",
            "is_active": "1",
        },
    )

    assert response.status_code == 302
    rows = db_rows("photo_clients")
    assert rows[0]["discount_text"] == ""
    created = client.get(f"/client/{rows[0]['slug']}")
    assert created.status_code == 200
    assert "Благодарность".encode() not in created.data
    assert b'class="client-discount"' not in created.data
    assert b'href="https://vk.ru/reviews-190646738"' in created.data


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


def test_photo_client_admin_updates_and_archives_client_records(client):
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
            "has_discount": "1",
            "message_text": "Новая ссылка готова.",
        },
    )
    unavailable = client.get("/client/new-slug")
    rows = db_rows("photo_clients")
    deleted = client.post(f"{site.ADMIN_PATH}/clients/{client_id}/delete", data={"csrf_token": csrf})
    archived_rows = db_rows("photo_clients")
    clients_tab = client.get(f"{site.ADMIN_PATH}/clients")

    assert updated.status_code == 302
    assert unavailable.status_code == 404
    assert rows[0]["slug"] == "old-slug"
    assert deleted.status_code == 302
    assert len(archived_rows) == 1
    assert archived_rows[0]["slug"] == "old-slug"
    assert archived_rows[0]["is_active"] == 0
    assert archived_rows[0]["archived_at"]
    assert client.get("/client/old-slug").status_code == 404
    assert b"https://ph.khudoverdiev.ru/client/old-slug" in clients_tab.data
    assert "Архив".encode() in clients_tab.data


def test_photo_client_admin_fetch_delete_archives_link_without_losing_record(client):
    client_id = insert_photo_client(slug="ivanova-2026")
    login_as_admin(client)
    with client.session_transaction() as session:
        csrf = session["_csrf_token"]

    response = client.post(
        f"{site.ADMIN_PATH}/clients/{client_id}/delete",
        headers={"X-Requested-With": "fetch", "X-CSRF-Token": csrf},
    )

    rows = db_rows("photo_clients")
    payload = response.get_json()
    assert response.status_code == 200
    assert payload["client_name"] == "Иванова"
    assert payload["url"] == "https://ph.khudoverdiev.ru/client/ivanova-2026"
    assert payload["archived_at"] == rows[0]["archived_at"]
    assert rows[0]["archived_at"]
    assert rows[0]["is_active"] == 0
    assert client.get("/client/ivanova-2026").status_code == 404


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


def test_photo_client_admin_fetch_rotate_returns_new_public_url_without_redirect(client):
    client_id = insert_photo_client(slug="ivanova-2026")
    login_as_admin(client)
    with client.session_transaction() as session:
        csrf = session["_csrf_token"]

    response = client.post(
        f"{site.ADMIN_PATH}/clients/{client_id}/rotate-link",
        headers={"X-Requested-With": "fetch", "X-CSRF-Token": csrf},
    )

    rows = db_rows("photo_clients")
    assert response.status_code == 200
    assert response.content_type.startswith("application/json")
    payload = response.get_json()
    assert payload["slug"] == rows[0]["slug"]
    assert payload["url"] == f"https://ph.khudoverdiev.ru/client/{rows[0]['slug']}"
    assert rows[0]["slug"] != "ivanova-2026"


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
    assert db_rows("photo_clients")[0]["archived_at"] is None


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
    daily_submission_limits = table_columns("daily_submission_limits")
    assert messages["name"]["notnull"] == 1
    assert messages["text"]["notnull"] == 1
    assert messages["message_type"]["notnull"] == 1
    assert messages["site_source"]["notnull"] == 1
    assert messages["created_at"]["notnull"] == 1
    assert visits["created_at"]["notnull"] == 1
    assert visits["site_source"]["notnull"] == 1
    assert unique_visits["visitor_id"]["pk"] == 1
    assert unique_visits["first_seen_at"]["notnull"] == 1
    assert photo_clients["client_name"]["notnull"] == 1
    assert photo_clients["slug"]["notnull"] == 1
    assert photo_clients["photo_link"]["notnull"] == 1
    assert photo_clients["is_active"]["notnull"] == 1
    assert "archived_at" in photo_clients
    assert daily_submission_limits["scope"]["notnull"] == 1
    assert daily_submission_limits["fingerprint"]["notnull"] == 1
    assert daily_submission_limits["day"]["notnull"] == 1
    assert daily_submission_limits["count"]["notnull"] == 1
    assert daily_submission_limits["first_seen_at"]["notnull"] == 1
    assert daily_submission_limits["last_seen_at"]["notnull"] == 1


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
