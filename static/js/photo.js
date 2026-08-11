(() => {
    const lightbox = document.getElementById("ph-lightbox");
    const lightboxImage = lightbox?.querySelector("img");
    const closeButton = lightbox?.querySelector("[data-lightbox-close]");
    const bookingModal = document.getElementById("booking");
    const bookingForm = bookingModal?.querySelector("[data-booking-form]");
    const bookingStatus = bookingModal?.querySelector("[data-booking-status]");
    const scrollCue = document.querySelector(".ph-scroll-cue");
    const videoPlayer = document.querySelector("[data-video-player]");
    const videoPlayButton = document.querySelector("[data-video-play]");
    const videoPlayerTitle = document.querySelector("[data-video-player-title]");
    const videoCards = [...document.querySelectorAll("[data-video-card]")];
    const scrollTargets = ["#about", "#portfolio", "#services", "#video", "#contact", "#ph-site-footer"]
        .map((selector) => document.querySelector(selector))
        .filter(Boolean);
    let lastTrigger = null;
    let lastBookingTrigger = null;

    const updateScrollCue = () => {
        if (!scrollCue) return;
        const scrollRange = document.documentElement.scrollHeight - window.innerHeight;
        const contact = document.getElementById("contact");
        const footer = document.getElementById("ph-site-footer");
        const footerReached = footer && footer.getBoundingClientRect().top <= window.innerHeight - 80;
        const contactReached = contact && contact.getBoundingClientRect().top <= window.innerHeight * 0.58;
        const atBottom = scrollRange > 0 && (footerReached || contactReached || window.scrollY >= scrollRange - 220);

        scrollCue.classList.toggle("is-up", atBottom);
        scrollCue.dataset.direction = atBottom ? "up" : "down";
        scrollCue.querySelector("span").textContent = atBottom ? "↑" : "↓";
        scrollCue.setAttribute("aria-label", atBottom ? "Вернуться в начало страницы" : "Перейти к следующему блоку");
    };

    const closeLightbox = () => {
        if (!lightbox || !lightboxImage) return;
        lightbox.classList.remove("is-open");
        lightbox.setAttribute("aria-hidden", "true");
        document.body.classList.remove("ph-modal-open");
        lightboxImage.removeAttribute("src");
        lastTrigger?.focus();
    };

    const openBooking = (trigger) => {
        if (!bookingModal || !bookingForm) return;
        lastBookingTrigger = trigger || document.activeElement;
        bookingModal.classList.add("is-open");
        bookingModal.setAttribute("aria-hidden", "false");
        document.body.classList.add("ph-modal-open");
        if (bookingStatus) bookingStatus.textContent = "";
        bookingForm.classList.remove("is-sent");
        bookingForm.querySelector("input:not([type='hidden']), select, textarea")?.focus();
    };

    const closeBooking = () => {
        if (!bookingModal) return;
        bookingModal.classList.remove("is-open");
        bookingModal.setAttribute("aria-hidden", "true");
        document.body.classList.remove("ph-modal-open");
        lastBookingTrigger?.focus();
    };

    const renderVideoPlayer = () => {
        if (!videoPlayer) return;
        const activeCard = videoCards.find((card) => card.classList.contains("is-active"));
        const src = videoPlayer.dataset.videoSrc || activeCard?.dataset.videoSrc || "";
        const title = videoPlayer.dataset.videoTitle || activeCard?.dataset.videoTitle || "Видеоработа";
        if (!src) return;

        const iframe = document.createElement("iframe");
        iframe.src = src.includes("autoplay=1") ? src : `${src}${src.includes("?") ? "&" : "?"}autoplay=1`;
        iframe.title = title;
        iframe.loading = "lazy";
        iframe.allow = "autoplay; encrypted-media; fullscreen; picture-in-picture; screen-wake-lock";
        iframe.allowFullscreen = true;
        videoPlayer.replaceChildren(iframe);
    };

    const setActiveVideo = (button, shouldPlay = false) => {
        if (!button || !videoPlayer) return;
        videoCards.forEach((card) => card.classList.toggle("is-active", card === button));
        videoPlayer.dataset.videoSrc = button.dataset.videoSrc || "";
        videoPlayer.dataset.videoTitle = button.dataset.videoTitle || "";
        if (videoPlayerTitle && videoPlayer.dataset.videoTitle) {
            videoPlayerTitle.textContent = videoPlayer.dataset.videoTitle;
        }
        if (shouldPlay) renderVideoPlayer();
    };

    document.querySelectorAll('.ph-header nav a[href$="#services"], .ph-header nav a[href="#services"]').forEach((link) => {
        if (link.textContent.trim() === "Съемки") link.textContent = "Фото";
    });

    const fixedWorkImages = [
        "portfolio-100.jpg",
        "portfolio-123.jpg",
        "portfolio-113.jpg",
        "portfolio-110.jpg",
        "portfolio-058.jpg",
    ];
    document.querySelectorAll("[data-photo-card]").forEach((card, cardIndex) => {
        const desiredImage = fixedWorkImages[cardIndex];
        const slides = [...card.querySelectorAll(".ph-work-slide")];
        slides.forEach((slide) => {
            const isDesired = Boolean(desiredImage && slide.querySelector("img")?.getAttribute("src")?.endsWith(desiredImage));
            slide.classList.toggle("is-active", isDesired);
            slide.setAttribute("aria-hidden", isDesired ? "false" : "true");
            slide.tabIndex = isDesired ? 0 : -1;
        });
    });

    if (videoCards.length) {
        setActiveVideo(videoCards.find((card) => card.classList.contains("is-active")) || videoCards[0]);
        videoCards.forEach((button) => {
            button.addEventListener("click", () => setActiveVideo(button, true));
        });
        videoPlayButton?.addEventListener("click", renderVideoPlayer);
    }

    document.querySelectorAll("[data-lightbox]").forEach((button) => {
        button.addEventListener("click", () => {
            if (button.getAttribute("aria-hidden") === "true") return;
            if (!lightbox || !lightboxImage) return;
            lastTrigger = button;
            lightboxImage.src = button.dataset.src || "";
            lightboxImage.alt = button.getAttribute("aria-label")?.replace("Открыть фотографию: ", "") || "Фотография";
            lightbox.classList.add("is-open");
            lightbox.setAttribute("aria-hidden", "false");
            document.body.classList.add("ph-modal-open");
            closeButton?.focus();
        });
    });

    closeButton?.addEventListener("click", closeLightbox);
    lightbox?.addEventListener("click", (event) => {
        if (event.target === lightbox) closeLightbox();
    });

    document.querySelectorAll("[data-booking-open]").forEach((button) => {
        button.addEventListener("click", (event) => {
            event.preventDefault();
            openBooking(button);
        });
    });

    document.querySelectorAll("[data-booking-close]").forEach((button) => {
        button.addEventListener("click", closeBooking);
    });

    scrollCue?.addEventListener("click", () => {
        if (scrollCue.dataset.direction === "up") {
            window.scrollTo({ top: 0, behavior: "smooth" });
            return;
        }

        const current = window.scrollY + window.innerHeight * 0.28;
        const target = scrollTargets.find((section) => section.offsetTop > current);
        (target || document.getElementById("ph-site-footer"))?.scrollIntoView({ behavior: "smooth", block: "start" });
    });

    updateScrollCue();
    window.addEventListener("scroll", updateScrollCue, { passive: true });
    window.addEventListener("resize", updateScrollCue);

    bookingForm?.addEventListener("submit", async (event) => {
        event.preventDefault();
        if (!bookingStatus) return;

        const submitButton = bookingForm.querySelector("button[type='submit']");
        const csrfToken = bookingForm.querySelector("input[name='csrf_token']")?.value || "";
        bookingForm.classList.remove("is-sent");
        bookingStatus.textContent = "Отправляю заявку...";
        if (submitButton) submitButton.disabled = true;

        try {
            const response = await fetch(bookingForm.action, {
                method: "POST",
                body: new FormData(bookingForm),
                headers: {
                    "X-Requested-With": "fetch",
                    "X-CSRF-Token": csrfToken,
                },
            });

            if (!response.ok) {
                throw new Error(`Request failed: ${response.status}`);
            }

            bookingForm.reset();
            bookingForm.classList.add("is-sent");
            bookingStatus.textContent = "Заявка отправлена. Я свяжусь с вами.";
        } catch (error) {
            bookingStatus.textContent = "Не получилось отправить заявку. Попробуйте ещё раз или напишите во ВКонтакте.";
        } finally {
            if (submitButton) submitButton.disabled = false;
        }
    });

    document.addEventListener("keydown", (event) => {
        if (event.key === "Escape" && lightbox?.classList.contains("is-open")) closeLightbox();
        if (event.key === "Escape" && bookingModal?.classList.contains("is-open")) closeBooking();
    });

    if (window.location.hash === "#booking") {
        openBooking();
    }
})();
