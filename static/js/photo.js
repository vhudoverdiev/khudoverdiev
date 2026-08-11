(() => {
    const lightbox = document.getElementById("ph-lightbox");
    const lightboxImage = lightbox?.querySelector("img");
    const closeButton = lightbox?.querySelector("[data-lightbox-close]");
    const bookingModal = document.getElementById("booking");
    const bookingForm = bookingModal?.querySelector("[data-booking-form]");
    const bookingStatus = bookingModal?.querySelector("[data-booking-status]");
    const scrollCue = document.querySelector(".ph-scroll-cue");
    const scrollTargets = ["#brands", "#about", "#portfolio", "#services", "#video", "#contact", "#ph-site-footer"]
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

    document.querySelectorAll("[data-photo-card]").forEach((card) => {
        const slides = [...card.querySelectorAll(".ph-work-slide")];
        const counter = card.querySelector("[data-card-counter]");
        if (!slides.length) return;

        let activeIndex = Math.max(0, slides.findIndex((slide) => slide.classList.contains("is-active")));

        const render = () => {
            slides.forEach((slide, index) => {
                slide.classList.toggle("is-active", index === activeIndex);
                slide.setAttribute("aria-hidden", index === activeIndex ? "false" : "true");
                slide.tabIndex = index === activeIndex ? 0 : -1;
            });
            if (counter) {
                counter.textContent = `${String(activeIndex + 1).padStart(2, "0")} / ${String(slides.length).padStart(2, "0")}`;
            }
        };

        card.querySelector("[data-card-prev]")?.addEventListener("click", () => {
            activeIndex = (activeIndex - 1 + slides.length) % slides.length;
            render();
        });
        card.querySelector("[data-card-next]")?.addEventListener("click", () => {
            activeIndex = (activeIndex + 1) % slides.length;
            render();
        });
        render();
    });

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
