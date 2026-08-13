(() => {
    const lightbox = document.getElementById("ph-lightbox");
    const lightboxImage = lightbox?.querySelector("img");
    const closeButton = lightbox?.querySelector("[data-lightbox-close]");
    const bookingModal = document.getElementById("booking");
    const bookingForm = bookingModal?.querySelector("[data-booking-form]");
    const bookingStatus = bookingModal?.querySelector("[data-booking-status]");
    const scrollCue = document.querySelector(".ph-scroll-cue");
    const heroButtons = [...document.querySelectorAll(".ph-actions .ph-button")];
    const videoPlayer = document.querySelector("[data-video-player]");
    const videoFrame = document.querySelector("[data-video-frame]");
    const videoCards = [...document.querySelectorAll("[data-video-card]")];
    const bookingSuccessModal = document.getElementById("booking-success");
    const bookingSuccessCloseButtons = [...document.querySelectorAll("[data-booking-success-close]")];
    const bookingNudge = document.querySelector("[data-booking-nudge]");
    const bookingNudgeOpen = bookingNudge?.querySelector("[data-booking-nudge-open]");
    const bookingNudgeClose = bookingNudge?.querySelector("[data-booking-nudge-close]");
    const menuToggle = document.querySelector(".ph-menu-toggle");
    const menuBackdrop = document.querySelector(".ph-menu-backdrop");
    const mobileNav = document.getElementById("ph-mobile-nav");
    const scrollTargets = ["#about", "#portfolio", "#services", "#video", "#reviews", "#contact", "#ph-site-footer"]
        .map((selector) => document.querySelector(selector))
        .filter(Boolean);
    let lastTrigger = null;
    let lastBookingTrigger = null;
    let bookingNudgeDismissed = false;

    const setMobileMenu = (isOpen, restoreFocus = false) => {
        if (!menuToggle || !mobileNav) return;
        document.body.classList.toggle("ph-menu-open", isOpen);
        menuToggle.setAttribute("aria-expanded", isOpen ? "true" : "false");
        menuToggle.setAttribute("aria-label", isOpen ? "\u0417\u0430\u043a\u0440\u044b\u0442\u044c \u043c\u0435\u043d\u044e" : "\u041e\u0442\u043a\u0440\u044b\u0442\u044c \u043c\u0435\u043d\u044e");
        if (isOpen) {
            requestAnimationFrame(() => mobileNav.querySelector("a")?.focus());
        } else if (restoreFocus) {
            menuToggle.focus();
        }
    };

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
        scrollCue.querySelector("span").textContent = atBottom ? "\u2191" : "\u2193";
        scrollCue.setAttribute("aria-label", atBottom ? "\u0412\u0435\u0440\u043d\u0443\u0442\u044c\u0441\u044f \u0432 \u043d\u0430\u0447\u0430\u043b\u043e \u0441\u0442\u0440\u0430\u043d\u0438\u0446\u044b" : "\u041f\u0435\u0440\u0435\u0439\u0442\u0438 \u043a \u0441\u043b\u0435\u0434\u0443\u044e\u0449\u0435\u043c\u0443 \u0431\u043b\u043e\u043a\u0443");
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
        closeBookingSuccess();
        bookingModal.classList.remove("is-hidden");
        bookingNudge?.classList.remove("is-visible");
        document.body.classList.remove("ph-nudge-open");
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
        if (bookingStatus) bookingStatus.textContent = "";
        lastBookingTrigger?.focus();
    };

    const openBookingSuccess = () => {
        if (!bookingSuccessModal) return;
        bookingModal?.classList.add("is-hidden");
        bookingSuccessModal.classList.add("is-open");
        bookingSuccessModal.setAttribute("aria-hidden", "false");
        document.body.classList.add("ph-modal-open");
        requestAnimationFrame(() => {
            bookingSuccessCloseButtons[0]?.focus();
        });
    };

    const closeBookingSuccess = () => {
        if (!bookingSuccessModal) return;
        bookingSuccessModal.classList.remove("is-open");
        bookingSuccessModal.setAttribute("aria-hidden", "true");
        document.body.classList.remove("ph-modal-open");
        lastBookingTrigger?.focus();
    };

    const setHeroButtonState = (activeButton) => {
        if (!heroButtons.length) return;
        heroButtons.forEach((button) => {
            const isActive = button === activeButton;
            button.classList.toggle("ph-button-primary", isActive);
            button.classList.toggle("ph-button-quiet", !isActive);
            button.setAttribute("aria-pressed", isActive ? "true" : "false");
        });
    };

    const setActiveVideo = (button, shouldPlay = false) => {
        if (!button || !videoPlayer || !videoFrame) return;
        const videoTitle = button.dataset.videoTitle || "Видео";
        const videoSrc = button.dataset.videoSrc || "";
        const videoPoster = button.dataset.videoPoster || "";
        videoCards.forEach((card) => {
            const isActive = card === button;
            card.classList.toggle("is-active", isActive);
            card.setAttribute("aria-pressed", isActive ? "true" : "false");
        });
        videoPlayer.dataset.videoTitle = videoTitle;
        if (videoSrc && videoFrame.getAttribute("src") !== videoSrc) {
            videoFrame.pause?.();
            videoFrame.src = videoSrc;
            if (videoPoster) videoFrame.poster = videoPoster;
            videoFrame.load?.();
        } else if (videoPoster) {
            videoFrame.poster = videoPoster;
        }
        videoFrame.title = videoTitle;
        if (shouldPlay) {
            videoFrame.play?.().catch(() => {});
        }
    };
    const showBookingNudge = () => {
        if (!bookingNudge || bookingNudgeDismissed || bookingModal?.classList.contains("is-open")) return;
        bookingNudge.classList.add("is-visible");
        bookingNudge.setAttribute("aria-hidden", "false");
        document.body.classList.add("ph-nudge-open");
    };

    const closeBookingNudge = () => {
        if (!bookingNudge) return;
        bookingNudgeDismissed = true;
        bookingNudge.classList.remove("is-visible");
        bookingNudge.setAttribute("aria-hidden", "true");
        document.body.classList.remove("ph-nudge-open");
    };

    const closeCustomSelect = (customSelect, shouldFocus = false) => {
        if (!customSelect) return;
        const trigger = customSelect.querySelector("[data-custom-select-trigger]");
        customSelect.classList.remove("is-open");
        trigger?.setAttribute("aria-expanded", "false");
        customSelect.querySelectorAll("[data-custom-select-option]").forEach((option) => {
            option.tabIndex = -1;
        });
        if (shouldFocus) trigger?.focus();
    };

    const closeAllCustomSelects = (except = null) => {
        document.querySelectorAll("[data-custom-select]").forEach((customSelect) => {
            if (customSelect !== except) closeCustomSelect(customSelect);
        });
    };

    const initCustomSelects = () => {
        if (!bookingForm) return;
        bookingForm.querySelectorAll(".ph-booking-fields select").forEach((select) => {
            if (select.dataset.customSelectReady === "true") return;

            const labelText = select.closest("label")?.querySelector("span")?.textContent?.trim() || "\u0412\u044b\u0431\u0435\u0440\u0438\u0442\u0435 \u0437\u043d\u0430\u0447\u0435\u043d\u0438\u0435";
            const customSelect = document.createElement("div");
            const trigger = document.createElement("button");
            const value = document.createElement("span");
            const list = document.createElement("div");
            const listId = `${select.name || "select"}-custom-list`;

            customSelect.className = "ph-custom-select";
            customSelect.dataset.customSelect = "";
            trigger.type = "button";
            trigger.className = "ph-custom-select-trigger";
            trigger.dataset.customSelectTrigger = "";
            trigger.setAttribute("aria-haspopup", "listbox");
            trigger.setAttribute("aria-expanded", "false");
            trigger.setAttribute("aria-controls", listId);
            trigger.setAttribute("aria-label", labelText);
            value.className = "ph-custom-select-value";
            value.dataset.customSelectValue = "";
            list.className = "ph-custom-select-list";
            list.id = listId;
            list.role = "listbox";
            list.setAttribute("aria-label", labelText);

            const optionButtons = [...select.options].map((option, index) => {
                const button = document.createElement("button");
                button.type = "button";
                button.className = "ph-custom-select-option";
                button.dataset.customSelectOption = "";
                button.role = "option";
                button.tabIndex = -1;
                button.textContent = option.textContent;
                button.dataset.value = option.value;
                button.addEventListener("click", () => {
                    select.selectedIndex = index;
                    select.dispatchEvent(new Event("change", { bubbles: true }));
                    closeCustomSelect(customSelect, true);
                });
                list.append(button);
                return button;
            });

            const updateCustomSelect = () => {
                const selectedOption = select.options[select.selectedIndex] || select.options[0];
                value.textContent = selectedOption?.textContent || "";
                optionButtons.forEach((button, index) => {
                    const isSelected = index === select.selectedIndex;
                    button.classList.toggle("is-selected", isSelected);
                    button.setAttribute("aria-selected", isSelected ? "true" : "false");
                });
            };

            const openCustomSelect = () => {
                closeAllCustomSelects(customSelect);
                customSelect.classList.add("is-open");
                trigger.setAttribute("aria-expanded", "true");
                optionButtons.forEach((option) => {
                    option.tabIndex = 0;
                });
                (optionButtons[select.selectedIndex] || optionButtons[0])?.focus();
            };

            trigger.append(value);
            customSelect.append(trigger, list);
            select.classList.add("ph-native-select");
            select.dataset.customSelectReady = "true";
            select.after(customSelect);
            updateCustomSelect();

            trigger.addEventListener("click", () => {
                if (customSelect.classList.contains("is-open")) {
                    closeCustomSelect(customSelect);
                } else {
                    openCustomSelect();
                }
            });

            trigger.addEventListener("keydown", (event) => {
                if (["Enter", " ", "ArrowDown", "ArrowUp"].includes(event.key)) {
                    event.preventDefault();
                    openCustomSelect();
                }
            });

            list.addEventListener("keydown", (event) => {
                const currentIndex = optionButtons.indexOf(document.activeElement);
                if (event.key === "Escape") {
                    event.preventDefault();
                    closeCustomSelect(customSelect, true);
                    return;
                }
                if (!["ArrowDown", "ArrowUp", "Home", "End"].includes(event.key)) return;
                event.preventDefault();
                const lastIndex = optionButtons.length - 1;
                const nextIndex = event.key === "Home"
                    ? 0
                    : event.key === "End"
                        ? lastIndex
                        : event.key === "ArrowUp"
                            ? Math.max(0, currentIndex - 1)
                            : Math.min(lastIndex, currentIndex + 1);
                optionButtons[nextIndex]?.focus();
            });

            select.addEventListener("change", updateCustomSelect);
        });
    };

    document.querySelectorAll(".ph-booking-head > p:not(.ph-section-index)").forEach((paragraph) => {
        paragraph.remove();
    });

    document.querySelectorAll('.ph-header nav a[href$="#services"], .ph-header nav a[href="#services"]').forEach((link) => {
        if (link.textContent.trim() === "\u0421\u044a\u0435\u043c\u043a\u0438") link.textContent = "\u0424\u043e\u0442\u043e";
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
    }

    if (heroButtons.length) {
        const activeHeroButton = heroButtons.find((button) => button.getAttribute("href") === window.location.hash);
        setHeroButtonState(activeHeroButton || null);
        heroButtons.forEach((button) => {
            button.addEventListener("click", () => setHeroButtonState(button));
        });
    }

    initCustomSelects();
    document.addEventListener("click", (event) => {
        if (!event.target.closest("[data-custom-select]")) closeAllCustomSelects();
    });

    document.querySelectorAll("[data-lightbox]").forEach((button) => {
        button.addEventListener("click", () => {
            if (button.getAttribute("aria-hidden") === "true") return;
            if (!lightbox || !lightboxImage) return;
            lastTrigger = button;
            lightboxImage.src = button.dataset.src || "";
            lightboxImage.alt = button.getAttribute("aria-label")?.replace("\u041e\u0442\u043a\u0440\u044b\u0442\u044c \u0444\u043e\u0442\u043e\u0433\u0440\u0430\u0444\u0438\u044e: ", "") || "\u0424\u043e\u0442\u043e\u0433\u0440\u0430\u0444\u0438\u044f";
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
            setMobileMenu(false);
            openBooking(button);
        });
    });

    menuToggle?.addEventListener("click", () => {
        setMobileMenu(menuToggle.getAttribute("aria-expanded") !== "true");
    });
    menuBackdrop?.addEventListener("click", () => setMobileMenu(false, true));
    mobileNav?.querySelectorAll("a").forEach((link) => {
        link.addEventListener("click", () => setMobileMenu(false));
    });

    document.querySelectorAll("[data-booking-close]").forEach((button) => {
        button.addEventListener("click", closeBooking);
    });

    bookingSuccessCloseButtons.forEach((button) => {
        button.addEventListener("click", closeBookingSuccess);
    });
    bookingSuccessModal?.addEventListener("click", (event) => {
        if (event.target === bookingSuccessModal) closeBookingSuccess();
    });

    bookingNudgeOpen?.addEventListener("click", () => {
        closeBookingNudge();
        openBooking(bookingNudgeOpen);
    });
    bookingNudgeClose?.addEventListener("click", closeBookingNudge);
    if (bookingNudge) {
        window.setTimeout(showBookingNudge, 120000);
    }

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

        const submitButton = bookingForm.querySelector("button[type='submit']");
        const csrfToken = bookingForm.querySelector("input[name='csrf_token']")?.value || "";
        const setBookingStatus = (text) => {
            if (bookingStatus) bookingStatus.textContent = text;
        };
        bookingForm.classList.remove("is-sent");
        setBookingStatus("\u041e\u0442\u043f\u0440\u0430\u0432\u043b\u044f\u044e \u0437\u0430\u044f\u0432\u043a\u0443...");
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
            requestAnimationFrame(() => {
                bookingForm.querySelectorAll(".ph-booking-fields select").forEach((select) => {
                    select.dispatchEvent(new Event("change", { bubbles: true }));
                });
            });
            setBookingStatus("");
            closeBooking();
            openBookingSuccess();
        } catch (error) {
            setBookingStatus("\u041d\u0435 \u043f\u043e\u043b\u0443\u0447\u0438\u043b\u043e\u0441\u044c \u043e\u0442\u043f\u0440\u0430\u0432\u0438\u0442\u044c \u0437\u0430\u044f\u0432\u043a\u0443. \u041f\u043e\u043f\u0440\u043e\u0431\u0443\u0439\u0442\u0435 \u0435\u0449\u0451 \u0440\u0430\u0437 \u0438\u043b\u0438 \u043d\u0430\u043f\u0438\u0448\u0438\u0442\u0435 \u0432\u043e \u0412\u041a\u043e\u043d\u0442\u0430\u043a\u0442\u0435.");
        } finally {
            if (submitButton) submitButton.disabled = false;
        }
    });

    document.addEventListener("keydown", (event) => {
        if (event.key === "Escape" && document.body.classList.contains("ph-menu-open")) setMobileMenu(false, true);
        if (event.key === "Escape") closeAllCustomSelects();
        if (event.key === "Escape" && lightbox?.classList.contains("is-open")) closeLightbox();
        if (event.key === "Escape" && bookingSuccessModal?.classList.contains("is-open")) closeBookingSuccess();
        if (event.key === "Escape" && bookingModal?.classList.contains("is-open")) closeBooking();
    });

    if (window.location.hash === "#booking") {
        openBooking();
    }

    window.matchMedia("(min-width: 761px)").addEventListener("change", (event) => {
        if (event.matches) setMobileMenu(false);
    });
})();
