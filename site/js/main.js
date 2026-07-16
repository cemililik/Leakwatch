/* Shared interactions for the Leakwatch "Redacted" site:
   mobile navigation, copy-to-clipboard, scroll reveals, the hero scan-reveal
   animation, and the Formspree-backed contact form. */
(function () {
  "use strict";

  var reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  function t(key) { return (window.LWI18n && window.LWI18n.t(key)) || key; }

  /* ---- Mobile nav --------------------------------------------------------- */
  function initNav() {
    var burger = document.getElementById("navBurger");
    var menu = document.getElementById("navMenu");
    if (!burger || !menu) return;

    function closeNav() {
      if (!menu.classList.contains("nav-open")) return;
      menu.classList.remove("nav-open"); menu.style.cssText = "";
      burger.setAttribute("aria-expanded", "false");
    }
    function openNav() {
      menu.classList.add("nav-open");
      burger.setAttribute("aria-expanded", "true");
      menu.style.cssText = "display:flex;position:fixed;top:var(--nav-h);left:0;right:0;flex-direction:column;gap:2px;padding:12px 16px;background:var(--panel);border-bottom:1px solid var(--line-2);z-index:90";
    }

    burger.addEventListener("click", function (e) {
      e.stopPropagation();
      if (menu.classList.contains("nav-open")) closeNav(); else openNav();
    });
    menu.querySelectorAll("a").forEach(function (a) {
      a.addEventListener("click", closeNav);
    });
    document.addEventListener("click", function (e) {
      if (menu.classList.contains("nav-open") && !menu.contains(e.target) && e.target !== burger) closeNav();
    });
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape") closeNav();
    });
  }

  /* ---- Copy to clipboard -------------------------------------------------- */
  function copyText(text, btn) {
    var done = function () {
      if (!btn) return;
      btn.classList.add("copied");
      var orig = btn.innerHTML;
      btn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" aria-hidden="true"><path d="M5 13l4 4L19 7" stroke-linecap="round" stroke-linejoin="round"/></svg>';
      setTimeout(function () { btn.classList.remove("copied"); btn.innerHTML = orig; }, 1600);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done).catch(function () {});
    } else {
      var ta = document.createElement("textarea");
      ta.value = text; document.body.appendChild(ta); ta.select();
      try { document.execCommand("copy"); done(); } catch (e) {}
      document.body.removeChild(ta);
    }
  }
  window.LWCopy = copyText;
  function initCopy() {
    document.querySelectorAll("[data-copy]").forEach(function (line) {
      var btn = line.querySelector(".copy-btn");
      var text = line.getAttribute("data-copy");
      if (btn && text) btn.addEventListener("click", function () { copyText(text, btn); });
    });
  }

  /* ---- Scroll reveal ------------------------------------------------------ */
  function initReveal() {
    var els = document.querySelectorAll(".reveal");
    if (reduceMotion || !("IntersectionObserver" in window)) {
      els.forEach(function (el) { el.classList.add("in"); });
      return;
    }
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (e.isIntersecting) { e.target.classList.add("in"); io.unobserve(e.target); }
      });
    }, { threshold: 0.12 });
    els.forEach(function (el) { io.observe(el); });
  }

  /* ---- Hero scan-reveal animation ---------------------------------------- */
  function initScan() {
    var doc = document.getElementById("heroDoc");
    var redacts = doc ? [].slice.call(doc.querySelectorAll(".redact")) : [];
    var cards = doc ? [].slice.call(doc.querySelectorAll(".finding-card")) : [];

    // Hover/tap-peek on any redaction bar (headline word, detector index
    // chips, hero document). Delegated from document so it keeps working
    // after the i18n layer re-renders nodes with innerHTML on a language
    // switch. `mouseover` covers pointer/mouse users; `click` and
    // `touchstart` give touch and keyboard-activated users the same reveal
    // (a hover-only interaction would otherwise leave the redacted text
    // permanently hidden on touch devices).
    function peekReveal(e) {
      var r = e.target && e.target.closest ? e.target.closest(".redact[data-real]") : null;
      if (r) r.classList.add("revealed");
    }
    document.addEventListener("mouseover", peekReveal);
    document.addEventListener("click", peekReveal);
    document.addEventListener("touchstart", peekReveal, { passive: true });

    function run() {
      if (!doc) return;
      var sl = document.getElementById("scanLine");
      var stamp = document.getElementById("docStamp");
      redacts.forEach(function (r) { r.classList.remove("revealed"); });
      cards.forEach(function (c) { c.classList.remove("in"); });
      if (stamp) stamp.classList.remove("in");

      if (reduceMotion) {
        redacts.forEach(function (r) { r.classList.add("revealed"); });
        cards.forEach(function (c) { c.classList.add("in"); });
        if (stamp) { stamp.classList.add("in"); stamp.textContent = "3 FINDINGS · 2 VERIFIED"; }
        return;
      }

      if (sl) {
        sl.style.transition = "none"; sl.style.top = "0"; sl.style.opacity = "0";
        requestAnimationFrame(function () {
          sl.style.transition = "top 2.4s linear, opacity .3s"; sl.style.opacity = "1";
          var body = doc.querySelector(".doc-body");
          if (body) sl.style.top = (body.offsetHeight - 40) + "px";
        });
      }
      cards.forEach(function (card, i) {
        setTimeout(function () {
          if (redacts[i]) redacts[i].classList.add("revealed");
          card.classList.add("in");
        }, 700 + i * 620);
      });
      setTimeout(function () {
        if (sl) sl.style.opacity = "0";
        if (stamp) { stamp.classList.add("in"); stamp.textContent = "3 FINDINGS · 2 VERIFIED"; }
      }, 700 + cards.length * 620 + 200);
    }

    document.querySelectorAll("[data-scan]").forEach(function (b) {
      b.addEventListener("click", run);
    });
    if (doc) setTimeout(run, 500);
  }

  /* ---- Contact form (Formspree) ------------------------------------------ */
  function initContactForm() {
    var form = document.getElementById("contactForm");
    if (!form) return;
    var statusEl = document.getElementById("cf-status");
    var btn = document.getElementById("cf-submit");

    function setStatus(kind, msg) {
      if (!statusEl) return;
      statusEl.className = "form-status show" + (kind ? " " + kind : "");
      statusEl.textContent = msg;
    }

    form.addEventListener("submit", function (e) {
      e.preventDefault();
      var action = form.getAttribute("action") || "";
      if (!form.checkValidity()) { form.reportValidity(); return; }
      setStatus("", t("contact.f.sending"));
      if (btn) btn.disabled = true;

      var FORM_TIMEOUT_MS = 15000;
      var controller = ("AbortController" in window) ? new AbortController() : null;
      var timer = controller ? setTimeout(function () { controller.abort(); }, FORM_TIMEOUT_MS) : null;

      fetch(action, {
        method: "POST",
        body: new FormData(form),
        headers: { Accept: "application/json" },
        signal: controller ? controller.signal : undefined
      })
        .then(function (r) {
          if (r.ok) { form.reset(); setStatus("ok", t("contact.f.ok")); }
          else { setStatus("err", t("contact.f.err")); }
        })
        .catch(function () { setStatus("err", t("contact.f.err")); })
        .finally(function () {
          if (timer) clearTimeout(timer);
          if (btn) btn.disabled = false;
        });
    });
  }

  /* ---- Boot --------------------------------------------------------------- */
  function init() {
    initNav();
    initCopy();
    initReveal();
    initScan();
    initContactForm();
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
