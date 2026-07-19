/* Documentation portal controller.
   Renders the sidebar navigation and page content from the compiled manual
   bags (js/manuals/*.js), driven by a `#/<section>/<page>` hash route.
   Handles language switching, search, Mermaid diagrams, code copy buttons,
   prev/next paging, and the reading-progress bar. */
(function () {
  "use strict";

  var INDEX = window.LW_MANUAL_INDEX;
  if (!INDEX) return;

  var navEl = document.getElementById("docsNav");
  var contentEl = document.getElementById("docContent");
  var crumbEl = document.getElementById("breadcrumb");
  var mobileCrumbEl = document.getElementById("mobileCrumb");
  var pagerEl = document.getElementById("docPager");
  var searchEl = document.getElementById("docsSearch");
  var sidebarEl = document.getElementById("docsSidebar");
  var progressEl = document.getElementById("docsProgress");
  var tocNavEl = document.getElementById("tocNav");
  var tocAsideEl = document.getElementById("docsToc");
  var tocHeadings = [];

  var ICONS = {
    rocket: '<path d="M5 15c-1.5 1.5-2 5-2 5s3.5-.5 5-2"/><path d="M9 11a12 12 0 0 1 7-8c2.5 0 4 1.5 4 4a12 12 0 0 1-8 7l-3-3Z"/><circle cx="14.5" cy="9.5" r="1.2"/>',
    scan: '<circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3" stroke-linecap="round"/>',
    shield: '<path d="M12 3 4 6v6c0 5 3.4 8.5 8 9.7 4.6-1.2 8-4.7 8-9.7V6l-8-3Z"/><path d="m9 12 2 2 4-4" stroke-linecap="round" stroke-linejoin="round"/>',
    key: '<circle cx="8" cy="15" r="4"/><path d="m11 12 8-8 2 2M16 7l2 2" stroke-linecap="round"/>',
    sliders: '<path d="M4 6h10M18 6h2M4 12h2M10 12h10M4 18h7M15 18h5" stroke-linecap="round"/><circle cx="16" cy="6" r="2"/><circle cx="8" cy="12" r="2"/><circle cx="13" cy="18" r="2"/>',
    output: '<path d="M14 3v4a1 1 0 0 0 1 1h4"/><path d="M5 3h9l5 5v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2Z"/>',
    ci: '<circle cx="6" cy="6" r="2.5"/><circle cx="6" cy="18" r="2.5"/><circle cx="18" cy="18" r="2.5"/><path d="M6 8.5v7M8.5 18H15a3 3 0 0 0 3-3v-2"/>',
    book: '<path d="M4 5a2 2 0 0 1 2-2h13v16H6a2 2 0 0 0-2 2V5Z"/><path d="M4 19a2 2 0 0 0 2 2h13"/>'
  };
  var COPY_SVG = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>';

  /* ---- Manual bags (lazy-loaded per language) ------------------------------
     js/manuals/en.js and js/manuals/tr.js are generated, sizeable (~300KB
     each) globals-setting scripts (window.LW_MANUAL[lang] = {...}), not ES
     modules. Only the currently active language is fetched up front; the
     other one is fetched on first switch, mirroring the Mermaid lazy-load
     pattern above. */
  var _manualLoads = {};
  function loadManual(l) {
    if (window.LW_MANUAL && window.LW_MANUAL[l]) return Promise.resolve();
    if (_manualLoads[l]) return _manualLoads[l];
    _manualLoads[l] = new Promise(function (resolve) {
      var s = document.createElement("script");
      s.src = "js/manuals/" + l + ".js";
      s.onload = function () { resolve(); };
      s.onerror = function () { resolve(); }; // render() falls back to a "not found" state
      document.head.appendChild(s);
    });
    return _manualLoads[l];
  }

  function lang() { return window.LWI18n ? window.LWI18n.getLang() : (INDEX.default || "en"); }
  function t(key) { return window.LWI18n ? window.LWI18n.t(key) : key; }
  function bag(l) {
    var m = window.LW_MANUAL || {};
    return m[l || lang()] || m[INDEX.default || "en"] || {};
  }
  function titleFor(obj) { return (obj.title && (obj.title[lang()] || obj.title[INDEX.default])) || obj.id; }

  // Flat ordered list of pages for prev/next.
  function flat() {
    var out = [];
    INDEX.sections.forEach(function (s) {
      s.pages.forEach(function (p) {
        out.push({ key: s.id + "/" + p.id, section: s, page: p });
      });
    });
    return out;
  }

  /* ---- Sidebar ------------------------------------------------------------ */
  function buildNav() {
    navEl.innerHTML = "";
    INDEX.sections.forEach(function (s) {
      var sec = document.createElement("div");
      sec.className = "docs-nav-section";
      sec.dataset.section = s.id;

      var title = document.createElement("div");
      title.className = "docs-nav-title";
      title.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">' + (ICONS[s.icon] || "") + "</svg><span>" + escapeHtml(titleFor(s)) + "</span>";
      sec.appendChild(title);

      var ul = document.createElement("ul");
      s.pages.forEach(function (p) {
        var key = s.id + "/" + p.id;
        var li = document.createElement("li");
        var a = document.createElement("a");
        a.className = "docs-nav-link";
        a.href = "#/" + key;
        a.dataset.key = key;
        a.textContent = titleFor(p);
        li.appendChild(a);
        ul.appendChild(li);
      });
      sec.appendChild(ul);
      navEl.appendChild(sec);
    });
  }

  function setActive(key) {
    navEl.querySelectorAll(".docs-nav-link").forEach(function (a) {
      a.classList.toggle("active", a.dataset.key === key);
    });
  }

  /* ---- Rendering ---------------------------------------------------------- */
  function currentKey() {
    var h = location.hash.replace(/^#\/?/, "");
    return h || (flat()[0] && flat()[0].key);
  }

  function render() {
    var key = currentKey();
    var data = bag()[key] || bag("en")[key];
    var meta = flat().filter(function (x) { return x.key === key; })[0];

    if (!data) {
      contentEl.innerHTML = '<p class="docs-empty">' + escapeHtml(t("docs.notfound") || "Not found") + "</p>";
      pagerEl.innerHTML = "";
      crumbEl.textContent = "";
      return;
    }

    contentEl.innerHTML = data.html;
    document.title = data.title + " — Leakwatch";
    setActive(key);

    var crumb = meta
      ? "<b>" + escapeHtml(titleFor(meta.section)) + "</b> / " + escapeHtml(titleFor(meta.page))
      : "";
    crumbEl.innerHTML = crumb;
    if (mobileCrumbEl) mobileCrumbEl.innerHTML = crumb;

    enhanceCode();
    renderMermaid();
    buildPager(key);
    buildToc();

    contentEl.querySelectorAll("img").forEach(function (img) { img.loading = "lazy"; });
    window.scrollTo({ top: 0, behavior: "auto" });
    updateProgress();
  }

  function buildPager(key) {
    var list = flat();
    var idx = -1;
    for (var i = 0; i < list.length; i++) { if (list[i].key === key) { idx = i; break; } }
    pagerEl.innerHTML = "";
    if (idx === -1) return;
    if (idx > 0) {
      var prev = list[idx - 1];
      pagerEl.appendChild(pagerLink(prev, "prev", t("docs.prev") || "Previous"));
    }
    if (idx < list.length - 1) {
      var next = list[idx + 1];
      pagerEl.appendChild(pagerLink(next, "next", t("docs.next") || "Next"));
    }
  }
  function pagerLink(item, dir, label) {
    var a = document.createElement("a");
    a.href = "#/" + item.key;
    a.className = dir;
    a.innerHTML = '<div class="dir">' + (dir === "prev" ? "← " : "") + escapeHtml(label) + (dir === "next" ? " →" : "") +
      '</div><div class="ttl">' + escapeHtml(titleFor(item.page)) + "</div>";
    return a;
  }

  /* ---- Code copy buttons -------------------------------------------------- */
  function enhanceCode() {
    contentEl.querySelectorAll("pre").forEach(function (pre) {
      var code = pre.querySelector("code");
      if (code && /\blanguage-mermaid\b/.test(code.className)) return;
      var text = code ? code.textContent : pre.textContent;
      var btn = document.createElement("button");
      btn.className = "copy-btn";
      btn.setAttribute("aria-label", "Copy code");
      btn.innerHTML = COPY_SVG;
      btn.addEventListener("click", function () { if (window.LWCopy) window.LWCopy(text, btn); });
      pre.appendChild(btn);
    });
  }

  /* ---- Mermaid ------------------------------------------------------------ */
  var _mermaid = null;
  function loadMermaid() {
    if (_mermaid) return Promise.resolve(_mermaid);
    // Pinned to an exact version (not a floating "@11") so a CDN release
    // can't silently change what code runs on this page.
    return import("https://cdn.jsdelivr.net/npm/mermaid@11.4.1/dist/mermaid.esm.min.mjs")
      .then(function (mod) {
        _mermaid = mod.default;
        _mermaid.initialize({
          startOnLoad: false,
          theme: document.documentElement.getAttribute("data-theme") === "light" ? "default" : "dark",
          securityLevel: "strict",
          fontFamily: "JetBrains Mono, monospace"
        });
        return _mermaid;
      });
  }
  function renderMermaid() {
    var blocks = contentEl.querySelectorAll("pre > code.language-mermaid");
    if (!blocks.length) return;
    var nodes = [];
    blocks.forEach(function (code) {
      var div = document.createElement("div");
      div.className = "mermaid";
      div.textContent = code.textContent;
      code.parentElement.replaceWith(div);
      nodes.push(div);
    });
    loadMermaid().then(function (m) {
      try { m.run({ nodes: nodes }); } catch (e) {}
    }).catch(function () {});
  }

  /* ---- Search ------------------------------------------------------------- */
  function initSearch() {
    if (!searchEl) return;
    searchEl.addEventListener("input", function () {
      var q = searchEl.value.toLowerCase().trim();
      navEl.querySelectorAll(".docs-nav-section").forEach(function (sec) {
        var visible = 0;
        sec.querySelectorAll(".docs-nav-link").forEach(function (a) {
          var match = !q || a.textContent.toLowerCase().indexOf(q) !== -1;
          a.classList.toggle("hidden", !match);
          if (match) visible++;
        });
        sec.classList.toggle("hidden", visible === 0);
      });
    });
  }

  /* ---- Mobile sidebar ----------------------------------------------------- */
  function initMobileSidebar() {
    var toggle = document.getElementById("sidebarToggle");
    if (toggle && sidebarEl) {
      toggle.addEventListener("click", function () { sidebarEl.classList.toggle("open"); });
    }
    navEl.addEventListener("click", function (e) {
      if (e.target.closest(".docs-nav-link") && sidebarEl) sidebarEl.classList.remove("open");
    });
  }

  /* ---- "On this page" table of contents ---------------------------------- */
  function buildToc() {
    if (!tocNavEl) return;
    tocNavEl.innerHTML = "";
    tocHeadings = [].slice.call(contentEl.querySelectorAll("h2[id], h3[id]"));
    if (!tocHeadings.length) {
      if (tocAsideEl) tocAsideEl.classList.add("empty");
      return;
    }
    if (tocAsideEl) tocAsideEl.classList.remove("empty");
    tocHeadings.forEach(function (h) {
      var a = document.createElement("a");
      a.className = "toc-link " + (h.tagName === "H3" ? "lvl-3" : "lvl-2");
      a.textContent = h.textContent;
      a.setAttribute("role", "link");
      a.setAttribute("tabindex", "0");
      a.dataset.id = h.id;
      function go() {
        h.scrollIntoView({ behavior: "smooth", block: "start" });
        setTocActive(h.id);
      }
      a.addEventListener("click", function (e) { e.preventDefault(); go(); });
      a.addEventListener("keydown", function (e) { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); go(); } });
      tocNavEl.appendChild(a);
    });
    updateTocActive();
  }

  function setTocActive(id) {
    if (!tocNavEl) return;
    tocNavEl.querySelectorAll(".toc-link").forEach(function (a) {
      a.classList.toggle("active", a.dataset.id === id);
    });
  }

  function updateTocActive() {
    if (!tocHeadings.length) return;
    var top = (parseInt(getComputedStyle(document.documentElement).scrollPaddingTop, 10) || 90) + 16;
    var current = tocHeadings[0];
    for (var i = 0; i < tocHeadings.length; i++) {
      if (tocHeadings[i].getBoundingClientRect().top <= top) current = tocHeadings[i];
      else break;
    }
    setTocActive(current.id);
  }

  /* ---- Progress bar ------------------------------------------------------- */
  function updateProgress() {
    if (!progressEl) return;
    var h = document.documentElement;
    var max = h.scrollHeight - h.clientHeight;
    progressEl.style.width = (max > 0 ? (h.scrollTop / max) * 100 : 0) + "%";
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  /* ---- Boot --------------------------------------------------------------- */
  // Kick off the active language's manual fetch immediately (don't wait on
  // DOMContentLoaded) so it's in flight as early as possible.
  var manualReady = loadManual(lang());

  function init() {
    buildNav();
    initSearch();
    initMobileSidebar();

    if (!location.hash) {
      location.replace("#/" + currentKey());
    }
    render();

    window.addEventListener("hashchange", render);
    window.addEventListener("scroll", function () { updateProgress(); updateTocActive(); }, { passive: true });
    document.addEventListener("lw:langchange", function (e) {
      _mermaid = null; // re-init theme/locale on next diagram
      var l = (e.detail && e.detail.lang) || lang();
      loadManual(l).then(function () {
        buildNav();
        if (searchEl) searchEl.value = "";
        render();
      });
    });
  }
  function boot() {
    manualReady.then(init);
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
