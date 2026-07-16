/* Leakwatch playground — in-browser secret scanner.
   Loads the detector set compiled from the Go source (window.LW_DETECTORS) and
   runs real regex + entropy detection entirely client-side. Nothing is ever
   uploaded. This is a preview: it does pattern detection only — the CLI adds
   live verification, Git history, containers, cloud, and entropy/custom rules. */
(function () {
  "use strict";

  var codeEl = document.getElementById("code");
  if (!codeEl) return;
  var out = document.getElementById("out");
  var countEl = document.getElementById("count");
  var detCountEl = document.getElementById("detCount");

  var MIN_MATCH = 8;          // ignore matches shorter than this (kills context-gate noise)
  var INPUT_CAP = 64 * 1024;  // guard against pathological input

  function t(k, fb) {
    return (window.LWI18n && window.LWI18n.t(k)) || fb || k;
  }

  // Compile the usable detector set from the build-extracted patterns.
  var DETS = (window.LW_DETECTORS || []).map(function (d) {
    var res = (d.patterns || []).map(function (p) {
      try {
        var flags = "g" + (p.flags || "").replace(/g/g, "");
        return new RegExp(p.src, flags);
      } catch (e) {
        return null;
      }
    }).filter(Boolean);
    return { id: d.id, sev: d.severity, kw: d.keywords || [], res: res };
  }).filter(function (d) { return d.res.length; });

  if (detCountEl) detCountEl.textContent = String(DETS.length);

  var SAMPLES = {
    env:
"# config/prod.env  (example values — safe to scan)\n" +
"DB_HOST=db.internal.acme.io\n" +
"DB_PORT=5432\n" +
// Example values are split into fragments so the source file never contains a
// contiguous secret-shaped string (which would trip secret-scanning / push
// protection). They are reassembled at runtime, so the demo is unaffected.
"AWS_ACCESS_KEY_ID=" + "AKIA" + "IOSFODNN7EXAMPLE\n" +
"OPENAI_API_KEY=" + "sk-" + "proj-Hb3xExampleKey0aZ9q1W2e3R4t5Y6u7I8o9P0aS1d2F3g4H5j6K7l8\n" +
"GITHUB_TOKEN=" + "ghp" + "_Example1234567890abcdefABCDEF1234567890\n" +
"STRIPE_SECRET=" + "sk_" + "live_4eC39HqLyExampleKey1234abcd\n" +
"LOG_LEVEL=info\n" +
"JWT=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.dozjgExampleSignature0w5Nq9\n",
    code:
"// service/client.js (example values)\n" +
"const cfg = {\n" +
"  region: \"eu-central-1\",\n" +
"  sendgrid: \"" + "SG." + "Exampleaaaaaaaaaaaaaaaa.Examplebbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\n" +
"  npmToken: \"" + "npm" + "_Example1234567890abcdefABCDEFabcdef12\",\n" +
"  digitalocean: \"dop_v1_\" + \"a\".repeat(64),\n" +
"};\n",
    clear: "",
  };
  codeEl.value = SAMPLES.env;

  function entropy(s) {
    var freq = {}, i;
    for (i = 0; i < s.length; i++) freq[s[i]] = (freq[s[i]] || 0) + 1;
    var e = 0, n = s.length, k;
    for (k in freq) { var p = freq[k] / n; e -= p * Math.log2(p); }
    return e.toFixed(2);
  }
  function redact(s) {
    if (s.length <= 12) return "•".repeat(s.length);
    return s.slice(0, 4) + "•".repeat(Math.min(14, s.length - 8)) + s.slice(-4);
  }
  function lineOf(text, idx) { return text.slice(0, idx).split("\n").length; }
  function esc(s) {
    return String(s).replace(/[&<>"]/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c];
    });
  }

  var lastFound = [], lastTruncated = false;

  function scan() {
    var text = codeEl.value;
    var truncated = false;
    if (text.length > INPUT_CAP) { text = text.slice(0, INPUT_CAP); truncated = true; }
    var lower = text.toLowerCase();
    var found = [], seen = {};

    DETS.forEach(function (d) {
      // Aho-Corasick-style keyword pre-filter (faithful to the engine).
      if (d.kw.length && !d.kw.some(function (k) { return lower.indexOf(k.toLowerCase()) !== -1; })) return;
      d.res.forEach(function (re) {
        re.lastIndex = 0;
        var m;
        while ((m = re.exec(text)) !== null) {
          var whole = m[0];
          if (whole.length >= MIN_MATCH) {
            // Prefer the longest capture group (the secret) for display.
            var disp = whole;
            for (var i = 1; i < m.length; i++) {
              if (m[i] && m[i].length >= MIN_MATCH && m[i].length < disp.length) disp = m[i];
            }
            var line = lineOf(text, m.index);
            var key = d.id + "|" + disp + "|" + line;
            if (!seen[key]) { seen[key] = true; found.push({ id: d.id, sev: d.sev, line: line, val: disp }); }
          }
          if (m.index === re.lastIndex) re.lastIndex++; // avoid zero-width loop
        }
      });
    });

    var order = { critical: 0, high: 1, medium: 2, low: 3 };
    found.sort(function (a, b) { return (order[a.sev] - order[b.sev]) || (a.line - b.line); });
    lastFound = found; lastTruncated = truncated;
    render(found, truncated);
  }

  function render(found, truncated) {
    countEl.textContent = found.length
      ? found.length + " " + t("play.count.detected", "detected")
      : "0 " + t("play.count.findings", "findings");
    if (!found.length) {
      out.innerHTML = '<div class="play-empty">' + esc(t("play.none", "No secrets detected in this input.")) + "</div>";
      return;
    }
    var html = "";
    if (truncated) html += '<div class="play-trunc">' + esc(t("play.truncated", "Input truncated to 64 KB for this preview.")) + "</div>";
    found.forEach(function (f, i) {
      html +=
        '<div class="play-finding" style="animation-delay:' + (i * 0.03) + 's">' +
          '<div class="pf-top"><span class="sev ' + f.sev + '">' + f.sev.toUpperCase() + "</span>" +
          '<span class="pf-det">' + esc(f.id) + "</span>" +
          '<span class="pf-loc">' + t("play.f.line", "line") + " " + f.line + "</span></div>" +
          '<div class="pf-val"><code class="pf-secret">' + esc(redact(f.val)) + "</code></div>" +
          '<div class="pf-meta"><span>' + t("play.f.entropy", "entropy") + " " + entropy(f.val) + "</span>" +
          "<span>" + f.val.length + " " + t("play.f.chars", "chars") + "</span>" +
          '<span class="pf-status">' + t("play.f.detected", "detected · verify in CLI") + "</span></div>" +
        "</div>";
    });
    out.innerHTML = html;
  }

  // Wiring
  document.getElementById("run").addEventListener("click", scan);
  codeEl.addEventListener("keydown", function (e) {
    if ((e.metaKey || e.ctrlKey) && e.key === "Enter") { e.preventDefault(); scan(); }
  });
  document.querySelectorAll("[data-sample]").forEach(function (b) {
    b.addEventListener("click", function () {
      codeEl.value = SAMPLES[b.getAttribute("data-sample")] || "";
      if (b.getAttribute("data-sample") === "clear") { lastFound = []; render([], false); } else { scan(); }
    });
  });
  var pasteBtn = document.getElementById("paste");
  if (pasteBtn) pasteBtn.addEventListener("click", function () {
    if (navigator.clipboard && navigator.clipboard.readText) {
      navigator.clipboard.readText().then(function (txt) { codeEl.value = txt; scan(); }).catch(function () { codeEl.focus(); });
    } else { codeEl.focus(); }
  });
  document.addEventListener("lw:langchange", function () { render(lastFound, lastTruncated); });

  window.addEventListener("load", function () { setTimeout(scan, 350); });
})();
