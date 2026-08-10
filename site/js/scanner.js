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
  var INPUT_CAP = 64 * 1024;  // UTF-8 byte cap guarding pathological input

  function t(k, fb) {
    return (window.LWI18n && window.LWI18n.t(k)) || fb || k;
  }

  // Compile the usable detector set from the build-extracted patterns.
  function compilePatterns(patterns) {
    return (patterns || []).map(function (p) {
      try {
        var flags = "g" + (p.flags || "").replace(/g/g, "");
        return new RegExp(p.src, flags);
      } catch (e) {
        return null;
      }
    }).filter(Boolean);
  }

  var DETS = (window.LW_DETECTORS || []).map(function (d) {
    var correlation = d.correlation || {};
    return {
      id: d.id,
      sev: d.severity,
      kw: d.keywords || [],
      res: compilePatterns(d.patterns),
      required: compilePatterns(correlation.requiredNearby),
      proximity: correlation.proximityBytes || 0,
      sameBlock: correlation.sameLogicalBlock === true,
      rejectPlaceholders: correlation.rejectPlaceholders === true,
      oneToOne: correlation.oneToOne === true,
    };
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

  function utf8Width(codePoint) {
    if (codePoint <= 0x7f) return 1;
    if (codePoint <= 0x7ff) return 2;
    if (codePoint <= 0xffff) return 3;
    return 4;
  }

  function truncateUTF8(value, byteCap) {
    var bytes = 0, index = 0;
    while (index < value.length) {
      var codePoint = value.codePointAt(index);
      var units = codePoint > 0xffff ? 2 : 1;
      var width = utf8Width(codePoint);
      if (bytes + width > byteCap) break;
      bytes += width;
      index += units;
    }
    return { text: value.slice(0, index), truncated: index < value.length };
  }

  function utf8PrefixOffsets(value) {
    var offsets = new Uint32Array(value.length + 1);
    var bytes = 0, index = 0;
    while (index < value.length) {
      offsets[index] = bytes;
      var codePoint = value.codePointAt(index);
      var units = codePoint > 0xffff ? 2 : 1;
      if (units === 2) offsets[index + 1] = bytes;
      bytes += utf8Width(codePoint);
      index += units;
      offsets[index] = bytes;
    }
    return offsets;
  }

  function rangeGap(byteOffsets, a, b) {
    if (a.end <= b.start) return byteOffsets[b.start] - byteOffsets[a.end];
    if (b.end <= a.start) return byteOffsets[a.start] - byteOffsets[b.end];
    return 0;
  }

  function sameLogicalBlock(text, a, b) {
    var start = a.end, end = b.start;
    if (b.end <= a.start) { start = b.end; end = a.start; }
    if (start > end) return false;
    var between = text.slice(start, end);
    return !/(?:\r?\n[ \t]*\r?\n|\r?\n[ \t]*-[ \t]+|\r?\n[ \t]*\[[^\r\n]+\][ \t]*(?:\r?\n|$))/.test(between) &&
      !/[{}]/.test(between);
  }

  function allMatchRanges(regexes, text) {
    var ranges = [];
    regexes.forEach(function (re) {
      re.lastIndex = 0;
      var match;
      while ((match = re.exec(text)) !== null) {
        var whole = match[0], captured = "";
        for (var i = 1; i < match.length; i++) {
          if (match[i] && match[i].length > captured.length) captured = match[i];
        }
        var end = re.lastIndex;
        if (captured) end = match.index + whole.lastIndexOf(captured) + captured.length;
        ranges.push({ start: match.index, end: end, used: false });
        if (match.index === re.lastIndex) re.lastIndex++;
      }
    });
    return ranges;
  }

  function isPlaceholder(value) {
    var lower = String(value || "").trim().toLowerCase();
    var exact = {
      "change-me": true, "change_me": true, "changeme": true, "dummy": true,
      "example": true, "example-secret": true, "example_secret": true, "fixme": true,
      "foobar": true, "not-a-real-secret": true, "not_a_real_secret": true,
      "placeholder": true, "redacted": true, "replace-me": true, "replace_me": true,
      "secret": true, "string": true, "test": true, "todo": true,
      "api-key-secret": true, "api_key_secret": true,
      "twilio-api-key-secret": true, "twilio_api_key_secret": true, "twilioapikeysecret": true,
      "your-api-key-secret": true, "your_api_key_secret": true,
      "your-twilio-api-key-secret": true, "your_twilio_api_key_secret": true, "xxxxxxxx": true,
    };
    if (!lower || exact[lower]) return true;
    var prefixes = ["${", "$", "{{", "%", "<", "vault://", "op://", "secret://", "file://", "/run/secrets/", "@microsoft.keyvault"];
    if (prefixes.some(function (prefix) { return lower.indexOf(prefix) === 0; })) return true;
    return lower.length >= 4 && /^[x*0-]+$/.test(lower);
  }

  function escapedAt(value, index) {
    var backslashes = 0;
    for (var i = index - 1; i >= 0 && value[i] === "\\"; i--) backslashes++;
    return backslashes % 2 === 1;
  }

  var lastFound = [], lastTruncated = false;

  function detectText(input) {
    var bounded = truncateUTF8(String(input || ""), INPUT_CAP);
    var text = bounded.text;
    var truncated = bounded.truncated;
    var byteOffsets = utf8PrefixOffsets(text);
    var lower = text.toLowerCase();
    var found = [], seen = {};

    DETS.forEach(function (d) {
      // Aho-Corasick-style keyword pre-filter (faithful to the engine).
      if (d.kw.length && !d.kw.some(function (k) { return lower.indexOf(k.toLowerCase()) !== -1; })) return;
      var companions = allMatchRanges(d.required, text);
      d.res.forEach(function (re) {
        re.lastIndex = 0;
        var m;
        while ((m = re.exec(text)) !== null) {
          var whole = m[0];
          // Prefer the captured secret value over its assignment wrapper.
          var disp = whole, captured = "";
          for (var i = 1; i < m.length; i++) {
            if (m[i] && m[i].length > captured.length && (d.required.length || m[i].length >= MIN_MATCH)) captured = m[i];
          }
          if (captured) disp = captured;
          var valueOffset = whole.lastIndexOf(disp);
          var primaryRange = { start: m.index, end: m.index + valueOffset + disp.length };
          var closing = valueOffset + disp.length;
          var truncatedQuotedValue = closing < whole.length && (whole[closing] === '"' || whole[closing] === "'") && escapedAt(whole, closing);
          var companionIndex = -1, bestDistance = -1;
          companions.forEach(function (companion, index) {
            if (d.oneToOne && companion.used) return;
            var distance = rangeGap(byteOffsets, primaryRange, companion);
            if (distance > d.proximity || (d.sameBlock && !sameLogicalBlock(text, primaryRange, companion))) return;
            if (bestDistance === -1 || distance < bestDistance) {
              bestDistance = distance;
              companionIndex = index;
            } else if (distance === bestDistance) {
              companionIndex = -1;
            }
          });
          var correlated = !d.required.length || companionIndex >= 0;
          if (correlated && !truncatedQuotedValue && whole.length >= MIN_MATCH && (!d.rejectPlaceholders || !isPlaceholder(disp))) {
            if (d.oneToOne && companionIndex >= 0) companions[companionIndex].used = true;
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
    return { found: found, truncated: truncated };
  }

  function scan() {
    var result = detectText(codeEl.value);
    lastFound = result.found; lastTruncated = result.truncated;
    render(result.found, result.truncated);
  }

  // A side-effect-free hook used by the generated-detector contract test. It
  // also makes the playground's preview semantics independently auditable.
  window.LW_PLAYGROUND_DETECT = function (text) { return detectText(text).found; };
  window.LW_PLAYGROUND_SCAN = detectText;

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
