/* eslint-disable @typescript-eslint/no-unused-vars */
/*!
 * E-Learning Kiosk Lock
 * Standalone injectable focus lock for Moodle / e-learning pages.
 *
 * Usage:
 *   window.ELEARNING_KIOSK_CONFIG = {
 *     apiBaseUrl: "https://your-kiosk-host.example.com",
 *     lockAfterMs: 3000,
 *   };
 *   // then load this file with <script src=".../kiosk-lock.js" defer></script>
 *
 * Google Authenticator-style TOTP: when a client secret is configured, this
 * script computes the expected 4-digit code from the local clock and compares
 * it with the code entered by the student. No snapshot and no verification
 * request is needed. Long tokens/QR are still verified offline with the
 * Ed25519 public key. A Moodle role probe ensures only students are locked;
 * teachers/admins are skipped.
 */
(function () {
  "use strict";

  if (window.top !== window.self) return;
  if (window.__ELEARNING_KIOSK_LOCK_LOADED__) return;
  window.__ELEARNING_KIOSK_LOCK_LOADED__ = true;

  var DEFAULTS = {
    apiBaseUrl: "",
    lockAfterMs: 3000,
    storageKey: "elearning-kiosk-lock",
    zIndex: 2147483647,
    publicKeyJwk: null,
    studentOnly: true,
    roleEndpoint: "",
    roleCacheMs: 60000,
    assumeStudentWhenUnknown: false,
    staffUserIds: [],
    studentUserIds: [],
    domDefaultIsStudent: true,
    debug: false,
    demoMode: false,
    totpSecret: null,
    totpPeriodSeconds: 30,
    totpDigits: 4,
    totpGraceWindows: 0,
    clientVerify: false,
    signedKeyUrl: "/api/kiosk/signed-key",
    serverVerify: false,
    codeVerifyUrl: "/api/kiosk/verify-code",
    onLock: null,
    onUnlock: null,
  };

  var config = Object.assign({}, DEFAULTS, window.ELEARNING_KIOSK_CONFIG || {});

  // Legacy TOTP client-side. Alur aktif sekarang adalah QR/token yang
  // diverifikasi dengan public key; mode ini hanya aktif jika totpSecret
  // diberikan secara eksplisit.
  if (
    !config.totpSecret &&
    window.ELEARNING_KIOSK_TOTP &&
    window.ELEARNING_KIOSK_TOTP.secret
  ) {
    config.totpSecret = String(window.ELEARNING_KIOSK_TOTP.secret);
    if (window.ELEARNING_KIOSK_TOTP.periodSeconds) {
      config.totpPeriodSeconds = Number(
        window.ELEARNING_KIOSK_TOTP.periodSeconds,
      );
    }
    if (window.ELEARNING_KIOSK_TOTP.digits) {
      config.totpDigits = Number(window.ELEARNING_KIOSK_TOTP.digits);
    }
  }
  var storage = makeStorageKeys(config.storageKey);

  var locked = false;
  var awayAt = null;
  var awayTimer = null;
  var blurTimer = null;
  var busy = false;
  var initialized = false;
  var roleResolved = !config.studentOnly;
  var isStudent = !config.studentOnly;
  var roleStatus = {
    isStudent: !config.studentOnly,
    source: config.studentOnly ? "pending" : "disabled",
  };
  var rolePromise = null;
  var roleRequestId = 0;
  var previousHtmlOverflow = "";
  var previousBodyOverflow = "";
  var previousBodyInert = false;
  var publicJwkCache = null;
  var demoPublicKey = null;
  var demoTimer = null;
  var demoFetchId = 0;
  var signedKeyCache = null;
  var signedKeyTimer = null;
  var signedKeyFetchId = 0;
  var totpKeyCache = null;
  var totpKeyCacheSecret = null;
  var scannerStream = null;
  var scannerVideo = null;
  var scannerDetector = null;
  var scannerActive = false;
  var scannerFrame = null;

  var host = null;
  var shadow = null;
  var ui = null;

  function makeStorageKeys(prefix) {
    return {
      locked: prefix + ":locked",
      away: prefix + ":awayAt",
      role: prefix + ":role:",
      used: prefix + ":usedTokens",
      device: prefix + ":deviceId",
    };
  }

  function log() {
    if (!config.debug) return;
    try {
      console.log.apply(console, ["[kiosk-lock]"].concat(Array.prototype.slice.call(arguments)));
    } catch (_) {
      /* ignore */
    }
  }

  function safeGet(key) {
    try {
      return window.localStorage.getItem(key);
    } catch (_) {
      return null;
    }
  }

  function safeSet(key, value) {
    try {
      window.localStorage.setItem(key, value);
    } catch (_) {
      /* private mode / blocked storage */
    }
  }

  function safeRemove(key) {
    try {
      window.localStorage.removeItem(key);
    } catch (_) {
      /* ignore */
    }
  }

  function getDeviceId() {
    var existing = safeGet(storage.device);
    if (existing) return existing;

    var id = "";

    try {
      if (window.crypto && typeof window.crypto.randomUUID === "function") {
        id = window.crypto.randomUUID();
      } else if (window.crypto && window.crypto.getRandomValues) {
        var bytes = new Uint8Array(16);
        window.crypto.getRandomValues(bytes);
        id = Array.prototype.map
          .call(bytes, function (byte) {
            return byte.toString(16).padStart(2, "0");
          })
          .join("");
      }
    } catch (_) {
      /* fall through */
    }

    if (!id) {
      id = "dev-" + Date.now().toString(36) + "-" + Math.random().toString(36).slice(2);
    }

    safeSet(storage.device, id);
    return id;
  }

  function apiUrl(path) {
    var base = String(config.apiBaseUrl || "").replace(/\/+$/, "");
    return base + path;
  }

  function getCurrentUserId() {
    try {
      if (window.M && window.M.cfg && window.M.cfg.userId) {
        return String(window.M.cfg.userId);
      }
    } catch (_) {
      /* ignore */
    }

    var profileLink = document.querySelector(
      'a[href*="/user/profile.php?id="]',
    );
    if (!profileLink) return null;

    var match = String(profileLink.href).match(/[?&]id=(\d+)/);
    return match ? match[1] : null;
  }

  function readRoleCache() {
    if (!config.roleCacheMs || config.roleCacheMs <= 0) return null;

    var userId = getCurrentUserId();
    if (!userId) return null;

    try {
      var raw = safeGet(storage.role + userId);
      if (!raw) return null;
      var cached = JSON.parse(raw);
      if (
        cached &&
        typeof cached.isStudent === "boolean" &&
        Date.now() - cached.timestamp < config.roleCacheMs
      ) {
        return cached;
      }
    } catch (_) {
      /* ignore */
    }

    return null;
  }

  function writeRoleCache(result) {
    var userId = getCurrentUserId();
    if (!userId) return;

    try {
      safeSet(
        storage.role + userId,
        JSON.stringify({
          isStudent: result.isStudent,
          timestamp: Date.now(),
        }),
      );
    } catch (_) {
      /* ignore */
    }
  }

  function normalizeIdList(value) {
    if (!Array.isArray(value)) return [];
    return value
      .map(function (item) {
        return String(item).trim();
      })
      .filter(Boolean);
  }

  function looksLikeStaffUi() {
    if (document.body && document.body.classList.contains("editing")) {
      return true;
    }

    if (document.body && /^page-admin/.test(document.body.id)) {
      return true;
    }

    if (/^\/admin(\/|$)/.test(window.location.pathname)) {
      return true;
    }

    var currentUserId = getCurrentUserId();
    if (currentUserId) {
      var teacherLinks = document.querySelectorAll(
        '.teachers a[href*="/user/view.php?id="], .teachers a[href*="/user/profile.php?id="]',
      );

      for (var t = 0; t < teacherLinks.length; t += 1) {
        var match = String(teacherLinks[t].href).match(/[?&]id=(\d+)/);
        if (match && match[1] === currentUserId) return true;
      }
    }

    var selectors = [
      'a[href*="/course/edit.php"]',
      'a[href*="/course/management.php"]',
      'a[href*="/course/modedit.php"]',
      'a[href*="/grade/edit/tree/"]',
      'a[href*="/grade/report/grader/"]',
      'a[href*="/report/outline/"]',
      'a[href*="/report/log/"]',
      'a[href*="/report/participation/"]',
      'a[href*="/report/progress/"]',
      'a[href*="/backup/backup.php"]',
      'a[href*="/question/edit.php"]',
      'a[href*="/mod/quiz/edit.php"]',
      'a[href*="/mod/quiz/report.php"]',
      'a[href*="/mod/assign/view.php"][href*="action=grading"]',
      '[data-action="toggle-edit-mode"]',
      '[data-region="courseadministration"]',
      ".courseadmin",
      'a[href*="/admin/settings.php"]',
      'a[href*="/admin/user.php"]',
      'a[href*="/admin/roles/"]',
      'a[href*="/admin/search.php"]',
      '#nav-drawer a[href*="/admin/"]',
      '.usermenu a[href*="/admin/"]',
    ];

    for (var i = 0; i < selectors.length; i += 1) {
      try {
        if (document.querySelector(selectors[i])) return true;
      } catch (_) {
        /* ignore invalid selector */
      }
    }

    return false;
  }

  function detectStudentFromDom() {
    var userId = getCurrentUserId();
    var staffIds = normalizeIdList(config.staffUserIds);
    var studentIds = normalizeIdList(config.studentUserIds);

    if (userId && staffIds.indexOf(userId) !== -1) {
      return {
        isStudent: false,
        source: "dom-staff-list",
        userid: userId,
      };
    }

    if (userId && studentIds.indexOf(userId) !== -1) {
      return {
        isStudent: true,
        source: "dom-student-list",
        userid: userId,
      };
    }

    if (
      document.body &&
      (document.body.classList.contains("notloggedin") ||
        document.body.id === "page-login-index")
    ) {
      return { isStudent: false, source: "dom-not-logged-in", userid: userId };
    }

    if (looksLikeStaffUi()) {
      return { isStudent: false, source: "dom-staff-ui", userid: userId };
    }

    return {
      isStudent: Boolean(config.domDefaultIsStudent),
      source: "dom-default",
      userid: userId,
    };
  }

  function determineStudentRole() {
    if (!config.studentOnly) {
      return Promise.resolve({ isStudent: true, source: "disabled" });
    }

    var cached = readRoleCache();
    if (cached) {
      return Promise.resolve({
        isStudent: cached.isStudent,
        source: "cache",
      });
    }

    if (!config.roleEndpoint) {
      var domResult = detectStudentFromDom();
      writeRoleCache(domResult);
      return Promise.resolve(domResult);
    }

    return fetch(config.roleEndpoint, {
      credentials: "same-origin",
      cache: "no-store",
      headers: { Accept: "application/json" },
    })
      .then(function (response) {
        if (!response.ok) {
          throw new Error("role endpoint HTTP " + response.status);
        }

        var contentType = response.headers.get("content-type") || "";
        if (contentType.indexOf("application/json") === -1) {
          throw new Error("role endpoint bukan JSON");
        }

        return response.json();
      })
      .then(function (data) {
        if (!data || typeof data.isStudent !== "boolean") {
          throw new Error("respons role tidak valid");
        }

        var result = {
          isStudent: data.isStudent,
          source: "server",
          userid: data.userid,
          archetypes: data.archetypes,
        };

        writeRoleCache(result);
        return result;
      })
      .catch(function (error) {
        log("role check failed", error);
        return {
          isStudent: Boolean(config.assumeStudentWhenUnknown),
          source: "error-fallback",
        };
      });
  }

  function hasAppFocus() {
    if (document.visibilityState !== "visible") return false;
    if (document.hasFocus()) return true;

    var active = document.activeElement;
    return Boolean(active && active.tagName === "IFRAME");
  }

  function clearAwayTimer() {
    if (awayTimer !== null) {
      window.clearTimeout(awayTimer);
      awayTimer = null;
    }
  }

  function clearBlurTimer() {
    if (blurTimer !== null) {
      window.clearTimeout(blurTimer);
      blurTimer = null;
    }
  }

  function markAway() {
    if (locked || awayAt !== null) return;

    awayAt = Date.now();
    safeSet(storage.away, String(awayAt));
    clearAwayTimer();

    awayTimer = window.setTimeout(function () {
      if (awayAt !== null && Date.now() - awayAt >= config.lockAfterMs) {
        awayAt = null;
        lock("away-timeout");
      }
    }, config.lockAfterMs + 50);
  }

  function markBack() {
    clearAwayTimer();
    clearBlurTimer();

    if (awayAt === null) {
      safeRemove(storage.away);
      return;
    }

    var elapsed = Date.now() - awayAt;
    awayAt = null;
    safeRemove(storage.away);

    // Returned to the app within the 3-second grace period: cancel the lock.
    if (elapsed >= config.lockAfterMs) {
      lock("returned-after-away");
    }
  }

  function onVisibilityChange() {
    if (document.visibilityState === "hidden") {
      markAway();
    } else {
      markBack();
    }
  }

  function onBlur() {
    clearBlurTimer();
    // Wait a tick so focus moving into an iframe is not treated as leaving.
    blurTimer = window.setTimeout(function () {
      blurTimer = null;
      if (!hasAppFocus()) markAway();
    }, 80);
  }

  function onFocus() {
    // Always cancel: document.hasFocus() may still be false while the
    // browser is dispatching the focus event.
    markBack();
  }

  function onUserActivity() {
    if (document.visibilityState === "visible") markBack();
  }

  function onPageHide() {
    // Only persist when the app is actually hidden/closed. Normal same-tab
    // navigation should not lock the user after a slow page load.
    if (document.visibilityState === "hidden") markAway();
  }

  function onPageShow() {
    if (locked) return;

    var stored = Number(safeGet(storage.away) || 0);
    if (stored && Date.now() - stored >= config.lockAfterMs) {
      safeRemove(storage.away);
      lock("restored-page");
    } else if (stored) {
      safeRemove(storage.away);
    }
  }

  function onStorage(event) {
    if (event.key === storage.locked && event.newValue === "1" && !locked) {
      lock("other-tab");
    }
  }

  function checkBootState() {
    if (safeGet(storage.locked) === "1") {
      lock("stored-lock");
      return;
    }

    var stored = Number(safeGet(storage.away) || 0);
    safeRemove(storage.away);

    if (stored && Date.now() - stored >= config.lockAfterMs) {
      lock("boot-away");
    }
  }

  function lock(reason) {
    if (locked) return;

    ensureInitialized();

    if (!roleResolved) {
      if (rolePromise) {
        rolePromise.then(function (student) {
          if (student) lock(reason);
        });
      }
      return;
    }

    if (!isStudent) {
      log("lock skipped: user bukan siswa", reason || "manual");
      return;
    }

    doLock(reason);
  }

  function doLock(reason) {
    if (locked || !isStudent) return;

    locked = true;
    awayAt = null;
    clearAwayTimer();
    safeSet(storage.locked, "1");
    safeRemove(storage.away);
    showOverlay();
    emit("lock", { reason: reason || "manual" });
    callHook(config.onLock, { reason: reason || "manual" });
    log("locked", reason || "manual");
  }

  function unlock() {
    if (!locked) return;

    locked = false;
    safeRemove(storage.locked);
    safeRemove(storage.away);
    clearAwayTimer();
    stopScanner();
    stopDemoKeyRefresh();
    stopSignedKeyRefresh();
    hideOverlay();
    emit("unlock", {});
    callHook(config.onUnlock, {});
    log("unlocked");
  }

  function callHook(hook, detail) {
    if (typeof hook !== "function") return;
    try {
      hook(detail);
    } catch (_) {
      /* ignore hook errors */
    }
  }

  function emit(name, detail) {
    try {
      window.dispatchEvent(
        new CustomEvent("elearning-kiosk:" + name, { detail: detail || {} }),
      );
    } catch (_) {
      /* ignore */
    }
  }

  function setError(message) {
    if (!ui) return;
    ui.error.textContent = message || "";
    ui.error.classList.toggle("is-visible", Boolean(message));
    if (message) {
      ui.panel.classList.remove("shake");
      void ui.panel.offsetWidth;
      ui.panel.classList.add("shake");
    }
  }

  function setBusy(value) {
    if (!ui) return;
    busy = value;
    if (ui.scanButton) {
      ui.scanButton.disabled = value;
      if (!value && !scannerActive && !config.demoMode) {
        ui.scanButton.style.display = "";
      }
    }
    if (ui.demoButton) ui.demoButton.disabled = value;
  }

  function handleKeydown(event) {
    if (!locked) return;

    if (event.key === "Escape") {
      event.preventDefault();
      event.stopPropagation();
      return;
    }

    if (event.key !== "Tab" || !ui) return;

    var focusables = [ui.scanButton, ui.fullscreenButton].filter(function (el) {
      return el && el.style.display !== "none";
    });

    if (!focusables.length) return;

    var current = shadow.activeElement;
    var index = focusables.indexOf(current);

    event.preventDefault();
    if (index === -1) {
      focusables[0].focus();
    } else {
      var direction = event.shiftKey ? -1 : 1;
      focusables[
        (index + direction + focusables.length) % focusables.length
      ].focus();
    }
  }

  function stopScanner() {
    scannerActive = false;

    if (scannerFrame !== null) {
      window.cancelAnimationFrame(scannerFrame);
      scannerFrame = null;
    }

    if (scannerStream) {
      try {
        scannerStream.getTracks().forEach(function (track) {
          track.stop();
        });
      } catch (_) {
        /* ignore */
      }
    }

    if (scannerVideo) {
      try {
        scannerVideo.pause();
        scannerVideo.srcObject = null;
      } catch (_) {
        /* ignore */
      }
    }

    scannerStream = null;
    scannerVideo = null;
    scannerDetector = null;

    if (ui && ui.scanner) {
      ui.scanner.classList.remove("is-visible");
      ui.scanner.innerHTML = "";
    }

    if (ui && ui.scanButton && !busy) {
      ui.scanButton.disabled = false;
      if (!config.demoMode) {
        ui.scanButton.style.display = "";
      }
    }
  }

  function scanLoop() {
    if (!scannerActive || !scannerDetector || !scannerVideo) return;

    scannerDetector
      .detect(scannerVideo)
      .then(function (codes) {
        if (!scannerActive) return;

        if (codes && codes.length && codes[0].rawValue) {
          var value = String(codes[0].rawValue);
          stopScanner();
          verifyToken(value);
          return;
        }

        scannerFrame = window.requestAnimationFrame(scanLoop);
      })
      .catch(function () {
        if (scannerActive) {
          scannerFrame = window.requestAnimationFrame(scanLoop);
        }
      });
  }

  function startScanner() {
    if (!ui || busy) return;

    if (
      !("BarcodeDetector" in window) ||
      !navigator.mediaDevices ||
      !navigator.mediaDevices.getUserMedia
    ) {
      setError(
        "Browser ini tidak mendukung scan QR Code. Gunakan Chrome/Edge terbaru.",
      );
      return;
    }

    stopScanner();
    setError("");

    scannerVideo = document.createElement("video");
    scannerVideo.className = "kiosk__video";
    scannerVideo.setAttribute("playsinline", "");
    scannerVideo.muted = true;

    ui.scanner.innerHTML = "";
    ui.scanner.appendChild(scannerVideo);

    var cancelButton = document.createElement("button");
    cancelButton.type = "button";
    cancelButton.className = "kiosk__scan-cancel";
    cancelButton.textContent = "Batal";
    cancelButton.addEventListener("click", stopScanner);
    ui.scanner.appendChild(cancelButton);
    ui.scanner.classList.add("is-visible");
    ui.scanButton.style.display = "none";

    navigator.mediaDevices
      .getUserMedia({
        video: { facingMode: { ideal: "environment" } },
        audio: false,
      })
      .then(function (stream) {
        scannerStream = stream;
        scannerVideo.srcObject = stream;
        return scannerVideo.play();
      })
      .then(function () {
        scannerDetector = new window.BarcodeDetector({ formats: ["qr_code"] });
        scannerActive = true;
        scanLoop();
      })
      .catch(function () {
        stopScanner();
        setError(
          "Tidak dapat mengakses kamera. Izinkan akses kamera lalu coba lagi.",
        );
      });
  }

  function verifyToken(token) {
    if (!locked || busy) return Promise.resolve(false);

    var value = String(token || "").trim();
    if (!value) return Promise.resolve(false);

    setError("");
    setBusy(true);

    return verifyUnlockToken(value)
      .then(function () {
        unlock();
        return true;
      })
      .catch(function (error) {
        if (error && error.name === "NotSupportedError") {
          setError(
            "Browser ini belum mendukung verifikasi Ed25519. Gunakan Chrome, Edge, atau Safari terbaru.",
          );
        } else if (error && error.message) {
          setError(error.message);
        } else {
          setError(
            "QR Code tidak valid atau sudah kedaluwarsa. Minta QR baru ke pengawas.",
          );
        }
        return false;
      })
      .then(function (result) {
        setBusy(false);
        return result;
      });
  }

  function base64UrlToBytes(value) {
    var base64 = String(value).replace(/-/g, "+").replace(/_/g, "/");
    while (base64.length % 4) base64 += "=";

    var raw = window.atob(base64);
    var bytes = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i += 1) {
      bytes[i] = raw.charCodeAt(i);
    }
    return bytes;
  }

  function base64UrlToJson(value) {
    var bytes = base64UrlToBytes(value);
    var text = new TextDecoder().decode(bytes);
    return JSON.parse(text);
  }

  function getPublicJwk() {
    if (config.publicKeyJwk && typeof config.publicKeyJwk === "object") {
      return Promise.resolve(config.publicKeyJwk);
    }

    if (typeof config.publicKeyJwk === "string") {
      try {
        return Promise.resolve(JSON.parse(config.publicKeyJwk));
      } catch (_) {
        return Promise.reject(new Error("publicKeyJwk di config tidak valid."));
      }
    }

    if (publicJwkCache) return Promise.resolve(publicJwkCache);

    return fetch(apiUrl("/api/kiosk/public-key"), {
      credentials: "omit",
      headers: { Accept: "application/json" },
    })
      .then(function (response) {
        if (!response.ok) throw new Error("Public key server tidak tersedia.");
        return response.json();
      })
      .then(function (data) {
        if (!data || !data.jwk) throw new Error("Public key server tidak valid.");
        publicJwkCache = data.jwk;
        return publicJwkCache;
      });
  }

  function readUsedTokens() {
    try {
      var raw = safeGet(storage.used);
      if (!raw) return [];
      var parsed = JSON.parse(raw);
      if (!Array.isArray(parsed)) return [];
      return parsed.filter(function (item) {
        return (
          item &&
          typeof item.jti === "string" &&
          typeof item.exp === "number"
        );
      });
    } catch (_) {
      return [];
    }
  }

  function writeUsedTokens(tokens) {
    try {
      safeSet(storage.used, JSON.stringify(tokens.slice(-50)));
    } catch (_) {
      /* ignore */
    }
  }

  function assertUnusedToken(jti) {
    if (!jti) return;

    var now = Math.floor(Date.now() / 1000);
    var used = readUsedTokens().filter(function (item) {
      return item.exp > now;
    });

    for (var i = 0; i < used.length; i += 1) {
      if (used[i].jti === jti) {
        throw new Error("Token ini sudah pernah dipakai. Minta token baru.");
      }
    }
  }

  function markTokenUsed(jti, exp) {
    if (!jti) return;

    var now = Math.floor(Date.now() / 1000);
    var used = readUsedTokens().filter(function (item) {
      return item.exp > now;
    });
    used.push({ jti: jti, exp: exp });
    writeUsedTokens(used);
  }

  function verifyUnlockToken(token) {
    if (!window.crypto || !window.crypto.subtle) {
      return Promise.reject(
        new Error("Browser tidak mendukung Web Crypto. Gunakan browser terbaru."),
      );
    }

    var parts = String(token).trim().split(".");
    if (parts.length !== 3) {
      if (/^\d{4}$/.test(String(token).trim())) {
        return Promise.reject(
          new Error("Key 4 digit tidak valid. Minta key baru ke pengawas."),
        );
      }
      return Promise.reject(
        new Error("Key tidak valid. Gunakan key dari pengawas."),
      );
    }

    var header;
    var payload;
    try {
      header = base64UrlToJson(parts[0]);
      payload = base64UrlToJson(parts[1]);
    } catch (_) {
      return Promise.reject(new Error("Token pembuka tidak dapat dibaca."));
    }

    if (header.alg !== "EdDSA") {
      return Promise.reject(new Error("Algoritma token tidak didukung."));
    }

    if (payload.iss !== "elearning-kiosk") {
      return Promise.reject(new Error("Penerbit token tidak dikenal."));
    }

    var audience = payload.aud;
    var audienceOk = Array.isArray(audience)
      ? audience.indexOf("kiosk-client") !== -1
      : audience === "kiosk-client";

    if (!audienceOk) {
      return Promise.reject(new Error("Token bukan untuk aplikasi ini."));
    }

    if (payload.scope !== "kiosk-unlock") {
      return Promise.reject(new Error("Token bukan untuk membuka kiosk."));
    }

    var windowStart = Number(payload.windowStart);
    var windowEnd = Number(payload.windowEnd);
    var now = Date.now();
    var clockSkewMs = 5000;

    if (!isFinite(windowStart) || !isFinite(windowEnd)) {
      return Promise.reject(new Error("Token tidak memiliki jendela waktu."));
    }

    if (now < windowStart - clockSkewMs || now > windowEnd + clockSkewMs) {
      return Promise.reject(
        new Error("Token pengawas sudah kedaluwarsa. Minta token baru."),
      );
    }

    if (!payload.exp || payload.exp * 1000 + clockSkewMs < now) {
      return Promise.reject(
        new Error("Token pengawas sudah kedaluwarsa. Minta token baru."),
      );
    }

    var jti = payload.jti ? String(payload.jti) : "";

    try {
      assertUnusedToken(jti);
    } catch (error) {
      return Promise.reject(error);
    }

    return getPublicJwk()
      .then(function (jwk) {
        return window.crypto.subtle.importKey(
          "jwk",
          jwk,
          { name: "Ed25519" },
          false,
          ["verify"],
        );
      })
      .then(function (key) {
        var signature = base64UrlToBytes(parts[2]);
        var data = new TextEncoder().encode(parts[0] + "." + parts[1]);
        return window.crypto.subtle.verify(
          { name: "Ed25519" },
          key,
          signature,
          data,
        );
      })
      .then(function (valid) {
        if (!valid) {
          throw new Error("Tanda tangan token tidak valid.");
        }

        markTokenUsed(jti, payload.exp);
        return true;
      });
  }

  function setDemoKeyText(value) {
    if (ui && ui.demoKey) ui.demoKey.textContent = value;
  }

  function stopDemoKeyRefresh() {
    if (demoTimer !== null) {
      window.clearTimeout(demoTimer);
      demoTimer = null;
    }
    demoFetchId += 1;
  }

  function getDemoPublicKey() {
    if (demoPublicKey) return Promise.resolve(demoPublicKey);

    return fetch(apiUrl("/api/kiosk/demo-public-key"), {
      credentials: "omit",
      cache: "no-store",
      headers: { Accept: "application/json" },
    })
      .then(function (response) {
        if (!response.ok) throw new Error("Public key demo tidak tersedia.");
        return response.json();
      })
      .then(function (data) {
        if (!data || !data.jwk) throw new Error("Public key demo tidak valid.");
        return window.crypto.subtle.importKey(
          "jwk",
          data.jwk,
          { name: "Ed25519" },
          false,
          ["verify"],
        );
      })
      .then(function (key) {
        demoPublicKey = key;
        return key;
      });
  }

  function refreshDemoKey() {
    if (!config.demoMode || !ui || !ui.demoKey) return Promise.resolve(null);

    if (ui.error.classList.contains("is-visible")) setError("");

    var requestId = ++demoFetchId;

    return fetch(apiUrl("/api/kiosk/demo-key"), {
      credentials: "omit",
      cache: "no-store",
      headers: { Accept: "application/json" },
    })
      .then(function (response) {
        return response.json().then(function (data) {
          if (!response.ok || !data || !data.ok) {
            throw new Error(
              (data && data.error) || "Key demo tidak tersedia.",
            );
          }
          return data;
        });
      })
      .then(function (data) {
        var code = String(data.code || "");

        if (
          !/^\d{4}$/.test(code) ||
          typeof data.payload !== "string" ||
          typeof data.signature !== "string" ||
          typeof data.windowStart !== "number" ||
          typeof data.windowEnd !== "number" ||
          typeof data.serverNow !== "number" ||
          typeof data.periodMs !== "number" ||
          data.windowEnd - data.windowStart !== data.periodMs
        ) {
          throw new Error("Data key demo tidak valid.");
        }

        return getDemoPublicKey().then(function (publicKey) {
          return window.crypto.subtle
            .verify(
              { name: "Ed25519" },
              publicKey,
              base64UrlToBytes(data.signature),
              new TextEncoder().encode(data.payload),
            )
            .then(function (valid) {
              if (!valid) throw new Error("Tanda tangan key demo tidak valid.");
              if (requestId !== demoFetchId) return null;

              setDemoKeyText(code);
              log("demo: key server terverifikasi", code);

              if (demoTimer !== null) window.clearTimeout(demoTimer);
              var delay = Math.max(500, data.windowEnd - data.serverNow + 300);
              demoTimer = window.setTimeout(refreshDemoKey, delay);
              return data;
            });
        });
      })
      .catch(function (error) {
        if (requestId !== demoFetchId) return null;

        setDemoKeyText("----");
        log("demo: gagal mengambil key", error);
        if (demoTimer !== null) window.clearTimeout(demoTimer);
        demoTimer = window.setTimeout(refreshDemoKey, 3000);
        return null;
      });
  }

  function verifyDemoKey(code) {
    return refreshDemoKey().then(function (current) {
      if (!current) {
        throw new Error("Key demo tidak tersedia. Coba lagi.");
      }

      if (current.code !== code) {
        throw new Error(
          "Key salah atau sudah berubah. Masukkan key terbaru di atas.",
        );
      }

      return true;
    });
  }

  function stopSignedKeyRefresh() {
    if (signedKeyTimer !== null) {
      window.clearTimeout(signedKeyTimer);
      signedKeyTimer = null;
    }

    signedKeyFetchId += 1;
    signedKeyCache = null;
  }

  function fetchSignedKey() {
    var requestId = ++signedKeyFetchId;

    return fetch(apiUrl(config.signedKeyUrl), {
      credentials: "omit",
      cache: "no-store",
      headers: { Accept: "application/json" },
    })
      .then(function (response) {
        return response.json().then(function (data) {
          if (!response.ok || !data || !data.ok) {
            throw new Error(
              (data && data.error) || "Signed key tidak tersedia.",
            );
          }
          return data;
        });
      })
      .then(function (data) {
        var code = String(data.code || "");

        if (
          !/^\d{4}$/.test(code) ||
          typeof data.payload !== "string" ||
          typeof data.signature !== "string" ||
          typeof data.windowStart !== "number" ||
          typeof data.windowEnd !== "number" ||
          typeof data.serverNow !== "number" ||
          typeof data.periodMs !== "number" ||
          data.windowEnd - data.windowStart !== data.periodMs ||
          data.payload !==
            "kiosk-key:" + data.windowStart + ":" + code
        ) {
          throw new Error("Data signed key tidak valid.");
        }

        return getPublicJwk()
          .then(function (jwk) {
            return window.crypto.subtle.importKey(
              "jwk",
              jwk,
              { name: "Ed25519" },
              false,
              ["verify"],
            );
          })
          .then(function (publicKey) {
            return window.crypto.subtle.verify(
              { name: "Ed25519" },
              publicKey,
              base64UrlToBytes(data.signature),
              new TextEncoder().encode(data.payload),
            );
          })
          .then(function (valid) {
            if (!valid) {
              throw new Error("Tanda tangan signed key tidak valid.");
            }
            if (requestId !== signedKeyFetchId) return null;

            signedKeyCache = {
              code: code,
              windowStart: data.windowStart,
              windowEnd: data.windowEnd,
              serverNow: data.serverNow,
            };

            log("signed key: snapshot terverifikasi");
            return signedKeyCache;
          });
      });
  }

  function startSignedKeyRefresh() {
    if (!config.clientVerify || config.totpSecret) return;

    stopSignedKeyRefresh();

    function tick() {
      fetchSignedKey()
        .then(function (snapshot) {
          if (!snapshot) return;

          var delay = Math.max(500, snapshot.windowEnd - Date.now() + 300);
          signedKeyTimer = window.setTimeout(tick, delay);
        })
        .catch(function (error) {
          log("signed key: gagal memperbarui", error);
          signedKeyTimer = window.setTimeout(tick, 3000);
        });
    }

    tick();
  }

  function isSignedKeyCurrent(snapshot) {
    if (!snapshot) return false;

    // Gunakan jam client, bukan serverNow dari snapshot, agar snapshot lama
    // tidak bisa di-replay dengan memalsukan waktu server.
    var now = Date.now();
    var clockSkewMs = 5000;

    return (
      now >= snapshot.windowStart - clockSkewMs &&
      now <= snapshot.windowEnd + clockSkewMs
    );
  }

  function compareSignedKey(snapshot, code) {
    if (!snapshot) {
      throw new Error("Key server tidak tersedia. Coba lagi.");
    }

    if (!isSignedKeyCurrent(snapshot)) {
      throw new Error(
        "Kode sudah kedaluwarsa. Minta kode terbaru ke pengawas.",
      );
    }

    if (snapshot.code !== code) {
      throw new Error(
        "Kode salah atau sudah berubah. Masukkan kode terbaru.",
      );
    }

    return true;
  }

  function verifySignedKey(code) {
    var cached = signedKeyCache;

    if (cached && isSignedKeyCurrent(cached)) {
      if (cached.code === code) {
        return Promise.resolve().then(function () {
          return compareSignedKey(cached, code);
        });
      }

      // Kode bisa saja baru berubah di batas 30 detik. Ambil snapshot baru
      // sebelum menyatakan kode salah.
      return fetchSignedKey().then(function (fresh) {
        return compareSignedKey(fresh, code);
      });
    }

    return fetchSignedKey().then(function (fresh) {
      return compareSignedKey(fresh, code);
    });
  }

  function hexToBytes(hex) {
    var normalized = String(hex || "")
      .replace(/^0x/i, "")
      .replace(/[^0-9a-f]/gi, "");

    if (normalized.length !== 64) {
      throw new Error("Secret TOTP client tidak valid (harus 64 hex).");
    }

    var bytes = new Uint8Array(normalized.length / 2);
    for (var i = 0; i < bytes.length; i += 1) {
      bytes[i] = parseInt(normalized.substr(i * 2, 2), 16);
    }
    return bytes;
  }

  function getTotpKey(secretHex) {
    if (totpKeyCache && totpKeyCacheSecret === secretHex) {
      return Promise.resolve(totpKeyCache);
    }

    var keyBytes = hexToBytes(secretHex);

    return window.crypto.subtle
      .importKey(
        "raw",
        keyBytes,
        { name: "HMAC", hash: "SHA-1" },
        false,
        ["sign"],
      )
      .then(function (key) {
        totpKeyCache = key;
        totpKeyCacheSecret = secretHex;
        return key;
      });
  }

  function generateTotpCode(secretHex, counter, digits) {
    var codeDigits = Math.max(4, Math.min(10, Number(digits) || 4));

    return Promise.resolve()
      .then(function () {
        return getTotpKey(secretHex);
      })
      .then(function (key) {
        var counterBuffer = new ArrayBuffer(8);
        var counterView = new DataView(counterBuffer);
        var high = Math.floor(counter / 4294967296);
        var low = counter % 4294967296;

        counterView.setUint32(0, high, false);
        counterView.setUint32(4, low, false);

        return window.crypto.subtle.sign("HMAC", key, counterBuffer);
      })
      .then(function (signature) {
        var hmac = new Uint8Array(signature);
        var offset = hmac[hmac.length - 1] & 0x0f;
        var binary =
          ((hmac[offset] & 0x7f) << 24) |
          ((hmac[offset + 1] & 0xff) << 16) |
          ((hmac[offset + 2] & 0xff) << 8) |
          (hmac[offset + 3] & 0xff);

        return String(binary % Math.pow(10, codeDigits)).padStart(
          codeDigits,
          "0",
        );
      });
  }

  function verifyTotpClient(code) {
    if (!window.crypto || !window.crypto.subtle) {
      return Promise.reject(
        new Error("Browser tidak mendukung Web Crypto. Gunakan browser terbaru."),
      );
    }

    return Promise.resolve().then(function () {
      var secret = String(config.totpSecret || "").trim();
      var periodSeconds = Math.max(
        5,
        Math.min(
          300,
          Math.round(Number(config.totpPeriodSeconds) || 30),
        ),
      );
      var codeDigits = Math.max(
        4,
        Math.min(10, Math.round(Number(config.totpDigits) || 4)),
      );
      var periodMs = periodSeconds * 1000;
      var counter = Math.floor(Date.now() / periodMs);
      var grace = Math.max(
        0,
        Math.min(2, Math.round(Number(config.totpGraceWindows) || 0)),
      );
      var counters = [counter];

      for (var i = 1; i <= grace; i += 1) {
        counters.push(counter - i);
        counters.push(counter + i);
      }

      return Promise.all(
        counters.map(function (value) {
          return generateTotpCode(secret, value, codeDigits);
        }),
      ).then(function (expectedCodes) {
        for (var index = 0; index < expectedCodes.length; index += 1) {
          if (expectedCodes[index] === code) return true;
        }

        throw new Error(
          "Kode salah atau sudah berubah. Masukkan kode terbaru.",
        );
      });
    });
  }

  function verifyServerCode(code) {
    return fetch(apiUrl(config.codeVerifyUrl), {
      method: "POST",
      credentials: "omit",
      cache: "no-store",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({
        code: code,
        deviceId: getDeviceId(),
      }),
    })
      .then(function (response) {
        return response
          .json()
          .catch(function () {
            return {};
          })
          .then(function (data) {
            if (!response.ok || !data || !data.ok) {
              var message =
                (data && data.error) ||
                "Kode tidak valid atau sudah kedaluwarsa.";
              var error = new Error(message);
              error.status = response.status;
              throw error;
            }

            if (!data.token) {
              throw new Error("Server tidak mengembalikan token pembuka.");
            }

            return verifyUnlockToken(data.token);
          });
      })
      .catch(function (error) {
        if (error && error.name === "TypeError") {
          throw new Error(
            "Tidak dapat menghubungi server. Gunakan token/QR atau coba lagi.",
          );
        }

        throw error;
      });
  }

  function buildUi() {
    if (host) return;

    host = document.createElement("div");
    host.id = "elearning-kiosk-lock-root";
    host.setAttribute("data-kiosk-lock", "true");
    host.style.cssText =
      "position:fixed;inset:0;z-index:" + config.zIndex + ";display:none;";
    document.documentElement.appendChild(host);

    shadow = host.attachShadow({ mode: "open" });
    shadow.innerHTML =
      '<div class="kiosk" role="dialog" aria-modal="true" aria-labelledby="kiosk-title">' +
      '<div class="kiosk__panel">' +
      '<div class="kiosk__header">' +
      '<svg class="kiosk__lock-icon" width="128" height="128" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
      '<rect width="18" height="11" x="3" y="11" rx="2" ry="2"></rect>' +
      '<path d="M7 11V7a5 5 0 0 1 10 0v4"></path>' +
      "</svg>" +
      '<h1 id="kiosk-title" class="kiosk__title">Aplikasi terkunci</h1>' +
      '<p class="kiosk__desc">Kamu meninggalkan aplikasi lebih dari ' +
      Math.round(config.lockAfterMs / 1000) +
      " detik.<br>Scan QR Code dari pengawas untuk membuka kunci.</p>" +
      "</div>" +
      '<div class="kiosk__form">' +
      '<div class="kiosk__error" role="alert" aria-live="assertive"></div>' +
      '<button class="kiosk__scan" type="button">Scan QR Code</button>' +
      '<div class="kiosk__scanner" aria-live="polite"></div>' +
      "</div>" +
      "</div>" +
      '<button class="kiosk__fullscreen" type="button" aria-label="Layar penuh" title="Layar penuh">' +
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
      '<path d="M8 3H5a2 2 0 0 0-2 2v3m18 0V5a2 2 0 0 0-2-2h-3m0 18h3a2 2 0 0 0 2-2v-3M3 16v3a2 2 0 0 0 2 2h3"></path>' +
      "</svg>" +
      "</button>" +
      "</div>";

    var cssText = typeof CSS === "string" ? CSS : "";

    try {
      if (
        cssText &&
        "adoptedStyleSheets" in shadow &&
        typeof CSSStyleSheet !== "undefined"
      ) {
        var sheet = new CSSStyleSheet();
        sheet.replaceSync(cssText);
        shadow.adoptedStyleSheets = [sheet];
      } else {
        throw new Error("adoptedStyleSheets unavailable");
      }
    } catch (_) {
      var styleElement = document.createElement("style");
      styleElement.textContent = cssText;
      shadow.insertBefore(styleElement, shadow.firstChild);
    }

    ui = {
      panel: shadow.querySelector(".kiosk__panel"),
      error: shadow.querySelector(".kiosk__error"),
      scanButton: shadow.querySelector(".kiosk__scan"),
      scanner: shadow.querySelector(".kiosk__scanner"),
      fullscreenButton: shadow.querySelector(".kiosk__fullscreen"),
    };

    ui.scanButton.addEventListener("click", startScanner);
    if (ui.fullscreenButton) {
      ui.fullscreenButton.addEventListener("click", handleFullscreenToggle);
    }

    updateFullscreenButton();
  }

  function showOverlay() {
    buildUi();
    stopScanner();
    setError("");
    setBusy(false);

    previousHtmlOverflow = document.documentElement.style.overflow;
    previousBodyOverflow = document.body ? document.body.style.overflow : "";
    previousBodyInert = document.body ? Boolean(document.body.inert) : false;
    document.documentElement.style.overflow = "hidden";
    if (document.body) {
      document.body.style.overflow = "hidden";
      document.body.inert = true;
    }

    host.style.display = "block";
    document.addEventListener("keydown", handleKeydown, true);

    window.setTimeout(function () {
      if (locked && ui && ui.scanButton) ui.scanButton.focus();
    }, 80);
  }

  function hideOverlay() {
    if (!host) return;

    host.style.display = "none";
    document.removeEventListener("keydown", handleKeydown, true);
    document.documentElement.style.overflow = previousHtmlOverflow;
    if (document.body) {
      document.body.style.overflow = previousBodyOverflow;
      document.body.inert = previousBodyInert;
    }
  }

  function attachListeners() {
    document.addEventListener("visibilitychange", onVisibilityChange);
    document.addEventListener("fullscreenchange", updateFullscreenButton);
    window.addEventListener("blur", onBlur);
    window.addEventListener("focus", onFocus);
    window.addEventListener("pagehide", onPageHide);
    window.addEventListener("pageshow", onPageShow);
    window.addEventListener("storage", onStorage);
    window.addEventListener("pointerdown", onUserActivity, true);
    window.addEventListener("keydown", onUserActivity, true);
    window.addEventListener("touchstart", onUserActivity, true);
  }

  function detachListeners() {
    document.removeEventListener("visibilitychange", onVisibilityChange);
    document.removeEventListener("fullscreenchange", updateFullscreenButton);
    window.removeEventListener("blur", onBlur);
    window.removeEventListener("focus", onFocus);
    window.removeEventListener("pagehide", onPageHide);
    window.removeEventListener("pageshow", onPageShow);
    window.removeEventListener("storage", onStorage);
    window.removeEventListener("pointerdown", onUserActivity, true);
    window.removeEventListener("keydown", onUserActivity, true);
    window.removeEventListener("touchstart", onUserActivity, true);
  }

  function ensureInitialized() {
    if (!initialized) init();
  }

  function init() {
    if (initialized) return;
    if (!document.documentElement || !document.body) {
      window.addEventListener("DOMContentLoaded", init, { once: true });
      return;
    }

    initialized = true;
    buildUi();
    attachListeners();

    var requestId = ++roleRequestId;

    rolePromise = determineStudentRole()
      .then(function (result) {
        if (requestId !== roleRequestId) return false;

        roleStatus = result;
        isStudent = Boolean(result.isStudent);
        roleResolved = true;

        if (!isStudent) {
          detachListeners();
          clearAwayTimer();
          clearBlurTimer();
          safeRemove(storage.locked);
          safeRemove(storage.away);
          log("role: bukan siswa, lock dinonaktifkan", result);
          return false;
        }

        checkBootState();
        log("initialized", { role: result });
        return true;
      })
      .catch(function (error) {
        if (requestId !== roleRequestId) return false;

        roleResolved = true;
        isStudent = Boolean(config.assumeStudentWhenUnknown);
        roleStatus = { isStudent: isStudent, source: "error" };

        if (isStudent) {
          checkBootState();
        } else {
          detachListeners();
          clearAwayTimer();
          clearBlurTimer();
          safeRemove(storage.locked);
          safeRemove(storage.away);
        }

        log("role check error", error);
        return isStudent;
      });
  }

  function configure(next) {
    if (!next || typeof next !== "object") return;

    var previousStorageKey = config.storageKey;
    config = Object.assign({}, config, next);

    if (typeof config.lockAfterMs !== "number" || config.lockAfterMs < 500) {
      config.lockAfterMs = DEFAULTS.lockAfterMs;
    }

    if (config.storageKey !== previousStorageKey) {
      storage = makeStorageKeys(config.storageKey);
    }
  }

  function handleFullscreenToggle() {
    if (document.fullscreenElement) {
      if (document.exitFullscreen) {
        document.exitFullscreen().catch(function () {
          /* ignore */
        });
      }
      return;
    }

    requestFullscreen().catch(function () {
      /* ignore */
    });
  }

  function updateFullscreenButton() {
    if (!ui || !ui.fullscreenButton) return;

    var isFullscreen = Boolean(document.fullscreenElement);
    var label = isFullscreen ? "Keluar layar penuh" : "Layar penuh";

    ui.fullscreenButton.setAttribute("aria-label", label);
    ui.fullscreenButton.title = label;
    ui.fullscreenButton.innerHTML = isFullscreen
      ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M8 3v3a2 2 0 0 1-2 2H3m18 0h-3a2 2 0 0 1-2-2V3m0 18v-3a2 2 0 0 1 2-2h3M3 16h3a2 2 0 0 1 2 2v3"></path></svg>'
      : '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M8 3H5a2 2 0 0 0-2 2v3m18 0V5a2 2 0 0 0-2-2h-3m0 18h3a2 2 0 0 0 2-2v-3M3 16v3a2 2 0 0 0 2 2h3"></path></svg>';
  }

  function requestFullscreen() {
    var element = document.documentElement;
    try {
      if (element.requestFullscreen) {
        return element.requestFullscreen({ navigationUI: "hide" });
      }
    } catch (_) {
      /* ignore */
    }
    return Promise.resolve();
  }

  function destroy() {
    clearAwayTimer();
    clearBlurTimer();
    stopScanner();
    stopDemoKeyRefresh();
    roleRequestId += 1;
    rolePromise = null;
    detachListeners();
    document.removeEventListener("keydown", handleKeydown, true);

    if (host && host.parentNode) host.parentNode.removeChild(host);
    host = null;
    shadow = null;
    ui = null;
    initialized = false;
    locked = false;
    roleResolved = !config.studentOnly;
    isStudent = !config.studentOnly;
    roleStatus = {
      isStudent: isStudent,
      source: config.studentOnly ? "pending" : "disabled",
    };

    if (document.body) {
      document.documentElement.style.overflow = previousHtmlOverflow;
      document.body.style.overflow = previousBodyOverflow;
      document.body.inert = previousBodyInert;
    }

    delete window.ElearningKioskLock;
    delete window.__ELEARNING_KIOSK_LOCK_LOADED__;
  }

  var CSS = `
    :host {
      color-scheme: light;
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      --background: #ffffff;
      --foreground: #252525;
      --card: #ffffff;
      --card-foreground: #252525;
      --popover: #ffffff;
      --popover-foreground: #252525;
      --primary: #343434;
      --primary-foreground: #fafafa;
      --secondary: #f5f5f5;
      --secondary-foreground: #343434;
      --muted: #f5f5f5;
      --muted-foreground: #737373;
      --accent: #f5f5f5;
      --accent-foreground: #343434;
      --destructive: #dc2626;
      --border: #e5e5e5;
      --input: #e5e5e5;
      --ring: #a3a3a3;
      --radius-lg: 0.625rem;
      --radius-xl: 0.875rem;
    }
    *, *::before, *::after { box-sizing: border-box; }
    .kiosk {
      position: fixed;
      inset: 0;
      overflow-y: auto;
      background: var(--background);
      color: var(--foreground);
    }
    .kiosk__fullscreen {
      position: fixed;
      top: 16px;
      right: 16px;
      z-index: 20;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 44px;
      height: 44px;
      padding: 0;
      border: 1px solid var(--border);
      border-radius: 9999px;
      background: var(--background);
      color: var(--foreground);
      box-shadow: 0 8px 24px -8px rgba(0, 0, 0, 0.35);
      cursor: pointer;
    }
    .kiosk__fullscreen:hover {
      background: var(--accent);
      color: var(--accent-foreground);
    }
    .kiosk__fullscreen:focus-visible {
      outline: 2px solid var(--ring);
      outline-offset: 2px;
    }
    .kiosk__fullscreen svg {
      width: 20px;
      height: 20px;
    }
    .kiosk__panel {
      position: relative;
      display: flex;
      flex-direction: column;
      justify-content: center;
      gap: 16px;
      width: 100%;
      min-height: 100dvh;
      padding: 24px;
      background: var(--background);
      color: var(--popover-foreground);
      font-size: 14px;
      line-height: 1.5;
    }
    .kiosk__header,
    .kiosk__form {
      width: 100%;
      max-width: 400px;
      margin-left: auto;
      margin-right: auto;
    }
    .kiosk__header {
      display: flex;
      flex-direction: column;
      gap: 8px;
    }
    .kiosk__lock-icon {
      width: 128px;
      height: 128px;
      align-self: center;
      color: var(--foreground);
    }
    .kiosk__title {
      margin: 0;
      font-size: 20px;
      line-height: 1.2;
      font-weight: 500;
      letter-spacing: -0.01em;
      text-align: center;
      color: var(--foreground);
    }
    .kiosk__desc {
      margin: 0;
      font-size: 16px;
      line-height: 1.5;
      color: var(--muted-foreground);
    }
    .kiosk__form {
      display: grid;
      gap: 16px;
      margin: 0 auto;
      padding: 0;
      border: 0;
      background: transparent;
    }
    .kiosk__field {
      display: grid;
      gap: 8px;
    }
    .kiosk__label {
      margin: 0;
      font-size: 14px;
      line-height: 1;
      font-weight: 500;
      color: var(--foreground);
    }
    .kiosk__input {
      display: block;
      width: 100%;
      height: 40px;
      min-width: 0;
      padding: 8px 12px;
      border: 1px solid var(--input);
      border-radius: var(--radius-lg);
      background: transparent;
      color: var(--foreground);
      font: inherit;
      font-size: 16px;
      line-height: 1.5;
      outline: none;
      transition: border-color 150ms ease, box-shadow 150ms ease;
    }
    .kiosk__input::placeholder { color: var(--muted-foreground); }
    .kiosk__input:focus-visible {
      border-color: var(--ring);
      box-shadow: 0 0 0 3px rgba(163, 163, 163, 0.5);
    }
    .kiosk__input:disabled {
      pointer-events: none;
      cursor: not-allowed;
      background: rgba(229, 229, 229, 0.5);
      opacity: 0.5;
    }
    .kiosk__input[aria-invalid="true"] {
      border-color: var(--destructive);
      box-shadow: 0 0 0 3px rgba(220, 38, 38, 0.2);
    }
    .kiosk__demo {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      padding: 10px;
      border: 1px solid var(--border);
      border-radius: var(--radius-lg);
      background: #fafafa;
    }
    .kiosk__demo-main {
      display: flex;
      flex-direction: column;
      gap: 2px;
      min-width: 0;
    }
    .kiosk__demo-label {
      font-size: 11px;
      line-height: 1.4;
      color: var(--muted-foreground);
    }
    .kiosk__demo-key {
      padding: 0;
      background: transparent;
      color: var(--foreground);
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 18px;
      line-height: 1.2;
      font-weight: 600;
      letter-spacing: 0.22em;
    }
    .kiosk__demo-button {
      height: 28px;
      padding: 0 10px;
      border: 1px solid var(--border);
      border-radius: var(--radius-lg);
      background: var(--background);
      color: var(--foreground);
      font: inherit;
      font-size: 12px;
      font-weight: 500;
      white-space: nowrap;
      cursor: pointer;
      transition: background 150ms ease;
    }
    .kiosk__demo-button:hover:not(:disabled) { background: var(--muted); }
    .kiosk__demo-button:disabled {
      pointer-events: none;
      cursor: not-allowed;
      opacity: 0.5;
    }
    .kiosk__error {
      display: none;
      padding: 8px 10px;
      border: 1px solid var(--border);
      border-radius: var(--radius-lg);
      background: var(--card);
      color: var(--destructive);
      font-size: 14px;
      line-height: 1.5;
    }
    .kiosk__error.is-visible { display: block; }
    .kiosk__scan {
      display: block;
      width: 100%;
      height: 48px;
      padding: 0 16px;
      border: 1px solid transparent;
      border-radius: var(--radius-lg);
      background: var(--primary);
      color: var(--primary-foreground);
      font: inherit;
      font-size: 15px;
      font-weight: 600;
      cursor: pointer;
      box-shadow: 0 8px 20px -12px rgba(0, 0, 0, 0.55);
      transition: opacity 150ms ease, transform 150ms ease;
    }
    .kiosk__scan:hover:not(:disabled) {
      opacity: 0.9;
    }
    .kiosk__scan:active:not(:disabled) {
      transform: translateY(1px);
    }
    .kiosk__scan:disabled {
      pointer-events: none;
      cursor: not-allowed;
      opacity: 0.5;
    }
    .kiosk__scanner {
      display: none;
      position: fixed;
      inset: 0;
      z-index: 100;
      overflow: hidden;
      background: #000;
    }
    .kiosk__scanner.is-visible { display: block; }
    .kiosk__video {
      display: block;
      width: 100%;
      height: 100%;
      max-height: none;
      object-fit: cover;
      background: #000;
    }
    .kiosk__scan-cancel {
      position: absolute;
      top: calc(1rem + env(safe-area-inset-top));
      right: calc(1rem + env(safe-area-inset-right));
      z-index: 1;
      height: 44px;
      padding: 0 16px;
      border: 1px solid rgba(255, 255, 255, 0.35);
      border-radius: 9999px;
      background: rgba(37, 37, 37, 0.72);
      color: #ffffff;
      font: inherit;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      -webkit-backdrop-filter: blur(8px);
      backdrop-filter: blur(8px);
    }
    .kiosk__button {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      width: 100%;
      height: 40px;
      padding: 0 12px;
      border: 1px solid transparent;
      border-radius: var(--radius-lg);
      background: var(--primary);
      color: var(--primary-foreground);
      font: inherit;
      font-size: 14px;
      font-weight: 500;
      line-height: 1;
      white-space: nowrap;
      cursor: pointer;
      transition: background 150ms ease, opacity 150ms ease, transform 100ms ease;
    }
    .kiosk__button:hover:not(:disabled) { background: #525252; }
    .kiosk__button:active:not(:disabled) { transform: translateY(1px); }
    .kiosk__button:disabled {
      pointer-events: none;
      cursor: not-allowed;
      opacity: 0.5;
    }
    .kiosk__button-icon {
      width: 16px;
      height: 16px;
      flex-shrink: 0;
    }
    .kiosk__spinner {
      display: none;
      width: 16px;
      height: 16px;
      border: 2px solid rgba(250, 250, 250, 0.35);
      border-top-color: var(--primary-foreground);
      border-radius: 50%;
      animation: kiosk-spin 1s linear infinite;
    }
    .kiosk__button.is-busy .kiosk__spinner { display: inline-block; }
    .kiosk__button.is-busy .kiosk__button-icon { display: none; }
    .kiosk__input:focus-visible,
    .kiosk__scan:focus-visible,
    .kiosk__button:focus-visible,
    .kiosk__demo-button:focus-visible {
      outline: none;
      box-shadow: 0 0 0 3px rgba(163, 163, 163, 0.5);
    }
    .shake { animation: kiosk-shake 0.36s ease; }
    @keyframes kiosk-spin { to { transform: rotate(360deg); } }
    @keyframes kiosk-shake {
      10%, 90% { transform: translateX(-1px); }
      20%, 80% { transform: translateX(2px); }
      30%, 50%, 70% { transform: translateX(-3px); }
      40%, 60% { transform: translateX(3px); }
    }
    @media (min-width: 768px) {
      .kiosk__input { font-size: 14px; }
    }
    @media (prefers-reduced-motion: reduce) {
      .kiosk__button, .kiosk__input, .kiosk__scan, .kiosk__demo-button { transition: none; }
      .shake { animation: none; }
      .kiosk__spinner { animation-duration: 1.4s; }
    }
  `;

  window.ElearningKioskLock = {
    version: "1.0.0",
    lock: function () {
      lock("manual");
    },
    unlock: unlock,
    submitToken: function (token) {
      return verifyToken(token);
    },
    isLocked: function () {
      return locked;
    },
    isStudent: function () {
      return roleResolved ? isStudent : null;
    },
    getRoleStatus: function () {
      return {
        resolved: roleResolved,
        isStudent: roleResolved ? isStudent : null,
        source: roleStatus.source,
      };
    },
    configure: configure,
    destroy: destroy,
    requestFullscreen: requestFullscreen,
    openSupervisorPanel: function () {
      window.open(apiUrl("/supervisor"), "_blank", "noopener,noreferrer");
    },
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init, { once: true });
  } else {
    init();
  }

})();
