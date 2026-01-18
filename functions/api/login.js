export async function onRequestPost(context) {
  const { request, env } = context;

  const origin = new URL(request.url).origin;
  const cors = {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Headers": "content-type",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
  };
  if (request.method === "OPTIONS") return new Response("", { headers: cors });

  // Helper to return JSON safely
  const j = (obj, status = 200, extraHeaders = {}) =>
    new Response(JSON.stringify(obj), {
      status,
      headers: { "content-type": "application/json", ...cors, ...extraHeaders },
    });

  try {
    // 1) Check required env
    if (!env) return j({ ok: false, diag: "env is missing" }, 500);

    if (!env.SESSION_SECRET || String(env.SESSION_SECRET).trim().length < 10) {
      return j({
        ok: false,
        diag: "SESSION_SECRET is missing or too short",
        hint:
          "Pages → Settings → Variables and Secrets → add Secret SESSION_SECRET (Production) → Redeploy",
      }, 500);
    }

    if (!env.USERS_KV || typeof env.USERS_KV.get !== "function") {
      return j({
        ok: false,
        diag: "USERS_KV binding is missing",
        hint:
          "Pages → Settings → Bindings → KV namespace → Variable name USERS_KV → select DASH_USERS → Save → Redeploy",
      }, 500);
    }

    // 2) Parse request body
    const body = await request.json().catch(() => null);
    if (!body) return j({ ok: false, diag: "Invalid JSON body" }, 400);

    const login = String(body.login || "").trim();
    const password = String(body.password || "");

    if (!login || !password) {
      return j({ ok: false, diag: "Missing login or password" }, 400);
    }

    // 3) Load user from KV
    const stored = await env.USERS_KV.get(login);
    if (!stored) {
      return j({
        ok: false,
        diag: "User not found in KV",
        login,
        hint:
          "KV DASH_USERS: add entry key=login (e.g. andril), value=saltB64:iterations:hashB64",
      }, 401);
    }

    // 4) Validate KV format
    if (typeof stored !== "string") {
      return j({ ok: false, diag: "KV value is not a string", login }, 500);
    }

    const parts = stored.split(":");
    if (parts.length !== 3) {
      return j({
        ok: false,
        diag: "KV value format invalid (need 3 parts: saltB64:iterations:hashB64)",
        login,
        stored_preview: stored.slice(0, 30) + "..." + stored.slice(-10),
      }, 500);
    }

    const [saltB64, itStr, hashB64] = parts;
    const iterations = Number(itStr);

    if (!Number.isFinite(iterations) || iterations < 10000) {
      return j({
        ok: false,
        diag: "Invalid iterations in KV value",
        login,
        iterations: itStr,
      }, 500);
    }

    // 5) Verify PBKDF2
    let ok = false;
    try {
      ok = await pbkdf2Verify(password, saltB64, iterations, hashB64);
    } catch (e) {
      return j({
        ok: false,
        diag: "PBKDF2 verify threw exception",
        login,
        error: String(e),
        hint:
          "Usually means saltB64/hashB64 are not valid base64 or contain spaces/newlines",
      }, 500);
    }

    if (!ok) {
      return j({
        ok: false,
        diag: "Password mismatch",
        login,
        hint:
          "Regenerate KV value with make('2344') and overwrite KV entry",
      }, 401);
    }

    // 6) Create cookie session
    const sid = await signSession(login, env.SESSION_SECRET);

    return j(
      { ok: true, login, diag: "Login OK; cookie set" },
      200,
      {
        "Set-Cookie": `sid=${sid}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400`,
      }
    );
  } catch (e) {
    // Catch-all to avoid 1101
    return new Response(
      JSON.stringify({
        ok: false,
        diag: "Unhandled exception in login.js",
        error: String(e),
      }),
      {
        status: 500,
        headers: { "content-type": "application/json", ...cors },
      }
    );
  }
}

/* ===== PBKDF2 verify ===== */
async function pbkdf2Verify(password, saltB64, iterations, hashB64) {
  const salt = Uint8Array.from(atob(saltB64), c => c.charCodeAt(0));

  const keyMat = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations },
    keyMat,
    256
  );

  const derived = new Uint8Array(bits);
  const derivedB64 = btoa(String.fromCharCode(...derived));

  return derivedB64 === hashB64;
}

/* ===== HMAC session signing ===== */
function base64url(str) {
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function hmac(secret, message) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  const bytes = Array.from(new Uint8Array(sig));
  return base64url(String.fromCharCode(...bytes));
}

async function signSession(login, secret) {
  const payload = `${login}:${Date.now()}`;
  const sig = await hmac(secret, payload);
  return `${payload}.${sig}`;
}
