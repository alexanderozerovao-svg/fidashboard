export async function onRequestPost(context) {
  const { request, env } = context;

  const origin = new URL(request.url).origin;
  const cors = {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Headers": "content-type",
    "Access-Control-Allow-Methods": "POST,OPTIONS",
  };
  if (request.method === "OPTIONS") {
    return new Response("", { headers: cors });
  }

  const json = (obj, status = 200, extra = {}) =>
    new Response(JSON.stringify(obj), {
      status,
      headers: { "content-type": "application/json", ...cors, ...extra },
    });

  try {
    const body = await request.json().catch(() => null);
    if (!body) return json({ ok: false }, 400);

    const login = String(body.login || "").trim();
    const password = String(body.password || "");

    if (!login || !password) return json({ ok: false }, 400);

    // 🔐 читаем ТОЛЬКО user:<login>
    const raw = await env.USERS_KV.get(`user:${login}`);
    if (!raw) return json({ ok: false }, 401);

    let record;
    try {
      record = JSON.parse(raw);
    } catch {
      return json({ ok: false }, 401);
    }

    const { hash, role } = record || {};
    if (!hash || !role) return json({ ok: false }, 401);

    const valid = await verifyPassword(password, hash);
    if (!valid) return json({ ok: false }, 401);

    const sid = await signSession(login, role, env.SESSION_SECRET);

    return json(
      { ok: true, login, role },
      200,
      {
        "Set-Cookie": `sid=${sid}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400`,
      }
    );
  } catch {
    return json({ ok: false }, 500);
  }
}

/* ===== password verify (PBKDF2) ===== */
async function verifyPassword(password, stored) {
  const parts = String(stored).split(":");
  if (parts.length !== 3) return false;

  const [saltB64, itStr, hashB64] = parts;
  const iterations = Number(itStr);
  if (!Number.isFinite(iterations) || iterations > 100000) return false;

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

/* ===== session signing ===== */
function base64url(str) {
  return btoa(str)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

async function hmac(secret, message) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(message)
  );
  const bytes = Array.from(new Uint8Array(sig));
  return base64url(String.fromCharCode(...bytes));
}

async function signSession(login, role, secret) {
  const payload = `${login}|${role}|${Date.now()}`;
  const sig = await hmac(secret, payload);
  return `${payload}.${sig}`;
}
