export async function onRequestPost(context) {
  const { request, env } = context;

  const cors = {
    "Access-Control-Allow-Origin": new URL(request.url).origin,
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Headers": "content-type",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
  };
  if (request.method === "OPTIONS") return new Response("", { headers: cors });

  const body = await request.json().catch(() => ({}));
  const login = String(body.login || "").trim();
  const password = String(body.password || "");

  if (!login || !password) {
    return new Response(JSON.stringify({ ok: false, error: "missing" }), {
      status: 400, headers: { "content-type": "application/json", ...cors },
    });
  }

  // USERS_KV value format: "saltB64:iterations:hashB64" (PBKDF2-SHA256)
  const stored = await env.USERS_KV.get(login);
  if (!stored) {
    return new Response(JSON.stringify({ ok: false }), {
      status: 401, headers: { "content-type": "application/json", ...cors },
    });
  }

  const ok = await pbkdf2Verify(password, stored);
  if (!ok) {
    return new Response(JSON.stringify({ ok: false }), {
      status: 401, headers: { "content-type": "application/json", ...cors },
    });
  }

  const sid = await signSession(login, env.SESSION_SECRET);
  return new Response(JSON.stringify({ ok: true, login }), {
    headers: {
      "content-type": "application/json",
      "Set-Cookie": `sid=${sid}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400`,
      ...cors,
    },
  });
}

async function pbkdf2Verify(password, stored) {
  const [saltB64, itStr, hashB64] = stored.split(":");
  const salt = Uint8Array.from(atob(saltB64), c => c.charCodeAt(0));
  const iterations = parseInt(itStr, 10);

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
