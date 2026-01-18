export async function onRequestGet(context) {
  const { request, env } = context;

  const cors = {
    "Access-Control-Allow-Origin": new URL(request.url).origin,
    "Access-Control-Allow-Credentials": "true",
  };

  const login = await verifySession(
    request.headers.get("Cookie"),
    env.SESSION_SECRET
  );

  return new Response(
    JSON.stringify({ ok: !!login, login }),
    {
      headers: {
        "content-type": "application/json",
        ...cors,
      },
    }
  );
}

/* ===== helpers ===== */

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

async function verifySession(cookie, secret) {
  if (!cookie) return null;

  const m = cookie.match(/sid=([^;]+)/);
  if (!m) return null;

  const token = m[1];
  const [payload, sig] = token.split(".");
  if (!payload || !sig) return null;

  const expected = await hmac(secret, payload);
  if (expected !== sig) return null;

  // payload = "login:timestamp"
  return payload.split(":")[0] || null;
}
