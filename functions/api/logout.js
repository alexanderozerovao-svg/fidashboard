function corsHeaders(request) {
  const origin = new URL(request.url).origin;
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Headers": "content-type",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
  };
}

function okResponse(request) {
  const cors = corsHeaders(request);
  return new Response(JSON.stringify({ ok: true }), {
    headers: {
      "content-type": "application/json",
      // удаляем cookie сессии
      "Set-Cookie": "sid=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0",
      ...cors,
    },
  });
}

// OPTIONS (preflight)
export async function onRequestOptions(context) {
  return new Response("", { headers: corsHeaders(context.request) });
}

// GET /api/logout
export async function onRequestGet(context) {
  return okResponse(context.request);
}

// POST /api/logout
export async function onRequestPost(context) {
  return okResponse(context.request);
}
