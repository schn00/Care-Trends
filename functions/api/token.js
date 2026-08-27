/**
 * Care Trends — token endpoint (Cloudflare Pages Function)
 * Route: /api/token   (same origin as the app, which is what lets the cookie work)
 *
 * WHAT THIS DOES
 *   Holds the Google OAuth client secret so the browser never sees it, and
 *   keeps the long-lived refresh token in an HttpOnly cookie so JavaScript in
 *   the page can never read it either. The browser gets only short-lived
 *   access tokens.
 *
 * WHAT THIS DOES NOT DO
 *   It never sees, stores, or forwards any care data. Nothing is persisted
 *   here at all — no database, no logs of token values. Care records travel
 *   directly between the browser and Google Drive and never pass through.
 *
 * REQUIRED ENVIRONMENT VARIABLES (Cloudflare Pages -> Settings -> Environment variables)
 *   GOOGLE_CLIENT_ID      the OAuth client id (also hard-coded in index.html; public)
 *   GOOGLE_CLIENT_SECRET  the OAuth client secret  -> mark as "Encrypt"
 *   COOKIE_KEY            32+ random chars, your own                -> mark as "Encrypt"
 *                         (generate: openssl rand -base64 32)
 *                         Rotating this signs every device out; it does not
 *                         touch any data.
 */

const COOKIE_NAME = "ct_rt";
const COOKIE_PATH = "/api";
const COOKIE_MAX_AGE = 400 * 24 * 60 * 60;   // ~400 days, the browser cap
const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
const GOOGLE_REVOKE_URL = "https://oauth2.googleapis.com/revoke";

/* ---------- cookie encryption (AES-GCM via WebCrypto) ----------
   The cookie is already HttpOnly, so page scripts can't read it. Encrypting
   it as well means a cookie lifted from a device backup or a browser profile
   on disk is useless without the server key. */
async function keyFrom(secret) {
  const raw = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(secret));
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unb64 = (s) => {
  const t = s.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(t + "=".repeat((4 - (t.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
};
async function seal(value, secret) {
  const key = await keyFrom(secret);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(value));
  return b64(iv) + "." + b64(ct);
}
async function unseal(packed, secret) {
  const [ivPart, ctPart] = String(packed).split(".");
  if (!ivPart || !ctPart) return null;
  try {
    const key = await keyFrom(secret);
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(ivPart) }, key, unb64(ctPart));
    return new TextDecoder().decode(pt);
  } catch (e) {
    return null;                       // wrong key, tampered, or rotated
  }
}

function readCookie(request, name) {
  const header = request.headers.get("Cookie") || "";
  for (const part of header.split(/;\s*/)) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i) === name) return decodeURIComponent(part.slice(i + 1));
  }
  return null;
}
function setCookie(value) {
  return `${COOKIE_NAME}=${encodeURIComponent(value)}; Path=${COOKIE_PATH}; Max-Age=${COOKIE_MAX_AGE}; HttpOnly; Secure; SameSite=Lax`;
}
const clearCookie = () => `${COOKIE_NAME}=; Path=${COOKIE_PATH}; Max-Age=0; HttpOnly; Secure; SameSite=Lax`;

function json(body, status, extraHeaders) {
  return new Response(JSON.stringify(body), {
    status: status || 200,
    headers: Object.assign(
      { "Content-Type": "application/json", "Cache-Control": "no-store" },
      extraHeaders || {}
    ),
  });
}

/* Same-origin only. The app and this function share a domain, so a request
   from anywhere else has no business here. */
function sameOrigin(request) {
  const origin = request.headers.get("Origin");
  if (!origin) return true;                      // non-CORS request
  try { return new URL(origin).host === new URL(request.url).host; }
  catch (e) { return false; }
}

export async function onRequestPost(context) {
  const { request, env } = context;

  if (!sameOrigin(request)) return json({ error: "bad_origin" }, 403);
  if (!env.GOOGLE_CLIENT_ID || !env.GOOGLE_CLIENT_SECRET || !env.COOKIE_KEY) {
    return json({ error: "server_not_configured", detail: "GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET and COOKIE_KEY must be set" }, 500);
  }

  let body;
  try { body = await request.json(); } catch (e) { return json({ error: "bad_request" }, 400); }
  const action = body && body.action;

  /* ---- 1. first sign-in on a device: swap the one-time code ---- */
  if (action === "exchange") {
    if (!body.code || !body.code_verifier || !body.redirect_uri) return json({ error: "missing_fields" }, 400);
    const params = new URLSearchParams({
      code: body.code,
      code_verifier: body.code_verifier,
      redirect_uri: body.redirect_uri,
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      grant_type: "authorization_code",
    });
    const r = await fetch(GOOGLE_TOKEN_URL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: params.toString(),
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) return json({ error: data.error || "exchange_failed", detail: data.error_description || "" }, r.status);
    if (!data.refresh_token) {
      /* Google only issues a refresh token with access_type=offline and, for a
         previously-approved account, prompt=consent. Without one this device
         would be back to hourly sign-ins, so say so rather than limp on. */
      return json({ error: "no_refresh_token", detail: "Google did not return a refresh token — the app must request access_type=offline and prompt=consent" }, 400);
    }
    const sealed = await seal(data.refresh_token, env.COOKIE_KEY);
    return json(
      { access_token: data.access_token, expires_in: data.expires_in || 3600 },
      200,
      { "Set-Cookie": setCookie(sealed) }
    );
  }

  /* ---- 2. every page load thereafter: refresh token -> access token ---- */
  if (action === "refresh") {
    const sealed = readCookie(request, COOKIE_NAME);
    if (!sealed) return json({ error: "no_session" }, 401);
    const refreshToken = await unseal(sealed, env.COOKIE_KEY);
    if (!refreshToken) return json({ error: "bad_session" }, 401, { "Set-Cookie": clearCookie() });

    const params = new URLSearchParams({
      refresh_token: refreshToken,
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      grant_type: "refresh_token",
    });
    const r = await fetch(GOOGLE_TOKEN_URL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: params.toString(),
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) {
      /* invalid_grant means the user revoked access, changed their password,
         or the grant expired — the cookie is dead, so clear it and make the
         app show "Connect Google" instead of retrying forever */
      const dead = data.error === "invalid_grant";
      return json({ error: data.error || "refresh_failed", detail: data.error_description || "" },
        dead ? 401 : r.status, dead ? { "Set-Cookie": clearCookie() } : {});
    }
    /* Google occasionally rotates the refresh token; store the new one if so */
    const headers = {};
    if (data.refresh_token) headers["Set-Cookie"] = setCookie(await seal(data.refresh_token, env.COOKIE_KEY));
    return json({ access_token: data.access_token, expires_in: data.expires_in || 3600 }, 200, headers);
  }

  /* ---- 3. disconnect this device ---- */
  if (action === "revoke") {
    const sealed = readCookie(request, COOKIE_NAME);
    if (sealed) {
      const refreshToken = await unseal(sealed, env.COOKIE_KEY);
      if (refreshToken) {
        await fetch(GOOGLE_REVOKE_URL, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({ token: refreshToken }).toString(),
        }).catch(() => {});
      }
    }
    return json({ ok: true }, 200, { "Set-Cookie": clearCookie() });
  }

  /* ---- 4. does this browser still have a session? (no Google round-trip) ---- */
  if (action === "status") {
    return json({ session: !!readCookie(request, COOKIE_NAME) });
  }

  return json({ error: "unknown_action" }, 400);
}

/* Anything other than POST is a mistake; answer plainly rather than 405-ing
   with an empty body, which is miserable to debug from a phone. */
export async function onRequest(context) {
  if (context.request.method === "POST") return onRequestPost(context);
  return json({ error: "method_not_allowed", detail: "POST only" }, 405);
}
