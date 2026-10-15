const SESSION_COOKIE = "natmap_index";
const SESSION_MAX_AGE = 400 * 24 * 3600;
const MAX_REPORT_BODY = 8 * 1024;
const MAX_SERVICES = 500;
const MAX_LIMITER_KEYS = 5000;
const RE_IPV4 =
  /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const RE_HOSTNAME =
  /^(?=.{1,253}\.?$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$/;
const RE_SERVICE_NAME = /^[\p{L}\p{N}][\p{L}\p{N}_.\- ]{0,63}$/u;
const RE_BAD_NAME_CHAR = /[\p{Cc}\p{Cf}]/u;
const FIELD_SEP = String.fromCharCode(0);

export default {
  async fetch(request, env) {
    if (!env.KV) {
      return plain("KV binding 'KV' is not configured", 500);
    }

    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method.toUpperCase();
    const cfg = getConfig(env);

    if (cfg.adminPath === cfg.indexPath) {
      return plain("ADMIN_PATH and INDEX_PATH must be different", 500);
    }

    const adminBase = `/${cfg.adminPath}`;
    const indexBase = `/${cfg.indexPath}`;
    const adminRe = escapeRegExp(adminBase);
    const ctx = { setCookies: [], nonce: randomNonce() };

    let res;
    try {
      if (path === "/api/report") {
        res =
          method === "POST"
            ? await handleReport(request, env, cfg)
            : method405("POST");
      } else if (path === "/healthz") {
        res = jsonResponse({ ok: true });
      } else if (path === "/favicon.ico") {
        res = new Response(FAVICON, {
          headers: {
            "Content-Type": "image/svg+xml",
            "Cache-Control": "public, max-age=86400",
          },
        });
      } else if (path === indexBase) {
        res =
          method === "GET"
            ? await routeIndex(request, env, cfg, ctx)
            : method405("GET");
      } else if (path === adminBase) {
        res =
          method === "GET"
            ? await routeAdminPage(request, env, cfg, ctx)
            : method405("GET");
      } else if (path === `${adminBase}/services`) {
        res =
          method === "POST"
            ? await routeCreate(request, env, cfg, ctx)
            : method405("POST");
      } else {
        const schemeM = path.match(
          new RegExp(`^${adminRe}/services/([^/]+)/scheme$`)
        );
        const tokenM = path.match(
          new RegExp(`^${adminRe}/services/([^/]+)/token$`)
        );
        const deleteM = path.match(
          new RegExp(`^${adminRe}/services/([^/]+)/delete$`)
        );
        if (method === "POST" && (schemeM || tokenM || deleteM)) {
          await requireAdminAuth(request, env, cfg);
          const name = safeDecode((schemeM || tokenM || deleteM)[1]);
          if (schemeM) {
            res = await routeUpdateScheme(request, env, cfg, name);
          } else if (tokenM) {
            res = await routeRotateToken(request, env, cfg, name);
          } else {
            res = await routeDelete(request, env, cfg, name);
          }
        } else {
          res = notFound();
        }
      }
    } catch (e) {
      if (e instanceof AuthError) {
        res = authErrorResponse(e.statusCode, e.realm, e.retryAfter, e.body);
      } else {
        console.error("natmap: unhandled error", e && e.stack ? e.stack : e);
        res = plain("Internal Server Error", 500);
      }
    }

    res = applyCookies(res, ctx);
    return withSecurityHeaders(res, ctx.nonce);
  },
};

function cspFor(nonce) {
  const n = nonce || "-";
  return [
    "default-src 'none'",
    `style-src 'nonce-${n}'`,
    `script-src 'nonce-${n}'`,
    "img-src data:",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join("; ");
}

function withSecurityHeaders(res, nonce) {
  const h = new Headers(res.headers);
  h.set("Content-Security-Policy", cspFor(nonce));
  h.set("X-Content-Type-Options", "nosniff");
  h.set("X-Frame-Options", "DENY");
  h.set("Referrer-Policy", "no-referrer");
  h.set("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
  h.set(
    "Strict-Transport-Security",
    "max-age=31536000; includeSubDomains"
  );
  if (!h.has("Cache-Control")) {
    h.set("Cache-Control", "no-store");
  }
  return new Response(res.body, {
    status: res.status,
    statusText: res.statusText,
    headers: h,
  });
}

function applyCookies(res, ctx) {
  if (!ctx.setCookies.length) return res;
  const headers = new Headers(res.headers);
  for (const c of ctx.setCookies) headers.append("Set-Cookie", c);
  return new Response(res.body, {
    status: res.status,
    statusText: res.statusText,
    headers,
  });
}

function plain(body, status = 200) {
  return new Response(body, {
    status,
    headers: { "Content-Type": "text/plain; charset=utf-8" },
  });
}

function jsonResponse(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });
}

function htmlResponse(html, status = 200) {
  return new Response(html, {
    status,
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}

function notFound() {
  return new Response(null, { status: 404 });
}

function method405(allow) {
  return new Response(null, {
    status: 405,
    headers: { Allow: allow, "Content-Type": "text/plain; charset=utf-8" },
  });
}

function redirect(location) {
  return new Response(null, { status: 303, headers: { Location: location } });
}

function getConfig(env) {
  return {
    indexPath: normalizePath(env.INDEX_PATH, "user"),
    adminPath: normalizePath(env.ADMIN_PATH, "admin"),
    indexUsername: String(env.INDEX_USERNAME || "user"),
    indexPassword: String(env.INDEX_PASSWORD || ""),
    adminUsername: String(env.ADMIN_USERNAME || "admin"),
    adminPassword: String(env.ADMIN_PASSWORD || ""),
    maxLoginAttempts: clampInt(env.MAX_LOGIN_ATTEMPTS, 5, 1, 100),
    lockoutSeconds: clampInt(env.LOCKOUT_SECONDS, 300, 10, 86400),
    publicDomain: normalizePublicDomain(env.PUBLIC_DOMAIN || ""),
    timeZone: normalizeTimeZone(env.TIMEZONE),
    reportRateLimit: clampInt(env.REPORT_RATE_LIMIT, 30, 0, 10000),
  };
}

function clampInt(value, fallback, min, max) {
  const n = parseInt(value, 10);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, n));
}

function normalizePath(value, fallback) {
  let p = String(value == null ? "" : value).trim();
  const q = p.search(/[?#]/);
  if (q !== -1) p = p.slice(0, q);
  p = p.replace(/^\/+/, "").replace(/\/+$/, "").replace(/\/{2,}/g, "/");
  p = p.replace(/[^A-Za-z0-9\-_.~]/g, "");
  return p || fallback;
}

function normalizePublicDomain(domain) {
  let d = String(domain || "").trim();
  const i = d.indexOf("://");
  if (i !== -1) d = d.slice(i + 3);
  d = d.replace(/\/+$/, "");
  return isValidHost(d) ? d : "";
}

function normalizeTimeZone(tz) {
  const s = String(tz || "").trim();
  if (!s) return "Asia/Shanghai";
  try {
    new Intl.DateTimeFormat("en-US", { timeZone: s });
    return s;
  } catch {
    return "Asia/Shanghai";
  }
}

class AuthError extends Error {
  constructor(statusCode, realm, retryAfter, body) {
    super();
    this.statusCode = statusCode;
    this.realm = realm;
    this.retryAfter = retryAfter;
    this.body = body;
  }
}

function authErrorResponse(statusCode, realm, retryAfter, body) {
  const headers = new Headers();
  if (statusCode === 401) headers.set("WWW-Authenticate", `Basic realm="${realm}"`);
  if (retryAfter != null) headers.set("Retry-After", String(retryAfter));
  if (body != null) headers.set("Content-Type", "text/plain; charset=utf-8");
  return new Response(body ?? null, { status: statusCode, headers });
}

function clientIp(request) {
  const cf = request.headers.get("CF-Connecting-IP");
  if (cf) return cf.trim().slice(0, 64);
  const fwd = request.headers.get("x-forwarded-for");
  if (fwd) return fwd.split(",")[0].trim().slice(0, 64);
  return "unknown";
}

function parseBasicAuth(request) {
  const header = request.headers.get("authorization");
  if (!header) return null;
  const m = header.match(/^Basic\s+(.+)$/i);
  if (!m) return null;
  let decoded;
  try {
    decoded = latin1ToUtf8(atob(m[1].trim()));
  } catch {
    return null;
  }
  const idx = decoded.indexOf(":");
  if (idx === -1) return { username: decoded, password: "" };
  return { username: decoded.slice(0, idx), password: decoded.slice(idx + 1) };
}

function latin1ToUtf8(bin) {
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder("utf-8").decode(bytes);
}

function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const max = Math.max(a.length, b.length);
  let diff = a.length ^ b.length;
  for (let i = 0; i < max; i++) {
    diff |= (a.charCodeAt(i) | 0) ^ (b.charCodeAt(i) | 0);
  }
  return diff === 0;
}

async function authenticate(request, env, cfg, credentials, username, password, realm) {
  const ip = clientIp(request);
  const now = Date.now() / 1000;
  const locked = await env.KV.get(`lockout:${ip}`);
  if (locked) {
    const until = parseInt(locked, 10);
    if (!Number.isNaN(until) && until > now) {
      throw new AuthError(429, realm, Math.max(1, Math.ceil(until - now)));
    }
  }

  if (credentials == null) {
    throw new AuthError(401, realm);
  }

  if (!safeEqual(credentials.username, username) || !safeEqual(credentials.password, password)) {
    const failKey = `fail:${ip}`;
    const raw = await env.KV.get(failKey);
    const count = (parseInt(raw || "0", 10) || 0) + 1;
    if (count >= cfg.maxLoginAttempts) {
      await env.KV.put(
        `lockout:${ip}`,
        String(Math.floor(now + cfg.lockoutSeconds)),
        { expirationTtl: cfg.lockoutSeconds }
      );
      await env.KV.delete(failKey);
      throw new AuthError(429, realm, cfg.lockoutSeconds);
    }
    await env.KV.put(failKey, String(count), { expirationTtl: cfg.lockoutSeconds });
    throw new AuthError(401, realm);
  }

  await env.KV.delete(`fail:${ip}`);
  await env.KV.delete(`lockout:${ip}`);
}

function sessionSecret(env, cfg) {
  return (
    env.SESSION_SECRET ||
    `natmap|${cfg.indexUsername}|${cfg.indexPassword}|${cfg.adminUsername}|${cfg.adminPassword}`
  );
}

async function hmacHex(secret, data) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(data));
  return toHex(new Uint8Array(sig));
}

async function sha256Hex(data) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(data));
  return toHex(new Uint8Array(buf));
}

async function sessionFingerprint(cfg) {
  return sha256Hex(
    [cfg.indexUsername, cfg.indexPassword, cfg.adminUsername, cfg.adminPassword].join(FIELD_SEP)
  );
}

async function indexSessionValue(env, cfg) {
  return hmacHex(sessionSecret(env, cfg), `index-session:${await sessionFingerprint(cfg)}`);
}

async function adminCsrfToken(env, cfg) {
  return hmacHex(sessionSecret(env, cfg), `csrf:${cfg.adminPath}`);
}

function readCookie(request, name) {
  const raw = request.headers.get("cookie");
  if (!raw) return null;
  for (const part of raw.split(";")) {
    const i = part.indexOf("=");
    if (i === -1) continue;
    if (part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return null;
}

async function buildIndexSessionCookie(request, env, cfg) {
  const value = await indexSessionValue(env, cfg);
  const attrs = [
    `${SESSION_COOKIE}=${value}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    `Max-Age=${SESSION_MAX_AGE}`,
  ];
  if (new URL(request.url).protocol === "https:") attrs.push("Secure");
  return attrs.join("; ");
}

async function hasValidIndexSession(request, env, cfg) {
  const got = readCookie(request, SESSION_COOKIE);
  if (!got) return false;
  return safeEqual(got, await indexSessionValue(env, cfg));
}

async function requireIndexAuth(request, env, cfg, ctx) {
  if (!cfg.indexPassword) return;
  if (await hasValidIndexSession(request, env, cfg)) return;
  const creds = parseBasicAuth(request);
  await authenticate(request, env, cfg, creds, cfg.indexUsername, cfg.indexPassword, "Service Index");
  ctx.setCookies.push(await buildIndexSessionCookie(request, env, cfg));
}

async function requireAdminAuth(request, env, cfg) {
  if (!cfg.adminPassword) {
    throw new AuthError(403, null, null, "admin disabled: set ADMIN_PASSWORD");
  }
  const creds = parseBasicAuth(request);
  await authenticate(request, env, cfg, creds, cfg.adminUsername, cfg.adminPassword, "Admin");
}

async function readFormChecked(request, env, cfg) {
  const origin = request.headers.get("origin");
  if (origin && origin !== "null") {
    let sameHost = false;
    try {
      sameHost = new URL(origin).host === new URL(request.url).host;
    } catch {
      sameHost = false;
    }
    if (!sameHost) throw new AuthError(403, null, null, "cross-origin form rejected");
  }
  const form = await request.formData();
  const got = String(form.get("_csrf") || "");
  if (!safeEqual(got, await adminCsrfToken(env, cfg))) {
    throw new AuthError(403, null, null, "invalid CSRF token");
  }
  return form;
}

function serviceKey(name) {
  return `service:${name}`;
}

function tokenIndexKey(hash) {
  return `tokenidx:${hash}`;
}

async function getService(env, name) {
  const raw = await env.KV.get(serviceKey(name));
  if (raw == null) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function storedTokenHash(svc) {
  if (!svc) return null;
  if (typeof svc.token_hash === "string" && svc.token_hash) return svc.token_hash;
  if (typeof svc.token === "string" && svc.token) return null;
  return null;
}

async function kvGetMany(env, names) {
  try {
    const values = await env.KV.get(names);
    if (Array.isArray(values)) return values;
  } catch {
  }
  const out = new Array(names.length);
  for (let i = 0; i < names.length; i++) {
    try {
      out[i] = await env.KV.get(names[i]);
    } catch {
      out[i] = null;
    }
  }
  return out;
}

async function listServices(env) {
  const result = {};
  let cursor;
  let n = 0;
  do {
    const page = await env.KV.list({ prefix: "service:", cursor });
    const names = page.keys.map((k) => k.name);
    if (names.length) {
      const values = await kvGetMany(env, names);
      for (let i = 0; i < names.length; i++) {
        const raw = values[i];
        if (raw == null) continue;
        const name = names[i].slice("service:".length);
        try {
          result[name] = JSON.parse(raw);
        } catch {
        }
        if (++n >= MAX_SERVICES) {
          return result;
        }
      }
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
  return result;
}

async function setService(env, name, svc) {
  await env.KV.put(serviceKey(name), JSON.stringify(svc));
}

async function deleteService(env, name, svc) {
  const hash = await resolveTokenHash(svc);
  await env.KV.delete(serviceKey(name));
  if (hash) await env.KV.delete(tokenIndexKey(hash));
}

async function resolveTokenHash(svc) {
  if (!svc) return null;
  if (typeof svc.token_hash === "string" && svc.token_hash) {
    return svc.token_hash;
  }
  if (typeof svc.token === "string" && svc.token) {
    return sha256Hex(svc.token);
  }
  return null;
}

async function findServiceByToken(env, token) {
  const hash = await sha256Hex(token);

  const indexed = await env.KV.get(tokenIndexKey(hash));
  if (indexed) {
    const svc = await getService(env, indexed);
    if (svc && (await resolveTokenHash(svc)) === hash) {
      return { name: indexed, svc };
    }
    await env.KV.delete(tokenIndexKey(hash));
  }

  if (await env.KV.get("meta:legacy-scanned")) return null;

  const services = await listServices(env);
  let upgraded = 0;
  for (const [name, svc] of Object.entries(services)) {
    const h = await resolveTokenHash(svc);
    if (!h) continue;
    if (h === hash) {
      await env.KV.put(tokenIndexKey(hash), name);
      const fresh = { ...svc, token_hash: h };
      delete fresh.token;
      await setService(env, name, fresh);
      return { name, svc: fresh };
    }
    if (upgraded < 200) {
      await env.KV.put(tokenIndexKey(h), name);
      if (typeof svc.token === "string" && svc.token) {
        const fresh = { ...svc, token_hash: h };
        delete fresh.token;
        await setService(env, name, fresh);
      }
      upgraded++;
    }
  }
  await env.KV.put("meta:legacy-scanned", "1", { expirationTtl: 86400 });
  return null;
}
const memoryLimiter = new Map();

function memoryRateOk(key, limit, windowMs) {
  if (!limit || limit <= 0) return true;
  const now = Date.now();
  const hits = (memoryLimiter.get(key) || []).filter((t) => now - t < windowMs);
  if (hits.length >= limit) {
    memoryLimiter.set(key, hits);
    return false;
  }
  hits.push(now);
  memoryLimiter.set(key, hits);
  if (memoryLimiter.size > MAX_LIMITER_KEYS) memoryLimiter.clear();
  return true;
}

async function handleReport(request, env, cfg) {
  const declared = parseInt(request.headers.get("content-length") || "", 10);
  if (Number.isFinite(declared) && declared > MAX_REPORT_BODY) {
    return jsonResponse({ detail: "payload too large" }, 413);
  }

  const ip = clientIp(request);
  if (!memoryRateOk(`rl:${ip}`, cfg.reportRateLimit, 10000)) {
    return jsonResponse({ detail: "too many reports" }, 429);
  }

  let raw;
  try {
    raw = await request.text();
  } catch {
    return jsonResponse({ detail: "unable to read body" }, 400);
  }
  if (raw.length > MAX_REPORT_BODY) {
    return jsonResponse({ detail: "payload too large" }, 413);
  }

  let body;
  try {
    body = JSON.parse(raw);
  } catch {
    return jsonResponse({ detail: "invalid JSON" }, 400);
  }
  if (!body || typeof body !== "object") {
    return jsonResponse({ detail: "invalid JSON" }, 400);
  }

  const token = typeof body.token === "string" ? body.token.trim() : "";
  const addr = typeof body.ip === "string" ? body.ip.trim() : "";
  const port = body.port;
  const protocol = typeof body.protocol === "string" ? body.protocol : "tcp";

  if (!token) return jsonResponse({ detail: "token is required" }, 400);
  if (token.length > 128) return jsonResponse({ detail: "token is too long" }, 400);
  if (!addr) return jsonResponse({ detail: "ip is required" }, 400);
  if (!isValidHost(addr)) {
    return jsonResponse({ detail: "ip must be a valid IPv4, IPv6 or hostname" }, 400);
  }
  if (typeof port !== "number" || !Number.isInteger(port) || port < 0 || port > 65535) {
    return jsonResponse({ detail: "port must be an integer between 0 and 65535" }, 400);
  }
  if (protocol !== "tcp" && protocol !== "udp") {
    return jsonResponse({ detail: "protocol must be tcp or udp" }, 400);
  }
  const found = await findServiceByToken(env, token);
  if (!found) return jsonResponse({ detail: "invalid token" }, 401);

  const { name, svc } = found;
  if (svc.ip === addr && svc.port === port && svc.protocol === protocol) {
    return jsonResponse({ ok: true, service: name, ip: addr, port, unchanged: true });
  }

  svc.ip = addr;
  svc.port = port;
  svc.protocol = protocol;
  svc.updated_at = Math.floor(Date.now() / 1000);
  await setService(env, name, svc);

  return jsonResponse({ ok: true, service: name, ip: addr, port });
}

async function routeIndex(request, env, cfg, ctx) {
  await requireIndexAuth(request, env, cfg, ctx);
  return htmlResponse(await renderIndex(env, cfg, ctx.nonce));
}

async function routeAdminPage(request, env, cfg, ctx) {
  await requireAdminAuth(request, env, cfg);
  return htmlResponse(await renderAdmin(env, cfg, ctx.nonce, {}));
}

async function routeCreate(request, env, cfg, ctx) {
  await requireAdminAuth(request, env, cfg);
  try {
    const form = await readFormChecked(request, env, cfg);
    const name = String(form.get("name") || "").trim();
    let scheme = String(form.get("scheme") || "http").trim();

    if (!name) {
      return htmlResponse(
        await renderAdmin(env, cfg, ctx.nonce, { error: "服务名不能为空" }),
        400
      );
    }
    if (!isValidServiceName(name)) {
      return htmlResponse(
        await renderAdmin(env, cfg, ctx.nonce, {
          error: "服务名只能包含中英文、数字、空格、下划线、连字符和点，且须以字母或数字开头（最长 64 字符）",
        }),
        400
      );
    }
    if (scheme !== "http" && scheme !== "https") scheme = "http";

    if ((await getService(env, name)) != null) {
      return htmlResponse(
        await renderAdmin(env, cfg, ctx.nonce, { error: `服务 ${name} 已存在` }),
        409
      );
    }

    const token = randomToken();
    const tokenHash = await sha256Hex(token);
    await setService(env, name, {
      token_hash: tokenHash,
      scheme,
      ip: null,
      port: null,
      protocol: "tcp",
      updated_at: null,
    });
    await env.KV.put(tokenIndexKey(tokenHash), name);

    return htmlResponse(
      await renderAdmin(env, cfg, ctx.nonce, { newToken: token, newName: name })
    );
  } catch (e) {
    if (e instanceof AuthError) {
      return htmlResponse(
        await renderAdmin(env, cfg, ctx.nonce, {
          error: csrfMessage(e, cfg.adminPath),
        }),
        e.statusCode
      );
    }
    throw e;
  }
}

async function routeUpdateScheme(request, env, cfg, name) {
  let form;
  try {
    form = await readFormChecked(request, env, cfg);
  } catch (e) {
    if (e instanceof AuthError) return redirect(`/${cfg.adminPath}?e=csrf`);
    throw e;
  }
  let scheme = String(form.get("scheme") || "http").trim();
  if (scheme !== "http" && scheme !== "https") scheme = "http";

  const svc = await getService(env, name);
  if (svc == null) {
    return htmlResponse(
      await renderAdmin(env, cfg, "", { error: `服务 ${name} 不存在` }),
      404
    );
  }
  svc.scheme = scheme;
  await setService(env, name, svc);
  return redirect(`/${cfg.adminPath}?e=ok`);
}

async function routeRotateToken(request, env, cfg, name) {
  try {
    await readFormChecked(request, env, cfg);
  } catch (e) {
    if (e instanceof AuthError) return redirect(`/${cfg.adminPath}?e=csrf`);
    throw e;
  }
  const svc = await getService(env, name);
  if (svc == null) {
    return redirect(`/${cfg.adminPath}?e=missing`);
  }
  const oldHash = await resolveTokenHash(svc);
  const token = randomToken();
  const tokenHash = await sha256Hex(token);

  const fresh = { ...svc, token_hash: tokenHash, updated_at: svc.updated_at || null };
  delete fresh.token;
  await setService(env, name, fresh);
  await env.KV.put(tokenIndexKey(tokenHash), name);
  if (oldHash && oldHash !== tokenHash) {
    await env.KV.delete(tokenIndexKey(oldHash));
  }

  return htmlResponse(
    await renderAdmin(env, cfg, "", { newToken: token, newName: name, rotated: true })
  );
}

async function routeDelete(request, env, cfg, name) {
  try {
    await readFormChecked(request, env, cfg);
  } catch (e) {
    if (e instanceof AuthError) return redirect(`/${cfg.adminPath}?e=csrf`);
    throw e;
  }
  const svc = await getService(env, name);
  if (svc == null) return redirect(`/${cfg.adminPath}?e=missing`);
  await deleteService(env, name, svc);
  return redirect(`/${cfg.adminPath}?e=deleted`);
}

function csrfMessage(e, adminPath) {
  if (e.body === "cross-origin form rejected") {
    return "请求被跨站拦截。请直接访问 /" + adminPath + " 后重试，不要从书签或跳转链接进入管理页。";
  }
  if (e.statusCode === 403) {
    return "请求被拒绝：CSRF 校验未通过，请刷新管理页后重新提交。";
  }
  return e.body || "请求被拒绝";
}

function isValidServiceName(name) {
  if (!name || name.length > 64) return false;
  if (RE_BAD_NAME_CHAR.test(name)) return false;
  return RE_SERVICE_NAME.test(name);
}

function isValidHost(s) {
  if (!s || typeof s !== "string") return false;
  if (s.length > 253) return false;

  if (RE_IPV4.test(s)) return true;

  if (/^\d+(\.\d+){3}$/.test(s)) return false;

  if (RE_HOSTNAME.test(s)) return true;

  if (s.includes(":") && s.length <= 45 && /^[0-9A-Fa-f:]+$/.test(s)) {
    const compress = (s.match(/::/g) || []).length;
    if (compress > 1) return false;
    if (/^[0-9A-Fa-f]*:[0-9A-Fa-f:.]+$/.test(s) || /^[0-9A-Fa-f:.]+:[0-9A-Fa-f]*$/.test(s)) {
      return true;
    }
  }
  return false;
}

function buildLink(svc, cfg) {
  const ip = svc.ip;
  if (!ip) return null;
  const scheme = svc.scheme === "https" ? "https" : "http";
  const host = cfg.publicDomain || ip;
  const bracketed = host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;
  const port = svc.port;
  if (port == null || port === 0) return `${scheme}://${bracketed}`;
  return `${scheme}://${bracketed}:${port}`;
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function escapeAttr(s) {
  return escapeHtml(s);
}

const timeFormatters = new Map();

function getFormatter(timeZone) {
  if (timeFormatters.has(timeZone)) return timeFormatters.get(timeZone);
  const f = new Intl.DateTimeFormat("en-CA", {
    timeZone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
  timeFormatters.set(timeZone, f);
  return f;
}

function formatTime(ts, timeZone) {
  if (!ts) return "从未上报";
  const parts = getFormatter(timeZone).formatToParts(new Date(ts * 1000));
  const g = {};
  for (const p of parts) if (p.type !== "literal") g[p.type] = p.value;
  const hour = g.hour === "24" ? "00" : g.hour;
  return `${g.year}-${g.month}-${g.day} ${hour}:${g.minute}:${g.second}`;
}

function safeDecode(s) {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

const STYLE = `
:root{
  --bg:#f4f6fa; --card:#fff; --line:#e3e8ef; --text:#1b2432; --muted:#667085;
  --accent:#2f6fed; --danger:#d64545; --warn-bg:#fffaeb;
  --warn-line:#f5e0a8; --warn-fg:#93610b;
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{
  margin:0; background:var(--bg); color:var(--text);
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Hiragino Sans GB","Microsoft YaHei",sans-serif;
  font-size:15px; line-height:1.55;
  -webkit-font-smoothing:antialiased;
}
.wrap{
  max-width:960px; margin:0 auto;
  padding:28px 18px calc(48px + env(safe-area-inset-bottom));
  padding-left:max(18px, env(safe-area-inset-left));
  padding-right:max(18px, env(safe-area-inset-right));
}
header.top{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:18px}
h1{font-size:20px;margin:0;letter-spacing:-.2px}
.sub{color:var(--muted);font-size:13px;margin:4px 0 0}
.count-pill{
  display:inline-flex;align-items:center;gap:6px;background:var(--card);
  border:1px solid var(--line);border-radius:999px;padding:4px 11px;
  font-size:12px;color:var(--muted);white-space:nowrap;
}
.count-pill b{color:var(--text);font-variant-numeric:tabular-nums}

table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:12px;overflow:hidden}
th,td{text-align:left;padding:11px 14px;border-bottom:1px solid var(--line);font-size:14px;vertical-align:middle}
th{background:#f8fafc;color:var(--muted);font-weight:600;font-size:12px;letter-spacing:.3px}
tr:last-child td{border-bottom:none}
td a{color:var(--accent);text-decoration:none;overflow-wrap:anywhere}
td a:hover{text-decoration:underline}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px;overflow-wrap:anywhere}
.empty{text-align:center;color:var(--muted);padding:36px 16px}
.muted{color:var(--muted)}
.open-btn{
  display:inline-flex;align-items:center;justify-content:center;gap:6px;
  background:var(--accent);color:#fff;text-decoration:none;
  padding:9px 16px;border-radius:9px;font-size:14px;font-weight:500;
  min-height:44px;
}
.open-btn:hover{background:#2559c4}

input[type=text],select{
  width:100%;padding:10px 12px;border:1px solid var(--line);border-radius:9px;
  font-size:16px;
  font-family:inherit;background:#fff;color:var(--text);
  min-height:44px;
}
input[type=text]:focus,select:focus{outline:2px solid #bfd3fb;outline-offset:-1px;border-color:var(--accent)}
button{
  padding:10px 16px;background:var(--accent);color:#fff;border:none;border-radius:9px;
  font-size:14px;font-weight:500;cursor:pointer;font-family:inherit;min-height:44px;
}
button:hover{background:#2559c4}
button.del{background:var(--danger)}
button.ghost{background:#fff;color:var(--muted);border:1px solid var(--line)}
button.ghost:hover{background:#f8fafc;color:var(--text)}
form.inline{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.ops{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.ops select{width:auto;min-width:88px}

.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px;margin-bottom:16px}
.card h2{font-size:15px;margin:0 0 14px}
.alert{border-radius:10px;padding:13px 15px;margin-bottom:16px;font-size:13px}
.alert-err{background:#fef3f2;border:1px solid #fecdc9;color:#b42318}
.alert-ok{background:#e7f8ee;border:1px solid #a9e5c3;color:#0a6b36}
.token-box{background:var(--warn-bg);border:1px solid var(--warn-line);border-radius:10px;padding:14px;margin-bottom:16px}
.token-label{font-size:13px;margin-bottom:8px;color:var(--warn-fg)}
.token-box code{
  display:block;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  font-size:15px;word-break:break-all;color:var(--warn-fg);user-select:all;
}
.foot{margin-top:22px;text-align:center}
.foot a{color:var(--muted);font-size:12px;text-decoration:none}
.foot a:hover{color:var(--accent)}
.hint{color:var(--muted);font-size:12px;margin:8px 0 0}
.row-flex{display:flex;gap:10px;flex-wrap:wrap}
.row-flex > input[type=text]{flex:1 1 180px;width:auto}
.row-flex > select{flex:0 0 auto;width:auto}
.row-flex > button{flex:0 0 auto}
@media (max-width:720px){
  .wrap{padding:20px 14px calc(40px + env(safe-area-inset-bottom))}
  h1{font-size:18px}
  header.top{align-items:center}

  table,thead,tbody,tr,td{display:block;width:100%}
  table{border:none;background:transparent;border-radius:0;overflow:visible}
  thead{display:none}

  tr{
    background:var(--card);
    border:1px solid var(--line);
    border-radius:12px;
    margin-bottom:12px;
    padding:14px 15px;
  }
  tr:last-child td{border-bottom:none}
  tr.empty-row{background:transparent;border:1px dashed var(--line)}

  td{
    display:flex;align-items:baseline;justify-content:space-between;gap:14px;
    padding:6px 0;border-bottom:none;text-align:right;
  }
  td[data-label]::before{
    content:attr(data-label);
    flex:0 0 auto;color:var(--muted);font-size:12.5px;font-weight:400;
    text-align:left;letter-spacing:.2px;
  }
  td[data-label] > *{min-width:0;text-align:right}
  td.cell-title{
    display:block;text-align:left;
    font-size:16px;font-weight:600;margin-bottom:8px;padding-bottom:8px;
    border-bottom:1px solid var(--line);
  }
  td.cell-title::before{display:none}
  td.cell-action{display:block;text-align:left;padding-top:10px;margin-top:2px}
  td.cell-action::before{display:none}
  td.cell-action .open-btn{width:100%}
  td.cell-ops{display:block;text-align:left;padding-top:12px}
  td.cell-ops::before{display:none}
  td.cell-ops .ops{display:grid;grid-template-columns:1fr 1fr;gap:8px}
  td.cell-ops .ops form{display:contents}
  td.cell-ops .ops select{width:100%;min-width:0}
  td.cell-ops .ops button{width:100%}
  td.cell-ops .ops form.rotate{grid-column:1 / -1}
  td.cell-ops .ops form.rotate button{background:#fff;color:var(--accent);border:1px solid var(--accent)}

  .empty-row td{padding:28px 12px;text-align:center}
  .empty-row td::before{display:none}
  .row-flex > input[type=text],
  .row-flex > select,
  .row-flex > button{flex:1 1 100%;width:100%}
  .form-stack{display:grid;gap:10px}
}

@media (prefers-reduced-motion:reduce){
  *{transition:none !important;animation:none !important}
}
`;

const FAVICON =
  "data:image/svg+xml," +
  encodeURIComponent(
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="14" fill="#2f6fed"/><path d="M20 44V20h11c7 0 12 5 12 12s-5 12-12 12H20z" fill="none" stroke="#fff" stroke-width="5" stroke-linejoin="round"/></svg>`
  );

function pageShell({ title, nonce, body, bodyClass = "" }) {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="color-scheme" content="light">
<meta name="referrer" content="no-referrer">
<title>${escapeHtml(title)}</title>
<link rel="icon" href="${FAVICON}">
<style nonce="${escapeAttr(nonce)}">${STYLE}</style>
</head>
<body${bodyClass ? ` class="${escapeAttr(bodyClass)}"` : ""}>
${body}
</body>
</html>`;
}

async function renderIndex(env, cfg, nonce) {
  const services = await listServices(env);
  const names = Object.keys(services).sort();
  const rows = [];

  for (const name of names) {
    const svc = services[name];
    const port = svc.port;
    const protocol = svc.protocol || "-";
    const updated = svc.updated_at;
    const link = buildLink(svc, cfg);

    const addrCell = svc.ip
      ? `<span class="mono">${escapeHtml(svc.ip)}${
          port != null && port !== 0 ? `:${escapeHtml(String(port))}` : ""
        }</span>`
      : `<span class="muted">等待首次上报</span>`;

    const linkCell = link
      ? `<a class="open-btn" href="${escapeAttr(link)}" target="_blank" rel="noopener noreferrer">打开 →</a>`
      : `<span class="muted">—</span>`;

    const timeCell = updated
      ? escapeHtml(formatTime(updated, cfg.timeZone))
      : `<span class="muted">—</span>`;

    rows.push(`
            <tr>
              <td class="cell-title" data-label="服务">${escapeHtml(name)}</td>
              <td data-label="地址">${addrCell}</td>
              <td data-label="协议"><span class="muted">${escapeHtml(String(protocol))}</span></td>
              <td data-label="最近更新">${timeCell}</td>
              <td class="cell-action">${linkCell}</td>
            </tr>`);
  }

  const rowsHtml = rows.length
    ? rows.join("")
    : `<tr class="empty-row"><td class="empty">还没有任何服务<br><span style="font-size:13px">到管理页创建服务后，客户端上报地址就会出现在这里</span></td></tr>`;

  const summary = names.length
    ? `<span class="count-pill">共 <b>${names.length}</b> 个服务</span>`
    : "";

  return pageShell({
    title: "服务目录",
    nonce,
    body: `<div class="wrap">
  <header class="top">
    <div>
      <h1>服务目录</h1>
      <p class="sub">点击按钮直接打开服务</p>
    </div>
    ${summary}
  </header>
  <table>
    <thead>
      <tr><th>服务名</th><th>地址</th><th>协议</th><th>最近更新</th><th>链接</th></tr>
    </thead>
    <tbody>${rowsHtml}</tbody>
  </table>
  <p class="foot"><a href="/${escapeAttr(cfg.adminPath)}">管理页 →</a></p>
</div>`,
  });
}

async function renderAdmin(env, cfg, nonce, opts = {}) {
  const { error, newToken, newName, rotated } = opts;

  let banner = "";
  if (error) {
    banner = `<div class="alert alert-err">${escapeHtml(error)}</div>`;
  }

  if (newToken) {
    const verb = rotated ? "已重新生成" : "已创建";
    banner += `<div class="token-box">
      <div class="token-label">服务 <b>${escapeHtml(newName)}</b> ${verb}，上报密钥（token）如下。
      <b>仅显示这一次</b>，请立即复制保存：</div>
      <code>${escapeHtml(newToken)}</code>
    </div>`;
  }

  const csrf = await adminCsrfToken(env, cfg);
  const hidden = `<input type="hidden" name="_csrf" value="${escapeAttr(csrf)}">`;
  const adminBase = `/${escapeAttr(cfg.adminPath)}`;

  const services = await listServices(env);
  const names = Object.keys(services).sort();
  const rows = [];

  for (const name of names) {
    const svc = services[name];
    const scheme = svc.scheme === "https" ? "https" : "http";
    const updated = svc.updated_at;
    const link = buildLink(svc, cfg);

    const addrCell = svc.ip
      ? `<span class="mono">${escapeHtml(svc.ip)}${
          svc.port != null && svc.port !== 0 ? `:${escapeHtml(String(svc.port))}` : ""
        }</span>`
      : `<span class="muted">—</span>`;

    const linkCell = link
      ? `<a href="${escapeAttr(link)}" target="_blank" rel="noopener noreferrer">测试 ↗</a>`
      : `<span class="muted">—</span>`;

    const timeCell = updated
      ? escapeHtml(formatTime(updated, cfg.timeZone))
      : `<span class="muted">—</span>`;

    const enc = encodeURIComponent(name);
    rows.push(`
            <tr>
              <td class="cell-title" data-label="服务">${escapeHtml(name)}</td>
              <td data-label="地址">${addrCell}</td>
              <td data-label="协议"><span class="muted">${escapeHtml(String(svc.protocol || "-"))}</span></td>
              <td data-label="最近更新">${timeCell}</td>
              <td data-label="链接">${linkCell}</td>
              <td class="cell-ops">
                <div class="ops">
                  <form method="post" action="${adminBase}/services/${enc}/scheme" class="inline">
                    ${hidden}
                    <select name="scheme" aria-label="协议">
                      <option value="http"${scheme === "http" ? " selected" : ""}>http</option>
                      <option value="https"${scheme === "https" ? " selected" : ""}>https</option>
                    </select>
                    <button type="submit">保存</button>
                  </form>
                  <form method="post" action="${adminBase}/services/${enc}/token" class="inline rotate">
                    ${hidden}
                    <button type="submit">重置密钥</button>
                  </form>
                  <form method="post" action="${adminBase}/services/${enc}/delete" class="inline"
                        data-confirm="确认删除服务 ${escapeAttr(name)}？删除后该服务需重新创建才能恢复。">
                    ${hidden}
                    <button type="submit" class="del">删除</button>
                  </form>
                </div>
              </td>
            </tr>`);
  }

  const rowsHtml = rows.length
    ? rows.join("")
    : `<tr class="empty-row"><td class="empty">还没有服务，用上方表单创建第一个</td></tr>`;
  const script = `<script nonce="${escapeAttr(
    nonce
  )}">document.addEventListener("submit",function(e){var f=e.target;var c=f.getAttribute&&f.getAttribute("data-confirm");if(c&&!window.confirm(c)){e.preventDefault();}});</script>`;

  return pageShell({
    title: "服务管理",
    nonce,
    body: `<div class="wrap">
  <h1>服务管理</h1>
  ${banner}
  <div class="card">
    <h2>创建服务</h2>
    <form method="post" action="${adminBase}/services" class="row-flex">
      ${hidden}
      <input type="text" name="name" placeholder="服务名，如 qbittorrent" maxlength="64"
             autocomplete="off" autocapitalize="off" spellcheck="false" required>
      <select name="scheme" aria-label="协议">
        <option value="http">http</option>
        <option value="https">https</option>
      </select>
      <button type="submit">创建并生成密钥</button>
    </form>
    <p class="hint">支持中英文、数字、空格、下划线、连字符与点，最长 64 字符。创建后会生成一次性 token。</p>
  </div>
  <div class="card">
    <h2>服务列表</h2>
    <table>
      <thead><tr><th>服务名</th><th>地址</th><th>协议</th><th>最近更新</th><th>链接</th><th>操作</th></tr></thead>
      <tbody>${rowsHtml}</tbody>
    </table>
  </div>
</div>
${script}`,
  });
}

function escapeRegExp(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function toHex(bytes) {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

function randomNonce() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return toHex(bytes);
}

function randomToken() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return toHex(bytes);
}
