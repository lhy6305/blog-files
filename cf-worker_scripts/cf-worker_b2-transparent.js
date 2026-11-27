// cf-worker_b2-transparent.js
// ---------------------------------------------------------------------------
// Two planes over one Backblaze B2 (S3) bucket.
//
//   control plane   "Authorization: AWS4-HMAC-SHA256" is present.
//                   Verified against INBOUND_*, then re-signed with B2_ADMIN_*
//                   and forwarded with every byte after the authority intact:
//                   method, path, query, body, headers. This is the plane that
//                   rclone / aws-cli / any S3 client talks to. It never reads or
//                   writes the edge cache, and bucket-level operations pass
//                   through like everything else: the caller is authenticated,
//                   so what it may do is the B2 key's decision, not this
//                   worker's. Only the public plane gates listing.
//
//   public plane    everything else: an anonymous, read-only file server.
//                   GET/HEAD only. The whole query is dropped (listing
//                   parameters survive behind ENABLE_PUBLIC_LISTING, ?dl/?fn are
//                   consumed here). Signed upstream with B2_READONLY_*, edge
//                   cached, IP rate limited, and behind the upstream-403
//                   breaker.
//
// A request carrying a signature never falls through to the public plane: it is
// either verified, or answered with the 403 body B2 itself returns.
//
// The public plane rewrites response headers (nosniff, CORS, Cache-Control,
// attachment). The control plane returns the upstream response as it is.
//
// Both planes share one edge-cache key space, namespaced per deployment by the
// required CACHE_NAMESPACE variable (see resolve_cache_origin below).
//
// Derived from https://github.com/backblaze-b2-samples/cloudflare-b2-proxy
// ---------------------------------------------------------------------------

import { DurableObject } from "cloudflare:workers";
import { AwsClient } from "./aws4fetch.js";

// Edge-cache keys. Every entry this worker stores lives under a synthetic origin
// built from CACHE_NAMESPACE, and the four prefixes below are disjoint: an
// object URL can never collide with a marker, and the control plane can never
// read an entry the public plane wrote.
//
// The origin is per-deployment on purpose. The Cache API namespace belongs to
// the zone, not to the script, so every worker routed on the same zone shares
// it: with a fixed origin, another worker could read, overwrite and delete
// these entries, and the breaker would be one key across all of them.
// CACHE_NAMESPACE is required and validated -- an empty or malformed value is a
// config error, never a default, because a silent default is the collision this
// exists to prevent.
var resolve_cache_origin = function (cfg) {
    var namespace = String(cfg.CACHE_NAMESPACE || "").trim();
    // One lowercase DNS label: no dot, no leading or trailing hyphen, 1..63 chars.
    if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(namespace)) return null;
    return "https://" + namespace + ".cache.internal";
};

// Stable across requests, so a range request, a ?dl download and a plain GET
// all share one entry.
var make_public_cache_key = function (cache_origin, path) {
    return cache_origin + "/dl" + path;
};

var make_control_cache_key = function (cache_origin, path) {
    return cache_origin + "/ctl" + path;
};

var make_path_marker_key = function (cache_origin, path) {
    return new Request(cache_origin + "/marker/path" + path);
};

var make_breaker_key = function (cache_origin) {
    return cache_origin + "/marker/breaker";
};

const settings = {
    // Required. Namespaces every cache key; see resolve_cache_origin.
    "CACHE_NAMESPACE": "",

    // Public plane kill switch. Off -> every anonymous request is a plain 404.
    "ENABLE_PUBLIC_PLANE": true,
    "ENABLE_DOWNLOAD_CACHE": true,
    // Public plane only: may an anonymous visitor list the bucket? The control
    // plane is authenticated and passes bucket operations through untouched.
    // Trailing-slash paths are treated as directory requests for parity with the
    // original worker.
    "ENABLE_PUBLIC_LISTING": false,

    // 36h / 5min / 6h. Browser TTL is deliberately not "immutable": keys are
    // overwritable, so a cached body must be allowed to go stale.
    "DL_CACHE_TTL_SEC": 129600,
    "DL_CACHE_404_TTL_SEC": 300,
    "DL_BROWSER_TTL_SEC": 21600,
    "RANGE_RETRY_ATTEMPTS": 3,

    "ENABLE_IP_RATE_LIMIT": true,
    "RATE_LIMIT_WINDOW_SEC": 15,
    "RATE_LIMIT_MAX_REQ": 30,
    "RATE_LIMIT_BLOCK_SEC": 600,      // 0 disables blocking
    "RATE_LIMIT_FAIL_OPEN": false,

    // B2 daily caps reset at 00:00 UTC, so a 403 blocks until then; while the
    // breaker is open one request per interval is let through to re-probe.
    "ENABLE_403_BREAKER": true,
    "BREAKER_PROBE_INTERVAL_SEC": 60,

    "B2_DEBUG": false,
};

// Group 1 is the bucket prefix of a virtual-hosted endpoint, group 2 the region.
// Both are absent for a custom or path-style endpoint, which is why BUCKET_NAME
// exists: the public plane has to know where the bucket lives.
const RE_B2_S3_HOST = /^(?:([^.]{1,63})\.)?s3\.([a-z0-9-]+)\.backblazeb2\.com$/i;

// SigV4 forces us to regenerate these, and Workers refuses to send some of them.
const DROP_REQUEST_HEADERS = [
    "host",
    "authorization",
    "x-amz-date",
    "x-amz-security-token",
    "x-amz-content-sha256",
    "connection",
    "transfer-encoding",
    "expect",                // 100-continue is not supported in Workers
    "x-amzn-trace-id",
];

// The only visitor headers that reach the public plane's upstream request. A
// whitelist, because anything else would hand B2 a header nobody asked for.
//
// These are attached after signing, never signed. Cloudflare's cache layer
// rewrites the origin request -- it drops them on a miss, because it has to
// fetch the object anyway, and substitutes its own during a revalidation -- and
// a signed header that arrives changed or missing is a flat refusal from B2:
// "header 'if-modified-since' is listed in signed headers, but is not present".
const PUBLIC_FORWARD_REQUEST_HEADERS = [
    "range",
    // Tells the upstream to send the whole object instead of the range when the
    // validator no longer matches. Without it a resumed download splices bytes
    // from two versions of the object together.
    "if-range",
    "if-match",
    "if-none-match",
    "if-modified-since",
    "if-unmodified-since",
];

const LISTING_PARAMS = [
    "list-type",
    "delimiter",
    "prefix",
    "marker",
    "continuation-token",
    "start-after",
    "max-keys",
    "encoding-type",
];

// Custom metadata and B2's info headers can carry internal notes; the public
// plane is world-readable, so they do not leave the worker.
const STRIP_RESPONSE_HEADER_PREFIXES = ["x-amz-meta-", "x-bz-"];

// Byte-exact copy of the 403 B2 returns for an unauthenticated S3 request
// (captured 2026-11-24 from https://s3.us-west-004.backblazeb2.com/, 180 bytes).
const DENY_BODY =
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n' +
    "<Error>\n" +
    "    <Code>AccessDenied</Code>\n" +
    "    <Message>Unauthenticated requests are not allowed for this api</Message>\n" +
    "</Error>\n";

var rand_hex = function (bytes) {
    var a = new Uint8Array(bytes);
    crypto.getRandomValues(a);
    var s = "";
    for (var i = 0; i < a.length; i++) {
        s += a[i].toString(16).padStart(2, "0");
    }
    return s;
};

// Dashboard variables are strings; the defaults in `settings` are typed. Both
// forms must work, and a stray space or newline from a copy-paste must not
// silently flip a switch off. Only "true" and "1" count as on, so a typo always
// fails closed (the switch stays off) rather than opening something.
var variable_is_true = function (v) {
    if (v === true) return true;
    if (typeof v !== "string") return false;
    var normalized = v.trim().toLowerCase();
    return normalized === "true" || normalized === "1";
};

// Same story for numbers, with one extra rule: a written 0 is a real value, not
// "unset". `Number("0") || fallback` would turn a deliberate 0 into the default,
// which is exactly the silent fallback this codebase refuses to do.
var number_or = function (value, fallback) {
    if (value === null || value === undefined || String(value).trim() === "") return fallback;
    var parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : fallback;
};

// null when the header is absent. An unattributable request must not share one
// limiter bucket with every other unattributable request: one of them would then
// be able to block the rest.
var get_client_ip = function (request) {
    // Set by Cloudflare and overwritten on the way in; x-forwarded-for is
    // client-controlled and is deliberately not consulted.
    var ip = request.headers.get("cf-connecting-ip");
    if (ip && ip.trim().length > 0) return ip.trim();
    return null;
};

var deny_as_b2_403 = function () {
    return new Response(DENY_BODY, {
        status: 403,
        headers: {
            "Content-Type": "application/xml",
            "Cache-Control": "max-age=0, no-cache, no-store",
            "Strict-Transport-Security": "max-age=63072000",
            "X-Content-Type-Options": "nosniff",
            "x-amz-request-id": rand_hex(8),
        },
    });
};

var build_error_response = function (message, status, extra_headers) {
    var headers = {
        "Content-Type": "text/plain; charset=utf-8",
        "Cache-Control": "max-age=0, no-cache, no-store",
    };
    Object.keys(extra_headers || {}).forEach(function (k) { headers[k] = extra_headers[k]; });
    return new Response(message, { status: status, headers: headers });
};

// Misconfiguration details go to the log only -- the visitor gets a bare 500, so
// the response never names an env var, an endpoint or a region. Each distinct
// problem is logged once per isolate: a bad config is a deploy-level constant,
// not a per-request event, but a second, different problem must still show up.
var CONFIG_LOGGED = new Set();
var B2_DEBUG_ON = false;

var config_error = function (problem, detail) {
    if (!CONFIG_LOGGED.has(problem)) {
        CONFIG_LOGGED.add(problem);
        console.error(JSON.stringify(Object.assign({ "event": "misconfig", "problem": problem }, detail)));
    }
    return B2_DEBUG_ON ? "Internal Server Error: " + problem : "Internal Server Error";
};

var upstream_error = function (event, message) {
    console.error(JSON.stringify({ "event": event, "error": String(message) }));
};

// For conditions that are constant per deploy (a missing binding, say), so a
// public request flood cannot turn one mistake into a log flood.
var LOGGED_ONCE = new Set();
var upstream_error_once = function (event, message) {
    var key = event + "|" + String(message);
    if (LOGGED_ONCE.has(key)) return;
    LOGGED_ONCE.add(key);
    upstream_error(event, message);
};

// Credential=KEYID/20261124/us-west-004/s3/aws4_request
var parse_scope = function (authorization) {
    var m = /Credential=([^,]+)/.exec(authorization || "");
    if (!m) { return null; }
    var p = m[1].split("/");
    if (p.length !== 5) { return null; }
    return { "key_id": p[0], "region": p[2], "service": p[3] };
};

var reason_hint = function (reason) {
    if (/header .* not found/.test(reason)) {
        return "a signed header did not arrive; Cloudflare rewrites accept-encoding and adds cf-*/x-forwarded-*, so those must stay out of SignedHeaders";
    }
    if (/signature mismatched/.test(reason)) {
        return "the client and this worker disagree on signed headers, canonical path, query order or credential scope";
    }
    if (/key id/.test(reason)) {
        return "the client signs with a key id that is not INBOUND_ACCESS_KEY_ID";
    }
    if (/15 minute window/.test(reason)) {
        return "the client's clock is more than 15 minutes away from the edge's";
    }
    return "";
};

// Failed verifications are the signal worth keeping, but a fixed budget can be
// burnt by an unauthenticated caller, which would silence the signal forever.
// A per-minute window bounds the flood without losing it.
var VERIFY_LOG_PER_MIN = 10;
var verify_log_window_start_ms = 0;
var verify_log_used = 0;
var verify_log_allowed = function () {
    var now = Date.now();
    if (now - verify_log_window_start_ms >= 60000) {
        verify_log_window_start_ms = now;
        verify_log_used = 0;
    }
    if (verify_log_used >= VERIFY_LOG_PER_MIN) return false;
    verify_log_used += 1;
    return true;
};

// ---------------------------------------------------------------------------
// Inbound signature verification (control plane only).
// ---------------------------------------------------------------------------
var verify_signature = async function (request, inbound_key_id, verify_inbound) {
    var authorization = request.headers.get("Authorization");
    if (!authorization) {
        return false;
    }

    if (!authorization.startsWith("AWS4-HMAC-SHA256")) {
        return false;
    }

    var re = new RegExp("^AWS4-HMAC-SHA256 Credential=([^,]+),\\s*SignedHeaders=([^,]+),\\s*Signature=(.+)$");

    var matched = authorization.match(re);
    if (!matched) {
        throw new Error("unsupported authorization type");
    }
    var [, credential, signedHeaders, signature] = matched;

    credential = credential.split("/");
    signedHeaders = signedHeaders.split(";");

    if (credential[0] !== inbound_key_id) {
        throw new Error("application key id not valid");
    }

    var datetime = request.headers.get("x-amz-date");
    if (!datetime) {
        throw new Error("header x-amz-date not found");
    }

    // SigV4's own freshness rule. Without it a leaked Authorization header
    // replays forever, and since the body is not part of what we verify (s3
    // takes the payload hash from x-amz-content-sha256) the window is the only
    // thing bounding a replay.
    var when = /^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z$/.exec(datetime);
    if (!when) {
        throw new Error("x-amz-date is not an ISO8601 basic timestamp");
    }
    var signed_at_ms = Date.UTC(Number(when[1]), Number(when[2]) - 1, Number(when[3]),
        Number(when[4]), Number(when[5]), Number(when[6]));
    if (Math.abs(Date.now() - signed_at_ms) > 900000) {
        throw new Error("x-amz-date outside the 15 minute window");
    }

    var headersToSign = signedHeaders.reduce((obj, key) => {
        var value = request.headers.get(key);
        if (value == null) {
            throw new Error("header " + key + " not found");
        }
        obj[key] = value;
        return obj;
    }, {});

    // No body: for s3 the payload hash comes from x-amz-content-sha256, so
    // aws4fetch never reads it (verified against 1.0.20). Passing the stream
    // here would only risk locking it.
    var inbound_resigned = await verify_inbound.sign(request.url, {
        method: request.method,
        headers: headersToSign,
        aws: {
            datetime: datetime,
            allHeaders: true,
        },
    });

    var generatedAuthorization = inbound_resigned.headers.get("Authorization");
    var generatedMatched = generatedAuthorization && generatedAuthorization.match(re);
    if (!generatedMatched) {
        throw new Error("unsupported authorization type");
    }
    var [,,, generatedSignature] = generatedMatched;

    if (signature !== generatedSignature) {
        throw new Error("signature mismatched");
    }
    return true;
};

// ---------------------------------------------------------------------------
// URL / path helpers
// ---------------------------------------------------------------------------
var split_request_url = function (request_url) {
    var tail = request_url.replace(/^[a-z]+:\/\/[^/?#]+/i, "");
    if (tail === "") {
        tail = "/";
    }
    var query_index = tail.indexOf("?");
    return {
        "path": query_index < 0 ? tail : tail.slice(0, query_index),
        "query": query_index < 0 ? "" : tail.slice(query_index + 1),
    };
};

// Parity with the original worker: a path ending in "/" is treated as a
// directory request. It cannot distinguish a real directory from an object
// whose name ends in "/", which is why ENABLE_PUBLIC_LISTING defaults to false.
var is_directory_request = function (path) {
    return path === "/" || path === "" || path.endsWith("/");
};

// ---------------------------------------------------------------------------
// Upstream-403 breaker. B2 answers a daily cap with 403 until 00:00 UTC, so the
// marker lives exactly that long; a per-path marker stops repeat offenders, the
// global breaker stops every *other* path from being tried once each.
// ---------------------------------------------------------------------------
var next_midnight_utc_ms = function () {
    var now = new Date();
    var next = new Date(now);
    next.setUTCHours(24, 0, 0, 0);
    return next.getTime();
};

var seconds_until = function (until_ms) {
    return Math.max(1, Math.ceil((until_ms - Date.now()) / 1000));
};

var make_block_entry = function (block_until_ms) {
    // 200, not 204: the Cache API only stores statuses it considers cacheable.
    return new Response(null, {
        status: 200,
        headers: {
            "x-block-until": String(block_until_ms),
            "x-last-probe": String(Date.now()),
            "Cache-Control": "public, max-age=" + String(seconds_until(block_until_ms)),
        },
    });
};

var build_429_response = function (block_until_ms) {
    return new Response("Too Many Requests", {
        status: 429,
        headers: {
            "Access-Control-Allow-Origin": "*",
            "Cache-Control": "no-store",
            "Retry-After": String(seconds_until(block_until_ms)),
            "Content-Type": "text/plain; charset=utf-8",
            "X-Content-Type-Options": "nosniff",
        },
    });
};

// Cache failures must never turn into a 500: the marker is an optimisation for
// the upstream, not a correctness requirement.
var cache_get = async function (key) {
    try {
        return await caches.default.match(key);
    } catch (e) {
        upstream_error("cache_read_failed", e);
        return null;
    }
};

var cache_put = async function (key, response) {
    try {
        await caches.default.put(key, response);
    } catch (e) {
        upstream_error("cache_write_failed", e);
    }
};

var cache_delete = async function (key) {
    try {
        await caches.default.delete(key);
    } catch (e) {
        upstream_error("cache_delete_failed", e);
    }
};

var mark_upstream_403 = async function (path, cfg, cache_origin) {
    var block_until_ms = next_midnight_utc_ms();
    await cache_put(make_path_marker_key(cache_origin, path), make_block_entry(block_until_ms));
    if (variable_is_true(cfg.ENABLE_403_BREAKER)) {
        await cache_put(make_breaker_key(cache_origin), make_block_entry(block_until_ms));
    }
    return block_until_ms;
};

// blocked: a 429 Response when the request must not reach the upstream.
// breaker_open: whether a breaker entry was seen, so the caller knows if a
// successful response owes it a delete (a cache delete per request is not free).
var check_upstream_403_state = async function (path, cfg, cache_origin) {
    var now = Date.now();

    var marker_key = make_path_marker_key(cache_origin, path);
    var marker = await cache_get(marker_key);
    if (marker) {
        var marker_until = Number(marker.headers.get("x-block-until") || 0);
        if (marker_until > now) {
            return { "blocked": build_429_response(marker_until), "breaker_open": false };
        }
        await cache_delete(marker_key);
    }

    if (!variable_is_true(cfg.ENABLE_403_BREAKER)) {
        return { "blocked": null, "breaker_open": false };
    }

    var breaker = await cache_get(make_breaker_key(cache_origin));
    if (!breaker) {
        return { "blocked": null, "breaker_open": false };
    }
    var breaker_until = Number(breaker.headers.get("x-block-until") || 0);
    if (breaker_until <= now) {
        await cache_delete(make_breaker_key(cache_origin));
        return { "blocked": null, "breaker_open": false };
    }
    var last_probe = Number(breaker.headers.get("x-last-probe") || 0);
    var probe_interval_ms = Math.max(number_or(cfg.BREAKER_PROBE_INTERVAL_SEC, 60), 1) * 1000;
    if (now - last_probe < probe_interval_ms) {
        return { "blocked": build_429_response(breaker_until), "breaker_open": true };
    }
    // Half-open: this request is the probe. Move the window forward now so a
    // burst of one IP cannot turn the probe slot into an open door.
    await cache_put(make_breaker_key(cache_origin), make_block_entry(breaker_until));
    return { "blocked": null, "breaker_open": true };
};

// ---------------------------------------------------------------------------
// IP rate limit (Durable Object, see IPRateLimiterDO at the bottom)
// ---------------------------------------------------------------------------
var check_ip_rate_limit = async function (request, env, cfg) {
    if (!variable_is_true(cfg.ENABLE_IP_RATE_LIMIT)) {
        return { "ok": true };
    }
    if (!env.IP_RATE_LIMITER) {
        upstream_error_once("limiter_binding_missing", "IP_RATE_LIMITER not bound, skipping rate limit");
        return { "ok": true };
    }
    var client_ip = get_client_ip(request);
    if (client_ip === null) {
        // Only internal callers lack the header -- every routed request gets it
        // from the edge -- so there is nothing to attribute and nothing to
        // count. RATE_LIMIT_FAIL_OPEN still decides what a *failed* call means.
        upstream_error_once("client_ip_missing", "cf-connecting-ip absent, skipping rate limit");
        return { "ok": true };
    }
    var stub = env.IP_RATE_LIMITER.get(env.IP_RATE_LIMITER.idFromName(client_ip));
    try {
        var resp = await stub.fetch("https://rate-limit/check", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
                now: Date.now(),
                window_sec: Math.max(number_or(cfg.RATE_LIMIT_WINDOW_SEC, 15), 1),
                max_req: Math.max(number_or(cfg.RATE_LIMIT_MAX_REQ, 30), 1),
                block_sec: Math.max(number_or(cfg.RATE_LIMIT_BLOCK_SEC, 0), 0),
            }),
        });
        var data = await resp.json().catch(() => ({ "ok": false, "reason": "invalid_limiter_response" }));
        if (resp.status === 429 || data.ok === false) {
            return {
                "ok": false,
                "retry_after_sec": Number(data.retryAfter) || 1,
                "reason": data.reason || "rate_limited",
            };
        }
        if (resp.status === 200 && data.ok === true) {
            return { "ok": true };
        }
        return { "ok": variable_is_true(cfg.RATE_LIMIT_FAIL_OPEN), "reason": "unexpected_limiter_response" };
    } catch (e) {
        upstream_error("limiter_failed", e);
        return { "ok": variable_is_true(cfg.RATE_LIMIT_FAIL_OPEN), "reason": "limiter_throw_exception" };
    }
};

// ---------------------------------------------------------------------------
// Credentials. Three pairs, three jobs, and no pair may repeat another's value:
// a public or inbound secret that equals the admin secret is the leak this
// worker exists to avoid.
// ---------------------------------------------------------------------------
const CREDENTIAL_PAIRS = [
    ["INBOUND_ACCESS_KEY_ID", "INBOUND_SECRET_ACCESS_KEY"],
    ["B2_ADMIN_KEY_ID", "B2_ADMIN_KEY"],
    ["B2_READONLY_KEY_ID", "B2_READONLY_KEY"],
];

var check_credentials_distinct = function (cfg) {
    var seen_ids = {};
    var seen_secrets = {};
    for (var i = 0; i < CREDENTIAL_PAIRS.length; i++) {
        var id = String(cfg[CREDENTIAL_PAIRS[i][0]] || "").trim();
        var secret = String(cfg[CREDENTIAL_PAIRS[i][1]] || "").trim();
        if (!id && !secret) continue;
        if (id && seen_ids[id]) {
            return CREDENTIAL_PAIRS[i][0] + " has the same value as " + seen_ids[id];
        }
        if (secret && seen_secrets[secret]) {
            return CREDENTIAL_PAIRS[i][1] + " has the same value as " + seen_secrets[secret];
        }
        if (id) seen_ids[id] = CREDENTIAL_PAIRS[i][0];
        if (secret) seen_secrets[secret] = CREDENTIAL_PAIRS[i][1];
    }
    return null;
};

var make_signer = function (key_id, secret, service, region) {
    return new AwsClient({
        "accessKeyId": key_id,
        "secretAccessKey": secret,
        "sessionToken": null,
        "service": service,
        "region": region,
        "cache": null,
        "retries": 0,       // sign() only; client.fetch() is never used
        "initRetryMs": null,
    });
};

// ---------------------------------------------------------------------------
// Control plane: verified, then forwarded verbatim.
// ---------------------------------------------------------------------------
var handle_control_plane = async function (request, env, cfg, cache_origin, upstream_host, signing_region, authorization) {
    var inbound_key_id = String(cfg.INBOUND_ACCESS_KEY_ID || "").trim();
    var inbound_secret = String(cfg.INBOUND_SECRET_ACCESS_KEY || "").trim();
    var admin_key_id = String(cfg.B2_ADMIN_KEY_ID || "").trim();
    var admin_secret = String(cfg.B2_ADMIN_KEY || "").trim();
    if (!inbound_key_id || !inbound_secret || !admin_key_id || !admin_secret) {
        return build_error_response(config_error("control plane credentials not bound", {
            "has_inbound_key_id": !!inbound_key_id,
            "has_inbound_secret": !!inbound_secret,
            "has_admin_key_id": !!admin_key_id,
            "has_admin_secret": !!admin_secret,
            "bindings": Object.keys(env).join(","),
        }), 500);
    }
    var conflict = check_credentials_distinct(cfg);
    if (conflict) {
        return build_error_response(config_error("credential pairs must not repeat", { "conflict": conflict }), 500);
    }

    // Rebuild the signing client from the client's own credential scope: that is
    // what it signed with, and the region is baked into both the scope and the
    // signing key. Falling back to our own region would reject authentic clients.
    var scope = parse_scope(authorization);
    var verify_inbound = make_signer(
        inbound_key_id,
        inbound_secret,
        (scope && scope.service) || "s3",
        (scope && scope.region) || signing_region
    );

    var verified = false;
    var verify_error = null;
    try {
        verified = (await verify_signature(request, inbound_key_id, verify_inbound)) === true;
    } catch (e) {
        verify_error = e;
    }
    if (!verified) {
        var reason = verify_error ? String(verify_error.message || verify_error) : "no AWS4-HMAC-SHA256 Authorization header";
        if (verify_log_allowed()) {
            console.error(JSON.stringify({
                "event": "verify_failed",
                "reason": reason,
                "hint": reason_hint(reason),
                "scope": scope,
            }));
        }
        if (B2_DEBUG_ON) {
            return build_error_response("Forbidden: " + reason, 403);
        }
        return deny_as_b2_403();
    }

    // A body re-signed by us cannot be the aws-chunked framing the client signed.
    if (/aws-chunked/i.test(request.headers.get("content-encoding") || "")
        || /^STREAMING-/i.test(request.headers.get("x-amz-content-sha256") || "")) {
        return build_error_response("aws-chunked request body is not supported", 501);
    }

    var url_parts = split_request_url(request.url);

    // No clone: the body is read here and nowhere else, and the unused branch of
    // a tee buffers the whole body instead of applying backpressure.
    var has_body = request.method !== "GET" && request.method !== "HEAD";
    var body = has_body ? request.body : null;

    var path_part = url_parts.path;
    var query_part = url_parts.query === "" ? "" : "?" + url_parts.query;

    // aws4fetch canonicalises the S3 path via decode->encode and maps a literal "+"
    // to a space; %2B keeps the signature and the bytes on the wire in sync.
    path_part = path_part.replace(/\+/g, "%2B");

    // aws4fetch would collapse %2F into a real "/" and silently address another key.
    if (/%2f/i.test(path_part)) {
        return build_error_response("Bad Request", 400);
    }

    var up_url = "https://" + upstream_host
        + (path_part.charAt(0) === "/" ? "" : "/") + path_part + query_part;

    var forward_headers = new Headers(request.headers);
    DROP_REQUEST_HEADERS.forEach(function (h) { forward_headers.delete(h); });

    // Sign host + x-amz-* only. Signing more would break: Cloudflare rewrites
    // accept-encoding *after* we sign, and cf-*/x-forwarded-* only exist on the
    // way out.
    var headers_to_sign = {};
    forward_headers.forEach(function (v, k) { if (k.startsWith("x-amz-")) headers_to_sign[k] = v; });

    // A real payload hash supplied by the client stays valid (the body is
    // forwarded unchanged); anything else is left to aws4fetch, which sets
    // UNSIGNED-PAYLOAD for s3. Read it from the inbound headers: it was dropped
    // from forward_headers above.
    var inbound_payload_sha256 = request.headers.get("x-amz-content-sha256") || "";
    if ((/^[0-9a-f]{64}$/i).test(inbound_payload_sha256)) {
        headers_to_sign["x-amz-content-sha256"] = inbound_payload_sha256;
    }

    var sign_admin = make_signer(admin_key_id, admin_secret, "s3", signing_region);
    var outbound_signed = await sign_admin.sign(up_url, {
        method: request.method,
        headers: headers_to_sign,
        body: body,
    });

    // aws4fetch ties "what gets signed" to "what gets sent"; we need them apart.
    var signed_forward_headers = new Headers(forward_headers);
    signed_forward_headers.set("authorization", outbound_signed.headers.get("authorization"));
    signed_forward_headers.set("x-amz-date", outbound_signed.headers.get("x-amz-date"));
    signed_forward_headers.set("x-amz-content-sha256", outbound_signed.headers.get("x-amz-content-sha256") || "UNSIGNED-PAYLOAD");

    var resp;
    try {
        var outbound_request;
        var outbound_init = {
            method: request.method,
            headers: signed_forward_headers,
            body: body,
            redirect: "manual",   // never follow: our Authorization is bound to the host we signed
        };
        try {
            outbound_request = new Request(outbound_signed.url, outbound_init);
        } catch (e) {
            // Node/undici insists on duplex for a streaming body; Workers ignores it.
            if (!(e instanceof TypeError) || !body) throw e;
            outbound_request = new Request(outbound_signed.url, Object.assign({ "duplex": "half" }, outbound_init));
        }
        resp = await fetch(outbound_request, {
            cf: {
                // The control plane must not read what the public plane cached,
                // and nothing of its own is worth caching.
                cacheEverything: false,
                cacheTtl: 0,
                cacheKey: make_control_cache_key(cache_origin, path_part),
            },
        });
    } catch (e) {
        upstream_error("upstream_fetch_failed", (e && e.message) || e);
        return build_error_response("Bad Gateway", 502);
    }

    // B2 answers a cross-region request with a 301 that names the real endpoint.
    // Following it is impossible (host-bound signature) and handing it to the
    // client would leak the endpoint and let it bypass the worker -- so it
    // becomes a 502. 304 is a legitimate conditional-GET answer and is not here.
    if (resp.status === 301 || resp.status === 302 || resp.status === 303
        || resp.status === 307 || resp.status === 308) {
        console.error(JSON.stringify({
            "event": "upstream_redirect",
            "status": resp.status,
            "region": resp.headers.get("x-amz-bucket-region") || null,
            "location": resp.headers.get("location") || null,
        }));
        return build_error_response("Bad Gateway", 502);
    }

    // A write just invalidated whatever the public plane has under that path.
    if (resp.status < 300 && (request.method === "PUT" || request.method === "DELETE" || request.method === "POST")) {
        await cache_delete(make_public_cache_key(cache_origin, path_part));
    }

    var control_headers = new Headers(resp.headers);
    control_headers.set("X-Content-Type-Options", "nosniff");
    return new Response(resp.body, {
        status: resp.status,
        statusText: resp.statusText,
        headers: control_headers,
    });
};

// ---------------------------------------------------------------------------
// Public plane: anonymous, read-only, cached.
// ---------------------------------------------------------------------------
var read_attachment_params = function (params) {
    // ?dl with no value counts as true; ?dl=0 turns it off. ?fn only names the
    // file -- without ?dl it changes nothing, which is the original behaviour.
    var forced = false;
    if (params.has("dl")) {
        var value = params.get("dl");
        forced = value === "" || variable_is_true(value);
    }
    var filename = params.has("fn") ? params.get("fn") : null;
    if (filename !== null) {
        filename = filename.replace(/[\u0000-\u001f\u007f]/g, "").slice(0, 255);
        if (filename === "") filename = null;
    }
    return { "forced": forced, "filename": filename };
};

var build_content_disposition = function (filename) {
    // filename="中文.pdf" throws (Headers values are byte strings), so the
    // RFC 5987 form is the only one that survives non-ASCII names.
    if (filename === null) return "attachment";
    return "attachment; filename*=UTF-8''" + encodeURIComponent(filename);
};

// B2 explains a refusal in an XML body and nowhere else: the status alone cannot
// tell a request-level mistake from an exhausted daily cap, and only one of the
// two is worth blocking the whole site for. Bounded, because the body is
// upstream-controlled and this runs on error paths.
var ERROR_CODE_MAX_BYTES = 4096;
var read_error_code = async function (response) {
    try {
        var body = response.clone().body;
        if (!body) return null;
        var reader = body.getReader();
        var decoder = new TextDecoder();
        var text = "";
        var seen = 0;
        while (seen < ERROR_CODE_MAX_BYTES) {
            var step = await reader.read();
            if (step.done) break;
            seen += step.value.byteLength;
            text += decoder.decode(step.value, { "stream": true });
        }
        await reader.cancel().catch(function () {});
        var matched = /<Code>([^<]{1,64})<\/Code>/.exec(text);
        return matched ? matched[1] : null;
    } catch (e) {
        return null;
    }
};

// Codes that mean "this request was wrong", not "this account is out of quota".
// The visitor's own headers decide them, so they must never open the breaker.
var REQUEST_LEVEL_403_CODES = new Set(["SignatureDoesNotMatch", "InvalidRequest"]);

var build_public_response = function (upstream_response, attachment, cfg) {
    var headers = new Headers(upstream_response.headers);
    Array.from(headers.keys()).forEach(function (name) {
        for (var i = 0; i < STRIP_RESPONSE_HEADER_PREFIXES.length; i++) {
            if (name.startsWith(STRIP_RESPONSE_HEADER_PREFIXES[i])) {
                headers.delete(name);
                return;
            }
        }
    });

    headers.set("Access-Control-Allow-Origin", "*");
    headers.set("Access-Control-Expose-Headers", "accept-ranges, content-range, content-length, etag");
    headers.set("X-Content-Type-Options", "nosniff");

    if (!headers.has("content-type")) {
        headers.set("Content-Type", "application/octet-stream");
    }
    if (attachment.forced && (upstream_response.status === 200 || upstream_response.status === 206)) {
        try {
            headers.set("Content-Disposition", build_content_disposition(attachment.filename));
        } catch (e) {
            headers.set("Content-Disposition", "attachment");
        }
    }

    // 304 carries the same freshness a 200 would: a shorter max-age here would
    // demote a 36h object to 5 minutes on every revalidation, which is the
    // opposite of what a conditional request is for.
    var fresh_status = upstream_response.status === 200
        || upstream_response.status === 206
        || upstream_response.status === 304;
    var browser_ttl = fresh_status
        ? Math.max(number_or(cfg.DL_BROWSER_TTL_SEC, 21600), 0)
        : 300;
    // Only a real answer is worth keeping. An error caused by this request (a 400
    // from a rewritten conditional header, 412, 416) or by the upstream (5xx)
    // must not be replayed to the next visitor for the next five minutes. 404
    // keeps its short TTL: it is an answer, not a failure.
    if (upstream_response.status >= 400 && upstream_response.status !== 404) {
        headers.set("Cache-Control", "no-store");
    } else {
        headers.set("Cache-Control", "public, max-age=" + String(browser_ttl));
    }

    var body = upstream_response.status === 304 || upstream_response.status === 204
        ? null
        : upstream_response.body;
    return new Response(body, {
        status: upstream_response.status,
        statusText: upstream_response.statusText,
        headers: headers,
    });
};

var handle_public_plane = async function (request, env, cfg, cache_origin, upstream_host, signing_region, host_bucket) {
    if (!variable_is_true(cfg.ENABLE_PUBLIC_PLANE)) {
        return build_error_response("Not Found", 404);
    }

    if (request.method === "OPTIONS") {
        return new Response(null, {
            status: 204,
            headers: {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, HEAD",
                // Same list as the forwarding whitelist, so a header the worker
                // forwards can never be one the preflight refused.
                "Access-Control-Allow-Headers": PUBLIC_FORWARD_REQUEST_HEADERS.join(", "),
                "Access-Control-Expose-Headers": "accept-ranges, content-range, content-length, etag",
                "Access-Control-Max-Age": "86400",
                "Cache-Control": "public, max-age=86400",
            },
        });
    }

    if (request.method !== "GET" && request.method !== "HEAD") {
        return build_error_response("Method Not Allowed", 405, {
            "Allow": "GET, HEAD, OPTIONS",
            "Access-Control-Allow-Origin": "*",
            "Cache-Control": "public, max-age=300",
        });
    }

    var readonly_key_id = String(cfg.B2_READONLY_KEY_ID || "").trim();
    var readonly_secret = String(cfg.B2_READONLY_KEY || "").trim();
    if (!readonly_key_id || !readonly_secret) {
        return build_error_response(config_error("public plane requires B2_READONLY_KEY_ID and B2_READONLY_KEY", {
            "has_readonly_key_id": !!readonly_key_id,
            "has_readonly_secret": !!readonly_secret,
            "bindings": Object.keys(env).join(","),
        }), 500);
    }
    var conflict = check_credentials_distinct(cfg);
    if (conflict) {
        return build_error_response(config_error("credential pairs must not repeat", { "conflict": conflict }), 500);
    }

    var url_parts = split_request_url(request.url);
    var public_path = url_parts.path.replace(/\+/g, "%2B");
    if (/%2f/i.test(public_path)) {
        return build_error_response("Bad Request", 400, { "Access-Control-Allow-Origin": "*" });
    }

    // Where the bucket lives: virtual-hosted endpoints already carry it, a
    // path-style or custom endpoint needs BUCKET_NAME or the visitor's key would
    // be read as a bucket name.
    var upstream_path;
    if (host_bucket) {
        upstream_path = public_path;
    } else {
        var bucket_name = String(cfg.BUCKET_NAME || "").trim();
        if (!bucket_name) {
            return build_error_response(config_error("BUCKET_NAME is required for the public plane on this endpoint", {
                "upstream_host": upstream_host,
            }), 500);
        }
        upstream_path = "/" + bucket_name + (public_path.charAt(0) === "/" ? public_path : "/" + public_path);
    }

    var params = new URLSearchParams(url_parts.query);
    // Only the root and the directory form are bucket-level here: the visitor's
    // path is object-key space, because the worker prefixes the bucket itself.
    var wants_listing = is_directory_request(public_path);
    if (wants_listing && !variable_is_true(cfg.ENABLE_PUBLIC_LISTING)) {
        return build_error_response("Directory Listing Not Allowed", 403, {
            "Access-Control-Allow-Origin": "*",
            "Cache-Control": "public, max-age=300",
        });
    }

    // Listing parameters are the only part of the query that ever reaches the
    // upstream; everything else (including ?dl/?fn) is consumed here. That keeps
    // the cache key to the set of real object names, so a visitor cannot mint
    // fresh cache entries by appending random parameters.
    var upstream_query = "";
    if (wants_listing) {
        var kept = new URLSearchParams();
        LISTING_PARAMS.forEach(function (name) {
            if (params.has(name)) kept.set(name, params.get(name));
        });
        upstream_query = kept.toString();
    }

    var attachment = read_attachment_params(params);

    var block_state = await check_upstream_403_state(public_path, cfg, cache_origin);
    if (block_state.blocked) {
        return block_state.blocked;
    }

    var limit = await check_ip_rate_limit(request, env, cfg);
    if (!limit.ok) {
        return build_error_response("Too Many Requests", 429, {
            "Access-Control-Allow-Origin": "*",
            "Cache-Control": "no-store",
            "Retry-After": String(limit.retry_after_sec || 1),
        });
    }

    var visitor_headers = new Headers();
    PUBLIC_FORWARD_REQUEST_HEADERS.forEach(function (name) {
        var value = request.headers.get(name);
        if (value !== null) visitor_headers.set(name, value);
    });

    // Sign host + x-amz-* only and attach the visitor's headers afterwards: then
    // the signature describes the request that actually reaches B2, whether the
    // edge forwards those headers, rewrites them or drops them. This is the same
    // split the control plane uses above.
    var sign_readonly = make_signer(readonly_key_id, readonly_secret, "s3", signing_region);
    var up_url = "https://" + upstream_host + upstream_path + (upstream_query === "" ? "" : "?" + upstream_query);
    var outbound_signed = await sign_readonly.sign(up_url, {
        method: request.method,
    });
    var send_headers = new Headers(outbound_signed.headers);
    visitor_headers.forEach(function (value, name) { send_headers.set(name, value); });

    // Cached by object path, never by request: ?dl/?fn variants share one entry
    // and only the response headers differ per request. GET only: a cached HEAD
    // would store the response without a body.
    var cf_options = variable_is_true(cfg.ENABLE_DOWNLOAD_CACHE) && !wants_listing && request.method === "GET"
        ? {
            cacheEverything: true,
            cacheKey: make_public_cache_key(cache_origin, upstream_path),
            // 304 is deliberately outside these ranges. It is reachable now that
            // the visitor's conditional headers survive to B2, and a stored 304
            // has no body: a later unconditional GET would be answered from it.
            cacheTtlByStatus: {
                "200-203": Math.max(number_or(cfg.DL_CACHE_TTL_SEC, 129600), 0),
                "205-299": Math.max(number_or(cfg.DL_CACHE_TTL_SEC, 129600), 0),
                "404": Math.max(number_or(cfg.DL_CACHE_404_TTL_SEC, 300), 0),
            },
        }
        : {
            cacheEverything: false,
            cacheTtl: 0,
            // Same family as the stored entries, distinct key: this path is
            // never written, it only has to stay out of the cached one.
            cacheKey: make_public_cache_key(cache_origin, "/nocache" + upstream_path),
        };

    // For large files Cloudflare returns the entire file rather than the
    // requested range. If the response has no content-range header, abort and
    // retry -- but only when the request is cacheable: the retry is worth the
    // bytes because the first answer fills the entry, and that is what makes the
    // second one a 206. With caching off it can only pay for the same object
    // twice more, so there the budget is a single attempt.
    //
    // If-Range is excluded from the retry: it makes "200, no content-range" a
    // legitimate answer (the validator no longer matches, so the whole object is
    // what the client asked for), and the loop cannot tell that apart from the
    // edge ignoring the range. Such a request takes the plain path below.
    var resp;
    if (visitor_headers.has("range") && !visitor_headers.has("if-range")) {
        var attempts = cf_options.cacheEverything
            ? Math.max(number_or(cfg.RANGE_RETRY_ATTEMPTS, 3), 1)
            : 1;
        while (true) {
            var controller = new AbortController();
            resp = await fetch(outbound_signed.url, {
                method: outbound_signed.method,
                headers: send_headers,
                signal: controller.signal,
                cf: cf_options,
            });
            if (resp.headers.has("content-range")) break;
            if (!resp.ok) break;
            attempts -= 1;
            if (attempts <= 0) {
                controller.abort();   // this attempt's body is never read
                upstream_error("range_retry_exhausted", outbound_signed.url);
                return build_error_response("An unexpected backend error occurred. Please contact the admin.", 500, {
                    "Cache-Control": "no-store",
                });
            }
            controller.abort();
        }
    } else {
        resp = await fetch(outbound_signed.url, {
            method: outbound_signed.method,
            headers: send_headers,
            cf: cf_options,
        });
    }

    // A cross-region request answers with a 301 that names the real endpoint.
    // Handing that to the visitor would leak the endpoint and let it go around
    // this worker -- the same guard the control plane applies. 304 is a
    // legitimate conditional answer and is not here.
    if (resp.status === 301 || resp.status === 302 || resp.status === 303
        || resp.status === 307 || resp.status === 308) {
        upstream_error("upstream_redirect", resp.headers.get("location") || "");
        return build_error_response("Bad Gateway", 502, {
            "Access-Control-Allow-Origin": "*",
        });
    }

    // B2 names the reason only in the body, so the status alone leaves the two
    // halves of a 403 indistinguishable. One line per distinct (status, code) per
    // isolate: a visitor can trigger these, so it must not become a log flood,
    // but standing there with no diagnosis at all is worse.
    var upstream_code = null;
    if (resp.status >= 400 && resp.status !== 404) {
        upstream_code = await read_error_code(resp);
        upstream_error_once("upstream_error_code", String(resp.status) + " " + String(upstream_code));
    }

    // 403 from a read-only key is never "that object is private" -- the bucket is
    // public by design. It is a daily cap, a wrong capability or a disabled key,
    // so it is treated as a systemic condition and kept away from the upstream.
    if (resp.status === 403) {
        // A listing 403 usually means the read-only key was not granted listFiles.
        // That is a config mistake on one operation, not a bucket-wide cap, so it
        // is passed through instead of taking the whole site down until midnight.
        if (wants_listing) {
            return build_public_response(resp, attachment, cfg);
        }
        // A request-level 403 -- a rewritten conditional header, a malformed
        // argument -- is decided by the visitor's own request. Blocking the path
        // for it, and opening the global breaker with it, would let one header
        // take every other path down until midnight UTC.
        if (REQUEST_LEVEL_403_CODES.has(upstream_code)) {
            return build_public_response(resp, attachment, cfg);
        }
        var block_until_ms = await mark_upstream_403(public_path, cfg, cache_origin);
        console.error(JSON.stringify({
            "event": "upstream_403",
            "path": public_path,
            "request_id": resp.headers.get("x-amz-request-id") || null,
            "block_until": block_until_ms,
        }));
        return build_429_response(block_until_ms);
    }

    // Any answer that is not a 403 means the upstream is healthy again; drop the
    // breaker so a recovered quota is not hidden behind a stale marker.
    if (block_state.breaker_open) {
        await cache_delete(make_breaker_key(cache_origin));
    }

    return build_public_response(resp, attachment, cfg);
};

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------
var main_handler = async function (request, env) {
    var url = new URL(request.url);
    if (url.protocol !== "https:") {
        url.protocol = "https:";
        url.port = "443";
        return Response.redirect(url.toString(), 301);
    }

    var cfg = Object.assign({}, settings, env);
    B2_DEBUG_ON = variable_is_true(cfg.B2_DEBUG);

    // Every cache key below is namespaced by this origin, so a deployment
    // without one would silently share the zone cache with other workers.
    var cache_origin = resolve_cache_origin(cfg);
    if (!cache_origin) {
        return build_error_response(config_error("CACHE_NAMESPACE must be one lowercase DNS label", {
            "value_length": String(cfg.CACHE_NAMESPACE || "").trim().length,
        }), 500);
    }

    var upstream_host = String(cfg.B2_ENDPOINT || "").trim()
        .replace(/^https?:\/\//i, "")
        .replace(/\/+$/, "")
        .toLowerCase();
    if (!upstream_host) {
        return build_error_response(config_error("B2_ENDPOINT is empty", {}), 500);
    }

    var host_match = RE_B2_S3_HOST.exec(upstream_host);
    var host_bucket = (host_match && host_match[1]) || "";
    var parsed_region = (host_match && host_match[2]) || "";
    var region_override = String(cfg.B2_REGION || "").trim().toLowerCase();

    // Lowercased on both sides: SigV4 regions are lowercase, and a dashboard typo
    // of "US-WEST-004" must not be reported as a conflict.
    if (region_override && parsed_region && region_override !== parsed_region) {
        return build_error_response(config_error("B2_REGION conflicts with B2_ENDPOINT", {
            "region_override": region_override,
            "parsed_region": parsed_region,
            "upstream_host": upstream_host,
        }), 500);
    }

    // SIGNING_REGION: never sent anywhere, it only seeds the signature and the
    // credential scope.
    var signing_region = region_override || parsed_region;
    if (!signing_region) {
        return build_error_response(config_error("cannot derive region from B2_ENDPOINT", {
            "upstream_host": upstream_host,
            "hint": "set B2_REGION; it is not sent to B2, it only scopes the signature",
        }), 500);
    }

    var authorization = request.headers.get("Authorization") || "";
    if (authorization.startsWith("AWS4-HMAC-SHA256")) {
        return handle_control_plane(request, env, cfg, cache_origin, upstream_host, signing_region, authorization);
    }
    return handle_public_plane(request, env, cfg, cache_origin, upstream_host, signing_region, host_bucket);
};

export default {
    async fetch(request, env) {
        // Nothing may escape as an uncaught exception: that turns into a
        // Cloudflare 500 with no trace of which check failed.
        try {
            return await main_handler(request, env);
        } catch (e) {
            console.error(JSON.stringify({
                "event": "uncaught",
                "error": String((e && (e.stack || e.message)) || e),
            }));
            return build_error_response("Internal Server Error", 500);
        }
    },
};

// ---------------------------------------------------------------------------
// Per-IP rate limiter.
//
// The counter is read-modify-write, so requests are serialised per instance:
// without that, a burst of 100 concurrent requests all read the same hits[] and
// all get allowed.
//
// State lives in memory and is flushed at most once per FLUSH_INTERVAL_MS. A
// burst therefore costs one durable write instead of one per request, while a
// drip (one request every few seconds, slow enough for the instance to be
// evicted) still flushes every time -- otherwise eviction would silently restart
// the window and the limiter would never fire.
// ---------------------------------------------------------------------------
const FLUSH_INTERVAL_MS = 1000;

export class IPRateLimiterDO extends DurableObject {
    constructor(state, env) {
        super(state, env);
        this.state = state;
        this.data = null;
        this.last_flush_ms = 0;
        this.chain = Promise.resolve();
    }

    async fetch(request) {
        if (request.method !== "POST") {
            return new Response("Method Not Allowed", { status: 405 });
        }
        var body = await request.json().catch(() => ({}));
        var result = await this.serialise(() => this.decide(body));
        return Response.json(result, { status: result.ok ? 200 : 429 });
    }

    serialise(work) {
        var next = this.chain.then(work, work);
        this.chain = next.then(() => {}, () => {});
        return next;
    }

    async decide(limit_request) {
        var now = number_or(limit_request.now, Date.now());
        var window_ms = Math.max(number_or(limit_request.window_sec, 15), 1) * 1000;
        var max_req = Math.max(number_or(limit_request.max_req, 30), 1);
        var block_ms = Math.max(number_or(limit_request.block_sec, 0), 0) * 1000;

        var data = await this.load();
        if (data.blocked_until_ms > now) {
            return {
                "ok": false,
                "reason": "blocked",
                "retryAfter": Math.ceil((data.blocked_until_ms - now) / 1000),
            };
        }
        // A finished block starts a clean slate: violations from the previous
        // window must not turn the next window into an instant block.
        if (data.blocked_until_ms > 0) {
            data.blocked_until_ms = 0;
            data.violation_count = 0;
            data.hits = [];
        }

        data.hits = data.hits.filter(function (ts) { return now - ts < window_ms; });

        if (data.hits.length >= max_req) {
            data.violation_count += 1;
            if (block_ms > 0 && data.violation_count >= 2) {
                data.blocked_until_ms = now + block_ms;
            }
            await this.flush(now, true);
            return {
                "ok": false,
                "reason": "rate_limited",
                "retryAfter": data.blocked_until_ms > now
                    ? Math.ceil((data.blocked_until_ms - now) / 1000)
                    : 1,
            };
        }

        data.hits.push(now);
        if (data.violation_count > 0) data.violation_count -= 1;
        await this.flush(now, false);
        return { "ok": true, "remaining": max_req - data.hits.length };
    }

    async load() {
        if (this.data) return this.data;
        // Validate instead of trusting: a stored entry from an older shape would
        // otherwise turn violation_count into NaN, and NaN never trips the limit.
        var stored = await this.state.storage.get("d");
        this.data = {
            "hits": Array.isArray(stored && stored.hits)
                ? stored.hits.filter(function (ts) { return typeof ts === "number"; })
                : [],
            "blocked_until_ms": Number((stored && stored.blocked_until_ms) || 0) || 0,
            "violation_count": Number((stored && stored.violation_count) || 0) || 0,
        };
        return this.data;
    }

    async flush(now, force) {
        if (!force && now - this.last_flush_ms < FLUSH_INTERVAL_MS) return;
        this.last_flush_ms = now;
        await this.state.storage.put("d", this.data);
    }
}
