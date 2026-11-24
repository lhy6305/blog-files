// cf-worker_b2-transparent.js
// ---------------------------------------------------------------------------
// Transparent Backblaze B2 (S3 API) proxy for Cloudflare Workers.
//
// Contract:
//   - rewrite the authority only; the endpoint decides path-style vs vhost-style
//   - re-sign (SigV4 signs the Host line, so changing the host always kills it)
//   - forward method / path / query / body / every other header verbatim
//   - return the upstream response untouched
//
// The inbound request MUST carry a valid AWS4-HMAC-SHA256 signature made with
// B2_APPLICATION_KEY_ID / B2_APPLICATION_KEY. This is not a public gateway;
// unsigned requests get the exact 403 body B2 itself would return.
//
// Derived from https://github.com/backblaze-b2-samples/cloudflare-b2-proxy
// ---------------------------------------------------------------------------

import { AwsClient } from './aws4fetch.js';

// ---------------------------------------------------------------------------
// Two different things, usually derived from one string:
//
//   UPSTREAM_HOST  (= B2_ENDPOINT)  what we connect to; becomes the Host header.
//                                   "s3.us-west-004.backblazeb2.com"            -> path-style
//                                   "my-bucket.s3.us-west-004.backblazeb2.com"  -> vhost-style
//                                   This is the ONLY value that appears on the wire.
//
//   SIGNING_REGION (= B2_REGION)    feeds nothing but the SigV4 credential scope
//                                   "<date>/<region>/s3/aws4_request" and the
//                                   signing-key derivation. Never sent anywhere.
//
// SIGNING_REGION is parsed out of UPSTREAM_HOST; B2_REGION exists only to override
// that parse (custom domains, explicit ports, non-B2 upstreams). Setting both is
// optional; setting them inconsistently is not an override, it is a broken signature.
// ---------------------------------------------------------------------------
const RE_B2_S3_HOST = /^(?:[^.]{1,63}\.)?s3\.([a-z0-9-]+)\.backblazeb2\.com$/i;

// Never forwarded upstream: hop-by-hop headers, plus the four that SigV4 forces us
// to regenerate (host / authorization / x-amz-date / x-amz-content-sha256).
const DROP = [
    "host",                  // fetch() always derives it from the target URL
    "authorization",         // re-signed below
    "x-amz-date",            // re-signed below
    "x-amz-security-token",  // long-lived key here; a stale token would be rejected
    "x-amz-content-sha256",  // recomputed below
    "connection",
    "transfer-encoding",
    "expect",                // 100-continue is not supported in Workers
    "x-amzn-trace-id",
];

// Byte-exact copy of the 403 B2 returns for an unauthenticated S3 request
// (captured 2026-11-24 from https://s3.us-west-004.backblazeb2.com/, 180 bytes).
const DENY_BODY =
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n' +
    "<Error>\n" +
    "    <Code>AccessDenied</Code>\n" +
    "    <Message>Unauthenticated requests are not allowed for this api</Message>\n" +
    "</Error>\n";

var rand_hex = function(bytes) {
    var a = new Uint8Array(bytes);
    crypto.getRandomValues(a);
    var s = "";
    for (var i = 0; i < a.length; i++) {
        s += a[i].toString(16).padStart(2, "0");
    }
    return s;
};

var deny_403 = function() {
    return new Response(DENY_BODY, {
        status: 403,
        headers: {
            "Content-Type": "application/xml",
            // No explicit Content-Length: the runtime derives it from the body (180),
            // and a hand-set value is one more thing that can throw.
            "Cache-Control": "max-age=0, no-cache, no-store",
            "Strict-Transport-Security": "max-age=63072000",
            "x-amz-request-id": rand_hex(8),
        },
    });
};

var build_error_response = function(message, status) {
    return new Response(message, {
        status: status,
        headers: {
            "Content-Type": "text/plain; charset=utf-8",
            "Cache-Control": "max-age=0, no-cache, no-store",
        },
    });
};

// Misconfiguration details go to the log only -- the visitor gets a bare 500, so
// the response never names an env var, an endpoint or a region. Logged once per
// isolate: a bad config is a deploy-level constant, not a per-request event.
var CONFIG_LOGGED = false;
var DEBUG = false;              // B2_DEBUG=1: name the failing check in the 500 body

var config_error = function(problem, detail) {
    if (!CONFIG_LOGGED) {
        CONFIG_LOGGED = true;
        console.error(JSON.stringify(Object.assign({ "event": "misconfig", "problem": problem }, detail)));
    }
    return DEBUG ? "Internal Server Error: " + problem : "Internal Server Error";
};

// Credential=KEYID/20261124/us-west-004/s3/aws4_request
var parse_scope = function(authorization) {
    var m = /Credential=([^,]+)/.exec(authorization || "");
    if (!m) { return null; }
    var p = m[1].split("/");
    if (p.length !== 5) { return null; }
    return { "key_id": p[0], "date": p[1], "region": p[2], "service": p[3] };
};

var reason_hint = function(reason) {
    if (/header .* not found/.test(reason)) {
        return "a signed header did not arrive; Cloudflare rewrites accept-encoding and adds cf-*/x-forwarded-*, so those must stay out of SignedHeaders";
    }
    if (/signature mismatched/.test(reason)) {
        return "the client and this worker disagree on signed headers, canonical path, query order or credential scope";
    }
    if (/key id/.test(reason)) {
        return "the client signs with a different key id than B2_APPLICATION_KEY_ID";
    }
    return "";
};

var VERIFY_LOG_BUDGET = 10;

var upstream_error = function(message) {
    console.error(JSON.stringify({ "event": "upstream_error", "error": String(message) }));
};

// ---------------------------------------------------------------------------
// Inbound signature verification -- unchanged from the original worker.
// ---------------------------------------------------------------------------
var verify_signature = async function(request, settings_instance, client) {
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

    credential = credential.split('/');
    signedHeaders = signedHeaders.split(';');

    if (credential[0] !== settings_instance.B2_APPLICATION_KEY_ID) {
        throw new Error("application key id not valid");
    }

    var datetime = request.headers.get("x-amz-date");
    if (!datetime) {
        throw new Error("header x-amz-date not found");
    }

    var headersToSign = signedHeaders.reduce((obj, key) => {
        var value = request.headers.get(key);
        if (value == null) {
            throw new Error("header " + key + " not found");
        }
        obj[key] = value;
        return obj;
    }, {});

    // No body: for s3 the payload hash comes from x-amz-content-sha256, so aws4fetch
    // never reads it. Passing the stream here would only risk locking it.
    var signedRequest = await client.sign(request.url, {
        method: request.method,
        headers: headersToSign,
        aws: {
            datetime: datetime,
            allHeaders: true,
        },
    });

    var generatedAuthorization = signedRequest.headers.get("Authorization");
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
// Transparent passthrough
// ---------------------------------------------------------------------------
var main_handler = async function(request, env) {

    // ---- config -----------------------------------------------------------
    var cfg = Object.assign({}, env);
    DEBUG = String(cfg.B2_DEBUG || "") === "1";

    // An unbound secret makes AwsClient throw before anything else can log, so it
    // is checked explicitly: names only, never values, and only to the log.
    var key_id = String(cfg.B2_APPLICATION_KEY_ID || "").trim();
    var key_secret = String(cfg.B2_APPLICATION_KEY || "").trim();
    if (!key_id || !key_secret) {
        return build_error_response(config_error("credentials not bound to this environment", {
            "has_key_id": !!key_id,
            "has_secret": !!key_secret,
            "bindings": Object.keys(env).join(","),
        }), 500);
    }

    // UPSTREAM_HOST: what we connect to, and the value that ends up in the Host
    // header. A bucket prefix selects virtual-hosted-style, its absence path-style.
    var upstream_host = String(cfg.B2_ENDPOINT || "").trim()
        .replace(/^https?:\/\//i, "")
        .replace(/\/+$/, "")
        .toLowerCase();

    // Lowercased on both sides: SigV4 regions are lowercase, and a dashboard typo of
    // "US-WEST-004" must not be reported as a conflict.
    var region_override = String(cfg.B2_REGION || "").trim().toLowerCase();
    var parsed_region   = (RE_B2_S3_HOST.exec(upstream_host) || [])[1] || "";

    if (!upstream_host) {
        return build_error_response(config_error("B2_ENDPOINT is empty", {}), 500);
    }

    // Both given but different is not an override, it is a broken signature: the
    // region is baked into both the credential scope and the signing key.
    if (region_override && parsed_region && region_override !== parsed_region) {
        return build_error_response(config_error("B2_REGION conflicts with B2_ENDPOINT", {
            "region_override": region_override,
            "parsed_region": parsed_region,
            "upstream_host": upstream_host,
        }), 500);
    }

    // SIGNING_REGION: never sent anywhere, it only seeds the signature.
    var signing_region = region_override || parsed_region;
    if (!signing_region) {
        return build_error_response(config_error("cannot derive region from B2_ENDPOINT", {
            "upstream_host": upstream_host,
            "hint": "set B2_REGION; it is not sent to B2, it only scopes the signature",
        }), 500);
    }

    var client = new AwsClient({
        "accessKeyId": key_id,
        "secretAccessKey": key_secret,
        "sessionToken": null,
        "service": "s3",
        "region": signing_region,
        "cache": null,
        "retries": null,
        "initRetryMs": null,
    });

    // ---- 1. the inbound signature is the only gate -------------------------
    // Verification has to reproduce what the CLIENT computed, so it uses the scope
    // from the client's own credential string -- not our signing region. A client
    // that signed for another region is still authentic; B2 judges the region.
    var authorization = request.headers.get("Authorization") || "";
    var scope = parse_scope(authorization);
    var verify_client = client;

    if (scope && scope.region && scope.service && scope.region !== signing_region) {
        verify_client = new AwsClient({
            "accessKeyId": key_id,
            "secretAccessKey": key_secret,
            "sessionToken": null,
            "service": scope.service,
            "region": scope.region,
            "cache": null,
            "retries": null,
            "initRetryMs": null,
        });
    }

    var verified = false;
    var verify_error = null;
    try {
        verified = (await verify_signature(request, cfg, verify_client)) === true;
    } catch (e) {
        verified = false;
        verify_error = e;
    }
    if (!verified) {
        var reason = verify_error ? String(verify_error.message || verify_error) : "no AWS4-HMAC-SHA256 Authorization header";
        if (VERIFY_LOG_BUDGET > 0) {
            VERIFY_LOG_BUDGET -= 1;
            console.error(JSON.stringify({
                "event": "verify_failed",
                "reason": reason,
                "hint": reason_hint(reason),
                "scope": scope,
                "authorization": authorization || null,
            }));
        }
        if (DEBUG) {
            return build_error_response("Forbidden: " + reason, 403);
        }
        return deny_403();
    }

    // ---- 2. bodies that cannot be re-signed --------------------------------
    if (/aws-chunked/i.test(request.headers.get("content-encoding") || "")
        || /^STREAMING-/i.test(request.headers.get("x-amz-content-sha256") || "")) {
        return build_error_response("aws-chunked request body is not supported", 501);
    }

    // Clone after verify, before the body is touched anywhere else.
    var has_body = request.method !== "GET" && request.method !== "HEAD";
    var body = has_body ? request.clone().body : null;

    // ---- 3. upstream URL: every byte after the authority is preserved ------
    var tail = request.url.replace(/^[a-z]+:\/\/[^/?#]+/i, "");
    if (tail === "") {
        tail = "/";
    }

    var qmark = tail.indexOf("?");
    var path_part = qmark < 0 ? tail : tail.slice(0, qmark);
    var query_part = qmark < 0 ? "" : tail.slice(qmark);

    // aws4fetch canonicalises the S3 path via decode->encode and maps a literal "+"
    // to a space; %2B keeps the signature and the bytes on the wire in sync.
    path_part = path_part.replace(/\+/g, "%2B");

    // aws4fetch would collapse %2F into a real "/" and silently address another key.
    if (/%2f/i.test(path_part)) {
        return build_error_response("Bad Request", 400);
    }

    var up_url = "https://" + upstream_host
        + (path_part.charAt(0) === "/" ? "" : "/") + path_part + query_part;

    // ---- 4. outbound headers: all of them, minus the DROP list -------------
    var out = new Headers(request.headers);
    DROP.forEach(function(h) { out.delete(h); });

    // ---- 5. sign host + x-amz-* only --------------------------------------
    // Signing more would break: Cloudflare rewrites accept-encoding *after* we sign,
    // and cf-* / x-forwarded-* only exist on the way out.
    var to_sign = {};
    out.forEach(function(v, k) { if (k.startsWith("x-amz-")) to_sign[k] = v; });

    // A real payload hash supplied by the client stays valid (we forward the same
    // body); anything else is left to aws4fetch, which sets UNSIGNED-PAYLOAD.
    // Read it from the inbound headers: it was dropped from `out` above.
    var client_sha = request.headers.get("x-amz-content-sha256") || "";
    if ((/^[0-9a-f]{64}$/i).test(client_sha)) {
        to_sign["x-amz-content-sha256"] = client_sha;
    }

    // ---- 6. re-sign for the new host --------------------------------------
    var signed = await client.sign(up_url, {
        method: request.method,
        headers: to_sign,
        body: body,
    });

    // ---- 7. splice the fresh signature into the full header set -----------
    // aws4fetch ties "what gets signed" to "what gets sent"; we need them apart.
    var fwd = new Headers(out);
    fwd.set("authorization", signed.headers.get("authorization"));
    fwd.set("x-amz-date", signed.headers.get("x-amz-date"));
    fwd.set("x-amz-content-sha256", signed.headers.get("x-amz-content-sha256") || "UNSIGNED-PAYLOAD");

    // ---- 8. passthrough, response untouched -------------------------------
    try {
        var resp = await fetch(new Request(signed.url, {
            method: request.method,
            headers: fwd,
            body: body,
            redirect: "manual",   // never follow: our Authorization is bound to the host we signed
        }));

        // B2 answers a cross-region request with a 301 that names the real endpoint.
        // Following it is impossible (host-bound signature) and handing it to the client
        // would leak the endpoint and let it bypass the worker -- so it becomes a 502.
        // 304 is a legitimate conditional-GET answer and is NOT in this list.
        if (resp.status === 301 || resp.status === 302 || resp.status === 303
            || resp.status === 307 || resp.status === 308) {
            // The location still points at the real endpoint, so it goes to the log and
            // nowhere else -- the visitor only ever learns that the gateway is broken.
            console.error(JSON.stringify({
                "event": "upstream_redirect",
                "status": resp.status,
                "region": resp.headers.get("x-amz-bucket-region") || null,
                "location": resp.headers.get("location") || null,
            }));
            return build_error_response("Bad Gateway", 502);
        }

        return resp;
    } catch (e) {
        upstream_error((e && e.message) || e);
        return build_error_response("Bad Gateway", 502);
    }
};

export default {
    async fetch(request, env) {
        // Nothing may escape as an uncaught exception: that turns into a Cloudflare
        // 500 with no trace of which check failed.
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
