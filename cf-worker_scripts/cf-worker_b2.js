
// Modified from https://github.com/backblaze-b2-samples/cloudflare-b2/blob/main/index.js and https://github.com/backblaze-b2-samples/cloudflare-b2-proxy/blob/master/index.js by ly65

import { DurableObject } from "cloudflare:workers";

import { AwsClient } from './aws4fetch.js'

var settings = {
    "ALLOW_LIST_BUCKET": false,
    "ALLOWED_HEADERS": [
        "content-type",
        "date",
        "host",
        "if-match",
        "if-modified-since",
        "if-none-match",
        "if-unmodified-since",
        "range",
        "x-amz-content-sha256",
        "x-amz-date",
        "x-amz-server-side-encryption-customer-algorithm",
        "x-amz-server-side-encryption-customer-key",
        "x-amz-server-side-encryption-customer-key-md5",
    ],
    // How many times to retry a range request where the response is missing content-range
    "RANGE_RETRY_ATTEMPTS": 3,

    "ENABLE_IP_RATE_LIMIT": true,
    "RATE_LIMIT_WINDOW_SEC": 15,
    "RATE_LIMIT_MAX_REQ": 30,
    "RATE_LIMIT_FAIL_OPEN": false,
    "RATE_LIMIT_BLOCK_SEC": 600, // Set to 0 to disable the block/ban function

    // Note: set the following params in the cloudflare dashboard to prevent possible leaking
    // B2_APPLICATION_KEY, B2_APPLICATION_KEY_ID, B2_ENDPOINT, BUCKET_NAME
    // Also don't forget to set the CUSTOM_PATH_SIGN_SALT variable
    // CUSTOM_PATH_SIGN_KEY0, CUSTOM_PATH_SIGN_KEY1
};

var settings_instance= {};

var UNSIGNABLE_HEADERS=[
                           // These headers appear in the request, but are not passed upstream
                           "x-forwarded-proto",
                           "x-real-ip",
                           // We can't include accept-encoding in the signature because Cloudflare
                           // sets the incoming accept-encoding header to "gzip, br", then modifies
                           // the outgoing request to set accept-encoding to "gzip".
                           // Not cool, Cloudflare!
                           "accept-encoding",
                       ];

// Filter out cf-* and any other headers we don't want to include in the signature
var filter_headers=function(headers) {
    return new Headers(Array.from(headers.entries()).filter(pair =>
                       !UNSIGNABLE_HEADERS.includes(pair[0])
                       && !pair[0].startsWith("cf-")
                       && !("ALLOWED_HEADERS" in settings_instance && !settings_instance.ALLOWED_HEADERS.includes(pair[0]))
                                                           ));
}

var arraybuffer2hex=function(ab) {
    var str_a=[];
    var v=new DataView(ab);
    for(var i=0; i < v.byteLength; i += 4) {
        str_a.push(v.getUint32(i).toString(16).padStart(8, "0"));
    }
    return str_a.join("");
};

var hash_func=async function(algo, str) {
    return arraybuffer2hex(await crypto.subtle.digest(algo, new TextEncoder().encode(str)));
};

var custom_sign_path=async function(str) {
    if(!("CUSTOM_PATH_SIGN_SALT" in settings_instance)||typeof settings_instance.CUSTOM_PATH_SIGN_SALT!=="string"||settings_instance.CUSTOM_PATH_SIGN_SALT.length<=0) {
        throw new Error("CUSTOM_PATH_SIGN_SALT not set");
    }
    var hash1=await hash_func("SHA-512", str+settings_instance.CUSTOM_PATH_SIGN_SALT+str);
    var hash2=await hash_func("SHA-384", hash1+settings_instance.CUSTOM_PATH_SIGN_SALT+str+settings_instance.CUSTOM_PATH_SIGN_SALT);
    var hash3=await hash_func("SHA-384", hash2+settings_instance.CUSTOM_PATH_SIGN_SALT+hash1+settings_instance.CUSTOM_PATH_SIGN_SALT);
    var hash4=await hash_func("SHA-256", hash2+str+hash3+settings_instance.CUSTOM_PATH_SIGN_SALT+hash1);
    var hash5=await hash_func("SHA-256", hash3+str+hash1+settings_instance.CUSTOM_PATH_SIGN_SALT+hash4+str+hash2);
    return hash5.slice(0, 24);
};

var aws_region;
var client;

// Verify the signature on the incoming request
var verify_signature = async function(request) {
    var authorization = request.headers.get("Authorization");
    if(!authorization) {
        return false;
    }

    // Parse the AWS V4 signature value
    var re = new RegExp("^AWS4-HMAC-SHA256 Credential=([^,]+),\\s*SignedHeaders=([^,]+),\\s*Signature=(.+)$");

    var matched = authorization.match(re);
    if(!matched) {
        throw new Error("unsupported authorization type");
    }
    var [, credential, signedHeaders, signature] = matched;

    credential = credential.split('/');
    signedHeaders = signedHeaders.split(';');

    // Verify that the request was signed with the expected key
    if(credential[0] != settings_instance.B2_APPLICATION_KEY_ID) {
        throw new Error("application key id not valid");
    }

    // Use the timestamp from the incoming signature
    var datetime = request.headers.get("x-amz-date");
    if(!datetime) {
        throw new Error("header x-amz-date not found");
    }

    // Extract the headers that we want from the complete set of incoming headers
    var headersToSign = signedHeaders.reduce((obj, key) => {
        var value = request.headers.get(key);
        if(value == null) {
            throw new Error("header "+key+" not found");
        }
        obj[key] = value;
        return obj;
    }, {});

    var signedRequest = await client.sign(request.url, {
        method: request.method,
        headers: headersToSign,
        body: request.body,
        aws: {
            datetime: datetime,
            allHeaders: true,
        },
    });

    // All we need is the signature component of the Authorization header
    var generatedAuthorization = signedRequest.headers.get("Authorization");
    var generatedMatched = generatedAuthorization && generatedAuthorization.match(re);
    if(!generatedMatched) {
        throw new Error("unsupported authorization type");
    }
    var [,,, generatedSignature] = generatedMatched;

    if(signature !== generatedSignature) {
        throw new Error("signature mismatched");
    }
    return true;
};

var variable_is_true=function(v) {
    return v===true || (typeof v === "string" && v.toLowerCase()==="true") || v==="1";
};
var variable_is_false=function(v) {
    return v===false || (typeof v === "string" && v.toLowerCase()==="false") || v==="0";
};

var get_client_ip=function(request) {
    var ip=request.headers.get("cf-connecting-ip");
    if(ip && ip.length>0) return ip.trim();
    //var xff=request.headers.get("x-forwarded-for");
    //if(xff && xff.length>0) return xff.split(",")[0].trim();
    return "0.0.0.0";
};

var check_ip_rate_limit=async function(request, env) {
    if(!variable_is_true(settings_instance.ENABLE_IP_RATE_LIMIT)) {
        return {ok: true};
    }
    if(!env.IP_RATE_LIMITER) {
        console.error("IP_RATE_LIMITER binding not found, skipping rate limit");
        return {ok: true};
    }
    var ip=get_client_ip(request);
    var id=env.IP_RATE_LIMITER.idFromName(ip);
    var stub=env.IP_RATE_LIMITER.get(id);
    var resp=null;
    try {
        resp=await stub.fetch("https://rate-limit/check", {
            method: "POST",
            headers: {"content-type":"application/json"},
            body: JSON.stringify({
                now: Date.now(),
                windowSec: Math.min(Number(settings_instance.RATE_LIMIT_WINDOW_SEC||10), 1),
                maxReq: Math.min(Number(settings_instance.RATE_LIMIT_MAX_REQ||40), 1),
                blockSec: Math.min(Number(settings_instance.RATE_LIMIT_BLOCK_SEC||0), 0),
            }),
        });
        var data=await resp.json().catch(()=>( {
            ok:false, reason:"invalid_limiter_response"
        }));
        if(resp.status===429 || data.ok===false) {
            return {
                ok: false,
                retryAfter: data.retryAfter||1,
                reason: data.reason||"rate_limited",
            };
        }
        if(resp.status===200 || data.ok===true) {
            return {
                ok: true,
            };
        }
    } catch {
        return {
            ok: variable_is_true(settings_instance.RATE_LIMIT_FAIL_OPEN),
            reason: "limiter_throw_exception",
        };
    }
    return {
        ok: false,
        reason: "failed_to_parse_limiter_response",
    };
};

// next day 00:00:00 UTC timestamp (ms)
var next_midnight_utc_ts=function() {
    var now=new Date();
    var next=new Date(now);
    next.setUTCHours(24, 0, 0, 0);
    return next.getTime();
};

// cache key for "upstream-403 block marker"
var build_upstream_403_marker_key=function(request) {
    var u=new URL(request.url);
    u.searchParams.set("__m", request.method);
    if(request.headers.has("range")) {
        u.searchParams.set("__r", request.headers.get("range"));
    }
    return new Request(u.toString(), { method: "GET" });
};

var build_429_response_from_block_until=function(blockUntilMs) {
    var retryAfterSec=Math.max(1, Math.ceil((blockUntilMs-Date.now())/1000));
    return new Response("Too Many Requests", {
        status: 429,
        headers: {
            "Access-Control-Allow-Origin": "*",
            // Do not store the 429 response
            "Cache-Control": "no-store",
            "Retry-After": String(retryAfterSec),
            "Content-Type": "text/plain; charset=utf-8",
        },
    });
};

var build_upstream_403_marker_response=function(blockUntilMs) {
    var ttlSec=Math.max(1, Math.ceil((blockUntilMs-Date.now())/1000));
    return new Response("", {
        status: 204,
        headers: {
            "x-upstream-403-block-until": String(blockUntilMs),
            "Cache-Control": "public, max-age="+String(ttlSec),
        },
    });
};

var main_handler=async function(request, env) {

    // Variables set in env have higher priority than those in settings_instance
    settings_instance=Object.assign(settings, env);

    // Extract the region from the endpoint
    // This should NOT throw an error, unless you set the B2_ENDPOINT wrongly
    aws_region=settings_instance.B2_ENDPOINT.match(new RegExp("^s3\\.([a-zA-Z0-9-]+)\\.backblazeb2\\.com$"))[1];

    // Create an S3 API client that can sign the outgoing request
    client=new AwsClient({
        "accessKeyId": settings_instance.B2_APPLICATION_KEY_ID,
        "secretAccessKey": settings_instance.B2_APPLICATION_KEY,
        "sessionToken": null,
        "service": "s3",
        "region": aws_region,
        "cache": null,
        "retries": null,
        "initRetryMs": null,
    });

    // First check if the request is an api request
    try {
        // false: not an api request
        // throw error: is an api request, but cannot verify
        if(await verify_signature(request) === true) {
            // Certain headers appear in the incoming request but are
            // removed from the outgoing request. If they are in the
            // signed headers, B2 can't validate the signature.

            var url = new URL(request.url);
            url.hostname = settings_instance.B2_ENDPOINT;
            // Send the signed request to B2 and wait for the upstream response
            return fetch(await client.sign(url, {
                method: request.method,
                headers: filter_headers(request.headers),
                body: request.body
            }));
        }
    } catch(e) {
        return new Response("api request cannot be verified: "+e.message, {
            status: 400,
            headers: {
                "Access-Control-Allow-Origin": "*",
                "Content-Type": "text/plain; charset=utf-8",
                "Cache-Control": "max-age=0, no-cache, no-store",
            },
        });
    }

    // if it's not an api request

    // Only allow GET and HEAD methods
    if(!["GET", "HEAD"].includes(request.method)) {
        return new Response("Method Not Allowed", {
            status: 405,
            headers: {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, HEAD",
                "Cache-Control": "public, max-age=300",
            },
        });
    }

    var url=new URL(request.url);

    if(request.headers.has("range")&&!request.headers.get("range").match(new RegExp("^bytes=(\\d+)-(\\d+)?$"))) {
        return new Response("Range Not Satisfiable", {
            status: 416,
            headers: {
                "Access-Control-Allow-Origin": "*",
                "Cache-Control": "public, max-age=300",
            },
        });
    }

    // Incoming protocol and port is taken from the worker's environment.
    // Local dev mode uses plain http on 8787, and it's possible to deploy
    // a worker on plain http. B2 only supports https on 443
    url.protocol="https:";
    url.port="443";

    // Trim multiple slashes
    var path=url.pathname.replace(new RegExp("\/{2,}", "g"), "/");
    // Remove leading slashes from path
    path=path.replace(new RegExp("^\/"), "");
    // Remove trailing slashes
    var flag_req_is_dir=false;
    if(path.endsWith("/")) {
        flag_req_is_dir=true;
    }
    path=path.replace(new RegExp("\/$"), "");

    // To ensure the signed results are the same
    try {
        if(path.toLowerCase().includes("%2f")) {
            return new Response("Bad Request", {
                status: 400,
            });
        }
        path=decodeURIComponent(path);
    } catch {
        return new Response("Bad Request", {
            status: 400,
        });
    }

    // Split the path into segments
    var path_seg=path.split("/");

    if(path_seg.length>=2) {
        if(path_seg[0]===settings_instance.CUSTOM_PATH_SIGN_KEY0&&path_seg[1]===settings_instance.CUSTOM_PATH_SIGN_KEY1) {
            return new Response(await custom_sign_path(path_seg.slice(2).join("/")), {
                status: 200,
            });
        }
    }

    var error_flag=false;
    do {
        if(path_seg.length<=0) {
            error_flag=true;
            break;
        }
        var cli_auth=path_seg.shift();
        url.pathname=path_seg.join("/");
        if(path_seg.length<=0) {
            flag_req_is_dir=true;
        }
        if(cli_auth!==await custom_sign_path(path_seg.join("/"))) {
            error_flag=true;
            break;
        }
        break;
    } while(false);

    if(error_flag) {
        return new Response("Bucket Not Found", {
            status: 400,
            headers: {
                "Access-Control-Allow-Origin": "*",
                "Cache-Control": "public, max-age=21600",
            },
        });
    }

    // USER WARNING: flag_req_is_dir CANNOT fully detect whether the path is ACTUALLY a directory or not

    if(!variable_is_true(settings_instance.ALLOW_LIST_BUCKET)&&flag_req_is_dir) {
        return new Response("Directory Listing Not Allowed", {
            status: 403,
            headers: {
                "Access-Control-Allow-Origin": "*",
                "Cache-Control": "public, max-age=300",
            },
        });
    }

    if(flag_req_is_dir) {
        url.pathname+="/";
    }

    // Bucket name is specified in the BUCKET_NAME variable
    url.hostname=settings_instance.BUCKET_NAME + "." + settings_instance.B2_ENDPOINT;

    // Check cached upstream-403 marker first
    var edgeCache=caches.default;
    var upstream403MarkerKey=build_upstream_403_marker_key(request);
    var cachedMarker=await edgeCache.match(upstream403MarkerKey);
    if(cachedMarker) {
        var blockUntilMs=Number(cachedMarker.headers.get("x-upstream-403-block-until")||0);
        if(blockUntilMs>Date.now()) {
            return build_429_response_from_block_until(blockUntilMs);
        } else {
            // Clean the marker
            await edgeCache.delete(upstream403MarkerKey);
        }
    }

    // IP rate limit for public download path
    var limit_result=await check_ip_rate_limit(request, env);
    if(!limit_result.ok) {
        return new Response("Too Many Requests", {
            status: 429,
            headers: {
                "Access-Control-Allow-Origin": "*",
                "Cache-Control": "no-store",
                "Retry-After": String(limit_result.retryAfter || 1),
                "Content-Type": "text/plain; charset=utf-8",
            },
        });
    }

    var force_download=(url.searchParams.has("dl")?url.searchParams.get("dl"):null);
    var custom_mime=(url.searchParams.has("mime")?url.searchParams.get("mime"):null);
    var custom_file_name=(url.searchParams.has("fn")?url.searchParams.get("fn"):null);

    // Certain headers, such as x-real-ip, appear in the incoming request but
    // are removed from the outgoing request. If they are in the outgoing
    // signed headers, B2 can't validate the signature.
    var headers=filter_headers(request.headers);

    // Remove query params before sign
    url.search="";

    // Sign the outgoing request
    var signed_request=await client.sign(url.toString(), {
        method: request.method,
        headers: headers,
    });

    // For large files, Cloudflare will return the entire file, rather than the requested range
    // So, if there is a range header in the request, check that the response contains the
    // content-range header. If not, abort the request and try again.
    // See https://community.cloudflare.com/t/cloudflare-worker-fetch-ignores-byte-request-range-on-initial-request/395047/4
    var ret;
    if(signed_request.headers.has("range")) {
        var attempts=Math.min(Number(settings_instance.RANGE_RETRY_ATTEMPTS), 1);
        var response;
        do {
            var controller=new AbortController();
            response=await fetch(signed_request.url, {
                method: signed_request.method,
                headers: signed_request.headers,
                signal: controller.signal,
                cf: {
                    cacheEverything: true,
                    cacheTtlByStatus: {
                        "200-299": 129600,
                        404: 300,
                    },
                }
            });
            if(response.headers.has("content-range")) {
                // Only log if it didn't work first time
                if(attempts < settings_instance.RANGE_RETRY_ATTEMPTS) {
                    console.log("Retry for "+signed_request.url+" succeeded - response has content-range header");
                }
                // Break out of loop and return the response
                break;
            } else if(response.ok) {
                attempts -= 1;
                console.error("Range header in request for "+signed_request.url+" but no content-range header in response. Will retry "+attempts+" more times");
                //if(attempts > 0) {
                // Do not abort on the last attempt, as we want to return the response
                // Just abort it. I want to have an error response.
                controller.abort();
                //}
            } else {
                // Response is not ok, so don't retry
                break;
            }
        } while(attempts > 0);

        if(attempts <= 0) {
            console.error("Tried range request for "+signed_request.url+" "+settings_instance.RANGE_RETRY_ATTEMPTS+" times, but no content-range in response.");
            if(response.ok) {
                return new Response("An unexpected backend error occurred. Please contact the admin.", {
                    status: 500,
                    headers: {
                        "Access-Control-Allow-Origin": "*",
                        "Cache-Control": "public, max-age=300",
                    },
                });
            }
        }

        // Return whatever response we have rather than an error response
        // This response cannot be aborted, otherwise it will raise an exception
        ret=response;
    } else {
        // Send the signed request to B2, returning the upstream response
        ret=await fetch(signed_request, {
            cf: {
                cacheEverything: true,
                cacheTtlByStatus: {
                    "200-299": 129600,
                    404: 300,
                },
            }
        });
    }

    // Upstream 403 => set block marker until next UTC midnight, respond 429 dynamically
    if(ret.status===403) {
        var blockUntilMs=next_midnight_utc_ts();
        await edgeCache.put(
            upstream403MarkerKey,
            build_upstream_403_marker_response(blockUntilMs)
        );
        return build_429_response_from_block_until(blockUntilMs);
    }

    if(variable_is_true(force_download)) {
        force_download=true;
    } else {
        force_download=false;
    }

    if(custom_mime===null&&ret.headers.has("content-type")) {
        custom_mime=ret.headers.get("content-type");
    }

    if(custom_mime===null || custom_mime==="null") {
        custom_mime="application/x-octet-stream";
    }

    var ret_hd=new Headers(ret.headers);
    ret_hd.set("Access-Control-Allow-Origin", "*");
    ret_hd.set("Cache-Control", "public, max-age=21600, immutable");
    ret_hd.set("Content-Type", custom_mime);
    if(force_download) {
        ret_hd.set("Content-Disposition", "attachment"+(custom_file_name===null?"":"; filename="+JSON.stringify(custom_file_name)));
    }

    if(ret.status != 200 && ret.status != 206) {
        ret_hd.set("Cache-Control", "public, max-age=300");
    }
    return new Response(ret.body, {
        status: ret.status,
        statusText: ret.statusText,
        headers: ret_hd,
    });
};

export default {
    async fetch(request, env) {
        return main_handler(request, env);
    },
};

export class IPRateLimiterDO extends DurableObject {
    constructor(state, env) {
        super(state, env);
        this.state = state;
        this.env = env;
    }

    async fetch(request) {
        if(request.method !== "POST") {
            return new Response("Method Not Allowed", { status: 405 });
        }

        var cfg = await request.json().catch(()=>( {}));
        var now = Number(cfg.now)||Date.now();
        var windowMs = (Number(cfg.windowSec)||10)*1000;
        var maxReq = Number(cfg.maxReq)||40;
        var blockMs = (Number(cfg.blockSec)||0)*1000;

        var data = await this.state.storage.get("d");
        if(!data) {
            data = {hits:[], blockedUntil:0, violations:0};
        }

        if(data.blockedUntil && now < data.blockedUntil) {
            var retry = Math.ceil((data.blockedUntil - now)/1000);
            return Response.json({
                ok: false,
                reason: "rate_limited",
                retryAfter: retry
            }, { status: 429 });
        }

        data.hits=(data.hits||[]).filter(ts => (now - ts) < windowMs);

        if(data.hits.length >= maxReq) {
            data.violations=(data.violations||0)+1;

            if(blockMs>0 && data.violations>=2) {
                data.blockedUntil=now+blockMs;
            }

            await this.state.storage.put("d", data);
            return Response.json({
                ok:false,
                reason:"rate_limited",
                retryAfter: 1
            }, { status: 429 });
        }

        data.hits.push(now);
        if(data.violations>0) data.violations -= 1;
        await this.state.storage.put("d", data);

        return Response.json({
            ok:true,
            remaining: maxReq - data.hits.length
        }, { status: 200 });
    }
}
