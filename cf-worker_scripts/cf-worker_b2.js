
// Modified from https://github.com/backblaze-b2-samples/cloudflare-b2/blob/main/index.js and https://github.com/backblaze-b2-samples/cloudflare-b2-proxy/blob/master/index.js by ly65

// Proxy Backblaze S3 compatible API requests, sending notifications to a webhook
//
// Adapted from https://github.com/obezuk/worker-signed-s3-template
//

import { AwsClient } from './aws4fetch.js'

var settings= {
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

    // Note: set the following params in the cloudflare dashboard to prevent possible leaking
    // B2_APPLICATION_KEY, B2_APPLICATION_KEY_ID, B2_ENDPOINT, BUCKET_NAME
    // Also dont't forget to set the CUSTOM_PATH_SIGN_SALT variable
    // CUSTOM_PATH_SIGN_KEY0, CUSTOM_PATH_SIGN_KEY1
};

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
                       && !("ALLOWED_HEADERS" in settings && !settings.ALLOWED_HEADERS.includes(pair[0]))
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
    if(!("CUSTOM_PATH_SIGN_SALT" in settings)||typeof settings.CUSTOM_PATH_SIGN_SALT!=="string"||settings.CUSTOM_PATH_SIGN_SALT.length<=0) {
        throw new Error("CUSTOM_PATH_SIGN_SALT not set");
    }
    var hash1=await hash_func("SHA-512", str+settings.CUSTOM_PATH_SIGN_SALT+str);
    var hash2=await hash_func("SHA-384", hash1+settings.CUSTOM_PATH_SIGN_SALT+str+settings.CUSTOM_PATH_SIGN_SALT);
    var hash3=await hash_func("SHA-384", hash2+settings.CUSTOM_PATH_SIGN_SALT+hash1+settings.CUSTOM_PATH_SIGN_SALT);
    var hash4=await hash_func("SHA-256", hash2+str+hash3+settings.CUSTOM_PATH_SIGN_SALT+hash1);
    var hash5=await hash_func("SHA-256", hash3+str+hash1+settings.CUSTOM_PATH_SIGN_SALT+hash4+str+hash2);
    return hash5.substr(0, 24);
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
    var [, credential, signedHeaders, signature] = authorization.match(re);

    credential = credential.split('/');
    signedHeaders = signedHeaders.split(';');

    // Verify that the request was signed with the expected key
    if(credential[0] != settings.B2_APPLICATION_KEY_ID) {
        throw new Error("application key id not valid");
    }

    // Use the timestamp from the incoming signature
    var datetime = request.headers.get("x-amz-date");

    if(!datetime) {
        throw new Error("datetime not found");
    }

    // Extract the headers that we want from the complete set of incoming headers
    var headersToSign = signedHeaders.map(key => ( {
        "name": key,
        "value": request.headers.get(key),
    })).reduce((obj, item) => (obj[item.name] = item.value, obj), {});

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
    var [,,, generatedSignature] = signedRequest.headers.get("Authorization").match(re);

    if(signature !== generatedSignature) {
        throw new Error("signature mismatched");
    }
    return true;
};

var main_handler=async function(request, env) {

    // Variables set in env have higher priority than those in settings
    settings=Object.assign(settings, env);

    // Extract the region from the endpoint
    // This should NOT throw an error, unless you set the B2_ENDPOINT wrongly
    aws_region=settings.B2_ENDPOINT.match(new RegExp("^s3\.([a-zA-Z0-9-]+)\.backblazeb2\.com$"))[1];

    // Create an S3 API client that can sign the outgoing request
    client=new AwsClient({
        "accessKeyId": settings.B2_APPLICATION_KEY_ID,
        "secretAccessKey": settings.B2_APPLICATION_KEY,
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
            url.hostname = settings.B2_ENDPOINT;
            // Send the signed request to B2 and wait for the upstream response
            return fetch(await client.sign(url, {
                method: request.method,
                headers: filter_headers(request.headers),
                body: request.body
            }));
        }
    } catch(e) {
        return new Response("api request cannot be verified: "+e.message, {
            status: 500,
            statusText: null,
            headers: {
                "content-type": "text/plain; charset=utf-8",
                "cache-control": "max-age=0, no-cache, no-store",
            },
        });
    }

    // ...if it's not an api request

    // Only allow GET and HEAD methods
    if(!["GET", "HEAD"].includes(request.method)) {
        return new Response("Method Not Allowed", {
            status: 405,
            statusText: null,
            headers: {
                "cache-control": "public, max-age=300",
            },
        });
    }

    var url=new URL(request.url);

    // Incoming protocol and port is taken from the worker's environment.
    // Local dev mode uses plain http on 8787, and it's possible to deploy
    // a worker on plain http. B2 only supports https on 443
    url.protocol="https:";
    url.port="443";

    // Remove query params
    url.search="";

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

    path=decodeURIComponent(path);

    // Split the path into segments
    var path_seg=path.split("/");

    if(path_seg.length>=2) {
        if(path_seg[0]===settings.CUSTOM_PATH_SIGN_KEY0&&path_seg[1]===settings.CUSTOM_PATH_SIGN_KEY1) {
            return new Response(await custom_sign_path(path_seg.slice(2).join("/")), {
                status: 200,
                statusText: null,
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
            statusText: null,
            headers: {
                "cache-control": "public, max-age=21600, immutable",
            },
        });
    }

    // USER WARNING: flag_req_is_dir CANNOT fully detect whether the path is ACTUALLY a directory or not

    if(!(settings.ALLOW_LIST_BUCKET===true||settings.ALLOW_LIST_BUCKET==="true"||settings.ALLOW_LIST_BUCKET==="1")&&flag_req_is_dir) {
        return new Response("Directory Listing Not Allowed", {
            status: 403,
            statusText: null,
            headers: {
                "cache-control": "public, max-age=300",
            },
        });
    }

    if(flag_req_is_dir) {
        url.pathname+="/";
    }

    // Bucket name is specified in the BUCKET_NAME variable
    url.hostname=settings.BUCKET_NAME + "." + settings.B2_ENDPOINT;

    // Certain headers, such as x-real-ip, appear in the incoming request but
    // are removed from the outgoing request. If they are in the outgoing
    // signed headers, B2 can't validate the signature.
    var headers=filter_headers(request.headers);

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
        var attempts=settings.RANGE_RETRY_ATTEMPTS;
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
                if(attempts < settings.RANGE_RETRY_ATTEMPTS) {
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
            console.error("Tried range request for "+signed_request.url+" "+settings.RANGE_RETRY_ATTEMPTS+" times, but no content-range in response.");
            if(response.ok) {
                return new Response("An unexpected backend error occured. Please contact the admin.", {
                    status: 500,
                    statusText: null,
                    headers: {
                        "cache-control": "public, max-age=300",
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

    var ret_hd=new Headers(ret.headers);
    ret_hd.set("Cache-Control", "public, max-age=21600, immutable");

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
