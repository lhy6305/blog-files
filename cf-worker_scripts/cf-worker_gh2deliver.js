var settings= {
    "ALLOWED_HEADERS": [
        "content-type",
        "date",
        "host",
        "if-match",
        "if-modified-since",
        "if-none-match",
        "if-unmodified-since",
        "range",
    ],
    "RANGE_RETRY_ATTEMPTS": 3,
    "REQUEST_TIMEOUT": 3*1000
};

// Filter out cf-* and any other headers we don't want to include in the request
var filter_headers=function(headers) {
    return new Headers(Array.from(headers.entries()).filter(function(pair) {
        if(pair[0].startsWith("cf-")) {
            return false;
        }
        if(("ALLOWED_HEADERS" in settings) && settings.ALLOWED_HEADERS.includes(pair[0])) {
            return false;
        }
        return true;
    }));
}

var main_handler=async function(request, env) {
    if(request.method == "OPTIONS") {
        var hd = new Headers();
        hd.append("Access-Control-Allow-Origin", "*");
        hd.append("Access-Control-Allow-Methods", "*");
        hd.append("Access-Control-Allow-Headers", "*");
        hd.append("Access-Control-Max-Age", "600")
        hd.append("Content-Type", "text/plain");
        return new Response(null, {
            status: 200,
            statusText: null,
            headers: hd
        });
    }

    if(["GET", "HEAD"].indexOf(request.method) == -1) {
        var hd = new Headers();
        hd.append("Access-Control-Allow-Origin", "*");
        hd.append("Access-Control-Allow-Methods", "HEAD, GET, OPTIONS");
        hd.append("Access-Control-Max-Age", "600")
        hd.append("Content-Type", "text/plain");
        return new Response("only HEAD,GET,OPTIONS methods are allowed", {
            status: 405,
            statusText: null,
            headers: hd
        });
    }

    let url = new URL(request.url);

    if(url.pathname.endsWith("/")) {
        var hd = new Headers();
        hd.append("Access-Control-Allow-Origin", "*");
        hd.append("Access-Control-Max-Age", "600")
        hd.append("Content-Type", "text/plain");
        return new Response("a directory can't be requested", {
            status: 400,
            statusText: null,
            headers: hd
        });
    }

    if(url.pathname == "/gen_200") {
        var hd = new Headers();
        hd.append("Access-Control-Allow-Origin", "*");
        hd.append("Cache-Control", "no-store; must-revalidate");
        hd.append("Content-Type", "text/plain");
        return new Response(null, {
            status: 200,
            statusText: null,
            headers: hd
        });
    }

    if(url.pathname == "/gen_204") {
        var hd = new Headers();
        hd.append("Access-Control-Allow-Origin", "*");
        hd.append("Cache-Control", "no-store; must-revalidate");
        hd.append("Content-Type", "text/plain");
        return new Response(null, {
            status: 204,
            statusText: null,
            headers: hd
        });
    }

    var target_repository_name=(url.searchParams.has("repo")?url.searchParams.get("repo"):"lhy6305/blog-files");
    var target_branch_name=(url.searchParams.has("tree")?url.searchParams.get("tree"):"main");

    // Validity check for repo and tree provided by user

    if(!new RegExp("^[0-9a-zA-Z\\-_\\.]{1,100}/[0-9a-zA-Z\\-_\\.]{1,100}$", "i").test(target_repository_name) || new RegExp("\\.\\.", "ig").test(target_repository_name) || !new RegExp("^[^\\x00-\\x1F\\x7F\\\\/]+$", "i").test(target_branch_name) || new RegExp("\\.\\.", "ig").test(target_branch_name)) {
        var hd = new Headers();
        hd.append("Access-Control-Allow-Origin", "*");
        hd.append("Cache-Control", "no-store; must-revalidate");
        hd.append("Content-Type", "text/plain");
        return new Response("Invalid Repository or Branch Name", {
            status: 400,
            statusText: null,
            headers: hd
        });
    }

    target_repository_name=encodeURIComponent(target_repository_name);
    target_branch_name=encodeURIComponent(target_branch_name);

    url.protocol = "https";
    url.hostname = "raw.githubusercontent.com";
    url.pathname = "/"+target_repository_name+"/refs/heads/"+target_branch_name+"/"+url.pathname;
    //url.hostname = "cdn.jsdelivr.net";
    //url.hostname = "fastly.jsdelivr.net";
    //url.pathname = "/gh/"+target_repository_name+"@"+target_branch_name+"/"+url.pathname;
    url.pathname = url.pathname.replaceAll("//", "/");

    var req_headers=filter_headers(request.headers);

    var force_download=(url.searchParams.has("dl")?url.searchParams.get("dl"):null);
    var custom_mime=(url.searchParams.has("mime")?url.searchParams.get("mime"):null);
    var custom_file_name=(url.searchParams.has("fn")?url.searchParams.get("fn"):null);

    // Remove all url.searchParams
    Object.keys(url.searchParams).map(function(key) {
        url.searchParams.delete(key);
    });

    console.log("modified request url: "+url.toString());

    // For large files, Cloudflare will return the entire file, rather than the requested range
    // So, if there is a range header in the request, check that the response contains the
    // content-range header. If not, abort the request and try again.
    // See https://community.cloudflare.com/t/cloudflare-worker-fetch-ignores-byte-request-range-on-initial-request/395047/4
    var ret;
    if(req_headers.has("range")) {
        var attempts=settings.RANGE_RETRY_ATTEMPTS;
        var response;
        do {
            var controller=new AbortController();
            var request_timeout=null;
            if(settings.REQUEST_TIMEOUT>0) {
                request_timeout=setTimeout(function() {
                    controller.abort();
                    console.error("request cancelled due to timeout after"+settings.REQUEST_TIMEOUT.toString()+"ms");
                }, settings.REQUEST_TIMEOUT);
            }
            response=await fetch(url, {
                method: request.method,
                headers: req_headers,
                signal: controller.signal,
                cf: {
                    cacheEverything: true,
                    cacheTtlByStatus: {
                        "200-299": 129600,
                        404: 300,
                    },
                }
            });
            if(request_timeout!==null) {
                clearTimeout(request_timeout);
                request_timeout=null;
            }
            if(response.headers.has("content-range")) {
                // Only log if it didn't work first time
                if(attempts < settings.RANGE_RETRY_ATTEMPTS) {
                    console.log("Retry for "+url+" succeeded - response has content-range header");
                }
                // Break out of loop and return the response
                break;
            } else if(response.ok) {
                attempts -= 1;
                console.error("Range header in request for "+url+" but no content-range header in response. Will retry "+attempts+" more times");
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
            console.error("Tried range request for "+request.url+" "+settings.RANGE_RETRY_ATTEMPTS+" times, but no content-range in response.");
            if(response.ok) {
                return new Response("An unexpected backend error occured. Please contact the admin.", {
                    status: 500,
                    statusText: null,
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
        // Send the request and return the upstream response
        ret=await fetch(url, {
            cf: {
                cacheEverything: true,
                cacheTtlByStatus: {
                    "200-299": 129600,
                    404: 300,
                },
            }
        });
    }

    console.log("request successful");

    if(((typeof force_download)=="string")&&force_download.length>0&&force_download.toLowerCase()!="false") {
        force_download=true;
    } else {
        force_download=false;
    }

    if(custom_mime===null&&ret.headers.has("content-type")) {
        custom_mime=ret.headers.get("content-type");
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
