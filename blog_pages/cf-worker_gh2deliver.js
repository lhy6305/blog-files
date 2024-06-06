addEventListener("fetch", event => {
    event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {

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

    url.protocol = "https";
    //url.hostname = "raw.githubusercontent.com";
    //url.pathname = "/lhy6305/blog-files/main/"+url.pathname;
    url.hostname = "cdn.jsdelivr.net";
    url.pathname = "/gh/lhy6305/blog-files@main/"+url.pathname;
    url.pathname = url.pathname.replaceAll("//", "/");

    let fetchOptions = {
        method: request.method,
        headers: request.headers,
        body: request.method === "GET" ? undefined : request.body,
    };

    let originalResponse = await fetch(url, fetchOptions);

    let responseOptions = {
        status: originalResponse.status,
        headers: originalResponse.headers,
    };

    return new Response(originalResponse.body, responseOptions);
}
