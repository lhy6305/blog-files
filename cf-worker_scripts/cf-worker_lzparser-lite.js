//exported from lzparser.php
//removed password function

addEventListener("fetch", event => {
    event.respondWith(handleRequest(event.request));
})

async function handleRequest(request) {
    var fid = "";
    var usp = new URLSearchParams(request.url.split("?")[1]);

    if(usp.has("fid")) {
        fid = usp.get("fid");
    }

    if(fid === "") {
        var hd = new Headers();
        hd.append("Access-Control-Allow-Origin", "*");
        hd.append("Access-Control-Allow-Methods", "*");
        hd.append("Access-Control-Allow-Headers", "*");
        hd.append("Access-Control-Max-Age", "600")
        hd.append("Content-Type", "text/plain");
        return new Response("param \"fid\" not found", {
            status: 400,
            statusText: null,
            headers: hd
        });
    }

    var url = "https://lanzoux.com/"+fid;
    var res = await fetch(url, {
        headers: {
            "Accept": "*/*",
            "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "DNT": "1",
            "Sec-GPC": "1",
            "Pragma": "no-cache",
            "Cache-Control": "no-cache",
        }
    })
    var re = await res.text();
    var ma = re.match(new RegExp("fn\\?[0-9a-zA-Z_]{20,}"));
    if(ma===null||ma.length<=0) {
        var hd = new Headers();
        hd.append("Access-Control-Allow-Origin", "*");
        hd.append("Access-Control-Allow-Methods", "*");
        hd.append("Access-Control-Allow-Headers", "*");
        hd.append("Access-Control-Max-Age", "600")
        hd.append("Content-Type", "text/plain");
        return new Response("erro1", {
            status: 500,
            statusText: null,
            headers: hd
        });
    }

    url = "https://lanzoux.com/"+ma[0];

    res = await fetch(url);
    re = await res.text();

    var sign = re.match(new RegExp("sign[\'\"]? ?[:=] ?[\'\"]([a-zA-Z0-9_]{20,})[\'\"]"));

    if(sign===null||sign.length<=0) {
        sign = re.match(new RegExp("([a-zA-Z0-9_]{20,})", "i"))
    }

    if(sign===null||sign.length<=0) {
        var hd = new Headers();
        hd.append("Access-Control-Allow-Origin", "*");
        hd.append("Access-Control-Allow-Methods", "*");
        hd.append("Access-Control-Allow-Headers", "*");
        hd.append("Access-Control-Max-Age", "600")
        hd.append("Content-Type", "text/plain");
        return new Response("erro2", {
            status: 500,
            statusText: null,
            headers: hd
        });
    }

    res = await fetch("https://lanzoux.com/ajaxm.php", {
        method: "POST",
        body: "action=downprocess&sign="+sign[1],
        headers: {
            "Accept": "*/*",
            "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36",
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "https://lanzoux.com",
            "X-Requested-With": "XMLHttpRequest",
            "Referer": url,
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "DNT": "1",
            "Sec-GPC": "1",
            "Pragma": "no-cache",
            "Cache-Control": "no-cache",
        }
    });

    re = await res.text();
    try {
        var jo=JSON.parse(re);
    } catch {
        jo=null;
    }

    if(!jo || jo["zt"] != 1 || !jo["dom"] || !jo["url"]) {
        var hd = new Headers();
        hd.append("Access-Control-Allow-Origin", "*");
        hd.append("Access-Control-Allow-Methods", "*");
        hd.append("Access-Control-Allow-Headers", "*");
        hd.append("Access-Control-Max-Age", "600")
        hd.append("Content-Type", "text/plain");
        return new Response("erro3", {
            status: 500,
            statusText: null,
            headers: hd
        });
    }

    url = jo["dom"]+"/file/"+jo["url"];

    var hd = new Headers();
    hd.append("Access-Control-Allow-Origin", "*");
    hd.append("Access-Control-Allow-Methods", "*");
    hd.append("Access-Control-Allow-Headers", "*");
    hd.append("Access-Control-Max-Age", "600");
    hd.append("Location", url);
    return new Response(url, {
        status: 302,
        statusText: null,
        headers: hd
    });
}