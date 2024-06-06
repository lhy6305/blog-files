
(function() {

    var encapi= {};
    //注意：要使用clone()，否则会覆盖原值
    encapi.keyhash=null;
    encapi.salt=null;
    encapi.time_delta=0;
    encapi.random_seed=null;

    var hex=CryptoJS.enc.Hex;
    var b64=CryptoJS.enc.Base64;
    var utf8=CryptoJS.enc.Utf8;

    var md5=CryptoJS.MD5;
    var sha256=CryptoJS.SHA256;
    var sha512=CryptoJS.SHA512;

    var aes=CryptoJS.AES;

    /*
        flag
        0xab
        a==1 添加api同步时间偏移
        b==1 返回 String()->utf8 的WordArray
    */
    var gt=function(flag) {
        try {
            var t=new Date().getTime();
            t=Number(t);
            if((flag&0x10)==0x10) {
                t+=encapi.time_delta;
            }
            if((flag&0x01)==0x01) {
                t=String(t);
                t=utf8.parse(t);
            }
            return t;
        } catch(e) {
            return false;
        }
    };

    encapi.gt=gt;

    encapi.log=function() {
        var a=["[encapi]"];
        for(var b=0; b<arguments.length; b++) {
            a.push(arguments[b]);
        }
        console.log.apply(null, a);
    };

    encapi.randomWordArray=CryptoJS.randomWordArray=function(len) {
        if(encapi.random_seed===null) {
            encapi.random_seed=sha512(gt(0x01).concat(gt(0x11)));
        }
        var out=CryptoJS.lib.WordArray.create();
        var l=len;
        while(l>0) {
            out.concat(md5(gt(0x11).concat(encapi.random_seed)));
            encapi.random_seed=sha512(out.clone().concat(gt(0x01)));
            l-=16;
        }
        out.sigBytes=len;
        out.clamp();
        return out;
    };

    encapi.setToken=function(tkn) {
        if(typeof tkn!="string") {
            return false;
        }
        if(tkn.length<=0) {
            return false;
        }
        encapi.salt=utf8.parse(md5(sha256(gt(0x01).concat(encapi.randomWordArray(16)).concat(gt(0x11)))).toString(hex));
        encapi.keyhash=sha512(encapi.salt.clone().concat(utf8.parse(tkn)).concat(encapi.salt));
        for(var a=0; a<10; a++) {
            tkn=encapi.randomWordArray(16).toString(hex);
        }
        encapi.log("token set succ");
    };

    encapi.destroyToken=function() {

        if(encapi.keyhash===null||encapi.salt===null) {
            encapi.keyhash=null;
            encapi.salt=null;
            return false;
        }

        for(var b=0; b<encapi.keyhash.words.length; b++) {
            encapi.keyhash.words[b]=0xffffffff;
        }
        for(var b=0; b<encapi.salt.length; b++) {
            encapi.salt.words[b]=0xffffffff;
        }

        for(var b=0; b<encapi.keyhash.words.length; b++) {
            encapi.keyhash.words[b]=0;
        }
        for(var b=0; b<encapi.salt.length; b++) {
            encapi.salt.words[b]=0;
        }

        for(var a=0; a<5; a++) {
            for(var b=0; b<encapi.keyhash.words.length; b++) {
                encapi.keyhash.words[b]=encapi.randomWordArray(4).words[0];
            }
            for(var b=0; b<encapi.salt.length; b++) {
                encapi.salt.words[b]=encapi.randomWordArray(4).words[0];
            }
        }
        encapi.keyhash=null;
        encapi.salt=null;
        encapi.log("token destroyed");
    };

    encapi.encrypt=function(d) {
        try {
            if(encapi.keyhash===null||encapi.salt===null) {
                return false;
            }
            var t=gt(0x10);
            t=String(t);
            var tw=utf8.parse(t);
            var i=md5(tw);
            var k=sha256(tw.clone().concat(encapi.keyhash).concat(encapi.salt).concat(tw));
            d=utf8.parse(d);
            return [ {"time":String(t), "sign":md5(sha256(encapi.salt.clone().concat(tw).concat(encapi.keyhash).concat(tw))).toString(hex).substring(0, 6), "salt":encapi.salt.toString(utf8), "data":aes.encrypt(d, k, {"iv":i, "mode":CryptoJS.mode.CBC, "padding":CryptoJS.pad.custompad}).toString()}, k, i];
        } catch(e) {
            return false;
        }
    };

    encapi.decrypt=function(j) {
        if(typeof j!="object") {
            return false;
        }
        try {
            var i;
            var k;
            if("k" in j&&"i" in j) {
                i=j["i"];
                k=j["k"];
            } else {
                var t=j["time"];
                t=String(t);
                var s=j["salt"];
                s=hex.parse(s);
                var tw=utf8.parse(t);
                i=md5(tw);
                k=sha256(tw.clone().concat(encapi.keyhash).concat(s).concat(tw));
            }
            var d=j["data"];

            return aes.decrypt(d, k, {"iv":i, "mode":CryptoJS.mode.CBC, "padding":CryptoJS.pad.custompad}).toString(utf8);
        } catch(e) {
            return false;
        }
    };

    encapi.sendRequest=function(url, mtd, cbk, dta, sync) {
        if(sync===undefined) {
            if(typeof cbk=="function") {
                sync=true;
            } else {
                sync=false;
            }
        }
        if(typeof cbk!="function") {
            cbk=new Function();
        }
        mtd=mtd.toUpperCase();
        var cu;
        try {
            cu=new XMLHttpRequest();
        } catch(e1) {
            try {
                cu=new ActiveXObject("Microsoft.XMLHTTP");
            } catch(e2) {
                encapi.log("XHR object construct failed");
                return false;
            }
        }
        if(sync) {
            cu.onreadystatechange=function() {
                if(cu.readyState==(XMLHttpRequest.DONE||4)) {
                    cbk(cu.responseText, cu);
                    try {
                        cu.abort();
                    } catch(e) {
                    }
                }
            };
        }
        cu.onerror=function() {
            try {
                cu.abort();
            } catch(e) {
            }
            cbk(false, cu);
        };
        cu.open(mtd, url, sync);
        cu.send(dta);
        return cu;
    };

    window.ly65encapi=encapi;
})();
/*
    salt生成算法（反正就是随机的128位）
    md5(sha256(time+randomBytes(16)+time))

    sign生成算法
    md5(sha256(salt+time+keyhash+time))
    取前3字节转成hex(strlen==6)
    校验sign忽略大小写

    加密data的key生成算法
    sha256(time+keyhash+salt+time)

    其中 keyhash=sha512(salt+api_key+salt) 预先计算

    加密data的iv生成算法
    md5(time)

    注意hash的输入（key salt time）是小写hex字符串（salt）或utf8字符串（key time），但hash输出是二进制字符串
*/
