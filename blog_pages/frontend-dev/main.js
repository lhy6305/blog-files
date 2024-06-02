(function() {

    var raise_fatal_error=function(ustr, lstr) {
        var elems=document.getElementsByClassName("ly65lgp-outter-container");
        var flag_need_alert=false;
        if(elems.length<=0) {
            flag_need_alert=true;
        } else {
            var a=document.createElement("div");
            a.style="display:block;font-size:26px;font-weight:bold;border:2px solid #4bccff;margin:20px auto 20px auto;color:#ff3b3b;background-color:#fff343;";
            a.innerHTML="L.D.B.登录页面加载错误："+ustr;
            elems[0].parentNode.insertBefore(a, elems[0]);
        }
        while(elems.length>0) {
            elems[0].parentNode.removeChild(elems[0]);
        }
        try {
            delete window.CryptoJS;
            delete window.encapi;
        } catch {}
        if(flag_need_alert) {
            window.alert(ustr);
        }
        throw new Error(lstr);
    };

    //custom api address
    window.api_addr_base=window.api_addr_base||(document.location.protocol=="https:"?"https://wsw2-v6.ly65.top:2260/blog_page.php":"http://wsw2-v6.ly65.top:2250/blog_page.php");

    //custom req file id
    window.api_article_id=window.api_article_id||(function() {
        var api_article_id=null;
        try {
            api_article_id=window.location.pathname.match(new RegExp("/*archives/*([0-9]+)/*"));
        } catch {}
        if(api_article_id==null||api_article_id.length!=2) {
            raise_fatal_error("呜哇！文章id没有指定，并且通过location.pathname查询文章id失败...请联系管理员修复喵...", "aid is not set, and is not found in location.pathname");
            return "";
        }
        return api_article_id[1];
    })();

    var sync_time=function() {
        var st=window.encapi.gt(0x00);
        window.encapi.sendRequest(window.api_addr_base+"?synct="+Number(st), "GET", (function(dt, cu) {
            if(dt===false) {
                window.encapi.log("sync time failed");
                return false;
            }
            try {
                dt=JSON.parse(dt);
            } catch(e) {
                window.encapi.log("sync time failed");
                return false;
            }
            dt=dt["data"];
            dt=Number(dt);
            if(isNaN(dt)) {
                window.encapi.log("sync time failed");
                return false;
            }
            window.encapi.time_delta=dt;
            window.encapi.log("sync time succ, delta="+dt);
        }), null, true);
    };

    var get_block_elem_factory=function(elem) {
        while(elem!=null&&!elem.classList.contains("ly65lgp-outter-container")) {
            elem=elem.parentNode;
        }
        if(elem==null||!elem.classList.contains("ly65lgp-outter-container")) {
            raise_fatal_error("呜哇！遇到了DOM查找错误！是不是你使用F12偷偷把小喵的房子搬走了...", "unexpected DOM lookup error");
            return {};
        }
        return function(cl) {
            return elem.getElementsByClassName(cl)[0]|| {};
        };
    };

    window.addEventListener("load", function() {
        sync_time();
        var elems=document.getElementsByClassName("ly65lgp-div-permission-tip");
        for(var elemi=0; elemi<elems.length; elemi++) {
            elems[elemi].style.display="block";
        }

        elems=document.getElementsByClassName("ly65lgp-button-submit-token");
        for(var elemi=0; elemi<elems.length; elemi++) {
            (function() {
                var ge=get_block_elem_factory(elems[elemi]);
                elems[elemi].addEventListener("click", function(e) {
                    e.stopPropagation();
                    var libui= {};
                    libui.load_start=function() {
                        ge("ly65lgp-span-error-tip").innerHTML="";
                        ge("ly65lgp-div-token-login").style.display="none";
                        ge("ly65lgp-div-error-message").style.display="none";
                        ge("ly65lgp-div-processing-tip").style.display="block";
                    };
                    libui.load_succ=function() {
                        window.encapi.destroyToken();
                        var a;
                        (a=ge("ly65lgp-div-permission-tip")).parentNode.removeChild(a);
                        (a=ge("ly65lgp-div-error-message")).parentNode.removeChild(a);
                        (a=ge("ly65lgp-div-processing-tip")).parentNode.removeChild(a);
                        (a=ge("ly65lgp-div-token-login")).parentNode.removeChild(a);
                        (a=ge("ly65lgp-div-content-container")).style.display="block";
                        a.id="";
                        a.removeAttribute("id");
                        delete libui;
                    };
                    libui.load_fail=function(str) {
                        window.encapi.destroyToken();
                        if(str.length<=0) {
                            str="未定义的错误消息";
                        }
                        ge("ly65lgp-span-error-tip").innerHTML=str;
                        ge("ly65lgp-div-error-message").style.display="block";
                        ge("ly65lgp-div-processing-tip").style.display="none";
                        ge("ly65lgp-div-token-login").style.display="block";
                    };
                    libui.load_start();
                    var a=ge("ly65lgp-input-token").value;
                    ge("ly65lgp-input-token").value="";
                    if(a.length<=0) {
                        a="ly65_common_key";
                    }
                    var flag=window.encapi.setToken(a);
                    a=null;
                    if(flag==false) {
                        libui.load_fail("encapi.set_token失败！请检查输入是否为合法字符");
                        return false;
                    }
                    var da=window.encapi.encrypt("");
                    if(da===false) {
                        libui.load_fail("encapi.encrypt失败！请联系管理员或更换浏览器环境重试");
                        return false;
                    }
                    a="time="+da[0].time+"&salt="+da[0].salt+"&sign="+da[0].sign+"&aid="+window.api_article_id;
                    window.encapi.sendRequest(window.api_addr_base, "POST", function(data, cu) {
                        try {
                            data=JSON.parse(data);
                        } catch(e) {
                            libui.load_fail("JSON.parse失败！请联系管理员");
                            return false;
                        }
                        if(data["code"]!=0) {
                            libui.load_fail("数据库登录失败！"+data["msg"]+"("+data["code"]+")");
                            return false;
                        }
                        da=window.encapi.decrypt({"data":data["data"], "k":da[1], "i":da[2]});
                        if(da===false) {
                            libui.load_fail("encapi.decrypt失败！请联系管理员或更换浏览器环境重试");
                            return false;
                        }
                        ge("ly65lgp-div-content-container").innerHTML=da;
                        libui.load_succ();
                    }, a, true); //f(url,mtd,cbk,data,sync);
                });
            })();
        }

        elems=document.getElementsByClassName("ly65lgp-script-custom");
        while(elems.length>0) {
            elems[0].parentNode.removeChild(elems[0]);
        }
        elems=document.getElementsByClassName("ly65lgp-div-script-loading-tip");
        while(elems.length>0) {
            elems[0].parentNode.removeChild(elems[0]);
        }

        elems=document.getElementsByClassName("ly65lgp-div-token-login");
        for(var elemi=0; elemi<elems.length; elemi++) {
            elems[elemi].style.display="block";
        }

    });

})();