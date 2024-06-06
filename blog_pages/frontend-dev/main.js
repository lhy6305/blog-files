(function() {
    if(!window.ly65lgp_flag_script_injecting||window.ly65lgp_flag_script_injected) {
        console.warn("warning: ly65encapi was imported wrongly: flag_script_injecting is "+window.ly65lgp_flag_script_injecting+" and flag_script_injected is "+window.ly65lgp_flag_script_injected);
        return;
    }

    //global custom api address (used only if window.ly65lgp_pages[].addr is empty)
    window.api_addr_base=window.api_addr_base||(document.location.protocol=="https:"?"https://wsw2-v6.ly65.top:2260/blog_page.php":"http://wsw2-v6.ly65.top:2250/blog_page.php");

    var sync_time=function() {
        var st=window.ly65encapi.gt(0x00);
        window.ly65encapi.sendRequest(window.api_addr_base+"?synct="+Number(st), "GET", (function(dt, cu) {
            if(dt===false) {
                window.ly65encapi.log("sync time failed");
                return false;
            }
            try {
                dt=JSON.parse(dt);
            } catch(e) {
                window.ly65encapi.log("sync time failed");
                return false;
            }
            dt=dt["data"];
            dt=Number(dt);
            if(isNaN(dt)) {
                window.ly65encapi.log("sync time failed");
                return false;
            }
            window.ly65encapi.time_delta=dt;
            window.ly65encapi.log("sync time succ, delta="+dt);
        }), null, true);
    };

    var get_block_elem_container=function(elem) {
        while(elem!=null&&!elem.classList.contains("ly65lgp-outter-container")) {
            elem=elem.parentNode;
        }
        if(elem==null||!elem.classList.contains("ly65lgp-outter-container")) {
            window.ly65lgp_raise_fatal_error("呜哇！遇到了预期外的DOM查找错误！你是不是偷偷使用F12把小喵的房子搬走了...", "unexpected DOM lookup error");
            //throw ...;
        }
        return elem;
    };

    var get_block_elem_container_state=function(elem) {
        elem=get_block_elem_container(elem);
        if(elem.getAttribute("ly65lgp-state")===null) {
            elem.setAttribute("ly65lgp-state", "before-init");
            elem.setAttribute("ly65lgp-aid", "");
            elem.setAttribute("ly65lgp-addr", "");
        }
        return elem.getAttribute("ly65lgp-state");
    };

    var get_block_elem_container_class_queryer=function(elem) {
        elem=get_block_elem_container(elem);
        return function(cl) {
            return elem.getElementsByClassName(cl)[0]|| {};
        };
    };

    var ly65lgp_newblock_handler=function() {
        try {
            window.removeEventListener("load", ly65lgp_newblock_handler);
        } catch {}

        sync_time();

        var elems=document.getElementsByClassName("ly65lgp-div-permission-tip");
        for(var elemi=0; elemi<elems.length; elemi++) {
            elems[elemi].style.display="block";
        }

        elems=document.getElementsByClassName("ly65lgp-button-submit-token");
        for(var elemi=0; elemi<elems.length; elemi++) {
            if(get_block_elem_container_state(elems[elemi])!="before-init") {
                continue;
            }
            var ct=get_block_elem_container(elems[elemi]);
            var pg= {};
            if(Array.isArray(window.ly65lgp_pages)&&window.ly65lgp_pages.length>0) {
                pg=window.ly65lgp_pages.shift();
            }
            if(!("aid" in pg)||typeof pg.aid !== "string"||pg.aid.length<=0) {
                pg.aid=(function() {
                    var api_article_id=null;
                    try {
                        api_article_id=window.location.pathname.match(new RegExp("/*archives/*([0-9]+)/*"));
                    } catch {}
                    if(api_article_id==null||api_article_id.length!=2) {
                        window.ly65lgp_raise_fatal_error("呜哇！文章id没有指定，并且通过location.pathname查询文章id失败了...快去联系管理员修复喵...", "aid is not set, and is not found in location.pathname");
                        //throw ...;
                    }
                    return api_article_id[1];
                })();
            }
            if(!("addr" in pg)||typeof pg.addr !== "string"||pg.addr.length<=7) {
                pg.addr=window.api_addr_base;
            }
            try {
                ct.setAttribute("ly65lgp-aid", pg.aid);
                ct.setAttribute("ly65lgp-addr", pg.addr);
            } catch(e) {
                window.ly65lgp_raise_fatal_error("呜哇！ct.setAttribute()出错了...快去联系管理员修复喵...<br><pre>"+e.name+": "+e.message+"</pre><pre>"+e.stack+"</pre>", e);
                //throw ...;
            }
            (function() {
                var ct=get_block_elem_container(elems[elemi]);
                var ge=get_block_elem_container_class_queryer(elems[elemi]);
                elems[elemi].addEventListener("click", function(e) {
                    e.stopPropagation();
                    var ct_aid=ct.getAttribute("ly65lgp-aid");
                    var ct_addr=ct.getAttribute("ly65lgp-addr");
                    if(ct_aid===null||ct_aid.length<=0||ct_addr===null||ct_addr.length<=7) {
                        window.ly65lgp_raise_fatal_error("呜哇！遇到了预期外的属性访问错误！你是不是使用F12偷偷把小喵写好的属性删掉了...", "container.aid or container.addr not exist");
                        //throw ...;
                    }
                    var libui= {};
                    libui.load_start=function() {
                        ge("ly65lgp-span-error-tip").innerHTML="";
                        ge("ly65lgp-div-token-login").style.display="none";
                        ge("ly65lgp-div-error-message").style.display="none";
                        ge("ly65lgp-div-processing-tip").style.display="block";
                    };
                    libui.load_succ=function() {
                        window.ly65encapi.destroyToken();
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
                        window.ly65encapi.destroyToken();
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
                    var flag=window.ly65encapi.setToken(a);
                    a=null;
                    if(flag==false) {
                        libui.load_fail("ly65encapi.set_token()执行失败！请检查输入是否为合法字符");
                        return false;
                    }
                    var da=window.ly65encapi.encrypt("");
                    if(da===false) {
                        libui.load_fail("ly65encapi.encrypt()执行失败！请更换浏览器环境重试，或联系管理员");
                        window.ly65lgp_raise_fatal_error("呜哇！ly65encapi.encrypt()执行失败！请更换浏览器环境重试，或联系管理员...", "unexpected ly65encapi.encrypt() failed");
                        //throw ...;
                        return false;
                    }
                    a="time="+da[0].time+"&salt="+da[0].salt+"&sign="+da[0].sign+"&aid="+ct_aid;
                    window.ly65encapi.sendRequest(ct_addr, "POST", function(data, cu) {
                        try {
                            data=JSON.parse(data);
                        } catch(e) {
                            libui.load_fail("JSON.parse()执行失败！请联系管理员");
                            return false;
                        }
                        if(data["code"]!=0) {
                            libui.load_fail("数据库登录失败！"+data["msg"]+"("+data["code"]+")");
                            return false;
                        }
                        da=window.ly65encapi.decrypt({"data":data["data"], "k":da[1], "i":da[2]});
                        if(da===false) {
                            libui.load_fail("ly65encapi.decrypt()执行失败！请重试，或联系管理员");
                            return false;
                        }
                        ge("ly65lgp-div-content-container").innerHTML=da;
                        libui.load_succ();
                    }, a, true); //f(url,mtd,cbk,data,sync);
                });
            })();
            ct.setAttribute("ly65lgp-state", "registered");
            //end of for loop
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
            if(get_block_elem_container_state(elems[elemi])!="registered") {
                continue;
            }
            elems[elemi].style.display="block";
        }

        elems=document.getElementsByClassName("ly65lgp-outter-container");
        for(var elemi=0; elemi<elems.length; elemi++) {
            if(elems[elemi].getAttribute("ly65lgp-state")=="registered") {
                elems[elemi].setAttribute("ly65lgp-state", "inited");
                continue;
            }
            if(elems[elemi].getAttribute("ly65lgp-state")=="inited") {
                continue;
            }
            //this should not be executed, or someone has modified the content
            window.ly65lgp_raise_fatal_error("呜哇！遇到了预期外的元素匹配错误！你是不是偷偷使用F12把小喵的房子搬走了...", "login block container element match failed");
            //throw ...;
        }
        //end of ly65lgp_newblock_handler()
    };

    if(document.readyState==="complete"||document.readyState==="interactive") {
        ly65lgp_newblock_handler();
    } else {
        window.addEventListener("load", ly65lgp_newblock_handler);
    }

    window.ly65lgp_newblock_handler=ly65lgp_newblock_handler;

    window.ly65lgp_flag_script_injecting=false;
    window.ly65lgp_flag_script_injected=true;
})();