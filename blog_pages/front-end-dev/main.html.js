
<div id="ly65lgp-div-script-loading-tip" style="font-size:26px;">
正在加载资源...
<br>
如果本条消息长时间无变化请检查是否已启用浏览器javascript
<br>
</div>

<script class="ly65lgp-script-custom" style="display:none;" src="https://cdn.jsdelivr.net/gh/lhy6305/js-plugins@b27d838c1b2b5b154eb8e52367736e595a80d4da/blog_pages/libcrypto_encapi_merged.js">
//include libcrypto_encapi_merged.js
</script>

<script class="ly65lgp-script-custom" style="display:none;">
(function(){

//custom api address
var api_addr_base="http://wsw2-v6.ly65.tk:2250/blog_page.php";


var ge=function(id){
return document.getElementById(id);
};
var syt=function(){
var st=encapi.gt(0x00);
encapi.sendRequest(api_addr_base+"?synct="+Number(st),"GET",(function(dt,cu){
if(dt===false){
encapi.log("sync time failed");
return false;
}
try{
dt=JSON.parse(dt);
}catch(e){
encapi.log("sync time failed");
return false;
}
dt=dt["data"];
dt=Number(dt);
if(isNaN(dt)){
encapi.log("sync time failed");
return false;
}
encapi.time_delta=dt;
encapi.log("sync time succ, delta="+dt);
}),null,true);
};
window.addEventListener("load",function(){
syt();
var load_start=function(){
ge("ly65lgp-span-error-tip").innerHTML="";
ge("ly65lgp-div-token-login").style.display="none";
ge("ly65lgp-div-error-message").style.display="none";
ge("ly65lgp-div-processing-tip").style.display="block";
};
var load_fail=function(str){
encapi.destroyToken();
if(str.length<=0){
str="未定义的错误消息";
}
ge("ly65lgp-span-error-tip").innerHTML=str;
ge("ly65lgp-div-error-message").style.display="block";
ge("ly65lgp-div-processing-tip").style.display="none";
ge("ly65lgp-div-token-login").style.display="block";
};
var load_succ=function(){
encapi.destroyToken();
var a;
(a=ge("ly65lgp-div-error-message")).parentNode.removeChild(a);
(a=ge("ly65lgp-div-processing-tip")).parentNode.removeChild(a);
(a=ge("ly65lgp-div-token-login")).parentNode.removeChild(a);
(a=ge("ly65lgp-div-content-container")).style.display="block";
delete window.CryptoJS;
delete window.encapi;
};
ge("ly65lgp-button-submit-token").addEventListener("click",function(){
load_start();
var a=ge("ly65lgp-input-token").value;
ge("ly65lgp-input-token").value="";
if(a.length<=0){
a="ly65_common_key";
}
var flag=window.encapi.setToken(a);
a=null;
if(flag==false){
load_fail("encapi.set_token失败！请检查输入是否为合法字符");
return false;
}
a=window.location.pathname.match(new RegExp("/*archives/*([0-9]+)/*"));
if(a.length!=2){
load_fail("location.pathname匹配文章id失败！请联系管理员");
return false;
}
var da=encapi.encrypt("");
if(da===false){
load_fail("encapi.encrypt失败！请联系管理员或更换浏览器环境重试");
return false;
}
a="time="+da[0].time+"&salt="+da[0].salt+"&sign="+da[0].sign+"&aid="+a[1];
encapi.sendRequest(api_addr_base,"POST",function(data,cu){
try{
data=JSON.parse(data);
}catch(e){
load_fail("JSON.parse失败！请联系管理员");
return false;
}
if(data["code"]!=0){
load_fail("数据库登录失败！"+data["msg"]);
return false;
}
da=encapi.decrypt({"data":data["data"],"k":da[1],"i":da[2]});
if(da===false){
load_fail("encapi.ecrypt失败！请联系管理员或更换浏览器环境重试");
return false;
}
ge("ly65lgp-div-content-container").innerHTML=da;
load_succ();
},a,true); //f(url,mtd,cbk,data,sync);
});



var a;
do{
a=document.getElementsByClassName("ly65lgp-script-custom");
a[0].parentNode.removeChild(a[0]);
}while(a.length>0);
(a=ge("ly65lgp-div-script-loading-tip")).parentNode.removeChild(a);
ge("ly65lgp-div-token-login").style.display="block";
});

})();
</script>

<div id="ly65lgp-div-error-message" style="display:none;font-size:26px;font-weight:bold;border:2px solid #4bccff;margin:20px auto 20px auto;color:#ff3b3b;background-color:#fff343;">
错误：<span id="ly65lgp-span-error-tip"></span>
<br>
</div>

<div id="ly65lgp-div-token-login" style="display:none;font-size:20px;border:2px solid #4bccff;text-align:center;margin:20px auto 20px auto;">
<br>
<span style="font-size:30px;">L.D.B数据库登录页面</span>
<br>
<span style="color:#888888;">提示：大部分文档可以不填密码直接访问</span>
<br>
<br>
请输入密码：<input id="ly65lgp-input-token" placeholder="或许可以留空试试...？">
<br>
<br>
<button id="ly65lgp-button-submit-token" style="border:2px solid #4bccff;background-color:#dffff8;">提交访问申请</button>
<br>
<br>
</div>

<div id="ly65lgp-div-processing-tip" style="display:none;font-size:26px;font-weight:bold;border:2px solid #4bccff;margin:20px auto 20px auto;color:#6db517;background-color:#ffeefb;">
正在处理您的请求，请稍后...
<br>
</div>

<div id="ly65lgp-div-content-container" style="display:none;"></div>
