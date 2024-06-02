<?php

set_time_limit(0);
ob_implicit_flush();
ignore_user_abort(true);
date_default_timezone_set("Asia/Shanghai");
//header("Access-Control-Allow-Origin: *");
header("Cache-Control: nocache");
header("Content-Type: application/json");
header("Pragma: no-cache");
function getms(){
list($ms,$s)=explode(" ",microtime());
$ms=substr($ms,2,3);
$ms=str_pad($ms,3,"0",STR_PAD_LEFT);
return (float)$s*1000+(float)$ms;
}

function show_error_and_exit($msg="",$code=400){
$dat=[];
$dat["code"]=$code;
$dat["msg"]=$msg;
$dat=json_encode($dat,JSON_UNESCAPED_UNICODE|JSON_PRETTY_PRINT);
header("Content-Length: ".strlen($dat));
echo $dat;
exit;
}

if(!function_exists("str_starts_with")){
function str_starts_with($haystack,$needle){
if(!is_string($needle)||!is_string($haystack)){
return false;
}
if(strlen($needle)<=0){
return true;
}
if(strlen($needle)>strlen($haystack)){
return false;
}
if(strncmp($needle,$haystack,strlen($needle))==0){
return true;
}
return false;
//end of str_starts_with
}
}

if(!function_exists("mb_str_pad")){
function mb_str_pad($str,$pad_len,$pad_str=" ",$dir=STR_PAD_RIGHT,$encoding=null){
$encoding=($encoding===null?mb_internal_encoding():$encoding);
$padBefore=($dir===STR_PAD_BOTH||$dir===STR_PAD_LEFT);
$padAfter=($dir===STR_PAD_BOTH||$dir===STR_PAD_RIGHT);
$pad_len-=mb_strlen($str,$encoding);
$targetLen=$padBefore&&$padAfter?$pad_len/2:$pad_len;
$strToRepeatLen=mb_strlen($pad_str,$encoding);
$repeatTimes=ceil($targetLen/$strToRepeatLen);
$repeatedString=str_repeat($pad_str,max(0,$repeatTimes)); // safe if used with valid utf-8 strings
$before=$padBefore?mb_substr($repeatedString,0,floor($targetLen),$encoding):"";
$after=$padAfter?mb_substr($repeatedString,0,ceil($targetLen),$encoding):"";
return $before.$str.$after;
//end of mb_str_pad
}
}
function custom_pad($d){
$p=16-(strlen($d)%16);
if($p==0){
$p=16;
}
if($p>1){
$d.=openssl_random_pseudo_bytes($p-1);
}
$d.=pack("H*",str_pad(base_convert($p,10,16),2,"0",STR_PAD_LEFT));
unset($p);
return $d;
}

function custom_unpad($d){
$p=unpack("H*",substr($d,-1))[1];
$p=(int)base_convert($p,16,10);
while($p>0){
$d=substr($d,0,-1);
$p--;
}
return $d;
}

function get_key_by_aid($aid,$dt){
$ks=__DIR__."/internal/blog_pages/0_blog_page_pwd.json";
if(!is_readable($ks)){
show_error_and_exit("request_failed_keystore_not_found",500);
}
$ks=file_get_contents($ks);
$ks=json_decode($ks,true);
if($ks===null){
show_error_and_exit("request_failed_invalid_keystore_data",500);
}
if(array_key_exists($aid,$ks)){
if(is_array($ks[$aid])){
$k=array_keys($ks[$aid]);
for($a=0;$a<count($k);$a++){
if(substr(md5(hex2bin(hash("sha256",$dt["salt"].$dt["time"].hex2bin(hash("sha512",$dt["salt"].$k[$a].$dt["salt"])).$dt["time"]))),0,6)==$dt["sign"]){
return [$k[$a],$ks[$aid][$k[$a]]];
}
}
unset($a);
unset($k);
return [false,false];
}
return [$ks[$aid],false];
}
return ["ly65_common_key",false];
}

function checkauth($dt){
//输入校验
$error_flag=false;
$dt["error_type"]=[];
if((!array_key_exists("time",$dt))||strlen($dt["time"])<=0){
$error_flag=true;
$dt["error_type"][]="param[\"time\"] required";
}else{
$dlt=(float)$dt["time"]-getms();

if($dlt>5*1000||$dlt<-5*1000){
$error_flag=true;
$dt["error_type"][]="param[\"time\"] expired";
}

unset($dlt);
}
if((!array_key_exists("data",$dt))||strlen($dt["data"])<=0){
$dt["data"]="";
}
if((!array_key_exists("salt",$dt))){
$error_flag=true;
$dt["error_type"][]="param[\"salt\"] not found";
}
if((!array_key_exists("sign",$dt))||strlen($dt["sign"])!=6){
$error_flag=true;
$dt["error_type"][]="param[\"sign\"] not found or has invalid length";
}
if((!array_key_exists("aid",$dt))||strlen($dt["aid"])<=0){
$error_flag=true;
$dt["error_type"][]="param[\"aid\"] required";
}
if($error_flag==true){
return [$error_flag,$dt,null,null];
}

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

$t=$dt["time"];
$k=get_key_by_aid($dt["aid"],$dt);
$dt["afid"]=$k[1];
$k=$k[0];
$s=$dt["salt"];

if($k===false){
$error_flag=true;
$dt["error_type"][]="no valid token matches the param[\"sign\"]";
return [$error_flag,$dt,null,null,-1];
}

$psi=substr(md5(hex2bin(hash("sha256",$s.$t.hex2bin(hash("sha512",$s.$k.$s)).$t))),0,6);

$psi=strtolower($psi);
$sig=strtolower($dt["sign"]);

if(strlen(preg_replace("#[0-9a-f]*#","",$sig))!==0||$psi!==$sig){
$error_flag=true;
$dt["error_type"][]="param[\"sign\"] is not valid";
}

if($error_flag==true){
return [$error_flag,$dt,null,null,-1];
}
unset($psi);
unset($sig);

$key=hex2bin(hash("sha256",$t.hex2bin(hash("sha512",$s.$k.$s)).$s.$t));

$i=hex2bin(md5($t));
$d=$dt["data"];

$d=openssl_decrypt($d,"aes-256-cbc",$key,OPENSSL_ZERO_PADDING,$i);
$d=custom_unpad($d);

$dt["data"]=$d;
unset($d);
unset($t);
unset($k);
unset($s);
return [$error_flag,$dt,$key,$i];
}


function get_authed_data($is_debug=false){
$pb=file_get_contents("php://input");
if(strlen($pb)<=0){
$dt=$_GET;
}else{
do{
$o=strlen($pb);
$pb=str_replace("&&","&",$pb);
}while((strlen($pb)-$o)!=0);
unset($o);
$pb=explode("&",$pb);
$dt=[];
foreach($pb as $a){
$a=explode("=",$a,2);
if(count($a)<2){
array_push($a,"");
}
$dt[$a[0]]=$a[1];
}
}
unset($pb);

//$dt:time,salt,[enc]data

$dt=checkauth($dt);
if(!$is_debug){
if($dt[0]){
usleep(random_int(3000,5000)*1000);
}else{
usleep(random_int(0,1000)*1000);
}
}
return $dt;

//[$error_flag,[time,salt,[dec]data,error_type,afid],$key,$i];
}

if(array_key_exists("synct",$_GET)){
$dat=[];
$dat["code"]=0;
$dat["msg"]="success";
$dat["data"]=(string)bcsub(getms(),$_GET["synct"],0);
$dat=json_encode($dat,JSON_UNESCAPED_UNICODE|JSON_PRETTY_PRINT);
header("Content-Length: ".strlen($dat));
echo $dat;
exit;
}

$dt=get_authed_data(true);
//[$error_flag,[time,salt,[dec]data,error_type],$key,$i];

if($dt[0]){
show_error_and_exit("request_failed_permission_denied: ".implode("|",$dt[1]["error_type"]),401);
}

/*
$msg=[];
$msg["on_error"]=$dt[0];
$msg["time"]=$dt[1]["time"];
$msg["sign"]=$dt[1]["sign"];
$msg["salt"]=$dt[1]["salt"];
$msg["article_id"]=$dt[1]["aid"];
$msg["article_file_id"]=$dt[1]["afid"];
$msg["error_type"]=$dt[1]["error_type"];
$msg["data_dec"]=$dt[1]["data"];
$msg["aes_key"]=base64_encode($dt[2]);
$msg["aes_iv"]=base64_encode($dt[3]);

$msg["data_enc"]=custom_pad($dt[1]["data"]);
$msg["data_enc"]=openssl_encrypt($msg["data_enc"],"aes-256-cbc",$dt[2],OPENSSL_ZERO_PADDING,$dt[3]);

$dat=[];
$dat["code"]=0;
$dat["msg"]="success";
$dat["data"]=$msg;
$dat=json_encode($dat,JSON_UNESCAPED_UNICODE|JSON_PRETTY_PRINT);
header("Content-Length: ".strlen($dat));
echo $dat;
*/

$article_root_pth=__DIR__."/internal/blog_pages/";

$afi=$article_root_pth.$dt[1]["aid"];
$afid=$dt[1]["afid"];

if($afid===false){
$afi.=".html";
}else{
$afi=$afid.".html";
}

if(!is_readable($afi)){
show_error_and_exit("request_failed_article_file_not_found: ".basename($afi),404);
}

$afi=file_get_contents($afi);

$afi=custom_pad($afi);
$afi=openssl_encrypt($afi,"aes-256-cbc",$dt[2],OPENSSL_ZERO_PADDING,$dt[3]);

$dat=[];
$dat["code"]=0;
$dat["msg"]="success";
$dat["data"]=$afi;

$dat=json_encode($dat,JSON_UNESCAPED_UNICODE|JSON_PRETTY_PRINT);
header("Content-Length: ".strlen($dat));
echo $dat;
