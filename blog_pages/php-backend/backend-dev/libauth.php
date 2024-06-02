<?php

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
$ks=__DIR__."/0_blog_page_pwd.json";
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
if(substr(md5(hex2bin(hash("sha256",$dt["salt"].$dt["time"].hex2bin(hash("sha512",$dt["salt"].$ks[$aid][$k[$a]].$dt["salt"])).$dt["time"]))),0,6)==$dt["sign"]){
return [$ks[$aid][$k[$a]],$k[$a]];
}
unset($a);
unset($k);
}
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

