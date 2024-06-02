<?php

set_time_limit(0);
ob_implicit_flush();
ignore_user_abort(true);
date_default_timezone_set("Asia/Shanghai");
//header("Access-Control-Allow-Origin: *");
header("Cache-Control: nocache");
header("Content-Type: application/json");
header("Pragma: no-cache");

require_once(__DIR__."/libutil.php");
require_once(__DIR__."/libauth.php");

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
show_error_and_exit("request_failed_permission_denied: ".json_encode($dt[1]["error_type"]),401);
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
