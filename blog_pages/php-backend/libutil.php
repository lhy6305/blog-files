<?php

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
return (string)$needle!==""&&strncmp($haystack,$needle,strlen($needle))===0;
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
