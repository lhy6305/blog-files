<?php

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

function getms(){
list($u,$s)=explode(" ",microtime());
return (string)round(((float)$u+(float)$s)*1000);
}
