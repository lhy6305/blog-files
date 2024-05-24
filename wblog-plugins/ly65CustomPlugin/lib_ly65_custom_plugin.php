<?php

require_once(__DIR__."/libutil.php");

function ly65_custom_hook__read_template($id){
if(strpos($id,".")===false){
$id.=".html";
}
$id=__DIR__."/template/".$id;
if(!is_readable($id)){
return -1;
}
$fi=file_get_contents($id);
clearstatcache(true);
if(filesize($id)!==strlen($fi)){
return -2;
}
unset($id);

$l=0;
do{
$l=strlen($fi);
$fi=str_replace("\r\n","\n",$fi);
}while($l!=strlen($fi));
unset($l);

$l=0;
do{
$l=strlen($fi);
$fi=str_replace("\r","\n",$fi);
}while($l!=strlen($fi));
unset($l);

$fi=explode("\n",$fi);
$fi=implode("\r\n",$fi);
return $fi;
}

function ly65_custom_hook__replace_anchor($str,$li){
$ptr=0;
for(;;){
$ma=[];
preg_match("/#REPLACE-ANCHOR-([0-9]+)#/",$str,$ma,PREG_OFFSET_CAPTURE,$ptr);
if(count($ma)<=0){
break;
}
if(!array_key_exists((int)$ma[1][0],$li)){
$li[$ma[1][0]]="";
}
$str=substr($str,0,$ma[0][1]).$li[$ma[1][0]].substr($str,$ma[0][1]+strlen($ma[0][0]));
$ptr=$ma[0][1]+strlen($li[$ma[1][0]]);
}
unset($ma);
return $str;
}

function ly65_custom_hook__on_before_render($archive){ //Widget_Archive
/*
header("Content-Type: text/plain;charset=utf-8");
var_dump($archive);
var_dump($archive->authorId);
var_dump($archive->type);
exit;
*/
if($archive->authorId!==2||$archive->type!="post"){
return;
}

//header("Content-Type: text/plain;charset=utf-8");

$str=$archive->text;

//cook string

$l=0;
do{
$l=strlen($str);
$str=str_replace("\r\n","\n",$str);
}while($l!=strlen($str));
unset($l);

$l=0;
do{
$l=strlen($str);
$str=str_replace("\r","\n",$str);
}while($l!=strlen($str));
unset($l);

$str=explode("\n",$str);


//match template sign

for($a=0;$a<count($str);$a++){

if(str_starts_with($str[$a],"#template|")){
$b=explode("|",$str[$a]);
if(count($b)<2){
continue;
}
if($b[0]!="#template"){
continue;
}
array_shift($b);
$tf=$b[0];
array_shift($b);
$tf_1=ly65_custom_hook__read_template($tf);

if($tf_1===-1){
$tf="<span style=\"font-size:26px;font-weight:bold;border:2px solid #4bccff;margin:20px auto 20px auto;color:#ff3b3b;background-color:#fff343;\">[lib_ly65_custom_plugin] [WARN] template file ".$tf." not found!!</span>";
$str[$a]=$tf;
continue;
}else if($tf_1===-2){
$tf="<span style=\"font-size:26px;font-weight:bold;border:2px solid #4bccff;margin:20px auto 20px auto;color:#ff3b3b;background-color:#fff343;\">[lib_ly65_custom_plugin] [WARN] template file ".$tf." short read!!</span>";
$str[$a]=$tf;
continue;
}

$tf=$tf_1;
unset($tf_1);

$tf=ly65_custom_hook__replace_anchor($tf,$b);
$str[$a]=$tf;
continue;
}

if(str_starts_with($str[$a],"#comment|")){
array_splice($str,$a,1);
$a--;
continue;
}

}
unset($a);
unset($b);
unset($tf);

//#template|ly65_LEG|文档权限分级 1 (perm_intl)<br>您尚未获取perm_intl级权限，请在下面验证身份

$str=implode("\r\n",$str);

//echo $str;
//exit;

$archive->text=$str;

}


