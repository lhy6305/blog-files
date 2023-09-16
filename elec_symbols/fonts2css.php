<?php
set_time_limit(0);
ob_implicit_flush();
ignore_user_abort(true);

$out="";

$out.="@font-face {\r\n";

$out.="font-family: \"elec_symbols\";\r\n";

$out.="src: url(\"data:font/woff2;base64,".base64_encode(file_get_contents("elec_symbols.woff2"))."\") format(\"woff2\"), url(\"data:font/woff;base64,".base64_encode(file_get_contents("elec_symbols.woff"))."\") format(\"woff\"), url(\"data:font/ttf;base64,".base64_encode(file_get_contents("elec_symbols.ttf"))."\") format(\"truetype\");\r\n";

$out.="}\r\n";

file_put_contents("elec_symbols.css",$out);

