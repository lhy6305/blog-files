<?php


//namespace TypechoPlugin\ly65_custom_plugin;

require_once(__DIR__."/lib_ly65_custom_plugin.php");

/**
 * N/A
 * 
 * @package ly65_custom_plugin
 * @author ly65
 * @version N/A
 */

class ly65CustomPlugin_Plugin implements Typecho_Plugin_Interface {

public static function activate(){
Typecho_Plugin::factory("Widget_Archive")->beforeRender=__CLASS__."::empty_func";
Typecho_Plugin::factory("Widget_Archive")->beforeRender="ly65_custom_hook__on_before_render";
}

public static function deactivate(){
}

public static function config($form){ //\Typecho\Widget\Helper\Form
//$form->addInput(new \Typecho\Widget\Helper\Form\Element\Text("word", null, "默认值", "标题", "描述"));
}

public static function personalConfig($form){ //\Typecho\Widget\Helper\Form
}

public static function empty_func($archive){
//empty function to let it load libs. or the hooks will not exist
}

}
