<?php
/**
* Jomres CMS Agnostic Plugin
* @author Woollyinwales IT <sales@jomres.net>
* @version Jomres 9 
* @package Jomres
* @copyright	2005-2015 Woollyinwales IT
* Jomres (tm) PHP files are released under both MIT and GPL2 licenses. This means that you can choose the license that best suits your project.
**/
class j00005plugin_manager
{
    public function __construct($componentArgs)
    {
        $MiniComponents = jomres_getSingleton("mcHandler");
        if ($MiniComponents->template_touch) {
            $this->template_touchable = false;
        } else {
            if (file_exists(get_showtime("ePointFilepath") . "language" . JRDS . get_showtime("lang") . ".php")) {
                require_once get_showtime("ePointFilepath") . "language" . JRDS . get_showtime("lang") . ".php";
            } else {
                if (file_exists(get_showtime("ePointFilepath") . "language" . JRDS . "en-GB.php")) {
                    require_once get_showtime("ePointFilepath") . "language" . JRDS . "en-GB.php";
                }
            }
        }
    }
    public function getRetVals()
    {
    }
}

?>