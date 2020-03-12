<?php
/**
* Jomres CMS Agnostic Plugin
* @author Mark Errington
* @version Jomres 9.x.x
* @package Jomres
* @copyright 2005-2020 Mark Errington
* Jomres (tm) PHP files are released under both MIT and GPL2 licenses. This means that you can choose the license that best suits your project.
**/
class plugin_info_plugin_manager
{
    public function __construct()
    {
        $this->data = array("name" => "plugin_manager", "category" => "System", "marketing" => "Displays and installs plugins that can be downloaded from Jomres.net, also allows you to install third party plugins.", "version" => "9.2.7", "description" => "Displays and installs plugins that can be downloaded from Jomres.net, also allows you to install third party plugins.", "lastupdate" => "2020/03/11", "min_jomres_ver" => "9.13.0", "manual_link" => "", "change_log" => "v1.1 Modified some defines. v1.2 Implemented new functionality that prevents clickable links from appearing in the Plugin Manager if their license is limited to certain set of plugins. Aesthetic/UI improvement. v1.4 Tweaked how we check for a cached file. v1.5 Updated plugin manager to allow installation of plugins via ajax, improves the UI. v1.6 Improved the UI to provide feedback while installing/uninstalling v1.7 Modified code to deal with new jomres_shortcode_parser class which replaces shortcode_parser class with is a widely used name in WP. v1.8 Version bump to ensure that users can install the update. v1.9 Node/javascript path related changes. v2.0 Notice resolved. v2.1 Language file added. v2.2 Jomres 9.10 related changes. v2.3 Plugin manager updated to allow 3pds to add their own tabs to the Plugin Manager page, this means that the showplugins script no longer needs to be overridden. v2.4 Plugin manager modified to ensure that temp .js files are removed during update, and notice fixed. v2.5 CSRF hardening added. v2.6 french language file added. v2.7 Tweaked how the installing plugin name is found.", "highlight" => "", "image" => "https://snippets.jomres.net/plugin_screenshots/2017-08-02_4tti8.png", "demo_url" => "", "author" => "Mark Errington", "authoremail" => " ");
    }
}

?>