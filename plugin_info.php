<?php

defined("_JOMRES_INITCHECK") or exit("");
if (!class_exists("iono_keys")) {
    /**
    * iono License Key File Handling
    *
    * @copyright Olate Ltd 2007
    * @link http://www.olate.co.uk
    * @version 1.0.0
    * @package iono
    */
    class iono_keys
    {
        /**
         * @var string The user's license key
         * @access private
         */
        public $license_key = NULL;
        /**
         * @var string The iono root site location
         * @access private
         */
        public $home_url_site = "https://license-server.jomres.net";
        /**
         * @var int The iono root site location port for access
         * @access private
         */
        public $home_url_port = 80;
        /**
         * @var string The iono location
         * @access private
         */
        public $home_url_iono = "/remote.php";
        /**
         * @var string The location of the key file to use
         * @access private
         */
        public $key_location = NULL;
        /**
         * @var string Remote Authentication String from your iono installation
         * @access private
         */
        public $remote_auth = NULL;
        /**
         * @var int The maximum age of the key file before it is regenerated (seconds)
         * @access private
         */
        public $key_age = NULL;
        /**
         * @var array The data stored in the key
         * @access private
         */
        public $key_data = NULL;
        /**
         * @var int Current timestamp. Needs to be constant throughout class so is set here
         * @access private
         */
        public $now = NULL;
        /**
         * @var int The result of the key actions
         * @access public
         */
        public $result = NULL;
        /**
         * Sets the class vars and then checks the key file.
         * @param string $license_key The user's license key
         * @param string $remote_auth The remote authorisation string from iono settings
         * @param string $key_location The location of the key file to use
         * @param int $key_age The maximum age of the key file before it is regenerated (seconds) default 15 days (1296000) 86400 = 1 day ( more or less ;) )
         */
        public function __construct($license_key, $remote_auth, $key_location, $key_age = 86400)
        {
            $this->license_key = $license_key;
            $this->remote_auth = $remote_auth;
            $this->key_location = $key_location;
            $this->key_age = $key_age;
            $this->now = time();
            $number_of_plugins_installed = count(glob(JOMRES_COREPLUGINS_ABSPATH . "*", GLOB_ONLYDIR));
            if (empty($license_key) && !file_exists($this->key_location) && $number_of_plugins_installed < 2) {
                $this->result = 14;
                return false;
            }
            if (empty($remote_auth)) {
                $this->result = 4;
                return false;
            }
            if (file_exists($this->key_location)) {
                $this->result = $this->read_key();
            } else {
                $this->result = $this->generate_key();
                if (empty($this->result)) {
                    $this->result = $this->read_key();
                }
            }
            unset($this->remote_auth);
            return true;
        }
        public function delete_keyfile()
        {
            @unlink($this->key_location);
        }
        /**
         * Gets the license details form the iono server and writes to the key file
         *
         * Responses:
         * - 8: License disabled
         * - 9: License suspended
         * - 5: License expired
         * - 10: Unable to open file for writing
         * - 11: Unable to write to file
         * - 12: Unable to communicate with iono
         * @return int Response code
         * @access private
         */
        public function generate_key()
        {
            $request = "remote=licenses&type=5&license_key=" . urlencode(base64_encode($this->license_key));
            $request .= "&host_ip=" . urlencode(base64_encode($_SERVER["SERVER_ADDR"])) . "&host_name=" . urlencode(base64_encode($_SERVER["SERVER_NAME"]));
            $request .= "&hash=" . urlencode(base64_encode(md5($request)));
            $base_uri = $this->home_url_site . $this->home_url_iono;
            try {
                $headers = array("Accept" => "application/json");
                $client = new GuzzleHttp\Client(array("base_uri" => $base_uri, "verify" => false, "headers" => $headers));
                $response = $client->get($base_uri . "?" . $request);
                $content = $response->getBody()->__toString();
            } catch (GuzzleHttp\Exception\RequestException $e) {
                echo $e->getMessage();
                echo "Network error";
                exit;
            }
            if (!$content) {
                return 12;
            }
            $string = urldecode($content);
            $exploded = explode("|", $string);
            switch ($exploded[0]) {
                case 0:
                    return 8;
                case 2:
                    return 9;
                case 3:
                    return 5;
                case 10:
                    return 4;
            }
            list(, $data["license_key"], $data["expiry"], $data["hostname"], $data["ip"]) = $exploded;
            $data["timestamp"] = $this->now;
            if (empty($data["hostname"])) {
                $data["hostname"] = $_SERVER["SERVER_NAME"];
            }
            if (empty($data["ip"])) {
                $data["ip"] = $_SERVER["SERVER_ADDR"];
            }
            $data_encoded = serialize($data);
            $data_encoded = base64_encode($data_encoded);
            $data_encoded = md5($this->now . $this->remote_auth) . $data_encoded;
            $data_encoded = strrev($data_encoded);
            $data_encoded_hash = sha1($data_encoded . $this->remote_auth);
            $fp = fopen($this->key_location, "w");
            if ($fp) {
                $fp_write = fwrite($fp, wordwrap($data_encoded . $data_encoded_hash, 40, "\n", true));
                if (!$fp_write) {
                    return 11;
                }
                fclose($fp);
            } else {
                return 10;
            }
        }
        /**
         * Read the key file and then return a response code
         *
         * Responses:
         * - 0: Unable to read key
         * - 1: Everything is OK
         * - 2: SHA1 hash incorrect (key may have been tampered with)
         * - 3: MD5 hash incorrect (key may have been tampered with)
         * - 4: License key does not match key string in key file
         * - 5: License has expired
         * - 6: Host name does not match key file
         * - 7: IP does not match key file
         * @return int Response code
         * @access private
         */
        public function read_key()
        {
            $key = file_get_contents($this->key_location);
            if ($key !== false) {
                $key = str_replace("\n", "", $key);
                $key_string = substr($key, 0, strlen($key) - 40);
                $key_sha_hash = substr($key, strlen($key) - 40, strlen($key));
                if (sha1($key_string . $this->remote_auth) == $key_sha_hash) {
                    $key = strrev($key_string);
                    $key_hash = substr($key, 0, 32);
                    $key_data = substr($key, 32);
                    $key_data = base64_decode($key_data);
                    $key_data = unserialize($key_data);
                    if (md5($key_data["timestamp"] . $this->remote_auth) == $key_hash) {
                        if ($this->key_age <= $this->now - $key_data["timestamp"]) {
                            unlink($this->key_location);
                            $this->result = $this->generate_key();
                            if (empty($this->result)) {
                                $this->result = $this->read_key();
                            }
                            return 1;
                        }
                        $this->key_data = $key_data;
                        if ($key_data["license_key"] != $this->license_key) {
                            return 4;
                        }
                        if ($key_data["expiry"] <= $this->now && $key_data["expiry"] != 1) {
                            return 5;
                        }
                        return 1;
                    }
                    return 3;
                }
                return 2;
            }
            return 0;
        }
        /**
         * Returns array of key data
         *
         * @return array Array of data in the key file
         */
        public function get_data()
        {
            return $this->key_data;
        }
        public function iono_save_new_license_if_sent()
        {
        }
        public function delete_encoded_plugins()
        {
            $jrcPath = JOMRESCONFIG_ABSOLUTE_PATH . JRDS . JOMRES_ROOT_DIRECTORY . JRDS . "core-plugins" . JRDS;
            foreach (glob($jrcPath . "*") as $directory) {
                if (file_exists($directory . JRDS . "plugin_info.php")) {
                    $line = fgets(fopen($directory . $entry . JRDS . "plugin_info.php ", "r"));
                    $result = substr($line, 0, 13);
                    if ($result == "<?php //004fb") {
                        $bang = explode(JRDS, $directory);
                        $plugin_name = end($bang);
                        var_dump($plugin_name);
                        exit;
                    }
                }
            }
            jr_import("minicomponent_registry");
            $registry = new minicomponent_registry(false);
            $registry->regenerate_registry();
        }
    }
}
if (!function_exists("iono_key_failure")) {
    function iono_key_failure($message, $key = "", $version)
    {
        $output = "";
        if (!AJAXCALL && !defined("LICENSE_EXPIRED_SEEN") && !defined("LICENSE_EXPIRED_MESSAGE")) {
            define("LICENSE_EXPIRED_SEEN", 1);
            if (!jomres_cmsspecific_areweinadminarea()) {
                $output .= "<html>\r\n\t\t\t\t\t<head>\r\n\t\t\t\t\t\t<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\">\r\n\t\t\t\t\t\t<link rel=\"stylesheet\" type=\"text/css\" href=\"//netdna.bootstrapcdn.com/bootstrap/3.1.1/css/bootstrap.min.css\">\r\n\t\t\t\t\t\t<script src=\"//ajax.googleapis.com/ajax/libs/jquery/1.7.2/jquery.min.js\"></script>\r\n\t\t\t\t\t\t<script src=\"//netdna.bootstrapcdn.com/bootstrap/3.1.1/js/bootstrap.min.js\"></script>\r\n\t\t\t\t\t\t<title>Site temporarily offline</title>\r\n\t\t\t\t\t\t<style>\r\n\t\t\t\t\t\t\t.steps a {\r\n\t\t\t\t\t\t\t\tpadding: 10px 12px 10px 25px;\r\n\t\t\t\t\t\t\t\tmargin-right: 5px;\r\n\t\t\t\t\t\t\t\tbackground: #efefef;\r\n\t\t\t\t\t\t\t\tposition: relative;\r\n\t\t\t\t\t\t\t\tdisplay: inline-block;\r\n\t\t\t\t\t\t\t\tcolor:#000;\r\n\t\t\t\t\t\t\t\ttext-decoration:none;\r\n\t\t\t\t\t\t\t}\r\n\t\t\t\t\t\t\t.steps a:hover {cursor: pointer; cursor: hand;}\r\n\t\t\t\t\t\t\t.steps a:before {\r\n\t\t\t\t\t\t\t\twidth: 0;\r\n\t\t\t\t\t\t\t\theight: 0;\r\n\t\t\t\t\t\t\t\tborder-top: 20px inset transparent;\r\n\t\t\t\t\t\t\t\tborder-bottom: 20px inset transparent;\r\n\t\t\t\t\t\t\t\tposition: absolute;\r\n\t\t\t\t\t\t\t\tcontent: \"\";\r\n\t\t\t\t\t\t\t\ttop: 0;\r\n\t\t\t\t\t\t\t\tleft: 0;\r\n\t\t\t\t\t\t\t}\r\n\t\t\t\t\t\t\t.steps a:after {\r\n\t\t\t\t\t\t\t\twidth: 0;\r\n\t\t\t\t\t\t\t\theight: 0;\r\n\t\t\t\t\t\t\t\tborder-top: 20px inset transparent;\r\n\t\t\t\t\t\t\t\tborder-bottom: 20px inset transparent;\r\n\t\t\t\t\t\t\t\tborder-left: 20px solid #efefef;\r\n\t\t\t\t\t\t\t\tposition: absolute;\r\n\t\t\t\t\t\t\t\tcontent: \"\";\r\n\t\t\t\t\t\t\t\ttop: 0;\r\n\t\t\t\t\t\t\t\tright: -20px;\r\n\t\t\t\t\t\t\t\tz-index: 2;\r\n\t\t\t\t\t\t\t}\r\n\t\t\t\t\t\t\t/*.steps a:last-child:after,*/\r\n\t\t\t\t\t\t\t.steps a:first-child:before {\r\n\t\t\t\t\t\t\t\tborder: none;\r\n\t\t\t\t\t\t\t}\r\n\t\t\t\t\t\t\t.steps a:first-child {\r\n\t\t\t\t\t\t\t\tpadding-left:15px;   \r\n\t\t\t\t\t\t\t\t-webkit-border-radius: 4px 0 0 4px;\r\n\t\t\t\t\t\t\t\t   -moz-border-radius: 4px 0 0 4px;\r\n\t\t\t\t\t\t\t\t\t\tborder-radius: 4px 0 0 4px;\r\n\t\t\t\t\t\t\t}\r\n\t\t\t\t\t\t\t.steps a:last-child {\r\n\t\t\t\t\t\t\t\t-webkit-border-radius: 0 4px 4px 0;\r\n\t\t\t\t\t\t\t\t   -moz-border-radius: 0 4px 4px 0;\r\n\t\t\t\t\t\t\t\t\t\tborder-radius: 0 4px 4px 0;\r\n\t\t\t\t\t\t\t}\r\n\t\t\t\t\t\t\t.steps .current {\r\n\t\t\t\t\t\t\t\tbackground: #007ACC;\r\n\t\t\t\t\t\t\t\tcolor: #fff;\r\n\t\t\t\t\t\t\t}\r\n\t\t\t\t\t\t\t.steps .current:after {\r\n\t\t\t\t\t\t\t\tborder-left-color: #007ACC;\r\n\t\t\t\t\t\t\t}\r\n\t\t\t\t\t\t</style>\r\n\t\t\t\t\t</head>\r\n\t\t\t\t\t<body>\r\n\t\t\t\t\t\t<div class=\"container\">\r\n\t\t\t\t\t\t\t<div>\r\n\t\t\t\t\t\t\t\t<img src=\"http://www.jomres.net/images/jomres.png\" class=\"img-rounded\"/>\r\n\t\t\t\t\t\t\t</div>\r\n\t\t\t\t";
            }
            if ($key == "") {
                $output .= "<h1 class=\"alert alert-danger\">Before you can use this software you will need to enter a valid key in the Jomres Site Configuration -> Misc tab</h1>";
            } else {
                if (jomres_cmsspecific_areweinadminarea()) {
                    $output .= "<h1 class=\"alert alert-danger\">Site is currently unavailable > " . $message . "</h1>";
                    if (basename($_SERVER["SCRIPT_FILENAME"], ".php") != "wp-login" && isset($_REQUEST["task"]) && $_REQUEST["task"] != "site_settings" && isset($_REQUEST["redirected"])) {
                        $output .= "<script type=\"text/javascript\">\r\n\t\t\t\t\t\t\t\t\tjomresJquery(window).on('load',function(){\r\n\t\t\t\t\t\t\t\t\t\tjomresJquery('#licenseOptions').modal('show');\r\n\t\t\t\t\t\t\t\t\t\t});\r\n\t\t\t\t\t\t\t\t\t</script>\r\n\t\t\t\t\t\t\t\t\t<div class=\"modal hide fade\" id=\"licenseOptions\">\r\n\t\t\t\t\t\t\t\t\t  <div class=\"modal-header\">\r\n\t\t\t\t\t\t\t\t\t\t<h3 class=\"center\">" . $message . " </h3>\r\n\t\t\t\t\t\t\t\t\t  </div>\r\n\t\t\t\t\t\t\t\t\t  <hr/>\r\n\t\t\t\t\t\t\t\t\t  <p class=\"center\">If you want to continue using Jomres plugins, you have 3 choices</p>\r\n\t\t\t\t\t\t\t\t\t  <div class=\"modal-body center\" style=\"padding:10px\">";
                        $this_jomres_version = explode(".", $version);
                        list($current_major_version, $current_minor_version, $current_revis_version) = $this_jomres_version;
                        $min_major_version = "9";
                        $min_minor_version = "9";
                        $min_revis_version = "6";
                        $r["LATERVERSION"] = "Requires a later version of Jomres";
                        if ($min_major_version <= $current_major_version && $min_minor_version <= $current_minor_version && $min_revis_version <= $current_revis_version) {
                            $condition = 1;
                        } else {
                            if ($min_major_version <= $current_major_version && $min_minor_version < $current_minor_version) {
                                $condition = 1;
                            } else {
                                if ($min_major_version < $current_major_version) {
                                    $condition = 1;
                                } else {
                                    $condition = 0;
                                }
                            }
                        }
                        if ($condition == 1) {
                            $output .= "<p><a href=\"" . JOMRES_SITEPAGE_URL_ADMIN . "&task=stripe_subscribe\" class=\"btn btn-primary\">Purchase a license</a></p>";
                        }
                        $output .= "<p><a href=\"" . JOMRES_SITEPAGE_URL_ADMIN . "&task=site_settings\" class=\"btn btn-primary\">Enter a valid key</a></p>";
                        if ($condition == 1) {
                            $output .= "<p><a href=\"" . JOMRES_SITEPAGE_URL_ADMIN . "&task=showplugins\" class=\"btn btn-primary\">Uninstall the Plugin Manager</a></p>";
                        } else {
                            $output .= "<p><a href=\"" . JOMRES_SITEPAGE_URL_ADMIN . "&task=showplugins\" class=\"btn btn-primary\">Uninstall all plugins</a></p>";
                        }
                        $output .= "</div>\r\n\t\t\t\t\t\t\t\t\t</div>\r\n\t\t\t\t\t\t\t\t\t";
                    }
                } else {
                    $output .= "<h1 class=\"alert alert-danger\">Sorry, this site is currently unavailable</h1>\r\n\t\t\t\t\t\t<div class=\"alert alert-info\"><p>Please contact the site administrator if you see this message</p></div>\r\n\t\t\t\t\t\t";
                }
            }
            if (!jomres_cmsspecific_areweinadminarea()) {
                $output .= "</div>\r\n\t\t\t\t</body>\r\n\t\t\t\t";
            }
        }
        if (!jomres_cmsspecific_areweinadminarea() && basename($_SERVER["SCRIPT_FILENAME"], ".php") != "wp-login") {
            echo $output;
            exit;
        }
        if (basename($_SERVER["SCRIPT_FILENAME"], ".php") != "wp-login" && !isset($_REQUEST["jrajax"])) {
            if (!isset($_REQUEST["task"])) {
                $_REQUEST["task"] = "";
            }
            if ($_REQUEST["task"] != "showplugins" && $_REQUEST["task"] != "site_settings" && $_REQUEST["task"] != "removeplugin" && $_REQUEST["task"] != "save_site_settings" && $_REQUEST["task"] != "prices" && $_REQUEST["task"] != "stripe_subscribe" && $_REQUEST["task"] != "stripe_subscribe_ajax" && $_REQUEST["task"] != "" && !defined(AUTO_UPGRADE)) {
                jomresRedirect(JOMRES_SITEPAGE_URL_ADMIN . "&task=stripe_subscribe&redirected=1");
            } else {
                if (!defined("LICENSE_EXPIRED_MESSAGE")) {
                    define("LICENSE_EXPIRED_MESSAGE", $output);
                }
            }
        }
    }
}
$siteConfig = jomres_singleton_abstract::getInstance("jomres_config_site_singleton");
$jrConfig = $siteConfig->get();
include JOMRESCONFIG_ABSOLUTE_PATH . JRDS . JOMRES_ROOT_DIRECTORY . JRDS . "jomres_config.php";
$licensing = new iono_keys($jrConfig["licensekey"], $remote_auth = "230a25e276da", JOMRESCONFIG_ABSOLUTE_PATH . JRDS . JOMRES_ROOT_DIRECTORY . JRDS . "temp" . JRDS . "key.php");
switch ($licensing->result) {
    case 0:
        $licensing->iono_save_new_license_if_sent();
        iono_key_failure("Unable to read the key file in the temporary directory", $jrConfig["licensekey"], $jrConfig["version"]);
        break;
    case 1:
        break;
    case 2:
        $licensing->iono_save_new_license_if_sent();
        iono_key_failure("The SHA1 hash is incorrect", $jrConfig["licensekey"], $jrConfig["version"]);
        break;
    case 3:
        $licensing->iono_save_new_license_if_sent();
        iono_key_failure("The MD5 hash is incorrect", $jrConfig["licensekey"], $jrConfig["version"]);
        break;
    case 4:
        $licensing->iono_save_new_license_if_sent();
        iono_key_failure("The license key does not match key saved in the key file", $jrConfig["licensekey"], $jrConfig["version"]);
        break;
    case 5:
        $licensing->iono_save_new_license_if_sent();
        iono_key_failure("The license has expired", $jrConfig["licensekey"], $jrConfig["version"]);
        break;
    case 6:
        $licensing->iono_save_new_license_if_sent();
        iono_key_failure("The stored host name does not match key file", $jrConfig["licensekey"], $jrConfig["version"]);
        break;
    case 7:
        $licensing->iono_save_new_license_if_sent();
        iono_key_failure("The IP does not match key file", $jrConfig["licensekey"], $jrConfig["version"]);
        break;
    case 8:
        $licensing->iono_save_new_license_if_sent();
        iono_key_failure("This license has been disabled", $jrConfig["licensekey"], $jrConfig["version"]);
        break;
    case 9:
        $licensing->iono_save_new_license_if_sent();
        iono_key_failure("This license has been suspended", $jrConfig["licensekey"], $jrConfig["version"]);
        break;
    case 10:
        $licensing->iono_save_new_license_if_sent();
        iono_key_failure("Unable to write the key file to the temporary directory", $jrConfig["licensekey"], $jrConfig["version"]);
        break;
    case 11:
        $licensing->iono_save_new_license_if_sent();
        iono_key_failure("Unable to write the key file to the temporary directory", $jrConfig["licensekey"], $jrConfig["version"]);
        break;
    case 12:
        $licensing->iono_save_new_license_if_sent();
        iono_key_failure("Unable to communicate with the license server", $jrConfig["licensekey"], $jrConfig["version"]);
        break;
    case 13:
        $licensing->iono_save_new_license_if_sent();
        iono_key_failure("License key is only valid for " . ALLOWED_PROPERTIES . " properties and you have exceeded that number of properties.", $jrConfig["licensekey"], $jrConfig["version"]);
        break;
    case 14:
        break;
}
if (!function_exists("get_number_of_allowed_properties")) {
    function get_number_of_allowed_properties()
    {
        return 999999999;
    }
}
/**
* Jomres CMS Agnostic Plugin
* @author Woollyinwales IT <sales@jomres.net>
* @version Jomres 9 
* @package Jomres
* @copyright	2005-2017 Woollyinwales IT
* Jomres (tm) PHP files are released under both MIT and GPL2 licenses. This means that you can choose the license that best suits your project.
**/
class plugin_info_plugin_manager
{
    public function __construct()
    {
        $this->data = array("name" => "plugin_manager", "category" => "System", "marketing" => "Displays and installs plugins that can be downloaded from Jomres.net, also allows you to install third party plugins.", "version" => (double) "2.7", "description" => "Displays and installs plugins that can be downloaded from Jomres.net, also allows you to install third party plugins.", "lastupdate" => "2019/10/21", "min_jomres_ver" => "9.13.0", "manual_link" => "", "change_log" => "v1.1 Modified some defines. v1.2 Implemented new functionality that prevents clickable links from appearing in the Plugin Manager if their license is limited to certain set of plugins. Aesthetic/UI improvement. v1.4 Tweaked how we check for a cached file. v1.5 Updated plugin manager to allow installation of plugins via ajax, improves the UI. v1.6 Improved the UI to provide feedback while installing/uninstalling v1.7 Modified code to deal with new jomres_shortcode_parser class which replaces shortcode_parser class with is a widely used name in WP. v1.8 Version bump to ensure that users can install the update. v1.9 Node/javascript path related changes. v2.0 Notice resolved. v2.1 Language file added. v2.2 Jomres 9.10 related changes. v2.3 Plugin manager updated to allow 3pds to add their own tabs to the Plugin Manager page, this means that the showplugins script no longer needs to be overridden. v2.4 Plugin manager modified to ensure that temp .js files are removed during update, and notice fixed. v2.5 CSRF hardening added. v2.6 french language file added. v2.7 Tweaked how the installing plugin name is found.", "highlight" => "", "image" => "https://snippets.jomres.net/plugin_screenshots/2017-08-02_4tti8.png", "demo_url" => "", "author" => "Vince Wooll", "authoremail" => "sales@jomres.net");
    }
}

?>