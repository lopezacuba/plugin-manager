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
 * Core file.
 *
 * @author Vince Wooll <sales@jomres.net>
 *
 * @version Jomres 9.9.12
 *
 * @copyright	2005-2017 Vince Wooll
 * Jomres (tm) PHP, CSS & Javascript files are released under both MIT and GPL2 licenses. This means that you can choose the license that best suits your project, and use it accordingly
 **/
class j16000addplugin
{
    public function __construct($componentArgs)
    {
        $MiniComponents = jomres_singleton_abstract::getInstance("mcHandler");
        if ($MiniComponents->template_touch) {
            $this->template_touchable = false;
        } else {
            $siteConfig = jomres_singleton_abstract::getInstance("jomres_config_site_singleton");
            $jrConfig = $siteConfig->get();
            $this_jomres_version = explode(".", $jrConfig["version"]);
            $debugging = false;
            if (!defined("JOMRES_INSTALLER")) {
                define("JOMRES_INSTALLER", 1);
            }
            $thirdparty = jomresGetParam($_REQUEST, "thirdparty", false);
            if (!class_exists("ZipArchive")) {
                $error_messsage["ERROR"] = "Error, ZipArchive not available on this server. Please ask your hosts to rebuild PHP with --enable-zip";
                echo $error_messsage["ERROR"];
            } else {
                $pluginName = jomresGetParam($_REQUEST, "plugin", "");
                if (isset($componentArgs["plugin"])) {
                    $pluginName = $componentArgs["plugin"];
                }
                $autoupgrade = (bool) jomresGetParam($_REQUEST, "autoupgrade", false);
                if (isset($componentArgs["autoupgrade"])) {
                    $autoupgrade = (bool) $componentArgs["autoupgrade"];
                }
                $ajax_install = (bool) jomresGetParam($_REQUEST, "ajax_install", false);
                if (isset($componentArgs["ajax_install"])) {
                    $ajax_install = (bool) $componentArgs["ajax_install"];
                }
                $progress_messages = array();
                $error_messsage = array();
                $output = array();
                $pageoutput = array();
                $auto_installation_result = array();
                $auto_installation_results = array();
                $output["NEXT_STEP"] = "";
                $pluginName = str_replace("<x>", "", $pluginName);
                $pluginName = str_replace("&#60;x&#62;", "", $pluginName);
                $v = explode(".", PHP_VERSION);
                $vprts = array("major" => $v[0], "minor" => $v[1], "release" => $v[2]);
                $php_version = $vprts["major"] . "." . $vprts["minor"];
                $key_validation = jomres_singleton_abstract::getInstance("jomres_check_support_key");
                $key_validation->check_license_key(true);
                $this->key_valid = $key_validation->key_valid;
                if ($key_validation->is_trial_license == "1" && !extension_loaded("IonCube Loader")) {
                    jomresRedirect(JOMRES_SITEPAGE_URL_ADMIN . "&task=loader_wizard");
                }
                if (!$this->key_valid) {
                    $current_licenses = array();
                    if (!empty($key_validation->plugin_licenses)) {
                        foreach ($key_validation->plugin_licenses as $key => $val) {
                            if ($val["status"] == 1) {
                                $current_licenses[$key] = $val["key"];
                            }
                        }
                    }
                }
                $user_allowed_to_download = false;
                if ($this->key_valid) {
                    $user_allowed_to_download = true;
                    $key_to_send = $key_validation->key_hash;
                } else {
                    if (array_key_exists($pluginName, $current_licenses)) {
                        $user_allowed_to_download = true;
                        $key_to_send = $current_licenses[$pluginName];
                    }
                }
                if ($thirdparty) {
                    $formElement = $_FILES["pluginfile"];
                    $blowdedUp = explode(".", $formElement["name"]);
                    $pluginName = $blowdedUp[0];
                }
                if ($thirdparty) {
                    $remote_pluginsDirPath = JOMRES_REMOTEPLUGINS_ABSPATH;
                } else {
                    $remote_pluginsDirPath = JOMRES_COREPLUGINS_ABSPATH;
                }
                if (strlen($pluginName) == 0 && !$thirdparty) {
                    $error_messsage["ERROR"] = "Error, no plugin name passed";
                    if ($autoupgrade) {
                        return false;
                    }
                }
                if (!is_dir($remote_pluginsDirPath)) {
                    if (!mkdir($remote_pluginsDirPath)) {
                        $error_messsage["ERROR"] = "Couldn't make " . $remote_pluginsDirPath . " folder. Please create it manually and ensure that apache/your web server has write access to that folder.";
                        if ($autoupgrade) {
                            return false;
                        }
                    } else {
                        $progress_messages[] = array("MESSAGE" => "Made " . $remote_pluginsDirPath . "");
                    }
                } else {
                    $progress_messages[] = array("MESSAGE" => "No need to make " . $remote_pluginsDirPath . "");
                }
                if (!is_dir(JOMRESCONFIG_ABSOLUTE_PATH . JOMRES_ROOT_DIRECTORY . JRDS . "updates") && !mkdir(JOMRESCONFIG_ABSOLUTE_PATH . JOMRES_ROOT_DIRECTORY . JRDS . "updates")) {
                    $error_messsage["ERROR"] = "Couldn't make the folder " . JOMRESCONFIG_ABSOLUTE_PATH . JOMRES_ROOT_DIRECTORY . JRDS . "updates" . " so quitting.";
                    echo $error_messsage["ERROR"];
                    return NULL;
                }
                $updateDirPath = JOMRESCONFIG_ABSOLUTE_PATH . JOMRES_ROOT_DIRECTORY . JRDS . "updates" . JRDS . $pluginName . JRDS;
                if (is_dir($updateDirPath)) {
                    $progress_messages[] = array("MESSAGE" => "Cleaning up " . $updateDirPath . " unpacked for a new installation of the plugin.");
                    emptyDir($updateDirPath);
                    rmdir($updateDirPath);
                }
                if (mkdir($updateDirPath)) {
                    $progress_messages[] = array("MESSAGE" => "Made " . $updateDirPath . " for a new installation of the plugin.");
                    if (mkdir($updateDirPath . "unpacked")) {
                        $progress_messages[] = array("MESSAGE" => "Made " . $updateDirPath . "unpacked for a new installation of the plugin.");
                        if ($thirdparty) {
                            if ((int) $_FILES["pluginfile"]["error"] == 0) {
                                $error = false;
                                $formElement = $_FILES["pluginfile"];
                                $blowdedUp = explode(".", $formElement["name"]);
                                $pluginName = $blowdedUp[0];
                                if ($formElement["name"] != "") {
                                    if (strstr($formElement["name"], "-")) {
                                        $pos = strpos($formElement["name"], "-");
                                        $temp_file_name = substr($formElement["name"], $pos + 1);
                                        $newfilename = $updateDirPath . $temp_file_name;
                                        $pos = strpos($temp_file_name, ".zip");
                                        $pluginName = substr($temp_file_name, 0, $pos);
                                    } else {
                                        $newfilename = $updateDirPath . $formElement["name"] . "";
                                    }
                                    if (is_uploaded_file($formElement["tmp_name"])) {
                                        $plugin_tmp = $formElement["tmp_name"];
                                        if (!copy($plugin_tmp, $newfilename)) {
                                            $error = true;
                                            $errorDesc = "<b>move_uploaded_file failed</b>";
                                        }
                                    }
                                }
                                if ($error) {
                                    $error_messsage["ERROR"] = $errorDesc;
                                    if ($autoupgrade) {
                                        return false;
                                    }
                                }
                            } else {
                                $error_codes = array("There is no error, the file uploaded with success", "The uploaded file exceeds the upload_max_filesize directive in php.ini", "The uploaded file exceeds the MAX_FILE_SIZE directive that was specified in the HTML form", "The uploaded file was only partially uploaded", "No file was uploaded", 6 => "Missing a temporary folder");
                                throw new Exception($error_codes[$_FILES["pluginfile"]["error"]]);
                            }
                        } else {
                            if ($user_allowed_to_download) {
                                $progress_messages[] = array("MESSAGE" => "Attempting download of " . $pluginName . "");
                                $newfilename = $updateDirPath . $pluginName . ".vnw";
                                $file_handle = fopen($newfilename, "wb");
                                if ($file_handle == false) {
                                    $error_messsage["ERROR"] = "Couldn't create new file " . $newfilename . ". Possible file permission problem?";
                                    if ($autoupgrade) {
                                        return false;
                                    }
                                }
                                $p = "&plugin=" . $pluginName;
                                $base_uri = "http://plugins.jomres4.net/";
                                $query_string = "index.php?r=gp&cms=" . _JOMRES_DETECTED_CMS . "&vnw=1&key=" . $key_to_send . $p . "&jomresver=" . $jrConfig["version"] . "&hostname=" . get_showtime("live_site") . "&php_version=" . $php_version;
                                $progress_messages[] = array("MESSAGE" => $base_uri . $query_string);
                                $content_type = "";
                                try {
                                    $client = new GuzzleHttp\Client(array("base_uri" => $base_uri));
                                    logging::log_message("Starting guzzle call to " . $base_uri . $query_string, "Guzzle", "DEBUG");
                                    $response = $client->request("GET", $query_string, array("sink" => $file_handle));
                                    $content_type = $response->getHeader("Content-Type");
                                } catch (Exception $e) {
                                    $jomres_user_feedback = jomres_singleton_abstract::getInstance("jomres_user_feedback");
                                    $jomres_user_feedback->construct_message(array("message" => "Could not download plugin " . $pluginName, "css_class" => "alert-danger alert-error"));
                                }
                                if ($content_type == "text/html") {
                                    $output2 = array();
                                    $pageoutput2 = array();
                                    $returned_error = json_decode(file_get_contents($newfilename));
                                    $output2["_JOMRES_ERROR"] = jr_gettext("_JOMRES_ERROR", "_JOMRES_ERROR", false, false);
                                    $output2["MESSAGE"] = filter_var($returned_error->message, FILTER_SANITIZE_STRING);
                                    $output2["PLUGIN_MANAGER_LINK"] = JOMRES_SITEPAGE_URL_ADMIN . "&task=showplugins";
                                    $output2["PLUGIN_MANAGER_TEXT"] = jr_gettext("_JOMRES_CUSTOMCODE_PLUGINMANAGER", "_JOMRES_CUSTOMCODE_PLUGINMANAGER", false, false);
                                    $pageoutput2[] = $output2;
                                    $tmpl = new patTemplate();
                                    $tmpl->addRows("pageoutput", $pageoutput2);
                                    $tmpl->setRoot(JOMRES_TEMPLATEPATH_ADMINISTRATOR);
                                    $tmpl->readTemplatesFromInput("plugin_manager_error.html");
                                    $tmpl->displayParsedTemplate();
                                    emptyDir($updateDirPath . "unpacked");
                                    rmdir($updateDirPath . "unpacked");
                                    return NULL;
                                }
                                if (is_resource($file_handle)) {
                                    fclose($file_handle);
                                }
                            } else {
                                echo "Oops, that key isn't valid";
                                return NULL;
                            }
                        }
                        if (!file_exists($newfilename) || filesize($newfilename) == 0) {
                            $error_messsage["ERROR"] = "Something went wrong downloading the update files. Quitting";
                            if ($autoupgrade) {
                                return false;
                            }
                        }
                        $progress_messages[] = array("MESSAGE" => "Downloaded " . $newfilename);
                        if (is_dir($updateDirPath . "unpacked")) {
                            $progress_messages[] = array("MESSAGE" => "Starting extraction of " . $newfilename);
                            clearstatcache();
                            $zip = new ZipArchive();
                            $res = $zip->open($newfilename);
                            if ($res === true) {
                                if (!$thirdparty) {
                                    $zip->extractTo($updateDirPath . "unpacked");
                                } else {
                                    $zip->extractTo($updateDirPath . "unpacked");
                                    $source = $updateDirPath . "unpacked" . JRDS . $pluginName . JRDS;
                                    $destination = $updateDirPath . "unpacked" . JRDS;
                                    dirmv($source, $destination);
                                    rmdir($source);
                                }
                                $zip->close();
                            } else {
                                $error_messsage["ERROR"] = " Unable to unzip " . $newfilename;
                            }
                            if (!unlink($newfilename)) {
                                $error_messsage["ERROR"] = "Error removing " . $newfilename;
                            }
                            $progress_messages[] = array("MESSAGE" => "Completed extract of " . $newfilename);
                            $progress_messages[] = array("MESSAGE" => "Moving contents of " . $updateDirPath . "unpacked to " . $remote_pluginsDirPath . $pluginName . "");
                            if (file_exists($updateDirPath . "unpacked" . JRDS . "plugin_dependencies_check.php")) {
                                require_once $updateDirPath . "unpacked" . JRDS . "plugin_dependencies_check.php";
                                $info = new plugin_check_dependencies();
                                if (!$info->test_result) {
                                    if ($this->key_valid) {
                                        foreach ($info->dependencies as $d) {
                                            $auto_installation_result = array();
                                            if (!$autoupgrade) {
                                                $auto_installation_result["MESSAGE"] = "Attempting to auto-install dependancies";
                                            }
                                            $result = $MiniComponents->specificEvent("16000", "addplugin", array("plugin" => $d, "autoupgrade" => true));
                                            if (!$autoupgrade) {
                                                $discovery_required = false;
                                                if ($result["success"]) {
                                                    $auto_installation_result["MESSAGE"] = "Auto installed " . $d . " as it is required by " . $pluginName . ".";
                                                    if ($result["discovery_required"]) {
                                                        $discovery_required = true;
                                                    }
                                                } else {
                                                    $auto_installation_result["MESSAGE"] = "Failed to auto install " . $d . ". Please install the plugin manually through the plugin manager.";
                                                }
                                                $auto_installation_results[] = $auto_installation_result;
                                            }
                                        }
                                    } else {
                                        $error_messsage["ERROR"] = " Failed dependencies check. Please ensure that you've installed the following plugins before attempting to install this one: ";
                                        foreach ($info->dependencies as $d) {
                                            $error_messsage["ERROR"] .= "<a href=\"" . JOMRES_SITEPAGE_URL_ADMIN . "&task=addplugin&no_html=1&plugin=" . $d . "\" target=\"_blank\">" . $d . "</a>";
                                        }
                                    }
                                }
                            }
                            $exclusions = array();
                            if (file_exists($updateDirPath . "unpacked" . JRDS . "plugin_exclusions_check.php")) {
                                require_once $updateDirPath . "unpacked" . JRDS . "plugin_exclusions_check.php";
                                $info = new plugin_check_exclusions();
                                if (!$info->test_result) {
                                    $error_messsage["ERROR"] = " Failed plugin_check_exclusions check. Please ensure that you've un-installed the following plugins before attempting to install this one: ";
                                    foreach ($info->exclusions as $d) {
                                        $exclusions[] = array("MESSAGE" => "Error, the plugin you are trying to install cannot be installed because " . $d . " is already installed.");
                                    }
                                    if ($autoupgrade) {
                                        return false;
                                    }
                                }
                            }
                            if (!file_exists($updateDirPath . "unpacked" . JRDS . "plugin_info.php")) {
                                $error_messsage["ERROR"] = " Plugin info file does not exist, cannot continue with installation. ";
                            } else {
                                require_once $updateDirPath . "unpacked" . JRDS . "plugin_info.php";
                                $classname = "plugin_info_" . $pluginName;
                                $plugin_class = new $classname();
                                $min_jomres_ver = explode(".", $plugin_class->data["min_jomres_ver"]);
                                if (count($min_jomres_ver) == 3 && count($this_jomres_version) == 3) {
                                    list($min_major_version, $min_minor_version, $min_revis_version) = $min_jomres_ver;
                                    list($current_major_version, $current_minor_version, $current_revis_version) = $this_jomres_version;
                                    $error = true;
                                    if ($min_major_version <= $current_major_version && $min_minor_version <= $current_minor_version && $min_revis_version <= $current_revis_version) {
                                        $error = false;
                                    }
                                    if ($min_major_version <= $current_major_version && $min_minor_version < $current_minor_version) {
                                        $error = false;
                                    }
                                    if ($min_major_version < $current_major_version) {
                                        $error = false;
                                    }
                                    if ($error) {
                                        $error_messsage["ERROR"] = "Error, this plugin requires at least version " . $plugin_class->data["min_jomres_ver"] . " of Jomres";
                                        if ($autoupgrade) {
                                            return false;
                                        }
                                    }
                                }
                                $plugin_installed_successfully = false;
                                if (is_dir(JOMRES_REMOTEPLUGINS_ABSPATH . $pluginName)) {
                                    emptyDir(JOMRES_REMOTEPLUGINS_ABSPATH . $pluginName);
                                    $progress_messages[] = array("MESSAGE" => "Removing " . JOMRES_REMOTEPLUGINS_ABSPATH . $pluginName . "");
                                    @rmdir(JOMRES_REMOTEPLUGINS_ABSPATH . $pluginName);
                                }
                                if (is_dir(JOMRES_COREPLUGINS_ABSPATH . $pluginName)) {
                                    emptyDir(JOMRES_COREPLUGINS_ABSPATH . $pluginName);
                                    $progress_messages[] = array("MESSAGE" => "Removing " . JOMRES_COREPLUGINS_ABSPATH . $pluginName . "");
                                    @rmdir(JOMRES_COREPLUGINS_ABSPATH . $pluginName);
                                }
                                if (!is_dir(JOMRES_COREPLUGINS_ABSPATH . $pluginName . JRDS) && !mkdir(JOMRES_COREPLUGINS_ABSPATH . $pluginName . JRDS)) {
                                    $error_messsage["ERROR"] = "Couldn't make the folder " . JOMRES_COREPLUGINS_ABSPATH . $pluginName . JRDS . " so quitting.";
                                    if ($autoupgrade) {
                                        return false;
                                    }
                                }
                                $result = dirmv($updateDirPath . "unpacked", $remote_pluginsDirPath . $pluginName, true, $funcloc = JRDS);
                                if ($result["success"]) {
                                    $progress_messages[] = array("MESSAGE" => "Moved contents of " . $newfilename . " to " . $remote_pluginsDirPath . $pluginName . "");
                                    emptyDir($updateDirPath . "unpacked");
                                    if (!rmdir($updateDirPath . "unpacked")) {
                                        echo "Error removing " . $updateDirPath . "unpacked";
                                    }
                                    if (!rmdir($updateDirPath)) {
                                        echo "Error removing " . $updateDirPath;
                                    }
                                    if (file_exists($remote_pluginsDirPath . $pluginName . JRDS . "plugin_install.php")) {
                                        require_once $remote_pluginsDirPath . $pluginName . JRDS . "plugin_install.php";
                                    }
                                    touch($remote_pluginsDirPath . $pluginName . JRDS . "index.html");
                                    if (isset($plugin_class->data["type"]) && ($plugin_class->data["type"] == "mambot" || $plugin_class->data["type"] == "module" || $plugin_class->data["type"] == "widget")) {
                                        if (this_cms_is_joomla() || this_cms_is_wordpress()) {
                                            if (!$autoupgrade) {
                                                $plugin_installed_successfully = true;
                                                $discovery_required = true;
                                            } else {
                                                $this->retVals = array("success" => true, "discovery_required" => true);
                                            }
                                        } else {
                                            if (!$autoupgrade) {
                                                $plugin_installed_successfully = true;
                                                if (!isset($discovery_required)) {
                                                    $discovery_required = false;
                                                }
                                            } else {
                                                $this->retVals = array("success" => true, "discovery_required" => false);
                                            }
                                        }
                                    } else {
                                        if (!$autoupgrade) {
                                            $plugin_installed_successfully = true;
                                            if (!isset($discovery_required)) {
                                                $discovery_required = false;
                                            }
                                        } else {
                                            $this->retVals = array("success" => true, "discovery_required" => false);
                                        }
                                    }
                                } else {
                                    $error_messsage["ERROR"] = "There was an error while unpacking and moving the plugin";
                                }
                            }
                        } else {
                            $error_messsage["ERROR"] = "Error " . $updateDirPath . "unpacked does not exist";
                        }
                        $registry = jomres_singleton_abstract::getInstance("minicomponent_registry");
                        $registry->regenerate_registry();
                        emptyDir(JOMRES_CACHE_ABSPATH);
                        if (!$autoupgrade) {
                            if ($plugin_installed_successfully) {
                                $success = array();
                                if ($discovery_required) {
                                    if ($plugin_class->data["type"] == "widget") {
                                        $output["NEXT_STEP"] = get_showtime("live_site") . "/" . JOMRES_ADMINISTRATORDIRECTORY . "/plugins.php";
                                        $success[] = array("MESSAGE" => "Successfully installed the " . $pluginName . " plugin. The next button will take you to the Wordpress plugins page where you can activate the plugin.");
                                    } else {
                                        $output["NEXT_STEP"] = get_showtime("live_site") . "/" . JOMRES_ADMINISTRATORDIRECTORY . "/index.php?option=com_installer&view=discover";
                                        $success[] = array("MESSAGE" => "Successfully installed the " . $pluginName . " plugin. The next button will take you to the Extension Discovery page where you can finish the plugin's installation.");
                                    }
                                } else {
                                    $output["NEXT_STEP"] = JOMRES_SITEPAGE_URL_ADMIN . "&task=showplugins#" . $pluginName;
                                    $success[] = array("MESSAGE" => "Successfully installed the " . $pluginName . " plugin. The next page will take you back to the Jomres plugin manager.");
                                }
                            }
                            $pageoutput[] = $output;
                            $error_messages[] = $error_messsage;
                            $tmpl = new patTemplate();
                            $tmpl->addRows("pageoutput", $pageoutput);
                            $tmpl->addRows("error_messages", $error_messages);
                            $tmpl->addRows("auto_installation_results", $auto_installation_results);
                            $tmpl->addRows("progress_messages", $progress_messages);
                            $tmpl->addRows("exclusions", $exclusions);
                            $tmpl->addRows("success", $success);
                            $tmpl->setRoot(JOMRES_TEMPLATEPATH_ADMINISTRATOR);
                            $tmpl->readTemplatesFromInput("plugin_installation_result.html");
                            $tmpl->displayParsedTemplate();
                        } else {
                            if ($ajax_install) {
                                ob_clean();
                                $this->retVals["install_button"] = "<a onclick=\"install_plugin('" . $pluginName . "');\" class=\"btn btn-primary\" id=\"install_button_content_" . $pluginName . "\" >Reinstall</a>";
                                $this->retVals["uninstall_button"] = "<a onclick=\"uninstall_plugin('" . $pluginName . "');\" class=\"btn btn-danger\" id=\"uninstall_button_content_" . $pluginName . "\">Uninstall</a>";
                                echo json_encode($this->retVals);
                            } else {
                                echo "1";
                            }
                        }
                    } else {
                        $error_messsage["ERROR"] = "Couldn't make the folder " . $updateDirPath . "unpacked so quitting.";
                        echo $error_messsage["ERROR"];
                        return NULL;
                    }
                } else {
                    $error_messsage["ERROR"] = "Couldn't make the folder " . $updateDirPath . " so quitting.";
                    echo $error_messsage["ERROR"];
                    return NULL;
                }
            }
        }
    }
    public function getRetVals()
    {
    }
}

?>