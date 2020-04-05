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
 * @version Jomres 9.9.5
 *
 * @copyright	2005-2017 Vince Wooll
 * Jomres (tm) PHP, CSS & Javascript files are released under both MIT and GPL2 licenses. This means that you can choose the license that best suits your project, and use it accordingly
 **/
class j16000showplugins
{
    public function __construct()
    {
        $MiniComponents = jomres_singleton_abstract::getInstance("mcHandler");
        if ($MiniComponents->template_touch) {
            $this->template_touchable = false;
        } else {
            if (isset($_REQUEST["purchase"])) {
                $items = "&items=" . jomresGetParam($_REQUEST, "items", "");
                $username = "&username=" . jomresGetParam($_REQUEST, "username", "");
                $password = "&password=" . jomresGetParam($_REQUEST, "password", "");
                jomresRedirect(jomresURL(JOMRES_SITEPAGE_URL_ADMIN . "&task=purchase_plugins" . $username . $password . $items), "");
                exit;
            }
            $ePointFilepath = get_showtime("ePointFilepath");
            $registry = jomres_singleton_abstract::getInstance("minicomponent_registry");
            $registry->regenerate_registry(true);
            jomres_cmsspecific_addheaddata("javascript", JOMRES_JS_RELPATH, "shop.js");
            jomres_cmsspecific_addheaddata("javascript", JOMRES_NODE_MODULES_RELPATH . "blockui-npm/", "jquery.blockUI.js");
            $siteConfig = jomres_singleton_abstract::getInstance("jomres_config_site_singleton");
            $jrConfig = $siteConfig->get();
            $this_jomres_version = explode(".", $jrConfig["version"]);
            $installed_plugins = array();
            $jrePath = JOMRES_REMOTEPLUGINS_ABSPATH;
            $third_party_plugins = array();
            if (!is_dir($jrePath) && !@mkdir($jrePath)) {
                echo "Error, unable to make folder " . $jrePath . " automatically therefore cannot install plugins. Please create the folder manually and ensure that it's writable by the web server";
            } else {
                $jrcPath = JOMRES_COREPLUGINS_ABSPATH;
                $third_party_plugins = array();
                if (!is_dir($jrcPath) && !@mkdir($jrcPath)) {
                    echo "Error, unable to make folder " . $jrcPath . " automatically therefore cannot install plugins. Please create the folder manually and ensure that it's writable by the web server";
                } else {
                    jr_import("jomres_check_support_key");
                    $key_validation = new jomres_check_support_key(JOMRES_SITEPAGE_URL_ADMIN . "&task=showplugins");
                    if (!isset($key_validation->allowed_plugins)) {
                        $key_validation->check_license_key(true);
                    }
                    $this->key_valid = $key_validation->key_valid;
                    if ($key_validation->is_trial_license == "1" && !extension_loaded("IonCube Loader") && trim($key_validation->key_hash) != "") {
                        jomresRedirect(JOMRES_SITEPAGE_URL_ADMIN . "&task=loader_wizard");
                    }
                    if ($key_validation->is_trial_license == "1" && function_exists("ioncube_loader_version")) {
                        $ioncubeVersion = ioncube_loader_version();
                        $ioncubeMajorVersion = (int) substr($ioncubeVersion, 0, strpos($ioncubeVersion, "."));
                        $ioncubeMinorVersion = (int) substr($ioncubeVersion, strpos($ioncubeVersion, ".") + 1);
                        if ($ioncubeMajorVersion < 5 || $ioncubeMajorVersion == 0 && $ioncubeMinorVersion < 21) {
                            echo "<p class='alert alert-warning'>Uh oh, Ioncube loaders are installed, however they may be too old to run these scripts.</p><p>Please visit <a href='http://www.ioncube.com/loaders.php' target='_blank'>Ioncube's website</a> to download the most current versions of the loader wizard. This will walk you through installing the loaders. Alternatively, ask your hosts for help.</p>";
                            return NULL;
                        }
                    }
                    $developer_user = false;
                    $siteConfig = jomres_singleton_abstract::getInstance("jomres_config_site_singleton");
                    $jrConfig = $siteConfig->get();
                    $current_licenses = array();
                    if ($this->key_valid) {
                        $developer_user = true;
                    } else {
                        if (isset($key_validation->plugin_licenses) && 0 < count($key_validation->plugin_licenses)) {
                            foreach ($key_validation->plugin_licenses as $key => $val) {
                                if ($val["status"] == 1) {
                                    $current_licenses[$key] = $val["key"];
                                }
                            }
                        }
                    }
                    $remote_plugins_data = queryUpdateServer("", "r=dp&format=json&cms=" . _JOMRES_DETECTED_CMS . "&key=" . $key_validation->key_hash);
                    $rp_array = json_decode($remote_plugins_data);
                    if (empty($rp_array)) {
                        echo "<div class='alert alert-error alert-danger'>Uh oh, Can't get a list of plugins from the plugin server. Is there a firewall preventing your server from talking to http://plugins.jomres4.net ?</div>";
                    } else {
                        foreach ($rp_array as $rp) {
                            $price_known = true;
                            if (!isset($rp->price)) {
                                $price_known = false;
                            }
                            $remote_plugins[trim(jomres_sanitise_string($rp->name))] = array("name" => isset($rp->name) ? trim(jomres_sanitise_string($rp->name)) : "", "version" => isset($rp->version) ? (double) $rp->version : 1, "lastupdate" => isset($rp->lastupdate) ? jomres_sanitise_string($rp->lastupdate) : "", "description" => isset($rp->description) ? jomres_sanitise_string($rp->description) : "", "type" => isset($rp->type) ? jomres_sanitise_string($rp->type) : "", "min_jomres_ver" => isset($rp->min_jomres_ver) ? jomres_sanitise_string($rp->min_jomres_ver) : "1", "price" => isset($rp->price) ? jomres_sanitise_string($rp->price) : "0", "manual_link" => isset($rp->manual_link) ? jomres_sanitise_string($rp->manual_link) : "", "change_log" => isset($rp->change_log) ? jomres_sanitise_string($rp->change_log) : "", "highlight" => isset($rp->highlight) ? jomres_sanitise_string($rp->highlight) : "", "image" => isset($rp->image) ? jomres_sanitise_string($rp->image) : "", "demo_url" => isset($rp->demo_url) ? addslashes($rp->demo_url) : "", "retired" => isset($rp->retired) ? (bool) $rp->retired : false);
                        }
                        $d = @dir($jrePath);
                        if ($d) {
                            while (false !== ($entry = $d->read())) {
                                $filename = $entry;
                                if (substr($entry, 0, 1) != "." && file_exists($jrePath . $entry . JRDS . "plugin_info.php")) {
                                    include_once $jrePath . $entry . JRDS . "plugin_info.php";
                                    $cname = "plugin_info_" . $entry;
                                    if (class_exists($cname)) {
                                        $info = new $cname();
                                        $installed_plugins[$info->data["name"]] = $info->data;
                                    }
                                }
                            }
                            foreach ($installed_plugins as $key => $val) {
                                if (!array_key_exists($key, $remote_plugins)) {
                                    $third_party_plugins[$key] = $val;
                                }
                            }
                        }
                        $d = @dir($jrcPath);
                        if ($d) {
                            while (false !== ($entry = $d->read())) {
                                $filename = $entry;
                                if (substr($entry, 0, 1) != "." && file_exists($jrcPath . $entry . JRDS . "plugin_info.php")) {
                                    $encoded = false;
                                    $fa_icon = "";
                                    $line = fgets(fopen($jrcPath . $entry . JRDS . "plugin_info.php", "r"));
                                    $result = substr($line, 0, 13);
                                    if ($result == "<?php //004fb") {
                                        $encoded = true;
                                        $fa_icon = "<i class=\"fa fa-lock\"></i>";
                                    }
                                    include_once $jrcPath . $entry . JRDS . "plugin_info.php";
                                    $cname = "plugin_info_" . $entry;
                                    if (class_exists($cname)) {
                                        $info = new $cname();
                                        $info->data["encoded"] = $encoded;
                                        $info->data["encoded_icon"] = $fa_icon;
                                        $installed_plugins[$info->data["name"]] = $info->data;
                                    }
                                }
                            }
                            foreach ($installed_plugins as $key => $val) {
                                if (!array_key_exists($key, $remote_plugins)) {
                                    $third_party_plugins[$key] = $val;
                                }
                            }
                        }
                        $encoded_count = 0;
                        foreach ($installed_plugins as $key => $val) {
                            if (isset($installed_plugins[$key]["encoded"]) && $installed_plugins[$key]["encoded"] == true) {
                                $encoded_count++;
                            }
                        }
                        $encoded_on_full_license = array();
                        $output = array();
                        $pageoutput = array();
                        $output["PAGETITLE"] = "Jomres Plugin Manager";
                        if ($jrConfig["licensekey"] == "") {
                            $output["LICENSE_MESSAGE"] = jr_gettext("NO_LICENSE_MESSAGE", "NO_LICENSE_MESSAGE", false);
                            $output["LICENSE_MESSAGE_CLASS"] = "danger";
                        } else {
                            if (!$this->key_valid) {
                                if ($key_validation->license_name == "Developer Subscription" || $key_validation->license_name == "Basic Subscription") {
                                    $output["LICENSE_MESSAGE"] = jr_gettext("PLUGIN_MANAGER_REMOVE_PLUGINS", "PLUGIN_MANAGER_REMOVE_PLUGINS", false);
                                    $output["LICENSE_MESSAGE_CLASS"] = "danger";
                                } else {
                                    $output["LICENSE_MESSAGE"] = jr_gettext("INVALID_LICENSE_MESSAGE", "INVALID_LICENSE_MESSAGE", false);
                                    $output["LICENSE_MESSAGE_CLASS"] = "danger";
                                }
                            } else {
                                $output["LICENSE_MESSAGE"] = jr_gettext("VALID_LICENSE_MESSAGE", "VALID_LICENSE_MESSAGE", false);
                                $output["LICENSE_MESSAGE_CLASS"] = "success";
                            }
                        }
                        $bronze_users = array();
                        if (!$developer_user) {
                            if ($jrConfig["license_server_username"] == "") {
                                $jrConfig["license_server_username"] = " ";
                                $jrConfig["license_server_password"] = " ";
                            }
                            $bronze_users[0]["license_server_username"] = $jrConfig["license_server_username"];
                            $bronze_users[0]["license_server_password"] = $jrConfig["license_server_password"];
                        }
                        if ($developer_user) {
                            $bronze_users[0]["dummy"] = " ";
                        }
                        $uninstall_text = "Uninstall";
                        $externalPluginTypes = array("component", "module", "mambot");
                        $this->set_main_plugins();
                        $thirdpartyplugins = array();
                        foreach ($third_party_plugins as $tpp) {
                            if (!isset($tpp["type"])) {
                                $tpp["type"] = "Unknown";
                            }
                            $type = $tpp["type"];
                            $n = $tpp["name"];
                            $row_class = "availablefordownload";
                            $uninstallAction = " ";
                            $already_installed = false;
                            $uninstallLink = "";
                            if (array_key_exists($n, $installed_plugins)) {
                                $already_installed = true;
                                $uninstallAction = $uninstall_text;
                                $row_class = "alreadyinstalled";
                                $uninstallLink = JOMRES_SITEPAGE_URL_ADMIN . "&task=removeplugin&no_html=1&plugin=" . $n;
                            }
                            $local_version = $installed_plugins[$n]["version"];
                            if (!array_key_exists($n, $installed_plugins)) {
                                $local_version = "N/A";
                            }
                            $r = array();
                            $r["UNINSTALL"] = $uninstallAction;
                            $r["ROWCLASS"] = $row_class;
                            $r["NAME"] = $tpp["name"];
                            $r["LOCALVERSION"] = $local_version;
                            if (!isset($tpp["authoremail"])) {
                                $tpp["authoremail"] = "Unknown";
                            }
                            if (!isset($tpp["author"])) {
                                $tpp["author"] = "Unknown";
                            }
                            if (!isset($tpp["description"])) {
                                $tpp["description"] = "Unknown";
                            }
                            $r["DESCRIPTION"] = stripslashes($tpp["description"]);
                            $r["AUTHOR"] = stripslashes($tpp["author"]);
                            $r["AUTHOREMAIL"] = stripslashes($tpp["authoremail"]);
                            $r["UNINSTALLLINK"] = $uninstallLink;
                            $r["THIRD_PARTY_PLUGIN_LATEST_AVAILABLE_VERSION"] = "Unknown";
                            $r["DEVELOPER_PAGE"] = "";
                            $r["LATEST_RELEASE"] = "";
                            if (isset($tpp["third_party_plugin_latest_available_version"])) {
                                $file_headers = @get_headers($tpp["third_party_plugin_latest_available_version"]);
                                if ($file_headers[0] != "HTTP/1.0 404 Not Found") {
                                    $r["MIN_JOMRES_VER"] = (double) $tpp["min_jomres_ver"];
                                    $ctx = stream_context_create(array("http" => array("timeout" => 1)));
                                    $remote_plugin_data = json_decode(@file_get_contents($tpp["third_party_plugin_latest_available_version"], false, $ctx));
                                    if (isset($remote_plugin_data->version)) {
                                        $r["THIRD_PARTY_PLUGIN_LATEST_AVAILABLE_VERSION"] = (double) $remote_plugin_data->version;
                                        $r["LATEST_RELEASE"] = $remote_plugin_data->releaseDate;
                                    }
                                }
                            }
                            if (isset($tpp["developer_page"])) {
                                $r["DEVELOPER_PAGE"] = "<a href=\"" . $tpp["developer_page"] . "\" target=\"_blank\">Website</a>";
                            }
                            $thirdpartyplugins[] = $r;
                        }
                        $span = 12;
                        if ($developer_user) {
                            $span = 11;
                        }
                        $output["SPAN"] = $span;
                        $install_text = "Install";
                        $reinstall_text = "Reinstall";
                        $upgrade_text = "Update";
                        $uninstall_text = "Uninstall";
                        $externalPluginTypes = array("component", "module", "mambot");
                        $jomresdotnet_plugins = array();
                        $jomresdotnet_apiplugins = array();
                        $jomresdotnet_webhooksplugins = array();
                        $plugins_needing_upgrading = array();
                        $all_installed_plugins = array();
                        $button_disabled_text = "";
                        if (!$this->key_valid) {
                            if (using_bootstrap()) {
                                $button_disabled_text = " disabled ";
                            } else {
                                $button_disabled_text = " ui-state-disabled ";
                            }
                        }
                        $retired_plugins = array();
                        $output["HPLUGINPRICE"] = "";
                        if (!$developer_user && $key_validation->shop_status == "OPEN") {
                            $output["HPLUGINPRICE"] = "Plugin price";
                        }
                        foreach ($remote_plugins as $rp) {
                            $r = array();
                            $type = $rp["type"];
                            $plugin_name = $rp["name"];
                            if ($developer_user) {
                                $n = $rp["name"];
                            } else {
                                if (array_key_exists($plugin_name, $current_licenses)) {
                                    $n = $plugin_name . "&plugin_key=" . $current_licenses[$plugin_name];
                                } else {
                                    $n = $rp["name"];
                                }
                            }
                            $min_jomres_ver = explode(".", $rp["min_jomres_ver"]);
                            $row_class = "";
                            $installAction = $install_text;
                            $uninstallAction = " ";
                            if (array_key_exists($rp["name"], $installed_plugins)) {
                                $uninstallAction = $uninstall_text;
                                $installAction = $reinstall_text;
                                $row_class = "ui-state-success";
                                $all_installed_plugins[] = $plugin_name;
                                if ($installed_plugins[$plugin_name]["version"] < $rp["version"]) {
                                    $plugins_needing_upgrading[] = $plugin_name;
                                    $installAction = $upgrade_text;
                                    $row_class = "ui-state-highlight";
                                }
                                if ($rp["retired"]) {
                                    $row_class = "ui-state-error";
                                    $retired_plugins[] = $plugin_name;
                                }
                            }
                            $r["INSTALL_LINK"] = "";
                            $r["INSTALL_TEXT"] = $installAction;
                            if (array_key_exists($plugin_name, $current_licenses) || $developer_user) {
                                $r["INSTALL_LINK"] = JOMRES_SITEPAGE_URL_ADMIN . "&task=addplugin&plugin=" . $n;
                                $r["INSTALL_TEXT"] = $installAction;
                            }
                            if (isset($installed_plugins[$plugin_name]["encoded_icon"])) {
                                $r["ENCODED_ICON"] = $installed_plugins[$plugin_name]["encoded_icon"];
                            } else {
                                $r["ENCODED_ICON"] = "";
                            }
                            $r["UNINSTALL_LINK"] = "";
                            $r["UNINSTALL_TEXT"] = "";
                            $r["UNINSTALL"] = "";
                            if (array_key_exists($rp["name"], $installed_plugins)) {
                                $r["UNINSTALL_LINK"] = JOMRES_SITEPAGE_URL_ADMIN . "&task=removeplugin&no_html=1&plugin=" . $n;
                                $r["UNINSTALL_TEXT"] = $uninstallAction;
                                if (!$rp["retired"]) {
                                    $r["UNINSTALL"] = "<a onclick=\"uninstall_plugin('" . $rp["name"] . "');\" class=\"btn btn-danger\" id=\"uninstall_button_content_" . $rp["name"] . "\" >" . $uninstall_text . "</a>";
                                } else {
                                    $r["UNINSTALL"] = "<a href=\"" . $r["UNINSTALL_LINK"] . "\" class=\"btn btn-success\" >" . $uninstall_text . "</a>";
                                }
                            }
                            if (isset($installed_plugins[$plugin_name])) {
                                $local_version = $installed_plugins[$plugin_name]["version"];
                            } else {
                                $local_version = "";
                            }
                            if (!array_key_exists($plugin_name, $installed_plugins)) {
                                $local_version = "N/A";
                            }
                            $style = "";
                            if ($rp["price"] == 0 && $row_class == "") {
                                $row_class = "";
                                $style = "";
                            }
                            $r["MANUAL_LINK"] = "";
                            $r["MANUAL_TEXT"] = "";
                            $r["MANUAL_CLASS"] = "";
                            if (isset($rp["manual_link"]) && $rp["manual_link"] != "") {
                                $r["MANUAL_LINK"] = $rp["manual_link"];
                                $r["MANUAL_TEXT"] = "Manual";
                                $r["MANUAL_CLASS"] = "btn";
                            }
                            $r["DEMO_LINK"] = "";
                            $r["DEMO_TEXT"] = "";
                            $r["DEMO_CLASS"] = "";
                            if (isset($rp["demo_url"]) && $rp["demo_url"] != "") {
                                $r["DEMO_LINK"] = $rp["demo_url"];
                                $r["DEMO_TEXT"] = "Demo";
                                $r["DEMO_CLASS"] = "btn";
                            }
                            $r["CHANGELOG"] = "";
                            if ($rp["change_log"] != "") {
                                $r["CHANGELOG"] = $rp["change_log"];
                            }
                            $r["HIGHLIGHT"] = "";
                            $r["HIGHLIGHT_CLASS"] = "";
                            if ($rp["highlight"] != "") {
                                $r["HIGHLIGHT"] = $rp["highlight"];
                                $r["HIGHLIGHT_CLASS"] = "alert alert-warning";
                            }
                            $readable_name = ucwords(" " . str_replace("_", " ", $rp["name"]));
                            $r["READABLE_NAME"] = $readable_name;
                            $r["IMAGE"] = $rp["image"];
                            $r["PLUGIN_NAME"] = $rp["name"];
                            $r["MIN_JOMRES_VER"] = $rp["min_jomres_ver"];
                            $r["LOCAL_VER"] = $local_version;
                            $r["REMOTE_VER"] = $rp["version"];
                            $r["PLUGIN_DESC"] = stripslashes($rp["description"]);
                            $r["LASTUPDATE"] = $rp["lastupdate"];
                            list($min_major_version, $min_minor_version, $min_revis_version) = $min_jomres_ver;
                            list($current_major_version, $current_minor_version, $current_revis_version) = $this_jomres_version;
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
                                $r["LATERVERSION"] = "";
                            }
                            if ($condition == 1 && (array_key_exists($rp["name"], $current_licenses) || $developer_user)) {
                                if (using_bootstrap()) {
                                    $r["INSTALL"] = "<a onclick=\"install_plugin('" . $rp["name"] . "');\" class=\"btn btn-primary\"  id=\"install_button_content_" . $rp["name"] . "\" >" . $r["INSTALL_TEXT"] . "</a>";
                                } else {
                                    $r["INSTALL"] = "<a href=\"" . $r["INSTALL_LINK"] . "\" class=\"fg-button ui-state-default ui-corner-all \"   >" . $r["INSTALL_TEXT"] . "</a>";
                                }
                            }
                            if ($key_validation->allowed_plugins[0] != "*" && !in_array($rp["name"], $key_validation->allowed_plugins)) {
                                $r["INSTALL"] = "<a class=\"btn btn-primary disabled\"  >" . $r["INSTALL_TEXT"] . "</a>";
                            }
                            if ($rp["retired"]) {
                                $r["INSTALL"] = "";
                            }
                            if (using_bootstrap()) {
                                switch ($row_class) {
                                    case "ui-state-success":
                                        $row_class = "alert alert-success";
                                        break;
                                    case "ui-state-highlight":
                                        $row_class = "alert alert-warning";
                                        break;
                                    case "freeplugin":
                                        $row_class = "alert alert-info";
                                        break;
                                    case "ui-state-error":
                                        $row_class = "alert alert-danger";
                                        break;
                                    default:
                                        $row_class = "";
                                        break;
                                }
                            }
                            $r["ROWCLASS"] = $row_class;
                            $r["STYLE"] = $style;
                            if (substr($rp["name"], 0, 4) == "api_") {
                                if ($rp["retired"] && array_key_exists($rp["name"], $installed_plugins)) {
                                    $jomresdotnet_apiplugins[] = $r;
                                } else {
                                    if (!$rp["retired"]) {
                                        $jomresdotnet_apiplugins[] = $r;
                                    }
                                }
                            } else {
                                if (substr($rp["name"], 0, 9) == "webhooks_") {
                                    if ($rp["retired"] && array_key_exists($rp["name"], $installed_plugins)) {
                                        $jomresdotnet_webhooksplugins[] = $r;
                                    } else {
                                        if (!$rp["retired"]) {
                                            $jomresdotnet_webhooksplugins[] = $r;
                                        }
                                    }
                                } else {
                                    if ($rp["retired"] && array_key_exists($rp["name"], $installed_plugins)) {
                                        $jomresdotnet_plugins[] = $r;
                                    } else {
                                        if (!$rp["retired"]) {
                                            $jomresdotnet_plugins[] = $r;
                                        }
                                    }
                                }
                            }
                        }
                        if (0 < count($retired_plugins)) {
                            $count = count($jomresdotnet_plugins);
                            for ($i = 0; $i < $count; $i++) {
                                if (in_array($jomresdotnet_plugins[$i]["PLUGIN_NAME"], $retired_plugins)) {
                                    $move = $jomresdotnet_plugins[$i];
                                    unset($jomresdotnet_plugins[$i]);
                                    array_unshift($jomresdotnet_plugins, $move);
                                }
                            }
                        }
                        if (0 < count($retired_plugins)) {
                            $count = count($jomresdotnet_apiplugins);
                            for ($i = 0; $i < $count; $i++) {
                                if (in_array($jomresdotnet_apiplugins[$i]["PLUGIN_NAME"], $retired_plugins)) {
                                    $move = $jomresdotnet_apiplugins[$i];
                                    unset($jomresdotnet_apiplugins[$i]);
                                    array_unshift($jomresdotnet_apiplugins, $move);
                                }
                            }
                        }
                        if (0 < count($retired_plugins)) {
                            $count = count($jomresdotnet_webhooksplugins);
                            for ($i = 0; $i < $count; $i++) {
                                if (in_array($jomresdotnet_webhooksplugins[$i]["PLUGIN_NAME"], $retired_plugins)) {
                                    $move = $jomresdotnet_webhooksplugins[$i];
                                    unset($jomresdotnet_webhooksplugins[$i]);
                                    array_unshift($jomresdotnet_webhooksplugins, $move);
                                }
                            }
                        }
                        $output["INSTALLED_PLUGINS"] = implode(",", $all_installed_plugins);
                        $output["PLUGINS_TO_UPGRADE"] = implode(",", $plugins_needing_upgrading);
                        if ($this->key_valid && !empty($plugins_needing_upgrading)) {
                            $plugins_require_upgrade[]["upgrade_text"] = "Upgrade all Core plugins. You must upgrade Jomres first before upgrading plugins.";
                        }
                        if (!isset($plugins_require_upgrade)) {
                            $plugins_require_upgrade = array();
                        }
                        $plugins_reinstall = array();
                        if ($this->key_valid) {
                            $plugins_reinstall[]["REINSTALL_TEXT"] = "Reinstall all installed plugins";
                        }
                        $third_party_dev_plugin_tabs = array();
                        $third_party_dev_plugin_tab_content = array();
                        $MiniComponents->triggerEvent("13200");
                        if (isset($MiniComponents->miniComponentData[13200])) {
                            $third_party_dev_tabs = $MiniComponents->miniComponentData[13200];
                        }
                        if (!empty($third_party_dev_tabs)) {
                            $counter = 0;
                            foreach ($third_party_dev_tabs as $tab) {
                                $third_party_dev_plugin_tabs[$counter]["THIRD_PARTY_PLUGIN_TAB_NAME"] = $tab["TAB_NAME"];
                                $third_party_dev_plugin_tabs[$counter]["THIRD_PARTY_PLUGIN_TAB_ID"] = $tab["TAB_ID"];
                                $third_party_dev_plugin_tab_content[$counter]["THIRD_PARTY_PLUGIN_TAB_CONTENT"] = $tab["TAB_CONTENTS"];
                                $third_party_dev_plugin_tab_content[$counter]["THIRD_PARTY_PLUGIN_TAB_ID"] = $tab["TAB_ID"];
                                $counter++;
                            }
                        }
                        $pageoutput[] = $output;
                        $tmpl = new patTemplate();
                        $tmpl->setRoot($ePointFilepath);
                        $tmpl->addRows("pageoutput", $pageoutput);
                        if ($key_validation->shop_status == "OPEN") {
                            $tmpl->addRows("bronze_users", $bronze_users);
                        }
                        $tmpl->addRows("encoded_on_full_license", $encoded_on_full_license);
                        $tmpl->addRows("thirdpartyplugins", $thirdpartyplugins);
                        $tmpl->addRows("jomresdotnet_plugins", $jomresdotnet_plugins);
                        $tmpl->addRows("jomresdotnet_apiplugins", $jomresdotnet_apiplugins);
                        $tmpl->addRows("jomresdotnet_webhooksplugins", $jomresdotnet_webhooksplugins);
                        $tmpl->addRows("plugins_require_upgrade", $plugins_require_upgrade);
                        $tmpl->addRows("reinstall_plugins", $plugins_reinstall);
                        $tmpl->addRows("third_party_dev_plugin_tabs", $third_party_dev_plugin_tabs);
                        $tmpl->addRows("third_party_dev_plugin_tab_content", $third_party_dev_plugin_tab_content);
                        $tmpl->readTemplatesFromInput("plugin_manager.html");
                        $tmpl->displayParsedTemplate();
                    }
                }
            }
        }
    }
    public function set_main_plugins()
    {
        $this->main_plugins = array();
        $this->main_plugins[] = "advanced_micromanage_tariff_editing_modes";
        $this->main_plugins[] = "black_bookings";
        $this->main_plugins[] = "book_guest_in_out";
        $this->main_plugins[] = "commission";
        $this->main_plugins[] = "core_gateway_paypal";
        $this->main_plugins[] = "coupons";
        $this->main_plugins[] = "custom_fields";
        $this->main_plugins[] = "guest_types";
        $this->main_plugins[] = "lastminute_config_tab";
        $this->main_plugins[] = "optional_extras";
        $this->main_plugins[] = "partners";
        $this->main_plugins[] = "property_creation_plugins";
        $this->main_plugins[] = "sms_clickatell";
        $this->main_plugins[] = "subscriptions";
        $this->main_plugins[] = "template_editing";
        $this->main_plugins[] = "wiseprice_config_tab";
        $this->main_plugins[] = "alternative_init";
        $this->main_plugins[] = "jomres_asamodule";
    }
    public function getRetVals()
    {
    }
}

?>