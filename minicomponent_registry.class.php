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
 * New for v3.2 of Jomres. Allows the system to create a registry file so that the minicomponent handler doesn't need to constantly search folders and record minicomponents on each run.
 */
class minicomponent_registry
{
    private static $configInstance = NULL;
    public function __construct()
    {
        $this->registeredClasses = array();
        $this->miniComponentDirectories = array();
        $this->eventPoints = array();
        $this->new_filesize = 0;
        $this->error_detected = false;
        $this->unWantedFolderContents = array(".", "..", "cvs", ".svn", "registry.php");
        $this->temp_directory = JOMRES_TEMP_ABSPATH;
        $this->registry_file = JOMRES_TEMP_ABSPATH . "registry.php";
        if (file_exists($this->registry_file)) {
            $this->original_filesize = @filesize($this->registry_file);
        } else {
            $this->original_filesize = 0;
        }
        if (!defined("AUTO_UPGRADE")) {
            if (!is_dir($this->temp_directory)) {
                mkdir($this->temp_directory);
            }
            if (!file_exists($this->registry_file)) {
                $this->regenerate_registry();
                $this->new_filesize = filesize($this->registry_file);
            }
            include_once $this->registry_file;
        }
    }
    public static function getInstance()
    {
        if (!self::$configInstance) {
            self::$configInstance = new self();
        }
        return self::$configInstance;
    }
    public function get_registered_classes()
    {
        return $this->registeredClasses;
    }
    public function get_minicomponent_directories()
    {
        return $this->miniComponentDirectories;
    }
    public function regenerate_registry($force_reload_allowed = false)
    {
        if (!defined("AUTO_UPGRADE")) {
            jomres_cmsspecific_addheaddata("javascript", JOMRES_NODE_MODULES_RELPATH . "blockui-npm/", "jquery.blockUI.js");
        }
        $siteConfig = jomres_singleton_abstract::getInstance("jomres_config_site_singleton");
        $jrConfig = $siteConfig->get();
        if (!isset($jrConfig["safe_mode"])) {
            $jrConfig["safe_mode"] = "0";
        }
        $this->registeredClasses = array();
        $this->miniComponentDirectories = array();
        $this->getMiniComponentCoreClasses();
        $this->getMiniComponentCMSSpecificClasses();
        if ($jrConfig["safe_mode"] == "0") {
            $this->getMiniCorePluginsClasses();
            $this->getMiniComponentRemoteClasses();
            if (!defined("AUTO_UPGRADE")) {
                $this->getMiniComponentCmsTemplateClasses();
            }
        }
        asort($this->registeredClasses);
        $this->save_registry_file();
        $this->new_filesize = filesize($this->registry_file);
        $task = jomresGetParam($_REQUEST, "task", "");
        if ($task == "rebuildregistry" || $task == "save_site_settings" || defined("AUTO_UPGRADE")) {
            $javascript_files_in_temp_dir = scandir_getfiles(JOMRES_TEMP_ABSPATH, $extension = "js");
            foreach ($javascript_files_in_temp_dir as $file) {
                unlink(JOMRES_TEMP_ABSPATH . $file);
            }
        }
        if (file_exists(JOMRES_TEMP_ABSPATH . "installed_plugins_data.php")) {
            unlink(JOMRES_TEMP_ABSPATH . "installed_plugins_data.php");
        }
        if (file_exists(JOMRES_TEMP_ABSPATH . "remote_plugins_data.php")) {
            unlink(JOMRES_TEMP_ABSPATH . "remote_plugins_data.php");
        }
        if (file_exists(JOMRES_TEMP_ABSPATH . "registry_classes.php")) {
            unlink(JOMRES_TEMP_ABSPATH . "registry_classes.php");
        }
        if (!defined("AUTO_UPGRADE")) {
            $shortcode_parser = jomres_singleton_abstract::getInstance("jomres_shortcode_parser");
            $shortcode_parser->build_shortcodes($force = true);
        }
        if ($this->original_filesize != $this->new_filesize && $force_reload_allowed) {
            echo "<script>\tjomresJquery.blockUI({ \n\t\t\tmessage: '<h3>Reloading the page as the registry has changed</h3>',\n\t\t\tbaseZ: 1030,\n\t\t\tcss: {\n\t\t\t\tborder: 'none', \n\t\t\t\tpadding: '15px', \n\t\t\t\tbackgroundColor: '#000', \n\t\t\t\t'-webkit-border-radius': '10px', \n\t\t\t\t'-moz-border-radius': '10px', \n\t\t\t\topacity: .8, \n\t\t\t\tcolor: '#fff' \n\t\t\t} });</script><script>window.location.reload();</script>";
        }
    }
    public function save_registry_file()
    {
        $existed = false;
        if (file_exists($this->registry_file)) {
            if (!unlink($this->registry_file)) {
                error_logging("Could not delete existing registry file  :: " . $this->registry_file);
                return false;
            }
            $existed = true;
        }
        $this->miniComponentDirectories = array_unique($this->miniComponentDirectories);
        sort($this->miniComponentDirectories);
        ksort($this->registeredClasses);
        foreach ($this->registeredClasses as $k => $v) {
            ksort($this->registeredClasses[$k]);
        }
        if (!file_put_contents($this->registry_file, "<?php\n##################################################################\ndefined( '_JOMRES_INITCHECK' ) or die( '' );\n##################################################################\n\n\$this->registeredClasses = " . var_export($this->registeredClasses, true) . ";\n\$this->miniComponentDirectories = " . var_export($this->miniComponentDirectories, true) . ";\n")) {
            trigger_error("ERROR: " . $this->registry_file . " can`t be saved. Please solve the permission problem and try again.", 256);
            exit;
        }
    }
    public function getMiniComponentCmsTemplateClasses()
    {
        if (!this_cms_is_joomla() && !this_cms_is_wordpress()) {
            return NULL;
        }
        if (this_cms_is_joomla()) {
            $db = JFactory::getDBO();
            $query = "SELECT `template` FROM #__template_styles WHERE `client_id` = 0 AND `home` = 1";
            $db->setQuery($query);
            $templateName = $db->loadResult();
            $jrePath = JOMRESCONFIG_ABSOLUTE_PATH . "templates" . JRDS . $templateName . JRDS . "html" . JRDS . "com_jomres" . JRDS;
        } else {
            if (this_cms_is_wordpress()) {
                $jrePath = get_stylesheet_directory() . JRDS . "html" . JRDS . "com_jomres" . JRDS;
            } else {
                return NULL;
            }
        }
        $d = @dir($jrePath);
        $docs = array();
        if ($d) {
            while (false !== ($entry = $d->read())) {
                $filename = $entry;
                if (substr($entry, 0, 1) != ".") {
                    $docs[] = $entry;
                }
            }
            $d->close();
            if (!empty($docs)) {
                sort($docs);
                foreach ($docs as $doc) {
                    $listdir = $jrePath . $doc . JRDS;
                    if (is_dir($listdir)) {
                        $dr = @dir($listdir);
                        if ($dr) {
                            while (false !== ($entry = $dr->read())) {
                                $filename = $entry;
                                $this->registerComponentFile($listdir, $filename, "cmstemplate");
                            }
                            $dr->close();
                        }
                    }
                }
            }
        }
    }
    public function getMiniComponentRemoteClasses()
    {
        $jrePath = JOMRES_REMOTEPLUGINS_ABSPATH;
        $d = @dir($jrePath);
        $docs = array();
        if ($d) {
            while (false !== ($entry = $d->read())) {
                $filename = $entry;
                if (substr($entry, 0, 1) != ".") {
                    $docs[] = $entry;
                }
            }
            $d->close();
            if (!empty($docs)) {
                sort($docs);
                foreach ($docs as $doc) {
                    $listdir = $jrePath . $doc . JRDS;
                    $dr = @dir($listdir);
                    if ($dr) {
                        while (false !== ($entry = $dr->read())) {
                            $filename = $entry;
                            $this->registerComponentFile($listdir, $filename, "remotecomponent");
                        }
                        $dr->close();
                    }
                }
            }
        }
    }
    public function getMiniComponentCMSSpecificClasses()
    {
        $jrePath = _JOMRES_DETECTED_CMS_SPECIFIC_FILES;
        $d = @dir($jrePath);
        if ($d) {
            while (false !== ($entry = $d->read())) {
                $filename = $entry;
                $this->registerComponentFile($jrePath, $filename, "cms_specific_component");
            }
            $d->close();
        }
    }
    public function getMiniComponentCoreClasses()
    {
        $listdirs = array(JOMRES_APP_ABSPATH);
        foreach ($listdirs as $listdir) {
            $d = @dir($listdir);
            if ($d) {
                while (false !== ($entry = $d->read())) {
                    $filename = $entry;
                    $this->registerComponentFile($listdir, $filename, "core");
                }
                $d->close();
            }
        }
    }
    public function getMiniCorePluginsClasses()
    {
        $jrePath = JOMRES_COREPLUGINS_ABSPATH;
        $d = @dir($jrePath);
        $docs = array();
        if ($d) {
            while (false !== ($entry = $d->read())) {
                $filename = $entry;
                if (substr($entry, 0, 1) != ".") {
                    $docs[] = $entry;
                }
            }
            $d->close();
            if (!empty($docs)) {
                sort($docs);
                foreach ($docs as $doc) {
                    $listdir = $jrePath . $doc . JRDS;
                    $dr = @dir($listdir);
                    if ($dr) {
                        while (false !== ($entry = $dr->read())) {
                            $filename = $entry;
                            $this->registerComponentFile($listdir, $filename, "core-plugin");
                        }
                        $dr->close();
                    }
                }
            }
        }
    }
    public function registerComponentFile($filePath, $filename, $eventType = "component")
    {
        $classfileEventName = "";
        if (0 < strpos($filename, "__")) {
            $bang = explode("__", $filename);
            $classfileEventPoint = $bang[0];
            $bang = explode(".", $bang[1]);
            $classfileEventName = $bang[0];
        } else {
            $strippedName = str_replace(".", "", $filename);
            $strippedName = substr($strippedName, 0, -8);
            $classfileEventPoint = substr($strippedName, 1, 5);
            if (0 < (int) $classfileEventPoint && (int) $classfileEventPoint <= 99999) {
                $classfileEventName = substr($strippedName, 6);
            }
        }
        $path_parts = pathinfo($filePath . $filename);
        if (isset($path_parts["extension"])) {
            $extension = $path_parts["extension"];
        }
        if (is_file($filePath . $filename) && !in_array(strtolower($filename), $this->unWantedFolderContents) && $classfileEventName != "" && strtolower($extension) == "php") {
            if (isset($this->registeredClasses[$classfileEventPoint][$classfileEventName]) && ($this->registeredClasses[$classfileEventPoint][$classfileEventName]["eventtype"] == "component" || $this->registeredClasses[$classfileEventPoint][$classfileEventName]["eventtype"] == "remotecomponent" || $this->registeredClasses[$classfileEventPoint][$classfileEventName]["eventtype"] == "cms_specific_component")) {
                $text = "";
                $text .= "<font color=\"red\" face=\"arial\" size=\"1\">Warning: Event override collision. You have two or more mini-components attempting to perform the same override function. System behaviour may be unpredictable" . "</font><br>";
                $text .= "<b>" . $classfileEventPoint . $classfileEventName . "</b><br>";
                $text .= "<b>" . $this->registeredClasses[$classfileEventPoint][$classfileEventName]["filepath"] . "</b><br>";
                $text .= "Collides with this and possibly more mini-components: " . "<br>";
                $text .= "<b>" . $classfileEventPoint . $classfileEventName . "</b><br>";
                $text .= "<b>" . $filePath . "</b><br>";
                echo $text;
                $this->error_detected = true;
                error_logging("Minicomponent collision :: " . $text);
            }
            $this->miniComponentDirectories[] = $filePath;
            $this->registeredClasses[$classfileEventPoint][$classfileEventName] = array("filepath" => $filePath, "eventtype" => $eventType);
        }
    }
}

?>