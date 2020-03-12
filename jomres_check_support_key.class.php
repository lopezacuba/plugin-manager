<?php
/**
 * Core file.
 *
 * @author Vince Wooll <sales@jomres.net>
 *
 * @version Jomres 9.9.10
 *
 * @copyright	2005-2017 Vince Wooll
 * Jomres (tm) PHP, CSS & Javascript files are released under both MIT and GPL2 licenses. This means that you can choose the license that best suits your project, and use it accordingly
 **/
class jomres_check_support_key
{
    public function __construct($task)
    {
        $this->task = $task;
        $this->key_valid = false;
        if (isset($_REQUEST["support_key"]) && 0 < strlen($_REQUEST["support_key"])) {
            $this->save_key($task);
        }
        $task = jomresGetParam($_REQUEST, "task", "");
        $this->shop_status = "CLOSED";
        $this->check_license_key();
    }
    public function get_shop_status()
    {
        $request = "request=shop_status";
        $response = query_shop($request);
        if (is_object($response)) {
            $this->shop_status = $response->status;
        } else {
            $this->shop_status = "CLOSED";
        }
    }
    public function remove_plugin_licenses_file()
    {
        unlink(JOMRES_TEMP_ABSPATH . $this->user_plugin_license_temp_file_name);
    }
    public function get_user_plugin_licenses()
    {
        include_once JOMRES_TEMP_ABSPATH . $this->user_plugin_license_temp_file_name;
        $this->plugin_licenses = plugin_licenses();
    }
    public function check_license_key($force = false)
    {
        $siteConfig = jomres_singleton_abstract::getInstance("jomres_config_site_singleton");
        $jrConfig = $siteConfig->get();
        $str = "key=" . $jrConfig["licensekey"];
        $this->key_hash = $jrConfig["licensekey"];
        $license_data = new stdClass();
        $license_data->license_name = "Unknown";
        $license_data->expires = "Unknown";
        $license_data->key_status = "Unknown";
        $license_data->owner = "Unknown";
        $license_data->license_valid = false;
        $license_data->allows_plugins = false;
        $license_data->is_trial_license = false;
        if (file_exists(JOMRES_TEMP_ABSPATH . "license_key_check_cache.php")) {
            $last_modified = filemtime(JOMRES_TEMP_ABSPATH . "license_key_check_cache.php");
            $seconds_timediff = time() - $last_modified;
            if (86400 < $seconds_timediff) {
                unlink(JOMRES_TEMP_ABSPATH . "license_key_check_cache.php");
            } else {
                include JOMRES_TEMP_ABSPATH . "license_key_check_cache.php";
            }
        }
        if (!file_exists(JOMRES_TEMP_ABSPATH . "license_key_check_cache.php") || $force) {
            $buffer = queryUpdateServer("check_key.php", $str, "updates");
            if ($buffer != "") {
                $license_data = json_decode($buffer);
                if ($license_data->license_valid === true) {
                    $license_data->license_valid = "1";
                } else {
                    $license_data->license_valid = "0";
                }
                if (is_null($license_data->expires)) {
                    $license_data->expires = "Unknown";
                }
                if (is_null($license_data->allows_plugins)) {
                    $license_data->allows_plugins = "Unknown";
                }
                if (is_null($license_data->is_trial_license)) {
                    $license_data->is_trial_license = "Unknown";
                }
                if (!isset($license_data->status)) {
                    $license_data->key_status = "Unknown";
                } else {
                    $license_data->key_status = $license_data->status;
                }
                $lic_data = "<?php\r\ndefined( '_JOMRES_INITCHECK' ) or die( '' );\r\n\$license_data\t= new stdClass;\r\n\$license_data->license_name = \"" . $license_data->license_name . "\";\r\n\$license_data->expires = \"" . $license_data->expires . "\";\r\n\$license_data->key_status = \"" . $license_data->key_status . "\";\r\n\$license_data->owner = \"" . $license_data->owner . "\";\r\n\$license_data->license_valid = \"" . $license_data->license_valid . "\";\r\n\$license_data->allows_plugins = \"" . $license_data->allows_plugins . "\";\r\n\$license_data->is_trial_license = \"" . $license_data->is_trial_license . "\";\r\n\$license_data->allowed_plugins = \"" . $license_data->allowed_plugins . "\";\r\n";
                file_put_contents(JOMRES_TEMP_ABSPATH . "license_key_check_cache.php", $lic_data);
            }
        }
        if (!empty($license_data)) {
            $this->expires = $license_data->expires;
            $this->key_status = $license_data->key_status;
            $this->owner = $license_data->owner;
            $this->license_name = $license_data->license_name;
            $this->allowed_plugins = array();
            if (isset($license_data->allowed_plugins)) {
                $this->allowed_plugins = explode(",", $license_data->allowed_plugins);
            }
            if ($license_data->license_valid == true) {
                $this->key_valid = true;
            }
            $this->allows_plugins = $license_data->allows_plugins;
            if ($license_data->is_trial_license == "Unknown") {
                $license_data->is_trial_license = false;
            }
            $this->is_trial_license = (bool) $license_data->is_trial_license;
        }
    }
}

?>