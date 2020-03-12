<?php

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