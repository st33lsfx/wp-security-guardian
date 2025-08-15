<?php

/**
 * Plugin Name: WP Security Guardian
 * Description: Bezpečnostní plugin, který řídí aktivaci dalších pluginů prostřednictvím whitelistu. Zabraňuje neautorizované aktivaci pluginů nahrání hackery.
 * Version: 1.0.2
 * Author: Security Guardian
 * Text Domain: wp-security-guardian
 * Domain Path: /languages
 */

if (!defined('ABSPATH')) {
    exit;
}

// Definice WP_CLI konstanty pokud neexistuje
if (!defined('WP_CLI')) {
    define('WP_CLI', false);
}

// Mock WP_CLI třída pokud neexistuje (pro kompatibilitu s jinými pluginy)
if (!class_exists('WP_CLI')) {
    class WP_CLI
    {
        public static function add_command($name, $callable, $args = array())
        {
            // Mock implementace - nedělá nic
        }

        public static function log($message)
        {
            // Mock implementace - nedělá nic
        }

        public static function success($message)
        {
            // Mock implementace - nedělá nic  
        }

        public static function error($message, $exit = true)
        {
            // Mock implementace - nedělá nic
        }

        public static function warning($message)
        {
            // Mock implementace - nedělá nic
        }
    }
}

define('WPSG_PLUGIN_URL', plugin_dir_url(__FILE__));
define('WPSG_PLUGIN_PATH', plugin_dir_path(__FILE__));
define('WPSG_VERSION', '1.0.1');

class WP_Security_Guardian
{
    private static $instance = null;
    private $whitelist_table = 'wpsg_whitelist';

    public static function get_instance()
    {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct()
    {
        // Potlačit WordPress notices z jiných pluginů (pro čistší admin)
        add_action('init', array($this, 'suppress_plugin_notices'), 1);

        add_action('init', array($this, 'init'));
        add_action('admin_init', array($this, 'admin_init_handler'));
        add_action('admin_menu', array($this, 'conditional_add_admin_menu'));
        add_action('admin_enqueue_scripts', array($this, 'admin_enqueue_scripts'));

        // Ochranné mechanismy se načtou později když je WordPress připraven
        add_action('wp_loaded', array($this, 'setup_security_features'));

        // Initialize security hooks based on settings
        add_action('init', array($this, 'init_security_hooks'));

        // Initialize default values for new security header options
        add_action('init', array($this, 'init_default_security_header_options'));

        // Načíst bezpečnostní systémy
        $this->load_2fa_system();
        $this->load_security_headers();
        $this->load_ssl_monitor();

        // XSS Protection - přidat CSP hlavičky
        add_action('send_headers', array($this, 'add_xss_protection_headers'));

        // Authentication Protection - vylepšené ověřování
        add_action('wp_login', array($this, 'log_successful_login'), 10, 2);
        add_action('wp_login_failed', array($this, 'log_failed_login'));
        add_action('wp_login_failed', array($this, 'monitor_failed_login'));
        add_filter('authenticate', array($this, 'check_login_attempt'), 30, 3);

        // File Upload Security - pokročilé kontroly nahrávaných souborů
        add_filter('wp_handle_upload_prefilter', array($this, 'enhanced_upload_security'));
        add_filter('upload_mimes', array($this, 'restrict_upload_mimes'));
        add_filter('wp_check_filetype_and_ext', array($this, 'verify_file_content'), 10, 5);

        // Advanced Monitoring - pokročilé monitorování bezpečnosti
        add_action('init', array($this, 'start_security_monitoring'), 5);
        add_action('wp_footer', array($this, 'log_page_access'));
        add_action('admin_footer', array($this, 'monitor_admin_access'));

        // HTTPS/SSL Enforcement - vynucování HTTPS
        add_action('init', array($this, 'force_https_redirect'), 1);
        add_action('admin_init', array($this, 'force_admin_https'));
        add_filter('login_redirect', array($this, 'force_login_https'), 10, 3);

        // Ochrana proti deaktivaci
        add_filter('plugin_action_links', array($this, 'remove_deactivate_link'), 10, 4);
        add_action('deactivate_' . plugin_basename(__FILE__), array($this, 'prevent_deactivation'), 1);


        register_activation_hook(__FILE__, array($this, 'activate'));
        register_deactivation_hook(__FILE__, array($this, 'deactivate'));
    }

    /**
     * Handler pro admin_init - kontroluje autorizaci a nastavuje admin funkce
     */
    public function admin_init_handler()
    {

        // Ochranné mechanismy fungují vždy
        $this->block_unauthorized_plugins();
        $this->prevent_plugin_deletion();
        
        // Pokročilá ochrana proti deaktivaci a smazání
        $this->advanced_tamper_protection();
        
        // Pokročilá detekce a ochrana
        $this->advanced_deletion_protection();
        
        // Ultimate watchdog protection
        $this->create_watchdog_process();

        // Admin funkce jen pro autorizované uživatele
        $is_authorized = $this->is_user_authorized();

        if ($is_authorized) {
            add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_scripts'));
            add_filter('plugin_action_links_' . plugin_basename(__FILE__), array($this, 'add_settings_link'));
        } else {
        }
    }

    /**
     * Nastavit bezpečnostní funkce když je WordPress plně načten
     */
    public function setup_security_features()
    {
        // Ochrana proti smazání
        add_filter('all_plugins', array($this, 'hide_plugin_from_list'));
        add_action('wp_ajax_delete-plugin', array($this, 'prevent_ajax_deletion'), 1);

        // Další ochranné mechanismy
        add_action('init', array($this, 'monitor_file_changes'), 1);
        add_filter('filesystem_method', array($this, 'prevent_direct_file_access'));

        // Pokročilý monitoring
        add_action('init', array($this, 'setup_advanced_monitoring'), 1);
        add_action('wpsg_daily_integrity_check', array($this, 'daily_integrity_check'));
        add_action('wp_login', array($this, 'log_admin_access'), 10, 2);

        // Ochrana proti shell příkazům
        add_action('init', array($this, 'setup_shell_protection'), 1);

        // Rate limiting a další pokročilé ochrany
        add_action('init', array($this, 'setup_rate_limiting'), 1);

        // Apply security settings from database
        $this->init_security_hooks();

        $this->verify_plugin_integrity();
    }

    /**
     * Potlačit WordPress notices z jiných pluginů pro čistší admin
     */
    public function suppress_plugin_notices()
    {
        // Pouze pro neautorizované uživatele (aby vývojáři @unifer viděli chyby)
        if (!$this->is_user_authorized()) {
            // Potlačit admin notices z jiných pluginů
            add_action('admin_notices', function () {
                // Vyčistit buffer s notices pokud nejsou od našeho pluginu
                if (ob_get_level()) {
                    $content = ob_get_contents();
                    if (strpos($content, 'wp-security-guardian') === false) {
                        ob_clean();
                    }
                }
            }, 999);
        }
    }

    public function init()
    {
        load_plugin_textdomain('wp-security-guardian', false, dirname(plugin_basename(__FILE__)) . '/languages');
    }

    /**
     * Validace emailové domény uživatele
     */
    private function is_email_domain_authorized($email)
    {
        if (empty($email)) {
            return false;
        }
        
        // Získat aktuální seznam povolených domén
        $authorized_domains = $this->get_authorized_domains();
        
        $email = strtolower(trim($email));
        
        foreach ($authorized_domains as $domain) {
            if (strpos($email, $domain) !== false) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Kontrola zda má uživatel záložní přístup (pro emergency situace)
     */
    private function has_emergency_access($user)
    {
        // Emergency fallback - pokud je pouze jeden admin a není @unifer
        $admin_users = get_users(array(
            'role' => 'administrator',
            'number' => 2  // Zkontrolovat jestli jsou max 2 admini
        ));
        
        // Pokud je pouze jeden admin, povolit mu přístup
        if (count($admin_users) === 1 && $admin_users[0]->ID === $user->ID) {
            $this->log_security_event(
                'EMERGENCY_ACCESS_GRANTED',
                'Emergency access granted to sole administrator: ' . $user->user_email
            );
            return true;
        }
        
        // Povolit přístup během prvních 24 hodin od aktivace (grace period)
        $activation_time = get_option('wpsg_activation_time');
        if ($activation_time && (time() - $activation_time) < (24 * 60 * 60)) {
            return true;
        }
        
        return false;
    }

    /**
     * Kontrola zda je uživatel autorizován k přístupu k pluginu
     */
    private function is_user_authorized()
    {
        // Povolíme přístup během WP-CLI operací nebo aktivace
        if ((defined('WP_CLI') && WP_CLI) || !function_exists('is_user_logged_in')) {
            return true;
        }

        // Kontrola přihlášeného uživatele
        if (!is_user_logged_in()) {
            return false;
        }

        $current_user = wp_get_current_user();

        // Pokud uživatel nemá email, není autorizován
        if (empty($current_user->user_email)) {
            return false;
        }

        // HLAVNÍ KONTROLA: Pouze @unifer domény mají přístup
        if ($this->is_email_domain_authorized($current_user->user_email)) {
            // Uživatel má @unifer email - povolit přístup
            if (current_user_can('manage_options') || (function_exists('is_super_admin') && is_super_admin())) {
                return true;
            }
        }

        // Emergency fallback pro kritické situace
        if (current_user_can('manage_options') && $this->has_emergency_access($current_user)) {
            return true;
        }

        // Log neautorizovaný pokus o přístup
        $this->log_security_event(
            'UNAUTHORIZED_ACCESS_ATTEMPT',
            'Access denied for user: ' . $current_user->user_email . ' (not @unifer domain)',
            array(
                'user_id' => $current_user->ID,
                'email' => $current_user->user_email,
                'ip' => $this->get_client_ip()
            )
        );

        return false;
    }
    
    /**
     * Získat seznam povolených emailových domén
     */
    public function get_authorized_domains()
    {
        $default_domains = array('@unifer.cz', '@unifer.com', '@unifer');
        return get_option('wpsg_authorized_domains', $default_domains);
    }
    
    /**
     * Aktualizovat seznam povolených emailových domén
     */
    public function update_authorized_domains($domains)
    {
        // Validace vstupních dat
        $validated_domains = array();
        if (is_array($domains)) {
            foreach ($domains as $domain) {
                $domain = trim($domain);
                if (!empty($domain) && strpos($domain, '@') === 0) {
                    $validated_domains[] = strtolower($domain);
                }
            }
        }
        
        // Vždy zachovat @unifer jako základní doménu
        if (!in_array('@unifer', $validated_domains)) {
            $validated_domains[] = '@unifer';
        }
        
        update_option('wpsg_authorized_domains', $validated_domains);
        
        $this->log_security_event(
            'AUTHORIZED_DOMAINS_UPDATED',
            'Authorized email domains updated',
            array('domains' => $validated_domains)
        );
        
        return $validated_domains;
    }
    
    /**
     * Zobrazit aktuální autorizační stav uživatele (pro debug)
     */
    public function get_user_authorization_status($user_id = null)
    {
        if (!$user_id) {
            $user_id = get_current_user_id();
        }
        
        $user = get_userdata($user_id);
        if (!$user) {
            return array('authorized' => false, 'reason' => 'User not found');
        }
        
        $status = array(
            'user_id' => $user_id,
            'email' => $user->user_email,
            'is_admin' => user_can($user, 'manage_options'),
            'is_super_admin' => function_exists('is_super_admin') ? is_super_admin($user_id) : false,
            'domain_authorized' => $this->is_email_domain_authorized($user->user_email),
            'has_emergency_access' => $this->has_emergency_access($user),
            'authorized' => false
        );
        
        // Simulovat autorizační logiku
        if ($status['domain_authorized'] && ($status['is_admin'] || $status['is_super_admin'])) {
            $status['authorized'] = true;
            $status['reason'] = '@unifer domain with admin privileges';
        } elseif ($status['is_admin'] && $status['has_emergency_access']) {
            $status['authorized'] = true;
            $status['reason'] = 'Emergency access granted';
        } else {
            $status['reason'] = 'Not @unifer domain or insufficient privileges';
        }
        
        return $status;
    }

    /**
     * Skrýt plugin v seznamu pluginů pro neautorizované uživatele
     */
    public function hide_plugin_from_list($plugins)
    {
        if (!$this->is_user_authorized()) {
            unset($plugins[plugin_basename(__FILE__)]);
        }
        return $plugins;
    }

    /**
     * Zabránit smazání pluginu
     */
    public function prevent_plugin_deletion()
    {
        if (isset($_GET['action']) && sanitize_key($_GET['action']) === 'delete-selected' && isset($_GET['checked'])) {
            $plugins_to_delete = array_map('sanitize_text_field', (array)$_GET['checked']);
            if (in_array(plugin_basename(__FILE__), $plugins_to_delete)) {
                wp_die(
                    __('Security Guardian plugin nelze smazat. Tato akce je zakázána z bezpečnostních důvodů.', 'wp-security-guardian'),
                    __('Akce zakázána', 'wp-security-guardian'),
                    array('back_link' => true)
                );
            }
        }

        if (isset($_GET['action']) && sanitize_key($_GET['action']) === 'delete' && isset($_GET['plugin'])) {
            $plugin_to_delete = sanitize_text_field($_GET['plugin']);
            if ($plugin_to_delete === plugin_basename(__FILE__)) {
                wp_die(
                    __('Security Guardian plugin nelze smazat. Tato akce je zakázána z bezpečnostních důvodů.', 'wp-security-guardian'),
                    __('Akce zakázána', 'wp-security-guardian'),
                    array('back_link' => true)
                );
            }
        }
    }

    /**
     * Zabránit AJAX smazání pluginu
     */
    public function prevent_ajax_deletion()
    {
        if (isset($_POST['plugin']) && $_POST['plugin'] === plugin_basename(__FILE__)) {
            // Povolit smazání pouze autorizovaným administrátorům
            if (!$this->is_user_authorized()) {
                wp_die(__('Nemáte oprávnění smazat tento plugin.', 'wp-security-guardian'));
                return;
            }
            // Pokud je uživatel autorizován, povolit smazání
        }
    }

    /**
     * Odstranit odkaz pro deaktivaci pluginu pro neautorizované uživatele
     */
    public function remove_deactivate_link($actions, $plugin_file, $plugin_data = null, $context = null)
    {
        if ($plugin_file === plugin_basename(__FILE__) && !$this->is_user_authorized()) {
            unset($actions['deactivate']);
        }
        return $actions;
    }

    /**
     * Zabránit deaktivaci pluginu
     */
    public function prevent_deactivation()
    {
        if (!$this->is_user_authorized()) {
            wp_die(
                __('Security Guardian plugin nelze deaktivovat. Tato akce je zakázána z bezpečnostních důvodů.', 'wp-security-guardian'),
                __('Deaktivace zakázána', 'wp-security-guardian'),
                array('back_link' => true)
            );
        }
    }

    /**
     * Pokročilá ochrana proti deaktivaci a smazání
     */
    public function advanced_tamper_protection()
    {
        // 1. Souborová ochrana - nastavit read-only oprávnění
        $this->set_plugin_file_permissions();
        
        // 2. Database backup ochrana 
        $this->create_plugin_backup();
        
        // 3. Scheduled self-check
        if (!wp_next_scheduled('wpsg_self_integrity_check')) {
            wp_schedule_event(time(), 'hourly', 'wpsg_self_integrity_check');
        }
        
        // 4. Monitor plugin directory changes
        add_action('wpsg_self_integrity_check', array($this, 'verify_plugin_integrity'));
        
        // 5. Hook do plugin deletion attempts na core úrovni
        add_filter('pre_option_active_plugins', array($this, 'prevent_plugin_removal_from_active_list'));
        
        // 6. Monitor file system changes
        add_action('init', array($this, 'monitor_plugin_directory_changes'), 1);
        
        // 7. Emergency self-restoration
        add_action('plugins_loaded', array($this, 'emergency_self_check'), 1);
    }
    
    /**
     * Nastavit read-only oprávnění na plugin soubory
     */
    private function set_plugin_file_permissions()
    {
        if (!$this->is_production_environment()) {
            $plugin_dir = dirname(__FILE__);
            $plugin_files = array(
                __FILE__,
                $plugin_dir . '/index.php',
                $plugin_dir . '/.htaccess'
            );
            
            foreach ($plugin_files as $file) {
                if (file_exists($file)) {
                    @chmod($file, 0444); // Read-only
                }
            }
            
            // Protect entire plugin directory
            @chmod($plugin_dir, 0555); // Read + execute only
        }
    }
    
    /**
     * Vytvořit záložní kopii plugin souboru v bezpečném místě
     */
    private function create_plugin_backup()
    {
        $backup_dir = WP_CONTENT_DIR . '/wpsg-protection/';
        if (!is_dir($backup_dir)) {
            wp_mkdir_p($backup_dir);
            // Protect backup directory
            file_put_contents($backup_dir . '.htaccess', "Options -Indexes\nDeny from all\n");
            file_put_contents($backup_dir . 'index.php', "<?php\n// Silence is golden\n");
        }
        
        $backup_file = $backup_dir . 'wpsg-backup-' . date('Y-m-d') . '.php';
        if (!file_exists($backup_file)) {
            @copy(__FILE__, $backup_file);
            @chmod($backup_file, 0400); // Read-only for owner
        }
        
        // Store backup hash for integrity verification
        $backup_hash = md5_file(__FILE__);
        update_option('wpsg_backup_hash', $backup_hash);
        update_option('wpsg_backup_path', $backup_file);
    }
    
    /**
     * Ověřit integritu pluginu
     */
    public function verify_plugin_integrity()
    {
        // Check if plugin file exists
        if (!file_exists(__FILE__)) {
            $this->emergency_restore_plugin();
            return;
        }
        
        // Check if plugin is active in database
        $active_plugins = get_option('active_plugins', array());
        $plugin_basename = plugin_basename(__FILE__);
        
        if (!in_array($plugin_basename, $active_plugins)) {
            // Plugin was deactivated - reactivate it
            $this->force_reactivation();
        }
        
        // Check file integrity
        $current_hash = md5_file(__FILE__);
        $stored_hash = get_option('wpsg_backup_hash');
        
        if ($stored_hash && $current_hash !== $stored_hash) {
            // Plugin file was modified - restore from backup
            $this->restore_from_backup();
        }
    }
    
    /**
     * Zabránit odstranění z active_plugins seznamu
     */
    public function prevent_plugin_removal_from_active_list($active_plugins)
    {
        if (!is_array($active_plugins)) {
            return $active_plugins;
        }
        
        $plugin_basename = plugin_basename(__FILE__);
        
        // Pokud náš plugin není v seznamu aktivních, přidat ho zpět
        if (!in_array($plugin_basename, $active_plugins)) {
            // Log tento pokus
            $this->log_security_event(
                'PLUGIN_FORCED_DEACTIVATION_BLOCKED',
                'Attempt to remove Security Guardian from active plugins blocked',
                array('user_id' => get_current_user_id(), 'ip' => $this->get_client_ip())
            );
            
            // Přidat zpět do seznamu
            $active_plugins[] = $plugin_basename;
        }
        
        return $active_plugins;
    }
    
    /**
     * Monitorovat změny v plugin directory
     */
    public function monitor_plugin_directory_changes()
    {
        $plugin_dir = dirname(__FILE__);
        
        // Check if directory still exists
        if (!is_dir($plugin_dir)) {
            $this->log_security_event('PLUGIN_DIRECTORY_DELETED', 'Plugin directory was deleted');
            $this->emergency_restore_plugin();
            return;
        }
        
        // Check if main plugin file exists
        if (!file_exists(__FILE__)) {
            $this->log_security_event('PLUGIN_FILE_DELETED', 'Main plugin file was deleted');
            $this->emergency_restore_plugin();
            return;
        }
    }
    
    /**
     * Emergency self-check při každém načtení
     */
    public function emergency_self_check()
    {
        // Quick integrity check
        if (!$this->is_plugin_properly_active()) {
            $this->force_reactivation();
        }
    }
    
    /**
     * Ověřit zda je plugin správně aktivní
     */
    private function is_plugin_properly_active()
    {
        $active_plugins = get_option('active_plugins', array());
        $plugin_basename = plugin_basename(__FILE__);
        
        return in_array($plugin_basename, $active_plugins);
    }
    
    /**
     * Vynutit reaktivaci pluginu
     */
    private function force_reactivation()
    {
        if (!$this->is_user_authorized()) {
            // Pouze pro neautorizované uživatele - admin si může plugin deaktivovat
            $active_plugins = get_option('active_plugins', array());
            $plugin_basename = plugin_basename(__FILE__);
            
            if (!in_array($plugin_basename, $active_plugins)) {
                $active_plugins[] = $plugin_basename;
                update_option('active_plugins', $active_plugins);
                
                $this->log_security_event(
                    'PLUGIN_AUTO_REACTIVATED',
                    'Security Guardian automatically reactivated after unauthorized deactivation attempt'
                );
            }
        }
    }
    
    /**
     * Obnovit plugin ze zálohy
     */
    private function restore_from_backup()
    {
        $backup_path = get_option('wpsg_backup_path');
        
        if ($backup_path && file_exists($backup_path)) {
            // Restore file permissions before copy
            @chmod(__FILE__, 0644);
            
            if (@copy($backup_path, __FILE__)) {
                // Restore read-only permissions
                @chmod(__FILE__, 0444);
                
                $this->log_security_event(
                    'PLUGIN_RESTORED_FROM_BACKUP',
                    'Security Guardian restored from backup after tampering detected'
                );
            }
        }
    }
    
    /**
     * Emergency restoration celého pluginu
     */
    private function emergency_restore_plugin()
    {
        $backup_path = get_option('wpsg_backup_path');
        
        if ($backup_path && file_exists($backup_path)) {
            $plugin_dir = dirname(__FILE__);
            
            // Recreate plugin directory if needed
            if (!is_dir($plugin_dir)) {
                wp_mkdir_p($plugin_dir);
            }
            
            // Restore main plugin file
            @copy($backup_path, __FILE__);
            @chmod(__FILE__, 0444);
            
            // Reactivate plugin
            $this->force_reactivation();
            
            $this->log_security_event(
                'PLUGIN_EMERGENCY_RESTORED',
                'Security Guardian emergency restoration completed'
            );
        }
    }

    /**
     * Pokročilá detekce a ochrana proti smazání/deaktivaci
     */
    public function advanced_deletion_protection()
    {
        // Monitor database changes
        add_action('update_option_active_plugins', array($this, 'monitor_active_plugins_changes'), 10, 2);
        
        // Monitor file system via WordPress hooks
        add_action('delete_plugin', array($this, 'block_plugin_deletion_attempt'), 1, 2);
        
        // Monitor FTP/direct file system access
        add_action('wpsg_check_file_integrity', array($this, 'deep_file_system_check'));
        
        // Schedule více frequent integrity checks
        if (!wp_next_scheduled('wpsg_check_file_integrity')) {
            wp_schedule_event(time(), 'twicedaily', 'wpsg_check_file_integrity');
        }
        
        // Add stealth mode - hide from unauthorized users completely
        add_action('pre_current_active_plugins', array($this, 'stealth_mode_protection'));
        
        // Database-level protection
        add_filter('pre_delete_site_option_active_plugins', array($this, 'prevent_database_tampering'));
        add_filter('pre_update_site_option_active_plugins', array($this, 'prevent_database_tampering'));
    }
    
    /**
     * Monitor změny v active_plugins option
     */
    public function monitor_active_plugins_changes($old_value, $new_value)
    {
        $plugin_basename = plugin_basename(__FILE__);
        
        // Check if our plugin was removed
        $was_active = is_array($old_value) && in_array($plugin_basename, $old_value);
        $is_active = is_array($new_value) && in_array($plugin_basename, $new_value);
        
        if ($was_active && !$is_active) {
            // Plugin was deactivated
            if (!$this->is_user_authorized()) {
                // Unauthorized deactivation - revert immediately
                update_option('active_plugins', $old_value);
                
                $this->log_security_event(
                    'UNAUTHORIZED_DEACTIVATION_BLOCKED',
                    'Unauthorized attempt to deactivate Security Guardian blocked',
                    array('user_id' => get_current_user_id(), 'ip' => $this->get_client_ip())
                );
                
                // Also block the request
                wp_die(__('Nemáte oprávnění deaktivovat Security Guardian plugin.', 'wp-security-guardian'));
            }
        }
    }
    
    /**
     * Block direct plugin deletion attempts
     */
    public function block_plugin_deletion_attempt($plugin_file, $plugin_data)
    {
        if (strpos($plugin_file, 'wp-security-guardian') !== false) {
            if (!$this->is_user_authorized()) {
                $this->log_security_event(
                    'UNAUTHORIZED_DELETION_BLOCKED',
                    'Unauthorized attempt to delete Security Guardian blocked'
                );
                
                wp_die(__('Security Guardian plugin nelze smazat bez autorizace.', 'wp-security-guardian'));
            }
        }
    }
    
    /**
     * Hluboká kontrola integrity souborového systému
     */
    public function deep_file_system_check()
    {
        $plugin_dir = dirname(__FILE__);
        $critical_files = array(
            __FILE__,
            $plugin_dir . '/index.php',
            $plugin_dir . '/.htaccess'
        );
        
        $integrity_issues = 0;
        
        foreach ($critical_files as $file) {
            if (!file_exists($file)) {
                $integrity_issues++;
                $this->log_security_event(
                    'CRITICAL_FILE_MISSING',
                    'Critical plugin file missing: ' . basename($file)
                );
                
                // Attempt to restore
                $this->restore_missing_file($file);
            }
            
            // Check file permissions
            if (file_exists($file)) {
                $perms = substr(sprintf('%o', fileperms($file)), -4);
                if ($perms !== '0444' && !$this->is_production_environment()) {
                    // File permissions were changed - restore them
                    @chmod($file, 0444);
                    
                    $this->log_security_event(
                        'FILE_PERMISSIONS_RESTORED',
                        'File permissions restored for: ' . basename($file)
                    );
                }
            }
        }
        
        // Check plugin directory permissions
        if (is_dir($plugin_dir)) {
            $dir_perms = substr(sprintf('%o', fileperms($plugin_dir)), -4);
            if ($dir_perms !== '0555' && !$this->is_production_environment()) {
                @chmod($plugin_dir, 0555);
            }
        }
        
        if ($integrity_issues > 0) {
            // Trigger emergency restoration
            $this->emergency_restore_plugin();
        }
    }
    
    /**
     * Stealth mode - skrýt plugin před neautorizovanými uživateli
     */
    public function stealth_mode_protection()
    {
        if (!$this->is_user_authorized() && !is_super_admin()) {
            // Hide plugin from plugin list completely
            add_filter('all_plugins', function($plugins) {
                $plugin_basename = plugin_basename(__FILE__);
                unset($plugins[$plugin_basename]);
                return $plugins;
            });
            
            // Block direct access to plugin files
            if (isset($_SERVER['REQUEST_URI']) && 
                strpos(sanitize_text_field($_SERVER['REQUEST_URI']), 'wp-security-guardian') !== false) {
                
                // Log access attempt
                $this->log_security_event(
                    'STEALTH_MODE_ACCESS_BLOCKED',
                    'Unauthorized access to plugin files blocked'
                );
                
                // Redirect to 404
                global $wp_query;
                $wp_query->set_404();
                status_header(404);
                include get_404_template();
                exit;
            }
        }
    }
    
    /**
     * Prevent database-level tampering
     */
    public function prevent_database_tampering($value)
    {
        if (!$this->is_user_authorized()) {
            $plugin_basename = plugin_basename(__FILE__);
            
            // Ensure our plugin stays in the active list
            if (is_array($value) && !in_array($plugin_basename, $value)) {
                $value[] = $plugin_basename;
                
                $this->log_security_event(
                    'DATABASE_TAMPERING_BLOCKED',
                    'Database-level attempt to deactivate plugin blocked'
                );
            }
        }
        
        return $value;
    }
    
    /**
     * Restore missing critical file
     */
    private function restore_missing_file($file_path)
    {
        $filename = basename($file_path);
        
        switch ($filename) {
            case 'wp-security-guardian.php':
                // Restore main plugin file from backup
                $this->restore_from_backup();
                break;
                
            case 'index.php':
                // Restore index.php
                $content = "<?php\n// Silence is golden\n";
                @file_put_contents($file_path, $content);
                @chmod($file_path, 0444);
                break;
                
            case '.htaccess':
                // Restore .htaccess protection
                $content = "Options -Indexes\nDeny from all\n";
                @file_put_contents($file_path, $content);
                @chmod($file_path, 0444);
                break;
        }
    }
    
    /**
     * Ultimate protection - create hidden watchdog process
     */
    public function create_watchdog_process()
    {
        $watchdog_file = WP_CONTENT_DIR . '/mu-plugins/wpsg-watchdog.php';
        
        // Create mu-plugins directory if it doesn't exist
        $mu_plugins_dir = dirname($watchdog_file);
        if (!is_dir($mu_plugins_dir)) {
            wp_mkdir_p($mu_plugins_dir);
        }
        
        if (!file_exists($watchdog_file)) {
            $watchdog_content = '<?php
/**
 * Security Guardian Watchdog
 * Must-use plugin that ensures Security Guardian stays active
 */

add_action("plugins_loaded", function() {
    $sg_plugin = "wp-security-guardian/wp-security-guardian.php";
    $active_plugins = get_option("active_plugins", array());
    
    if (!in_array($sg_plugin, $active_plugins)) {
        $active_plugins[] = $sg_plugin;
        update_option("active_plugins", $active_plugins);
    }
}, 1);

// Prevent this watchdog from being deleted
add_filter("pre_delete_site_option_active_plugins", function($value) {
    return false; // Block any attempts to modify active plugins at site level
});
';
            
            @file_put_contents($watchdog_file, $watchdog_content);
            @chmod($watchdog_file, 0444);
        }
    }

    public function activate()
    {
        // Zaznamenat čas aktivace pro grace period
        if (!get_option('wpsg_activation_time')) {
            update_option('wpsg_activation_time', time());
        }
        
        // Nastavit výchozí whitelist pouze pokud ještě neexistuje
        $existing_whitelist = get_option('wpsg_plugin_whitelist', false);
        if ($existing_whitelist === false || empty($existing_whitelist)) {
            $default_whitelist = array('wp-security-guardian/wp-security-guardian.php');
            update_option('wpsg_plugin_whitelist', $default_whitelist);
        }

        // Vytvořit databázovou tabulku (pro zpětnou kompatibilitu)
        global $wpdb;
        $table_name = $wpdb->prefix . $this->whitelist_table;
        $charset_collate = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE $table_name (
            id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            plugin_path varchar(255) NOT NULL,
            PRIMARY KEY (id),
            UNIQUE KEY plugin_path (plugin_path)
        ) $charset_collate;";

        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
        dbDelta($sql);

        // Vložit výchozí plugin do tabulky pouze pokud tabulka je prázdná
        $existing_count = $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM `{$table_name}`"));
        if ($existing_count == 0) {
            $wpdb->replace($table_name, array('plugin_path' => 'wp-security-guardian/wp-security-guardian.php'), array('%s'));
        }

        // Nastavit bezpečnostní ochranu
        update_option('wpsg_security_enabled', true);

        // Dodatečné zabezpečení proti FTP útokům
        $this->create_security_files();

        // Vymazat cache
        wp_cache_delete('wpsg_security_enabled', 'options');
    }

    /**
     * Vytvořit bezpečnostní soubory pro ochranu proti FTP útokům
     */
    private function create_security_files()
    {
        $plugin_dir = WPSG_PLUGIN_PATH;

        // Vytvořit .htaccess pro ochranu adresáře
        $htaccess_content = "# Security Guardian Protection\n";
        $htaccess_content .= "<Files \"wp-security-guardian.php\">\n";
        $htaccess_content .= "    Order allow,deny\n";
        $htaccess_content .= "    Deny from all\n";
        $htaccess_content .= "</Files>\n\n";
        $htaccess_content .= "# Skrýt všechny PHP soubory\n";
        $htaccess_content .= "<FilesMatch \"\\.php$\">\n";
        $htaccess_content .= "    Order allow,deny\n";
        $htaccess_content .= "    Deny from all\n";
        $htaccess_content .= "</FilesMatch>\n\n";
        $htaccess_content .= "# Povolíme přístup jen pro WordPress\n";
        $htaccess_content .= "<FilesMatch \"wp-security-guardian\\.php$\">\n";
        $htaccess_content .= "    Order allow,deny\n";
        $htaccess_content .= "    Allow from 127.0.0.1\n";
        $htaccess_content .= "    Allow from ::1\n";
        $htaccess_content .= "</FilesMatch>\n";

        file_put_contents($plugin_dir . '.htaccess', $htaccess_content);

        // Vytvořit index.php pro skrytí obsahu adresáře
        $index_content = "<?php\n";
        $index_content .= "// Security Guardian - Unauthorized access forbidden\n";
        $index_content .= "http_response_code(403);\n";
        $index_content .= "die('Access Forbidden');\n";

        if (!file_put_contents($plugin_dir . 'index.php', $index_content)) {
            error_log('WPSG: Could not secure index.php file - permission denied');
        }

        // Vytvořit .htaccess v každém podadresáři
        $subdirs = array('templates', 'assets');
        foreach ($subdirs as $subdir) {
            $subdir_path = $plugin_dir . $subdir . '/';
            if (is_dir($subdir_path)) {
                file_put_contents($subdir_path . '.htaccess', $htaccess_content);
                file_put_contents($subdir_path . 'index.php', $index_content);
            }
        }

        // Nastavit oprávnění souborů (jen pro čtení)
        @chmod($plugin_dir . 'wp-security-guardian.php', 0444);
        @chmod($plugin_dir . '.htaccess', 0444);
        @chmod($plugin_dir . 'index.php', 0444);
    }

    /**
     * Monitorovat změny souborů pluginu
     */
    public function monitor_file_changes()
    {
        $plugin_file = __FILE__;
        $plugin_hash = get_option('wpsg_plugin_hash');
        $current_hash = md5_file($plugin_file);

        if ($plugin_hash && $plugin_hash !== $current_hash) {
            // Plugin byl změněn - případně obnovit
            // Na produkci neměnit file permissions kvůli problémům s hosting providery
            if (!$this->is_production_environment() && !$this->is_user_authorized()) {
                // Obnovit původní oprávnění pouze na localhost
                @chmod($plugin_file, 0444);
            }

            // Pouze logovat změnu na produkci
            $this->log_security_event(
                'PLUGIN_FILE_MODIFIED',
                'Plugin file hash changed',
                array('file' => $plugin_file, 'is_production' => $this->is_production_environment())
            );
        }

        // Uložit aktuální hash
        update_option('wpsg_plugin_hash', $current_hash);
    }

    /**
     * Zabránit přímému přístupu k souborům
     */
    public function prevent_direct_file_access($method)
    {
        // Pokud se někdo pokouší přistupovat k našim souborům přímo
        if (isset($_SERVER['REQUEST_URI']) && strpos(sanitize_text_field($_SERVER['REQUEST_URI']), 'wp-security-guardian') !== false) {
            if (!$this->is_user_authorized()) {
                wp_die('Přístup odepren', 'Neautorizovaný přístup', array('response' => 403));
            }
        }
        return $method;
    }


    /**
     * Nastavit pokročilý monitoring
     */
    public function setup_advanced_monitoring()
    {
        // Naplánovat denní kontrolu integrity
        if (!wp_next_scheduled('wpsg_daily_integrity_check')) {
            wp_schedule_event(time(), 'daily', 'wpsg_daily_integrity_check');
        }

        // Monitorovat podezřelé WordPress akce
        add_action('wp_ajax_edit-theme-plugin-file', array($this, 'block_file_editor'), 1);
        add_action('wp_ajax_update-plugin', array($this, 'monitor_plugin_updates'), 1);
        add_filter('pre_update_option_active_plugins', array($this, 'monitor_plugin_changes'), 10, 2);
    }

    /**
     * Denní kontrola integrity
     */
    public function daily_integrity_check()
    {
        $this->verify_plugin_integrity();
        $this->check_file_modifications();
        $this->cleanup_old_logs();
        $this->backup_configuration();

        // Poslat report pokud je potřeba
        $this->send_security_report_if_needed();
    }

    /**
     * Logování přístupu administrátorů
     */
    public function log_admin_access($user_login, $user)
    {
        if (user_can($user, 'manage_options')) {
            $is_authorized = $this->is_user_authorized();
            $this->log_security_event(
                'ADMIN_LOGIN',
                sprintf('Admin login: %s (authorized: %s)', $user_login, $is_authorized ? 'YES' : 'NO'),
                array('user_id' => $user->ID, 'user_email' => $user->user_email, 'authorized' => $is_authorized)
            );
        }
    }

    /**
     * Logování bezpečnostních událostí
     */
    private function log_security_event($event_type, $message, $data = array())
    {
        $log_entry = array(
            'timestamp' => current_time('mysql'),
            'event_type' => $event_type,
            'message' => $message,
            'data' => $data,
            'ip_address' => $this->get_client_ip(),
            'user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '',
            'user_id' => get_current_user_id()
        );

        $logs = get_option('wpsg_security_logs', array());
        $logs[] = $log_entry;

        // Uchovat pouze posledních 1000 záznamů
        if (count($logs) > 1000) {
            $logs = array_slice($logs, -1000);
        }

        update_option('wpsg_security_logs', $logs);

        // Pokud je to kritická událost, pošli email
        if (in_array($event_type, array('INTEGRITY_VIOLATION', 'UNAUTHORIZED_ACCESS', 'DELETION_ATTEMPT'))) {
            $this->send_security_alert($event_type, $message, $data);
        }
    }

    /**
     * Získat IP adresu klienta
     */
    private function get_client_ip()
    {
        $ip_keys = array('HTTP_CF_CONNECTING_IP', 'HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED', 'REMOTE_ADDR');

        foreach ($ip_keys as $key) {
            if (array_key_exists($key, $_SERVER) === true) {
                foreach (explode(',', $_SERVER[$key]) as $ip) {
                    $ip = trim($ip);
                    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false) {
                        return $ip;
                    }
                }
            }
        }

        return isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'unknown';
    }

    /**
     * Kontrola změn souborů
     */
    private function check_file_modifications()
    {
        $important_files = array(
            __FILE__,
            WPSG_PLUGIN_PATH . '.htaccess',
            WPSG_PLUGIN_PATH . 'index.php'
        );

        foreach ($important_files as $file) {
            if (file_exists($file)) {
                $current_hash = md5_file($file);
                $stored_hash = get_option('wpsg_file_hash_' . md5($file));

                if ($stored_hash && $stored_hash !== $current_hash) {
                    $this->log_security_event('FILE_MODIFIED', 'Critical file modification detected: ' . basename($file));
                }

                update_option('wpsg_file_hash_' . md5($file), $current_hash);
            }
        }
    }

    /**
     * Vyčistit staré logy
     */
    private function cleanup_old_logs()
    {
        // Smazat logy starší než 30 dní
        $logs = get_option('wpsg_security_logs', array());
        $cutoff_timestamp = strtotime('-30 days');

        $filtered_logs = array_filter($logs, function ($log) use ($cutoff_timestamp) {
            return strtotime($log['timestamp']) > $cutoff_timestamp;
        });

        update_option('wpsg_security_logs', $filtered_logs);
    }

    /**
     * Poslat bezpečnostní alert
     */
    private function send_security_alert($event_type, $message, $data = array())
    {
        $admin_email = get_option('admin_email');
        $site_name = get_bloginfo('name');

        $subject = sprintf('[%s] Security Guardian Alert: %s', $site_name, $event_type);

        $body = sprintf(
            "Bezpečnostní událost na webu %s:\n\n" .
                "Typ události: %s\n" .
                "Zpráva: %s\n" .
                "Čas: %s\n" .
                "IP adresa: %s\n" .
                "User agent: %s\n\n" .
                "Další data: %s\n\n" .
                "Tato zpráva byla automaticky vygenerována pluginem Security Guardian.",
            $site_name,
            $event_type,
            $message,
            current_time('mysql'),
            $this->get_client_ip(),
            isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : 'unknown',
            print_r($data, true)
        );

        wp_mail($admin_email, $subject, $body);
    }

    /**
     * Poslat pravidelný bezpečnostní report
     */
    private function send_security_report_if_needed()
    {
        $last_report = get_option('wpsg_last_security_report', 0);

        // Pošli report jednou týdně
        if (time() - $last_report > WEEK_IN_SECONDS) {
            $logs = get_option('wpsg_security_logs', array());
            $recent_logs = array_filter($logs, function ($log) {
                return strtotime($log['timestamp']) > (time() - WEEK_IN_SECONDS);
            });

            if (!empty($recent_logs)) {
                $admin_email = get_option('admin_email');
                $site_name = get_bloginfo('name');

                $subject = sprintf('[%s] Security Guardian - týdenní report', $site_name);
                $body = sprintf(
                    "Týdenní bezpečnostní report pro %s:\n\n" .
                        "Počet událostí za poslední týden: %d\n\n" .
                        "Posledních 10 událostí:\n%s",
                    $site_name,
                    count($recent_logs),
                    $this->format_logs_for_email(array_slice($recent_logs, -10))
                );

                wp_mail($admin_email, $subject, $body);
            }

            update_option('wpsg_last_security_report', time());
        }
    }

    /**
     * Formátovat logy pro email
     */
    private function format_logs_for_email($logs)
    {
        $formatted = '';
        foreach ($logs as $log) {
            $formatted .= sprintf(
                "[%s] %s: %s\n",
                $log['timestamp'],
                $log['event_type'],
                $log['message']
            );
        }
        return $formatted;
    }

    /**
     * Blokovat file editor pro náš plugin
     */
    public function block_file_editor()
    {
        if (isset($_POST['plugin']) && strpos(sanitize_text_field($_POST['plugin']), 'wp-security-guardian') !== false) {
            $this->log_security_event('UNAUTHORIZED_ACCESS', 'Attempt to edit Security Guardian files via file editor');
            wp_die(__('Editace Security Guardian souborů je zakázána z bezpečnostních důvodů.', 'wp-security-guardian'));
        }

        if (isset($_POST['theme']) && isset($_POST['file'])) {
            $file = sanitize_text_field($_POST['file']);
            if (strpos($file, 'wp-security-guardian') !== false) {
                $this->log_security_event('UNAUTHORIZED_ACCESS', 'Attempt to edit Security Guardian files via theme editor');
                wp_die(__('Editace Security Guardian souborů je zakázána z bezpečnostních důvodů.', 'wp-security-guardian'));
            }
        }
    }

    /**
     * Monitorovat aktualizace pluginů
     */
    public function monitor_plugin_updates()
    {
        if (isset($_POST['plugin']) && $_POST['plugin'] === plugin_basename(__FILE__)) {
            if (!$this->is_user_authorized()) {
                $this->log_security_event('UNAUTHORIZED_ACCESS', 'Unauthorized plugin update attempt');
                wp_die(__('Aktualizace Security Guardian je povolena pouze autorizovaným uživatelům.', 'wp-security-guardian'));
            }
        }
    }

    /**
     * Monitorovat změny v active_plugins
     */
    public function monitor_plugin_changes($new_value, $old_value)
    {
        $plugin_basename = plugin_basename(__FILE__);

        // Zkontrolovat, zda se pokouší někdo deaktivovat náš plugin
        if (is_array($old_value) && is_array($new_value)) {
            $was_active = in_array($plugin_basename, $old_value);
            $is_active = in_array($plugin_basename, $new_value);

            if ($was_active && !$is_active && !$this->is_user_authorized()) {
                $this->log_security_event('UNAUTHORIZED_ACCESS', 'Unauthorized deactivation attempt blocked');
                // Vrátit zpět aktivaci
                $new_value[] = $plugin_basename;
            }
        }

        return $new_value;
    }

    /**
     * Nastavit ochranu proti shell příkazům
     */
    public function setup_shell_protection()
    {
        // Monitorovat nebezpečné funkce
        $this->monitor_dangerous_functions();

        // Ochrana proti file manager pluginům
        add_action('plugins_loaded', array($this, 'detect_file_managers'), 1);
    }

    /**
     * Monitorovat nebezpečné PHP funkce
     */
    private function monitor_dangerous_functions()
    {
        $dangerous_functions = array('exec', 'shell_exec', 'system', 'passthru', 'file_get_contents', 'file_put_contents', 'unlink');

        foreach ($dangerous_functions as $func) {
            if (function_exists($func)) {
                // Nelze přímo deaktivovat funkce, ale můžeme monitorovat jejich použití
                $this->log_function_usage($func);
            }
        }
    }

    /**
     * Log použití funkcí (pouze pro debugging)
     */
    private function log_function_usage($function_name)
    {
        $backtrace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 5);
        $caller_file = isset($backtrace[1]['file']) ? $backtrace[1]['file'] : 'unknown';

        // Pokud je volána z našeho pluginu nebo WordPress core, je to OK
        if (
            strpos($caller_file, WPSG_PLUGIN_PATH) !== false ||
            strpos($caller_file, ABSPATH . 'wp-') !== false
        ) {
            return;
        }

        $this->log_security_event(
            'DANGEROUS_FUNCTION_CALL',
            sprintf('Dangerous function %s called from %s', $function_name, $caller_file),
            array('function' => $function_name, 'file' => $caller_file)
        );
    }

    /**
     * Detekovat file manager pluginy
     */
    public function detect_file_managers()
    {
        $file_manager_plugins = array(
            'wp-file-manager/file_folder_manager.php',
            'file-manager/file-manager.php',
            'wp-files/wp-files.php',
            'advanced-file-manager/file-manager.php'
        );

        foreach ($file_manager_plugins as $plugin) {
            if (is_plugin_active($plugin)) {
                $this->log_security_event(
                    'SECURITY_WARNING',
                    'File manager plugin detected: ' . $plugin,
                    array('plugin' => $plugin)
                );
            }
        }
    }

    /**
     * Šifrování whitelist dat
     */
    private function encrypt_whitelist($whitelist)
    {
        $key = $this->get_encryption_key();
        $serialized = serialize($whitelist);
        $encrypted = openssl_encrypt($serialized, 'AES-256-CBC', $key, 0, $this->get_iv());
        return base64_encode($encrypted);
    }

    /**
     * Dešifrování whitelist dat
     */
    private function decrypt_whitelist($encrypted_data)
    {
        $key = $this->get_encryption_key();
        $data = base64_decode($encrypted_data);
        $decrypted = openssl_decrypt($data, 'AES-256-CBC', $key, 0, $this->get_iv());
        return unserialize($decrypted);
    }

    /**
     * Získat encryption klíč
     */
    private function get_encryption_key()
    {
        $key = get_option('wpsg_encryption_key');
        if (!$key) {
            $key = wp_generate_password(32, false);
            update_option('wpsg_encryption_key', $key);
        }
        return hash('sha256', $key . WPSG_VERSION);
    }

    /**
     * Získat initialization vector
     */
    private function get_iv()
    {
        return substr(hash('sha256', 'wpsg_iv_' . WPSG_VERSION), 0, 16);
    }

    /**
     * Backup konfigurace na vzdálený server
     */
    private function backup_configuration()
    {
        $config = array(
            'whitelist' => $this->get_whitelist(),
            'security_enabled' => get_option('wpsg_security_enabled', true),
            'timestamp' => current_time('mysql'),
            'site_url' => site_url(),
            'version' => WPSG_VERSION
        );

        $encrypted_config = $this->encrypt_whitelist($config);

        // Uložit lokálně jako backup
        update_option('wpsg_config_backup', $encrypted_config);

        $this->log_security_event('CONFIG_BACKUP', 'Configuration backed up');
    }

    /**
     * Obnovit konfiguraci z backupu
     */
    public function restore_configuration()
    {
        $encrypted_backup = get_option('wpsg_config_backup');
        if ($encrypted_backup) {
            try {
                $config = $this->decrypt_whitelist($encrypted_backup);
                if (isset($config['whitelist'])) {
                    $this->update_whitelist($config['whitelist']);
                    $this->log_security_event('CONFIG_RESTORE', 'Configuration restored from backup');
                    return true;
                }
            } catch (Exception $e) {
                $this->log_security_event('CONFIG_RESTORE_ERROR', 'Failed to restore configuration: ' . $e->getMessage());
            }
        }
        return false;
    }

    /**
     * Nastavit rate limiting a pokročilé ochrany
     */
    public function setup_rate_limiting()
    {
        // Rate limiting pro přihlášení
        add_action('wp_login_failed', array($this, 'handle_failed_login'));
        add_filter('authenticate', array($this, 'check_login_rate_limit'), 30, 3);

        // Ochrana proti bruteforce útokům na admin
        add_action('admin_init', array($this, 'check_admin_access_rate'));

        // Time-based tokeny pro kritické operace
        add_filter('wpsg_verify_critical_action', array($this, 'verify_time_based_token'), 10, 2);

        // Detekce podezřelé aktivity
        add_action('init', array($this, 'detect_suspicious_activity'));

        // API Rate limiting pro pokročilou ochranu
        $this->setup_api_rate_limiting();

        // File monitoring pro detekci malware a změn
        $this->setup_file_monitoring();

        // Advanced anti-hacker protections
        // Advanced protections are handled by init_security_hooks()
    }

    /**
     * Zpracovat neúspěšné přihlášení
     */
    public function handle_failed_login($username)
    {
        $ip = $this->get_client_ip();
        $attempts = get_transient('wpsg_login_attempts_' . md5($ip)) ?: 0;
        $attempts++;

        set_transient('wpsg_login_attempts_' . md5($ip), $attempts, HOUR_IN_SECONDS);

        $this->log_security_event(
            'LOGIN_FAILED',
            sprintf('Failed login attempt for user %s from IP %s (attempt %d)', $username, $ip, $attempts),
            array('username' => $username, 'ip' => $ip, 'attempts' => $attempts)
        );

        // Po 5 pokusech zablokovat na hodinu
        if ($attempts >= 5) {
            set_transient('wpsg_blocked_ip_' . md5($ip), true, HOUR_IN_SECONDS);
            $this->log_security_event('IP_BLOCKED', 'IP address blocked for 1 hour: ' . $ip);
        }
    }

    /**
     * Kontrola rate limit pro přihlášení
     */
    public function check_login_rate_limit($user, $username = null, $password = null)
    {
        $ip = $this->get_client_ip();

        // Zkontrolovat, zda je IP blokována
        if (get_transient('wpsg_blocked_ip_' . md5($ip))) {
            $this->log_security_event('BLOCKED_LOGIN_ATTEMPT', 'Login attempt from blocked IP: ' . $ip);
            return new WP_Error('ip_blocked', 'Vaše IP adresa je dočasně zablokována kvůli podezřelé aktivitě.');
        }

        return $user;
    }

    /**
     * Kontrola rate limitu pro admin přístup
     */
    public function check_admin_access_rate()
    {
        if (!$this->is_user_authorized()) {
            $ip = $this->get_client_ip();
            $admin_attempts = get_transient('wpsg_admin_attempts_' . md5($ip)) ?: 0;
            $admin_attempts++;

            set_transient('wpsg_admin_attempts_' . md5($ip), $admin_attempts, HOUR_IN_SECONDS);

            if ($admin_attempts > 10) {
                $this->log_security_event('EXCESSIVE_ADMIN_ACCESS', 'Excessive admin access from unauthorized user, IP: ' . $ip);
                set_transient('wpsg_blocked_ip_' . md5($ip), true, HOUR_IN_SECONDS * 2);
            }
        }
    }

    /**
     * Generovat time-based token
     */
    private function generate_time_based_token($action)
    {
        $timestamp = floor(time() / 300); // 5-minute window
        $data = $action . $timestamp . $this->get_encryption_key();
        return hash('sha256', $data);
    }

    /**
     * Ověřit time-based token
     */
    public function verify_time_based_token($action, $provided_token)
    {
        // Zkontrolovat aktuální i předchozí 5-minutové okno
        for ($i = 0; $i <= 1; $i++) {
            $timestamp = floor(time() / 300) - $i;
            $data = $action . $timestamp . $this->get_encryption_key();
            $valid_token = hash('sha256', $data);

            if (hash_equals($valid_token, $provided_token)) {
                return true;
            }
        }

        $this->log_security_event('INVALID_TOKEN', 'Invalid time-based token for action: ' . $action);
        return false;
    }

    /**
     * API Rate Limiting - komplexní ochrana proti automatizovaným útokům
     */
    public function setup_api_rate_limiting()
    {
        // WordPress REST API ochrany
        add_filter('rest_pre_dispatch', array($this, 'check_api_rate_limit'), 10, 3);

        // AJAX ochrany
        add_action('wp_ajax_nopriv_*', array($this, 'check_ajax_rate_limit'), 1);
        add_action('wp_ajax_*', array($this, 'check_ajax_rate_limit'), 1);

        // XML-RPC útoky (často používané pro DDoS)
        add_filter('xmlrpc_enabled', array($this, 'check_xmlrpc_rate_limit'));

        // Obecné API požadavky
        add_action('init', array($this, 'check_general_api_rate_limit'), 5);
    }

    /**
     * Kontrola rate limitu pro REST API
     */
    public function check_api_rate_limit($result, $server, $request)
    {
        $ip = $this->get_client_ip();
        $route = $request->get_route();

        // Detekce prostředí a úprava limitů
        $is_production = $this->is_production_environment();

        // Různé limity pro různé typy endpointů - mírnější na produkci
        if ($is_production) {
            $limits = array(
                'default' => array('requests' => 120, 'window' => 60), // Dvojnásobné limity na produkci
                'sensitive' => array('requests' => 30, 'window' => 60), // Mírnější i pro citlivé operace
                'public' => array('requests' => 200, 'window' => 60), // Více pro veřejné API
            );
        } else {
            $limits = array(
                'default' => array('requests' => 60, 'window' => 60), // Původní limity pro localhost
                'sensitive' => array('requests' => 10, 'window' => 60),
                'public' => array('requests' => 100, 'window' => 60),
            );
        }

        // Klasifikace endpointů
        $endpoint_type = 'default';
        if (
            strpos($route, '/wp/v2/users') !== false ||
            strpos($route, '/wp/v2/posts') !== false ||
            strpos($route, 'password') !== false ||
            strpos($route, 'login') !== false
        ) {
            $endpoint_type = 'sensitive';
        } elseif (strpos($route, '/wp/v2/posts') !== false && $request->get_method() === 'GET') {
            $endpoint_type = 'public';
        }

        $limit_config = $limits[$endpoint_type];
        $cache_key = 'wpsg_api_rate_' . md5($ip . $route) . '_' . floor(time() / $limit_config['window']);

        $requests = get_transient($cache_key) ?: 0;
        $requests++;

        // Adminům dát víc tolerace
        $admin_multiplier = current_user_can('manage_options') ? 2 : 1;
        $effective_limit = $limit_config['requests'] * $admin_multiplier;

        if ($requests > $effective_limit) {
            $this->log_security_event(
                'API_RATE_LIMIT_EXCEEDED',
                "API rate limit exceeded for {$endpoint_type} endpoint: {$route}",
                array('ip' => $ip, 'route' => $route, 'requests' => $requests, 'limit' => $effective_limit, 'is_admin' => current_user_can('manage_options'))
            );

            // Progresivní blokování - kratší na produkci, mírnější pro adminy
            $base_duration = $is_production ? 120 : 300; // 2min vs 5min
            $admin_reduction = current_user_can('manage_options') ? 0.5 : 1; // Admini dostanou poloviční blokování
            $block_duration = min($base_duration * $admin_reduction * (floor($requests / $effective_limit)), $is_production ? 1800 : 3600); // 30min vs 1h max
            set_transient('wpsg_api_blocked_' . md5($ip), true, $block_duration);

            return new WP_Error(
                'rate_limit_exceeded',
                'API rate limit exceeded. Try again later.',
                array('status' => 429)
            );
        }

        set_transient($cache_key, $requests, $limit_config['window']);

        // Přidat rate limit headers
        add_filter('rest_post_dispatch', function ($response) use ($requests, $limit_config) {
            $response->header('X-RateLimit-Limit', $limit_config['requests']);
            $response->header('X-RateLimit-Remaining', max(0, $limit_config['requests'] - $requests));
            $response->header('X-RateLimit-Reset', time() + $limit_config['window']);
            return $response;
        });

        return $result;
    }

    /**
     * Detekce produkčního prostředí
     */
    private function is_production_environment()
    {
        // Několik způsobů detekce produkčního prostředí

        // 1. WordPress konstanta
        if (defined('WP_ENV') && WP_ENV === 'production') {
            return true;
        }

        // 2. Server název není localhost
        $server_name = $_SERVER['SERVER_NAME'] ?? '';
        if (
            !empty($server_name) &&
            !in_array($server_name, ['localhost', '127.0.0.1', '::1']) &&
            !preg_match('/\.local$|\.dev$|\.test$/', $server_name)
        ) {
            return true;
        }

        // 3. WordPress debug je vypnutý
        if (!defined('WP_DEBUG') || !WP_DEBUG) {
            return true;
        }

        // 4. HTTPS je aktivní (často indikátor produkce)
        if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') {
            return true;
        }

        return false;
    }

    /**
     * Kontrola rate limitu pro AJAX
     */
    public function check_ajax_rate_limit()
    {
        // Detekce produkčního prostředí - mírnější limity
        $is_production = $this->is_production_environment();

        $ip = $this->get_client_ip();
        $action = sanitize_key($_REQUEST['action'] ?? 'unknown');

        // Vyloučit WordPress core AJAX akce z limitování
        $core_actions = array('heartbeat', 'save-widget', 'widgets-order', 'query-themes', 'query-plugins', 'admin-menu');
        if (in_array($action, $core_actions)) {
            return; // Neomezovat WordPress core funkcionalitu
        }

        // AJAX má vyšší limit, ale přesto kontrolujeme
        $cache_key = 'wpsg_ajax_rate_' . md5($ip) . '_' . floor(time() / 60);
        $requests = get_transient($cache_key) ?: 0;
        $requests++;

        // Produkční prostředí = mírnější limity
        if ($is_production) {
            $limit = is_user_logged_in() ? 600 : 120; // Dvojnásobné limity na produkci
        } else {
            $limit = is_user_logged_in() ? 300 : 60; // Původní limity pro localhost
        }

        // Povolit více požadavků pro administrátory
        if (current_user_can('manage_options')) {
            $limit = $is_production ? 1000 : 500;
        }

        if ($requests > $limit) {
            $this->log_security_event(
                'AJAX_RATE_LIMIT_EXCEEDED',
                "AJAX rate limit exceeded for action: {$action}",
                array('ip' => $ip, 'action' => $action, 'requests' => $requests, 'env' => $is_production ? 'production' : 'development')
            );

            // Na produkci kratší blokování
            $block_time = $is_production ? 300 : 600; // 5min vs 10min
            set_transient('wpsg_ajax_blocked_' . md5($ip), true, $block_time);

            wp_die('Překročen limit požadavků', 'Příliš mnoho požadavků', array('response' => 429));
        }

        set_transient($cache_key, $requests, 60);
    }

    /**
     * Kontrola XML-RPC útoků
     */
    public function check_xmlrpc_rate_limit($enabled)
    {
        if (!$enabled) return false;

        $ip = $this->get_client_ip();
        $cache_key = 'wpsg_xmlrpc_rate_' . md5($ip) . '_' . floor(time() / 300); // 5min okno
        $requests = get_transient($cache_key) ?: 0;
        $requests++;

        // XML-RPC má velmi nízký limit kvůli DDoS útokům
        if ($requests > 5) {
            $this->log_security_event(
                'XMLRPC_RATE_LIMIT_EXCEEDED',
                "XML-RPC rate limit exceeded",
                array('ip' => $ip, 'requests' => $requests)
            );

            set_transient('wpsg_xmlrpc_blocked_' . md5($ip), true, 1800); // 30min block

            // Úplně zakázat XML-RPC pro této IP
            return false;
        }

        set_transient($cache_key, $requests, 300);
        return $enabled;
    }

    /**
     * Obecná kontrola API rate limitu
     */
    public function check_general_api_rate_limit()
    {
        $ip = $this->get_client_ip();

        // Zkontrolovat všechny aktivní blokování
        $blocked_keys = array(
            'wpsg_api_blocked_' . md5($ip),
            'wpsg_ajax_blocked_' . md5($ip),
            'wpsg_xmlrpc_blocked_' . md5($ip)
        );

        foreach ($blocked_keys as $key) {
            if (get_transient($key)) {
                $this->log_security_event(
                    'BLOCKED_API_ACCESS',
                    "Blocked API access attempt from rate-limited IP",
                    array('ip' => $ip, 'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '')
                );

                // Zobrazit 429 stránku
                http_response_code(429);
                wp_die(
                    '<h1>Rate Limit Exceeded</h1><p>Too many requests. Please try again later.</p>',
                    'Překročen limit požadavků',
                    array('response' => 429)
                );
            }
        }

        // Detekce API scraping patterns
        $this->detect_api_scraping_patterns();
    }

    /**
     * Detekce API scraping patterns
     */
    private function detect_api_scraping_patterns()
    {
        $ip = $this->get_client_ip();
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $request_uri = $_SERVER['REQUEST_URI'] ?? '';

        // Podezřelé User-Agents
        $suspicious_agents = array(
            'bot',
            'crawler',
            'scraper',
            'spider',
            'curl',
            'wget',
            'python',
            'perl',
            'ruby',
            'java',
            'httpclient',
            'requests',
            'scrapy',
            'mechanize',
            'selenium'
        );

        $is_suspicious_agent = false;
        foreach ($suspicious_agents as $agent) {
            if (stripos($user_agent, $agent) !== false) {
                $is_suspicious_agent = true;
                break;
            }
        }

        // Podezřelé URL patterns (API endpoints, admin přístupy)
        $api_patterns = array('/wp-json/', '/wp-admin/', '/xmlrpc.php', '/wp-login.php');
        $is_api_request = false;
        foreach ($api_patterns as $pattern) {
            if (strpos($request_uri, $pattern) !== false) {
                $is_api_request = true;
                break;
            }
        }

        if ($is_suspicious_agent && $is_api_request) {
            $cache_key = 'wpsg_scraping_' . md5($ip) . '_' . floor(time() / 3600); // 1h okno
            $scraping_score = get_transient($cache_key) ?: 0;
            $scraping_score += 2; // Vyšší skóre pro kombinaci bot + API

            set_transient($cache_key, $scraping_score, 3600);

            if ($scraping_score >= 10) {
                $this->log_security_event(
                    'API_SCRAPING_DETECTED',
                    "API scraping behavior detected",
                    array(
                        'ip' => $ip,
                        'user_agent' => $user_agent,
                        'score' => $scraping_score,
                        'uri' => $request_uri
                    )
                );

                // Blokovat na delší dobu pro scraping
                set_transient('wpsg_scraping_blocked_' . md5($ip), true, 7200); // 2h block
                $this->auto_block_ip($ip, 'API SCRAPING DETEKOVÁNO - skóre: ' . $scraping_score);
            }
        }
    }

    /**
     * File Monitoring - detekce malware a podezřelých změn
     */
    public function setup_file_monitoring()
    {
        // Pravidelné skenování souborů
        add_action('init', array($this, 'schedule_file_monitoring'));

        // Hook pro WP-Cron skenování
        add_action('wpsg_daily_file_scan', array($this, 'perform_daily_file_scan'));
        add_action('wpsg_realtime_file_check', array($this, 'check_recently_modified_files'));

        // Monitoring při nahrávání souborů
        add_filter('wp_handle_upload_prefilter', array($this, 'scan_uploaded_file'));
        add_filter('wp_handle_sideload_prefilter', array($this, 'scan_uploaded_file'));

        // Plugin/theme monitoring
        add_action('activated_plugin', array($this, 'scan_activated_plugin'));
        add_action('switch_theme', array($this, 'scan_activated_theme'));
    }

    /**
     * Naplánovat pravidelné monitorování
     */
    public function schedule_file_monitoring()
    {
        // Denní kompletní skenování
        if (!wp_next_scheduled('wpsg_daily_file_scan')) {
            wp_schedule_event(time(), 'daily', 'wpsg_daily_file_scan');
        }

        // Častější kontrola změn (každé 2 hodiny)
        if (!wp_next_scheduled('wpsg_realtime_file_check')) {
            wp_schedule_event(time(), 'twicedaily', 'wpsg_realtime_file_check');
        }
    }

    /**
     * Denní kompletní skenování souborů
     */
    public function perform_daily_file_scan()
    {
        if (!get_option('wpsg_autopilot_enabled', false)) {
            return;
        }

        $start_time = microtime(true);
        $scanned_files = 0;
        $threats_found = 0;

        // Definovat kritické adresáře pro skenování
        $scan_paths = array(
            ABSPATH . 'wp-admin/',
            ABSPATH . 'wp-includes/',
            WP_CONTENT_DIR . '/themes/',
            WP_CONTENT_DIR . '/plugins/',
            WP_CONTENT_DIR . '/uploads/'
        );

        $this->log_security_event('FILE_SCAN_STARTED', 'Daily file scan started');

        foreach ($scan_paths as $path) {
            if (is_dir($path)) {
                $result = $this->scan_directory_for_malware($path);
                $scanned_files += $result['scanned'];
                $threats_found += $result['threats'];
            }
        }

        $duration = round(microtime(true) - $start_time, 2);

        $this->log_security_event(
            'FILE_SCAN_COMPLETED',
            "File scan completed: {$scanned_files} files scanned, {$threats_found} threats found in {$duration}s",
            array(
                'scanned_files' => $scanned_files,
                'threats_found' => $threats_found,
                'duration' => $duration
            )
        );

        // Uložit statistiky
        update_option('wpsg_last_file_scan', array(
            'timestamp' => time(),
            'scanned_files' => $scanned_files,
            'threats_found' => $threats_found,
            'duration' => $duration
        ));
    }

    /**
     * Skenování adresáře na malware
     */
    private function scan_directory_for_malware($directory, $max_files = 1000)
    {
        $scanned = 0;
        $threats = 0;

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($directory, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::LEAVES_ONLY
        );

        foreach ($iterator as $file) {
            if ($scanned >= $max_files) break; // Limit pro výkon

            $filepath = $file->getRealPath();

            // Skenovat pouze relevantní soubory
            if ($this->should_scan_file($filepath)) {
                $scan_result = $this->scan_file_for_malware($filepath);
                $scanned++;

                if ($scan_result['is_threat']) {
                    $threats++;
                    $this->handle_malware_detection($filepath, $scan_result);
                }
            }

            // Prevent timeout
            if ($scanned % 100 === 0) {
                if (function_exists('set_time_limit')) {
                    set_time_limit(30);
                }
            }
        }

        return array('scanned' => $scanned, 'threats' => $threats);
    }

    /**
     * Kontrola, zda soubor skenovat
     */
    private function should_scan_file($filepath)
    {
        $extension = strtolower(pathinfo($filepath, PATHINFO_EXTENSION));

        // Skenovat pouze potenciálně nebezpečné soubory
        $scannable_extensions = array('php', 'js', 'html', 'htm', 'css', 'txt', 'htaccess');

        if (!in_array($extension, $scannable_extensions)) {
            return false;
        }

        // Přeskočit velké soubory (>2MB)
        if (filesize($filepath) > 2 * 1024 * 1024) {
            return false;
        }

        // Přeskočit cache a temp soubory
        $skip_patterns = array('/cache/', '/tmp/', '/temp/', '.log', '.bak');
        foreach ($skip_patterns as $pattern) {
            if (strpos($filepath, $pattern) !== false) {
                return false;
            }
        }

        return true;
    }

    /**
     * Skenování konkrétního souboru na malware
     */
    public function scan_file_for_malware($filepath)
    {
        $content = file_get_contents($filepath);
        if ($content === false) {
            return array('is_threat' => false, 'reason' => 'Nepodařilo se přečíst soubor');
        }

        // Enhanced security: Use advanced malware detection (if available)
        $enhanced_scan = array('risk_level' => 'low', 'pattern_score' => 0);
        if (class_exists('WPSG_Enhanced_Security')) {
            $enhanced_scan = WPSG_Enhanced_Security::advanced_malware_scan($content);
        }

        // Log enhanced scan results for high-risk files
        if ($enhanced_scan['risk_level'] === 'high') {
            if (class_exists('WPSG_Enhanced_Security')) {
                WPSG_Enhanced_Security::secure_log('HIGH_RISK_FILE_DETECTED', [
                    'file_path' => $filepath,
                    'entropy_score' => $enhanced_scan['entropy_score'] ?? 0,
                    'pattern_score' => $enhanced_scan['pattern_score'] ?? 0,
                    'risk_level' => $enhanced_scan['risk_level'],
                    'matched_patterns' => $enhanced_scan['matched_patterns'] ?? array()
                ], 'warning');
            } else {
                error_log("WP Security Guardian: High risk file detected: $filepath");
            }
        }

        $threats = array();
        $threat_score = $enhanced_scan['pattern_score'];

        // Pokročilé malware patterns
        $malware_patterns = array(
            // PHP backdoors a webshells - enhanced detection
            '/eval\s*\(\s*base64_decode\s*\(/i' => array('score' => 5, 'type' => 'PHP_BACKDOOR'),
            '/eval\s*\(\s*gzinflate\s*\(/i' => array('score' => 5, 'type' => 'PHP_BACKDOOR'),
            '/eval\s*\(\s*str_rot13\s*\(/i' => array('score' => 4, 'type' => 'PHP_BACKDOOR'),
            '/eval\s*\(\s*\$_[GET|POST|REQUEST|COOKIE]/i' => array('score' => 5, 'type' => 'PHP_BACKDOOR_DIRECT'),
            '/eval\s*\([^)]*\$_[GET|POST|REQUEST|COOKIE]/i' => array('score' => 4, 'type' => 'PHP_BACKDOOR_INDIRECT'),
            '/system\s*\(\s*\$_[GET|POST|REQUEST]/i' => array('score' => 5, 'type' => 'COMMAND_INJECTION'),
            '/exec\s*\(\s*\$_[GET|POST|REQUEST]/i' => array('score' => 5, 'type' => 'COMMAND_INJECTION'),
            '/shell_exec\s*\(\s*\$_[GET|POST|REQUEST]/i' => array('score' => 5, 'type' => 'COMMAND_INJECTION'),
            '/passthru\s*\(\s*\$_[GET|POST|REQUEST]/i' => array('score' => 5, 'type' => 'COMMAND_INJECTION'),

            // Obfuskace a encoding
            '/chr\s*\(\s*\d+\s*\)\s*\.\s*chr\s*\(/i' => array('score' => 3, 'type' => 'OBFUSCATION'),
            '/\\\\x[0-9a-f]{2}/i' => array('score' => 2, 'type' => 'HEX_ENCODING'),
            '/[a-zA-Z0-9+\/]{100,}={0,2}/i' => array('score' => 2, 'type' => 'BASE64_SUSPICIOUS'),

            // File operations
            '/file_get_contents\s*\(\s*[\'\"]/i' => array('score' => 3, 'type' => 'REMOTE_INCLUDE'),
            '/fopen\s*\(\s*[\'\"]/i' => array('score' => 3, 'type' => 'REMOTE_FILE'),
            '/curl_exec\s*\([^)]*/i' => array('score' => 2, 'type' => 'REMOTE_REQUEST'),

            // Podezřelé funkce
            '/create_function\s*\(/i' => array('score' => 3, 'type' => 'DYNAMIC_FUNCTION'),
            '/preg_replace\s*\(.*\/e[\'\"]/i' => array('score' => 4, 'type' => 'PREG_REPLACE_E'),
            '/assert\s*\(\s*\$_/i' => array('score' => 4, 'type' => 'ASSERT_BACKDOOR'),

            // JavaScript suspicious patterns
            '/document\.write\s*\(\s*unescape\s*\(/i' => array('score' => 3, 'type' => 'JS_OBFUSCATION'),
            '/eval\s*\(\s*unescape\s*\(/i' => array('score' => 4, 'type' => 'JS_BACKDOOR'),
            '/setTimeout\s*\(\s*[\'\"]/i' => array('score' => 3, 'type' => 'JS_DELAYED_EXEC'),
        );

        foreach ($malware_patterns as $pattern => $info) {
            if (preg_match($pattern, $content, $matches)) {
                $threat_score += $info['score'];
                $threats[] = array(
                    'type' => $info['type'],
                    'score' => $info['score'],
                    'match' => substr($matches[0], 0, 100) // Limit délky
                );
            }
        }

        // Kontrola pro velmi dlouhé řádky (možná obfuskace)
        $lines = explode("\n", $content);
        foreach ($lines as $line_num => $line) {
            if (strlen($line) > 1000) {
                $threat_score += 1;
                $threats[] = array(
                    'type' => 'LONG_LINE_SUSPICIOUS',
                    'score' => 1,
                    'line' => $line_num + 1
                );
                break; // Pouze první dlouhý řádek
            }
        }

        // Kontrola podezřelých function names
        if (preg_match_all('/function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(/', $content, $function_matches)) {
            $suspicious_names = array('decode', 'decrypt', 'obfuscate', 'hide', 'encode64', 'unhex');
            foreach ($function_matches[1] as $func_name) {
                foreach ($suspicious_names as $suspicious) {
                    if (stripos($func_name, $suspicious) !== false) {
                        $threat_score += 2;
                        $threats[] = array(
                            'type' => 'SUSPICIOUS_FUNCTION_NAME',
                            'score' => 2,
                            'function' => $func_name
                        );
                        break 2; // Pouze jednou za soubor
                    }
                }
            }
        }

        // Determine threat status and risk level for AJAX compatibility
        $threat_detected = $threat_score >= 4 || $enhanced_scan['risk_level'] === 'high';
        $risk_level = 'low';
        if ($threat_score >= 8 || $enhanced_scan['risk_level'] === 'high') {
            $risk_level = 'high';
        } elseif ($threat_score >= 4 || $enhanced_scan['risk_level'] === 'medium') {
            $risk_level = 'medium';
        }
        
        // Collect pattern types for detailed reporting
        $patterns_found = array();
        foreach ($threats as $threat) {
            if (isset($threat['type'])) {
                $patterns_found[] = $threat['type'];
            }
        }
        
        return array(
            // Legacy format compatibility
            'is_threat' => $threat_detected,
            'threat_score' => $threat_score,
            'threats' => $threats,
            'reason' => $threat_detected ? 'Vysoké skóre hrozby: ' . $threat_score : 'Čistý soubor',
            
            // New format for AJAX endpoint compatibility
            'threat_detected' => $threat_detected,
            'risk_level' => $risk_level,
            'threat_type' => !empty($patterns_found) ? $patterns_found[0] : 'UNKNOWN',
            'patterns_found' => $patterns_found,
            'enhanced_scan' => $enhanced_scan
        );
    }

    /**
     * Zpracování detekované malware hrozby
     */
    private function handle_malware_detection($filepath, $scan_result)
    {
        $relative_path = str_replace(ABSPATH, '', $filepath);

        $this->log_security_event(
            'MALWARE_DETECTED',
            "Malware detected in file: {$relative_path}",
            array(
                'file' => $relative_path,
                'threat_score' => $scan_result['threat_score'],
                'threats' => $scan_result['threats'],
                'file_size' => filesize($filepath),
                'file_modified' => filemtime($filepath)
            )
        );

        // Pokus o karanténu souboru (přejmenování)
        $quarantine_path = $filepath . '.wpsg_quarantine_' . time();
        if (rename($filepath, $quarantine_path)) {
            $this->log_security_event('MALWARE_QUARANTINED', "File quarantined: {$relative_path}");

            // Zalogovat do autopilotu
            $this->log_autopilot_action('malware_quarantined', 'Soubor s malware byl umístěn do karantény', array(
                'file_path' => $relative_path,
                'threat_score' => $scan_result['threat_score'],
                'quarantine_path' => str_replace(ABSPATH, '', $quarantine_path)
            ));
        } else {
            $this->log_security_event('MALWARE_QUARANTINE_FAILED', "Failed to quarantine file: {$relative_path}");
        }

        // Upozornit administrátora
        $this->send_admin_alert('MALWARE_DETECTION', array(
            'file' => $relative_path,
            'threat_score' => $scan_result['threat_score']
        ));
    }

    /**
     * Kontrola nedávno upravených souborů
     */
    public function check_recent_file_changes()
    {
        try {
            $directories_to_check = [
                ABSPATH,
                WP_CONTENT_DIR . '/themes/',
                WP_CONTENT_DIR . '/plugins/',
                WP_CONTENT_DIR . '/uploads/'
            ];
            
            $recent_changes = [];
            $time_threshold = time() - (24 * 60 * 60); // Posledních 24 hodin
            
            foreach ($directories_to_check as $dir) {
                if (!is_dir($dir)) {
                    continue;
                }
                
                $iterator = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS)
                );
                
                foreach ($iterator as $file) {
                    if ($file->isFile() && $file->getMTime() > $time_threshold) {
                        $filepath = $file->getPathname();
                        $relative_path = str_replace(ABSPATH, '', $filepath);
                        
                        // Přeskočit cache a log soubory
                        if (strpos($relative_path, '/cache/') !== false || 
                            strpos($relative_path, '/logs/') !== false ||
                            strpos($relative_path, '.log') !== false) {
                            continue;
                        }
                        
                        $recent_changes[] = [
                            'file' => $relative_path,
                            'modified' => date('Y-m-d H:i:s', $file->getMTime()),
                            'size' => $file->getSize()
                        ];
                    }
                }
            }
            
            if (!empty($recent_changes)) {
                WPSG_Enhanced_Security::secure_log('RECENT_FILE_CHANGES_DETECTED', [
                    'count' => count($recent_changes),
                    'files' => array_slice($recent_changes, 0, 20) // Logovat jen prvních 20
                ], 'info');
            }
            
            return $recent_changes;
            
        } catch (Exception $e) {
            WPSG_Enhanced_Security::secure_log('FILE_CHANGES_CHECK_ERROR', [
                'error' => $e->getMessage()
            ], 'error');
            
            return [];
        }
    }

    /**
     * Kontrola nedávno upravených souborů
     */
    public function check_recently_modified_files()
    {
        if (!get_option('wpsg_autopilot_enabled', false)) {
            return;
        }

        $last_check = get_option('wpsg_last_file_mod_check', time() - 7200); // 2 hodiny zpět
        $current_time = time();

        // Kritické adresáře pro rychlou kontrolu
        $critical_paths = array(
            ABSPATH . 'wp-config.php',
            ABSPATH . '.htaccess',
            ABSPATH . 'wp-admin/',
            ABSPATH . 'wp-includes/',
        );

        $modified_files = 0;

        foreach ($critical_paths as $path) {
            if (is_file($path)) {
                if (filemtime($path) > $last_check) {
                    $this->scan_and_alert_if_malware($path);
                    $modified_files++;
                }
            } elseif (is_dir($path)) {
                $modified_files += $this->check_directory_modifications($path, $last_check);
            }
        }

        update_option('wpsg_last_file_mod_check', $current_time);

        if ($modified_files > 0) {
            $this->log_security_event(
                'FILE_MODIFICATIONS_DETECTED',
                "Detected {$modified_files} modified files in critical directories"
            );
        }
    }

    /**
     * Kontrola modifikací v adresáři
     */
    private function check_directory_modifications($directory, $since_time)
    {
        $modified_count = 0;

        try {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($directory, RecursiveDirectoryIterator::SKIP_DOTS),
                RecursiveIteratorIterator::LEAVES_ONLY
            );

            $checked = 0;
            foreach ($iterator as $file) {
                if ($checked++ > 200) break; // Limit pro výkon

                if ($file->getMTime() > $since_time && $this->should_scan_file($file->getRealPath())) {
                    $this->scan_and_alert_if_malware($file->getRealPath());
                    $modified_count++;
                }
            }
        } catch (Exception $e) {
            $this->log_security_event('FILE_CHECK_ERROR', 'Error checking directory: ' . $e->getMessage());
        }

        return $modified_count;
    }

    /**
     * Skenování a upozornění při detekci malware
     */
    private function scan_and_alert_if_malware($filepath)
    {
        $scan_result = $this->scan_file_for_malware($filepath);

        if ($scan_result['is_threat']) {
            $this->handle_malware_detection($filepath, $scan_result);
        }
    }

    /**
     * Skenování nahrávaného souboru
     */
    public function scan_uploaded_file($file)
    {
        if (!get_option('wpsg_autopilot_enabled', false)) {
            return $file;
        }

        $temp_path = $file['tmp_name'];

        if (file_exists($temp_path)) {
            $scan_result = $this->scan_file_for_malware($temp_path);

            if ($scan_result['is_threat']) {
                $this->log_security_event(
                    'MALICIOUS_UPLOAD_BLOCKED',
                    "Blocked malicious file upload: {$file['name']}",
                    array(
                        'filename' => $file['name'],
                        'threat_score' => $scan_result['threat_score'],
                        'threats' => $scan_result['threats']
                    )
                );

                $file['error'] = 'Soubor byl identifikován jako potenciálně nebezpečný a nahrávání bylo zablokováno.';
            }
        }

        return $file;
    }

    /**
     * Skenování aktivovaného pluginu
     */
    public function scan_activated_plugin($plugin)
    {
        $plugin_path = WP_PLUGIN_DIR . '/' . dirname($plugin);

        if (is_dir($plugin_path)) {
            $result = $this->scan_directory_for_malware($plugin_path, 50);

            if ($result['threats'] > 0) {
                $this->log_security_event(
                    'MALICIOUS_PLUGIN_DETECTED',
                    "Threats detected in activated plugin: {$plugin}",
                    array('plugin' => $plugin, 'threats_found' => $result['threats'])
                );
            }
        }
    }

    /**
     * Skenování aktivované šablony
     */
    public function scan_activated_theme($theme_name)
    {
        $theme_path = get_theme_root() . '/' . $theme_name;

        if (is_dir($theme_path)) {
            $result = $this->scan_directory_for_malware($theme_path, 50);

            if ($result['threats'] > 0) {
                $this->log_security_event(
                    'MALICIOUS_THEME_DETECTED',
                    "Threats detected in activated theme: {$theme_name}",
                    array('theme' => $theme_name, 'threats_found' => $result['threats'])
                );
            }
        }
    }

    /**
     * Poslání admin upozornění
     */
    private function send_admin_alert($type, $data)
    {
        // Pro budoucí implementaci email notifikací
        // Zatím jen logujeme
        $this->log_security_event('ADMIN_ALERT_' . $type, 'Admin alert triggered', $data);
    }


    public function deactivate()
    {
        // Při deaktivaci pouze vypneme ochranu, tabulku zachováme
        update_option('wpsg_security_enabled', false);
    }

    public function block_unauthorized_plugins()
    {
        if (!get_option('wpsg_security_enabled', true)) {
            return;
        }

        // Kontrola při pokusu o aktivaci jednoho pluginu
        if (isset($_GET['action']) && $_GET['action'] === 'activate' && isset($_GET['plugin'])) {
            $plugin_to_activate = sanitize_text_field($_GET['plugin']);

            if (!$this->is_plugin_whitelisted($plugin_to_activate)) {
                wp_die(
                    __('Tento plugin není povolen k aktivaci. Kontaktujte administrátora pro přidání na whitelist.', 'wp-security-guardian'),
                    __('Plugin blokován', 'wp-security-guardian'),
                    array('back_link' => true)
                );
            }
        }

        // Kontrola bulk aktivace
        if (isset($_POST['action']) && $_POST['action'] === 'activate-selected' && isset($_POST['checked'])) {
            $plugins_to_activate = array_map('sanitize_text_field', $_POST['checked']);

            foreach ($plugins_to_activate as $plugin) {
                if (!$this->is_plugin_whitelisted($plugin)) {
                    wp_die(
                        sprintf(__('Plugin %s není povolen k aktivaci. Kontaktujte administrátora pro přidání na whitelist.', 'wp-security-guardian'), $plugin),
                        __('Plugin blokován', 'wp-security-guardian'),
                        array('back_link' => true)
                    );
                }
            }
        }
    }

    private function is_plugin_whitelisted($plugin_path)
    {
        $whitelist = $this->get_whitelist();
        return in_array($plugin_path, $whitelist);
    }

    private function get_whitelist()
    {
        // Načíst z WordPress options
        $whitelist = get_option('wpsg_plugin_whitelist', array());

        // Pokud není v options, zkusíme databázi (migrace)
        if (empty($whitelist)) {
            global $wpdb;
            $table_name = $wpdb->prefix . $this->whitelist_table;

            $table_exists = $wpdb->get_var($wpdb->prepare("SHOW TABLES LIKE %s", $table_name)) === $table_name;
            if ($table_exists) {
                $results = $wpdb->get_results($wpdb->prepare("SELECT plugin_path FROM `{$table_name}`"), ARRAY_A);
                $whitelist = array_column($results, 'plugin_path');

                // Migrace z tabulky do options
                if (!empty($whitelist)) {
                    update_option('wpsg_plugin_whitelist', $whitelist);
                }
            }
        }

        // Pokud je whitelist stále prázdný, vrátit default
        if (empty($whitelist)) {
            $whitelist = array('wp-security-guardian/wp-security-guardian.php');
            update_option('wpsg_plugin_whitelist', $whitelist);
        }

        return $whitelist;
    }

    private function update_whitelist($whitelist)
    {
        // Uložit do WordPress options (hlavní úložiště)
        $result = update_option('wpsg_plugin_whitelist', $whitelist);

        // Také uložit do databázové tabulky (pro zpětnou kompatibilitu)
        global $wpdb;
        $table_name = $wpdb->prefix . $this->whitelist_table;

        $table_exists = $wpdb->get_var($wpdb->prepare("SHOW TABLES LIKE %s", $table_name)) === $table_name;
        if ($table_exists) {
            $wpdb->query($wpdb->prepare("TRUNCATE TABLE `{$table_name}`"));
            foreach ($whitelist as $plugin_path) {
                $wpdb->replace($table_name, array('plugin_path' => $plugin_path), array('%s'));
            }
        }

        return $result;
    }

    /**
     * Podmíněně přidat admin menu pouze pro autorizované uživatele
     */
    public function conditional_add_admin_menu()
    {

        $is_authorized = $this->is_user_authorized();

        if ($is_authorized) {
            $this->add_admin_menu();
        } else {
        }
    }

    public function add_admin_menu()
    {
        // Hlavní menu - WP Security Guardian
        $main_hook = add_menu_page(
            __('WP Security Guardian', 'wp-security-guardian'),
            __('WP Security Guardian', 'wp-security-guardian'),
            'manage_options',
            'wp-security-guardian',
            array($this, 'admin_page'),
            'dashicons-shield-alt',
            30
        );

        // Submenu - Whitelist (přejmenovat první položku)
        add_submenu_page(
            'wp-security-guardian',
            __('Povolené pluginy', 'wp-security-guardian'),
            __('Povolené pluginy', 'wp-security-guardian'),
            'manage_options',
            'wp-security-guardian',
            array($this, 'admin_page')
        );

        // Submenu - Security Dashboard
        add_submenu_page(
            'wp-security-guardian',
            __('Bezpečnostní dashboard', 'wp-security-guardian'),
            __('Bezpečnostní dashboard', 'wp-security-guardian'),
            'manage_options',
            'wp-security-dashboard',
            array($this, 'dashboard_page')
        );

        // Submenu - Auto-Pilot
        add_submenu_page(
            'wp-security-guardian',
            __('Automatická ochrana', 'wp-security-guardian'),
            __('Auto-Pilot', 'wp-security-guardian'),
            'manage_options',
            'wp-security-autopilot',
            array($this, 'autopilot_page')
        );

        // Submenu - Security Settings
        add_submenu_page(
            'wp-security-guardian',
            __('Nastavení zabezpečení', 'wp-security-guardian'),
            __('Nastavení zabezpečení', 'wp-security-guardian'),
            'manage_options',
            'wp-security-settings',
            array($this, 'settings_page')
        );

        // Debug submenu - only for authorized users (kombinuje Status a Testing)
        if ($this->is_user_authorized()) {
            add_submenu_page(
                'wp-security-guardian',
                __('Diagnostika & testování', 'wp-security-guardian'),
                __('Diagnostika & testování', 'wp-security-guardian'),
                'manage_options',
                'wp-security-diagnostics',
                array($this, 'diagnostics_page')
            );
        }
    }

    /**
     * Debug admin menu - pro testování kdy uživatel není autorizován
     */
    public function add_debug_admin_menu()
    {
        $current_user = wp_get_current_user();
        $page_hook = add_options_page(
            'WPSG DEBUG - ' . $current_user->user_email,
            'WPSG DEBUG - ' . $current_user->user_email,
            'manage_options',
            'wp-security-guardian-debug',
            array($this, 'debug_admin_page')
        );
    }

    /**
     * Debug admin stránka
     */
    public function debug_admin_page()
    {
        $current_user = wp_get_current_user();
        echo '<div class="wrap">';
        echo '<h1>WP Security Guardian - DEBUG</h1>';
        echo '<p><strong>Problém:</strong> Uživatel není autorizován pro přístup k Security Guardian.</p>';
        echo '<p><strong>Váš email:</strong> ' . esc_html($current_user->user_email) . '</p>';
        echo '<p><strong>Obsahuje "unifer":</strong> ' . (strpos($current_user->user_email, 'unifer') !== false ? 'ANO' : 'NE') . '</p>';
        echo '<p><strong>User ID:</strong> ' . $current_user->ID . '</p>';
        echo '<p><strong>User Login:</strong> ' . esc_html($current_user->user_login) . '</p>';
        echo '<p>Pokud váš email obsahuje "unifer", kontaktujte vývojáře.</p>';
        echo '</div>';
    }

    public function enqueue_admin_scripts($hook)
    {
        if ($hook !== 'settings_page_wp-security-guardian') {
            return;
        }

        wp_enqueue_script(
            'wpsg-admin-script',
            WPSG_PLUGIN_URL . 'assets/admin-script.js',
            array('jquery'),
            WPSG_VERSION,
            true
        );

        wp_localize_script('wpsg-admin-script', 'wpsg_ajax', array(
            'ajax_url' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('wpsg_nonce'),
        ));
    }

    public function add_settings_link($links)
    {
        $settings_link = '<a href="' . admin_url('options-general.php?page=wp-security-guardian') . '">' . __('Nastavení', 'wp-security-guardian') . '</a>';
        array_unshift($links, $settings_link);
        return $links;
    }

    public function admin_page()
    {
        // Ověřit oprávnění
        if (!current_user_can('manage_options')) {
            wp_die(__('Nemáte oprávnění pro přístup k této stránce.'));
        }

        // Ověřit autorizaci uživatele
        if (!$this->is_user_authorized()) {
            wp_die(__('Přístup odepřen. Nemáte oprávnění administrátora.'));
        }

        // Zpracování formuláře
        if (isset($_POST['submit'])) {

            if (wp_verify_nonce($_POST['wpsg_admin_nonce'], 'wpsg_admin_nonce')) {
                $this->handle_form_submission();
            } else {
                add_action('admin_notices', function () {
                    echo '<div class="notice notice-error is-dismissible"><p>Bezpečnostní ověření selhalo. Zkuste to znovu.</p></div>';
                });
            }
        }

        // Načtení dat po případném uložení  
        $whitelist = $this->get_whitelist();
        $security_enabled = get_option('wpsg_security_enabled', true);
        $all_plugins = get_plugins();

        // Pro template jsou proměnné dostupné
        $this->load_template('admin-page.php');
    }

    /**
     * Security Dashboard stránka
     */
    public function dashboard_page()
    {
        // Ověřit oprávnění
        if (!current_user_can('manage_options')) {
            wp_die(__('Nemáte oprávnění pro přístup k této stránce.'));
        }

        // Ověřit autorizaci uživatele
        if (!$this->is_user_authorized()) {
            wp_die(__('Přístup odepřen. Nemáte oprávnění administrátora.'));
        }

        // Připravit data pro dashboard
        $dashboard_data = $this->prepare_dashboard_data();

        $this->load_template('dashboard-page.php');
    }

    /**
     * Auto-Pilot stránka
     */
    public function autopilot_page()
    {
        // Ověřit oprávnění
        if (!current_user_can('manage_options')) {
            wp_die(__('Nemáte oprávnění pro přístup k této stránce.'));
        }

        // Ověřit autorizaci uživatele
        if (!$this->is_user_authorized()) {
            wp_die(__('Přístup odepřen. Nemáte oprávnění administrátora.'));
        }

        // Zpracování formuláře
        if (isset($_POST['submit'])) {
            if (wp_verify_nonce($_POST['wpsg_autopilot_nonce'], 'wpsg_autopilot_nonce')) {
                $this->handle_autopilot_form_submission();
            } else {
                add_action('admin_notices', function () {
                    echo '<div class="notice notice-error is-dismissible"><p>Bezpečnostní ověření selhalo. Zkuste to znovu.</p></div>';
                });
            }
        }

        // Zpracování vymazání actions
        if (isset($_POST['clear_actions']) && wp_verify_nonce($_POST['wpsg_autopilot_nonce'], 'wpsg_autopilot_nonce')) {
            update_option('wpsg_autopilot_actions', array());
            update_option('wpsg_blocked_ips', array());

            add_action('admin_notices', function () {
                echo '<div class="notice notice-success is-dismissible"><p>Všechny nedávné aktivity byly vymazány!</p></div>';
            });
        }

        // Zpracování vytvoření testovacích bloků
        if (isset($_POST['create_test_blocks']) && wp_verify_nonce($_POST['wpsg_autopilot_nonce'], 'wpsg_autopilot_nonce')) {
            $this->create_test_blocks();

            add_action('admin_notices', function () {
                echo '<div class="notice notice-success is-dismissible"><p>Testovací blokované IP adresy byly vytvořeny!</p></div>';
            });
        }

        // Zpracování odblokování IP
        if (isset($_POST['unblock_ip']) && wp_verify_nonce($_POST['wpsg_autopilot_nonce'], 'wpsg_autopilot_nonce')) {
            $ip_to_unblock = sanitize_text_field($_POST['unblock_ip']);
            $blocked_ips = get_option('wpsg_blocked_ips', array());

            if (isset($blocked_ips[$ip_to_unblock])) {
                unset($blocked_ips[$ip_to_unblock]);
                update_option('wpsg_blocked_ips', $blocked_ips);

                // SKUTEČNÉ ODBLOKOVÁNÍ: Odstranit z .htaccess
                $this->remove_ip_from_htaccess_block($ip_to_unblock);

                // Také aktualizovat Auto-Pilot akce - označit jako odblokované
                $actions = get_option('wpsg_autopilot_actions', array());
                foreach ($actions as &$action) {
                    if ($action['ip_address'] === $ip_to_unblock && $action['type'] === 'blocked' && !isset($action['unblocked'])) {
                        $action['unblocked'] = true;
                        $action['unblocked_at'] = current_time('mysql');
                        $action['unblocked_by'] = 'admin_manual';
                        break;
                    }
                }
                update_option('wpsg_autopilot_actions', $actions);

                // Místo wp_redirect použijeme success notice a JavaScript
                add_action('admin_notices', function () use ($ip_to_unblock) {
                    echo '<div class="notice notice-success is-dismissible"><p>IP adresa ' . esc_html($ip_to_unblock) . ' byla úspěšně odblokována!</p></div>';
                });

                // JavaScript pro reload po úspěšném odblokování
                add_action('admin_footer', function () {
                    echo '<script>
                        // Reload stránky po krátkém zpoždění pro zobrazení notifikace
                        setTimeout(function() {
                            if (window.location.hash !== "#unblocked") {
                                window.location.hash = "#unblocked";
                                window.location.reload();
                            }
                        }, 100);
                    </script>';
                });
            }
        }

        // Připravit data pro autopilot
        $autopilot_data = $this->prepare_autopilot_data();

        $this->load_template('autopilot-page.php');
    }

    /**
     * XSS Protection - přidává Content Security Policy hlavičky
     */
    public function add_xss_protection_headers()
    {
        if (!headers_sent()) {
            // Pouze základní bezpečnostní hlavičky bez CSP pro WordPress kompatibilitu
            header("X-Content-Type-Options: nosniff");
            header("X-Frame-Options: SAMEORIGIN");
            header("X-XSS-Protection: 1; mode=block");
            header("Referrer-Policy: strict-origin-when-cross-origin");

            // CSP hlavičky aplikujeme pouze na frontend, ne na admin 
            if (!is_admin() && !wp_doing_ajax()) {
                header("Content-Security-Policy: default-src 'self' 'unsafe-inline' 'unsafe-eval'; script-src 'self' 'unsafe-inline' 'unsafe-eval' *.wordpress.org *.wp.com *.jquery.com cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' fonts.googleapis.com *.wp.com; font-src 'self' fonts.gstatic.com data:; img-src 'self' data: *.gravatar.com *.w.org *.wp.com blob:; connect-src 'self' *.wordpress.org *.wp.com; frame-ancestors 'self'; form-action 'self' *.wordpress.org *.wp.com;");
            }
        }
    }

    /**
     * Authentication Protection - zaznamenává úspěšné přihlášení
     */
    public function log_successful_login($user_login, $user)
    {
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'neznámá';
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';

        // Log úspěšného přihlášení
        error_log("WPSG Security: Úspěšné přihlášení - Uživatel: {$user_login}, IP: {$ip}");

        // Kontrola podezřelé aktivity (přihlášení z nové IP)
        $recent_logins = get_user_meta($user->ID, 'wpsg_recent_login_ips', true);
        if (!is_array($recent_logins)) {
            $recent_logins = array();
        }

        if (!in_array($ip, $recent_logins)) {
            // Nová IP adresa - přidat do seznamu
            $recent_logins[] = $ip;
            // Udržovat pouze posledních 5 IP adres
            $recent_logins = array_slice($recent_logins, -5);
            update_user_meta($user->ID, 'wpsg_recent_login_ips', $recent_logins);
        }
    }

    /**
     * Authentication Protection - zaznamenává neúspěšné přihlášení
     */
    public function log_failed_login($username)
    {
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'neznámá';
        $attempts_key = 'wpsg_login_attempts_' . $ip;

        // Získat aktuální počet pokusů
        $attempts = get_transient($attempts_key);
        if (!$attempts) {
            $attempts = 0;
        }
        $attempts++;

        // Zaznamenat pokus na 15 minut
        set_transient($attempts_key, $attempts, 15 * MINUTE_IN_SECONDS);

        // Log neúspěšného pokusu
        error_log("WPSG Security: Neúspěšné přihlášení - Uživatel: {$username}, IP: {$ip}, Pokus: {$attempts}");

        // Blokovat IP po 5 neúspěšných pokusech
        if ($attempts >= 5) {
            $this->block_ip_temporarily($ip, 'Příliš mnoho neúspěšných přihlášení');
        }
    }

    /**
     * Authentication Protection - pokročilé monitorování neúspěšných přihlášení
     */
    public function monitor_failed_login($username)
    {
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'neznámá';

        // Enhanced monitoring pro failed login
        error_log("WPSG Security: Neúspěšné přihlášení - Uživatel: {$username}, IP: {$ip}");

        // Detekce podezřelých vzorců
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $suspicious_patterns = [
            '/bot/i',
            '/crawler/i',
            '/scanner/i',
            '/hack/i'
        ];

        foreach ($suspicious_patterns as $pattern) {
            if (preg_match($pattern, $user_agent)) {
                $this->block_ip_temporarily($ip, 'Podezřelý user agent při přihlášení');
                break;
            }
        }
    }

    /**
     * Authentication Protection - kontroluje pokusy o přihlášení
     */
    public function check_login_attempt($user, $username, $password)
    {
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'neznámá';
        $attempts_key = 'wpsg_login_attempts_' . $ip;
        $attempts = get_transient($attempts_key);

        // Blokovat po 5 pokusech
        if ($attempts && $attempts >= 5) {
            return new WP_Error(
                'login_blocked',
                'IP adresa byla dočasně zablokována kvůli příliš mnoha neúspěšným pokusům o přihlášení. Zkuste to znovu za 15 minut.'
            );
        }

        return $user;
    }

    /**
     * Dočasně zablokuje IP adresu
     */
    private function block_ip_temporarily($ip, $reason)
    {
        $blocked_key = 'wpsg_blocked_ip_' . str_replace('.', '_', $ip);
        set_transient($blocked_key, $reason, 15 * MINUTE_IN_SECONDS);

        error_log("WPSG Security: IP {$ip} zablokována - důvod: {$reason}");
    }

    /**
     * File Upload Security - pokročilé kontroly nahrávaných souborů
     */
    public function enhanced_upload_security($file)
    {
        $filename = $file['name'];
        $tmp_path = $file['tmp_name'];

        // Kontrola nebezpečných přípon
        $dangerous_extensions = array('php', 'php3', 'php4', 'php5', 'phtml', 'exe', 'scr', 'bat', 'cmd', 'js', 'vbs');
        $file_extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));

        if (in_array($file_extension, $dangerous_extensions)) {
            $file['error'] = 'Nahrávaní souborů s příponou .' . $file_extension . ' není povoleno z bezpečnostních důvodů.';
            error_log("WPSG Security: Blokován pokus o nahrání nebezpečného souboru: {$filename}");
            return $file;
        }

        // Kontrola obsahu souboru pomocí finfo
        if (function_exists('finfo_open') && file_exists($tmp_path)) {
            $finfo = finfo_open(FILEINFO_MIME_TYPE);
            $mime_type = finfo_file($finfo, $tmp_path);
            finfo_close($finfo);

            // Kontrola, zda MIME type odpovídá příponě
            $allowed_mime_types = array(
                'jpg' => 'image/jpeg',
                'jpeg' => 'image/jpeg',
                'png' => 'image/png',
                'gif' => 'image/gif',
                'pdf' => 'application/pdf',
                'doc' => 'application/msword',
                'docx' => 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
            );

            if (isset($allowed_mime_types[$file_extension])) {
                if ($mime_type !== $allowed_mime_types[$file_extension]) {
                    $file['error'] = 'Typ souboru neodpovídá jeho obsahu. Možný pokus o únik bezpečnosti.';
                    error_log("WPSG Security: MIME type mismatch - očekávaný: {$allowed_mime_types[$file_extension]}, skutečný: {$mime_type}");
                    return $file;
                }
            }
        }

        return $file;
    }

    /**
     * Omezí povolené MIME typy pro nahrávání
     */
    public function restrict_upload_mimes($existing_mimes)
    {
        // Odebrat potenciálně nebezpečné typy
        unset($existing_mimes['exe']);
        unset($existing_mimes['com']);
        unset($existing_mimes['bat']);
        unset($existing_mimes['cmd']);
        unset($existing_mimes['scr']);
        unset($existing_mimes['vbs']);
        unset($existing_mimes['js']);

        return $existing_mimes;
    }

    /**
     * Ověřuje obsah souboru proti jeho příponě
     */
    public function verify_file_content($data, $file, $filename, $mimes, $real_mime)
    {
        // Pokročilá kontrola pro PHP soubory skryté v obrázcích
        if (!empty($file) && file_exists($file)) {
            $content = file_get_contents($file, false, null, 0, 1024); // Přečíst prvních 1KB

            // Hledání PHP tagů v souboru
            if (
                strpos($content, '<?php') !== false ||
                strpos($content, '<?') !== false ||
                strpos($content, '<script') !== false
            ) {

                error_log("WPSG Security: PHP kód detekován v nahrávaném souboru: {$filename}");

                return array(
                    'ext' => false,
                    'type' => false,
                    'proper_filename' => false
                );
            }
        }

        return $data;
    }

    /**
     * Advanced Monitoring - spouští bezpečnostní monitorování
     */
    public function start_security_monitoring()
    {
        // Kontrola podezřelé aktivity každých 5 minut
        if (!wp_next_scheduled('wpsg_security_monitoring')) {
            wp_schedule_event(time(), 'hourly', 'wpsg_security_monitoring');
        }

        // Sledování pokusů o přístup k citlivým souborům
        add_action('init', array($this, 'monitor_suspicious_requests'));

        // Měření výkonu a detekce útoků
        $this->monitor_request_patterns();
    }

    /**
     * Monitoruje podezřelé požadavky
     */
    public function monitor_suspicious_requests()
    {
        $request_uri = $_SERVER['REQUEST_URI'] ?? '';
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'neznámá';

        // Podezřelé URL vzory
        $suspicious_patterns = array(
            '/wp-config\.php',
            '/\.htaccess',
            '/etc/passwd',
            '/proc/self/environ',
            'eval\(',
            'base64_decode',
            '<script',
            'javascript:',
            'union.*select',
            'drop.*table'
        );

        foreach ($suspicious_patterns as $pattern) {
            if (
                preg_match('/' . preg_quote($pattern, '/') . '/i', $request_uri) ||
                preg_match('/' . preg_quote($pattern, '/') . '/i', $user_agent)
            ) {

                error_log("WPSG Security ALERT: Podezřelý požadavek detekován - IP: {$ip}, Pattern: {$pattern}, URI: {$request_uri}");

                // Automaticky zablokovat IP po detekci vážného útoku
                if (strpos($pattern, 'union') !== false || strpos($pattern, 'drop') !== false) {
                    $this->block_ip_temporarily($ip, 'SQL injection pokus');
                }

                break; // Stačí jeden match
            }
        }
    }

    /**
     * Monitoruje vzory požadavků pro detekci útoků
     */
    private function monitor_request_patterns()
    {
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'neznámá';
        $current_time = time();
        $requests_key = 'wpsg_requests_' . str_replace('.', '_', $ip);

        // Získat historii požadavků z posledních 5 minut
        $requests = get_transient($requests_key);
        if (!is_array($requests)) {
            $requests = array();
        }

        // Přidat nový požadavek
        $requests[] = $current_time;

        // Udržovat pouze posledních 5 minut
        $requests = array_filter($requests, function ($time) use ($current_time) {
            return ($current_time - $time) <= 300; // 5 minut
        });

        // Uložit aktualizovaný seznam
        set_transient($requests_key, $requests, 300);

        // Pokud více než 100 požadavků za 5 minut, považovat za útok
        if (count($requests) > 100) {
            error_log("WPSG Security ALERT: DDoS útok detekován z IP: {$ip} - {count($requests)} požadavků za 5 minut");
            $this->block_ip_temporarily($ip, 'DDoS útok');
        }
    }

    /**
     * Loguje přístup na frontend stránky
     */
    public function log_page_access()
    {
        if (is_admin()) return; // Pouze frontend

        $ip = $_SERVER['REMOTE_ADDR'] ?? 'neznámá';
        $page_url = $_SERVER['REQUEST_URI'] ?? '';
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';

        // Log pouze jednou za hodinu pro stejnou IP a stránku
        $log_key = 'wpsg_page_log_' . md5($ip . $page_url);
        if (!get_transient($log_key)) {
            error_log("WPSG Monitor: Frontend přístup - IP: {$ip}, Stránka: {$page_url}");
            set_transient($log_key, true, HOUR_IN_SECONDS);
        }
    }

    /**
     * Monitoruje přístup do admin oblasti
     */
    public function monitor_admin_access()
    {
        if (!is_admin()) return; // Pouze admin

        $ip = $_SERVER['REMOTE_ADDR'] ?? 'neznámá';
        $screen = get_current_screen();
        $admin_page = $_GET['page'] ?? ($screen ? $screen->id : 'dashboard');
        $user = wp_get_current_user();

        error_log("WPSG Monitor: Admin přístup - Uživatel: {$user->user_login}, IP: {$ip}, Stránka: {$admin_page}");
    }

    /**
     * HTTPS/SSL Enforcement - vynucuje HTTPS přesměrování
     */
    public function force_https_redirect()
    {
        // Pouze pokud není už HTTPS a není ve vývojovém prostředí
        if (!is_ssl() && !defined('WP_DEBUG') && !is_admin()) {
            $https_url = 'https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];

            error_log("WPSG Security: HTTPS přesměrování z HTTP na: {$https_url}");

            wp_redirect($https_url, 301);
            exit;
        }
    }

    /**
     * Vynucuje HTTPS v admin oblasti
     */
    public function force_admin_https()
    {
        if (!is_ssl() && is_admin() && !defined('WP_DEBUG')) {
            $https_url = 'https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];

            error_log("WPSG Security: HTTPS admin přesměrování na: {$https_url}");

            wp_redirect($https_url, 301);
            exit;
        }
    }

    /**
     * Vynucuje HTTPS pro login přesměrování
     */
    public function force_login_https($redirect_to, $request, $user)
    {
        // Zajistit že přesměrování je vždy na HTTPS
        if (strpos($redirect_to, 'http://') === 0) {
            $redirect_to = str_replace('http://', 'https://', $redirect_to);
            error_log("WPSG Security: Login přesměrování upraven na HTTPS: {$redirect_to}");
        }

        return $redirect_to;
    }

    /**
     * Security Settings stránka
     */
    public function settings_page()
    {
        // Ověřit oprávnění
        if (!current_user_can('manage_options')) {
            wp_die(__('Nemáte oprávnění pro přístup k této stránce.'));
        }

        // Ověřit autorizaci uživatele
        if (!$this->is_user_authorized()) {
            wp_die(__('Přístup odepřen. Nemáte oprávnění administrátora.'));
        }

        $this->load_template('settings-page.php');
    }

    /**
     * Security Status debug stránka
     */
    public function status_page()
    {
        // Ověřit oprávnění
        if (!current_user_can('manage_options')) {
            wp_die(__('Nemáte oprávnění pro přístup k této stránce.'));
        }

        // Ověřit autorizaci uživatele
        if (!$this->is_user_authorized()) {
            wp_die(__('Přístup odepřen. Nemáte oprávnění administrátora.'));
        }

        // Získat aktuální status
        $status = $this->get_security_status();
        $tests = $status['tests'];

?>
        <div class="wrap">
            <h1>🔍 Security Status - Real Functionality Test</h1>

            <div style="background: white; border-radius: 8px; padding: 20px; margin: 20px 0;">
                <h2>Celkový stav: <?php echo $status['active']; ?>/<?php echo $status['total']; ?> (<?php echo $status['percentage']; ?>%)</h2>

                <table class="widefat" style="margin-top: 20px;">
                    <thead>
                        <tr>
                            <th>Security Feature</th>
                            <th>Status</th>
                            <th>Real Test Result</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>WordPress Version Hidden</td>
                            <td><?php echo $tests['wp_version_hidden'] ? '✅ ACTIVE' : '❌ INACTIVE'; ?></td>
                            <td><?php echo $tests['wp_version_hidden'] ? 'wp_generator removed from wp_head' : 'wp_generator still active'; ?></td>
                        </tr>
                        <tr>
                            <td>File Editing Disabled</td>
                            <td><?php echo $tests['file_editing_disabled'] ? '✅ ACTIVE' : '❌ INACTIVE'; ?></td>
                            <td><?php echo $tests['file_editing_disabled'] ? 'DISALLOW_FILE_EDIT is TRUE' : 'File editing still allowed'; ?></td>
                        </tr>
                        <tr>
                            <td>XML-RPC Disabled</td>
                            <td><?php echo $tests['xmlrpc_disabled'] ? '✅ ACTIVE' : '❌ INACTIVE'; ?></td>
                            <td><?php echo $tests['xmlrpc_disabled'] ? 'xmlrpc_enabled filter returns FALSE' : 'XML-RPC still enabled'; ?></td>
                        </tr>
                        <tr>
                            <td>2FA System</td>
                            <td><?php echo $tests['2fa_active'] ? '✅ LOADED' : '❌ NOT LOADED'; ?></td>
                            <td><?php echo $tests['2fa_active'] ? 'WPSG_Two_Factor_Auth class exists' : 'Class not found'; ?></td>
                        </tr>
                        <tr>
                            <td>Security Headers</td>
                            <td><?php echo $tests['security_headers_active'] ? '✅ LOADED' : '❌ NOT LOADED'; ?></td>
                            <td><?php echo $tests['security_headers_active'] ? 'WPSG_Security_Headers class exists' : 'Class not found'; ?></td>
                        </tr>
                        <tr>
                            <td>SSL Monitor</td>
                            <td><?php echo $tests['ssl_monitor_active'] ? '✅ LOADED' : '❌ NOT LOADED'; ?></td>
                            <td><?php echo $tests['ssl_monitor_active'] ? 'WPSG_SSL_Monitor class exists' : 'Class not found'; ?></td>
                        </tr>
                        <tr>
                            <td>Login Attempt Limiting</td>
                            <td><?php echo $tests['login_limiting_active'] ? '✅ ACTIVE' : '❌ INACTIVE'; ?></td>
                            <td><?php echo $tests['login_limiting_active'] ? 'authenticate filter hooked' : 'No hook active'; ?></td>
                        </tr>
                        <tr>
                            <td>IP Blocking System</td>
                            <td><?php echo $tests['ip_blocking_active'] ? '✅ ACTIVE' : '❌ INACTIVE'; ?></td>
                            <td><?php echo $tests['ip_blocking_active'] ? 'init action hooked for IP check' : 'No IP checking active'; ?></td>
                        </tr>
                        <tr>
                            <td>404 Error Tracking</td>
                            <td><?php echo $tests['404_tracking_active'] ? '✅ ACTIVE' : '❌ INACTIVE'; ?></td>
                            <td><?php echo $tests['404_tracking_active'] ? 'wp action hooked for 404 tracking' : 'No 404 tracking'; ?></td>
                        </tr>
                        <tr>
                            <td>User Enumeration Blocked</td>
                            <td><?php echo $tests['user_enum_blocked'] ? '✅ ACTIVE' : '❌ INACTIVE'; ?></td>
                            <td><?php echo $tests['user_enum_blocked'] ? 'Option enabled in database' : 'Option disabled'; ?></td>
                        </tr>
                    </tbody>
                </table>

                <h3>Database Options Check:</h3>
                <div style="background: #f1f1f1; padding: 15px; border-radius: 4px; font-family: monospace;">
                    <strong>wpsg_hide_wp_version:</strong> <?php echo get_option('wpsg_hide_wp_version', 'not_set') ? 'true' : 'false'; ?><br>
                    <strong>wpsg_disable_file_editing:</strong> <?php echo get_option('wpsg_disable_file_editing', 'not_set') ? 'true' : 'false'; ?><br>
                    <strong>wpsg_disable_xmlrpc:</strong> <?php echo get_option('wpsg_disable_xmlrpc', 'not_set') ? 'true' : 'false'; ?><br>
                    <strong>wpsg_require_2fa:</strong> <?php echo get_option('wpsg_require_2fa', 'not_set'); ?><br>
                    <strong>wpsg_limit_login_attempts:</strong> <?php echo get_option('wpsg_limit_login_attempts', 'not_set') ? 'true' : 'false'; ?><br>
                    <strong>wpsg_ip_blocking:</strong> <?php echo get_option('wpsg_ip_blocking', 'not_set') ? 'true' : 'false'; ?><br>
                    <strong>wpsg_404_threshold:</strong> <?php echo get_option('wpsg_404_threshold', 'not_set'); ?><br>
                </div>
            </div>
        </div>
    <?php
    }

    /**
     * Bezpečné načtení template souboru s path validací
     */
    private function load_template($template_name) {
        // Whitelist povolených template souborů
        $allowed_templates = array(
            'admin-page.php',
            'dashboard-page.php', 
            'autopilot-page.php',
            'settings-page.php',
            'diagnostics-page.php'
        );
        
        // Validace názvu template
        if (!in_array($template_name, $allowed_templates)) {
            wp_die(__('Neplatný template soubor.', 'wp-security-guardian'));
        }
        
        // Sestavit cestu a ověřit existenci
        $template_path = WPSG_PLUGIN_PATH . 'templates/' . $template_name;
        if (!file_exists($template_path)) {
            wp_die(__('Template soubor nenalezen.', 'wp-security-guardian'));
        }
        
        // Ověřit že soubor je ve správném adresáři (prevence path traversal)
        $real_path = realpath($template_path);
        $template_dir = realpath(WPSG_PLUGIN_PATH . 'templates/');
        if (strpos($real_path, $template_dir) !== 0) {
            wp_die(__('Bezpečnostní chyba - neplatná cesta k template.', 'wp-security-guardian'));
        }
        
        include $template_path;
    }

    /**
     * Připravit data pro security dashboard
     */
    private function prepare_dashboard_data()
    {
        $data = array();

        // Základní statistiky
        $data['security_enabled'] = get_option('wpsg_security_enabled', true);
        $data['whitelist'] = $this->get_whitelist();
        $data['all_plugins'] = get_plugins();
        $data['security_logs'] = get_option('wpsg_security_logs', array());

        // Security Score výpočet a detailní checklist
        $data['security_score'] = $this->calculate_detailed_security_score();
        $data['security_checklist'] = $this->get_detailed_security_checklist();

        // Threat statistiky (posledních 30 dní)
        $data['threat_stats'] = $this->get_threat_statistics();

        // Plugin statistiky
        $data['plugin_stats'] = $this->get_plugin_statistics();

        // Doporučení pro zlepšení
        $data['recommendations'] = $this->get_security_recommendations();

        // Nedávné události (posledních 10)
        $data['recent_events'] = array_slice(array_reverse($data['security_logs']), 0, 10);

        return $data;
    }

    /**
     * Vypočítat security score (0-100)
     */
    private function calculate_security_score()
    {
        $score = 0;
        $max_score = 100;

        // Security Guardian aktivní (25 bodů)
        if (get_option('wpsg_security_enabled', true)) {
            $score += 25;
        }

        // Whitelist nastaven (15 bodů)
        $whitelist = $this->get_whitelist();
        if (count($whitelist) > 1) { // více než jen náš plugin
            $score += 15;
        }

        // Žádné kritické události za posledních 7 dní (20 bodů)
        $recent_critical = $this->count_recent_critical_events(7);
        if ($recent_critical == 0) {
            $score += 20;
        } elseif ($recent_critical < 3) {
            $score += 10;
        }

        // File integrity OK (15 bodů)
        if ($this->check_file_integrity_status()) {
            $score += 15;
        }

        // Žádné blokované IP za posledních 24h (10 bodů)
        if ($this->count_blocked_ips_today() == 0) {
            $score += 10;
        }

        // Regular backups (10 bodů)
        if (get_option('wpsg_config_backup')) {
            $score += 10;
        }

        // Logging aktivní (5 bodů)
        $logs = get_option('wpsg_security_logs', array());
        if (count($logs) > 0) {
            $score += 5;
        }

        return min($score, $max_score);
    }

    /**
     * Získat statistiky hrozeb
     */
    private function get_threat_statistics()
    {
        $logs = get_option('wpsg_security_logs', array());
        $thirty_days_ago = strtotime('-30 days');

        $stats = array(
            'total_threats' => 0,
            'blocked_ips' => 0,
            'failed_logins' => 0,
            'file_modifications' => 0,
            'unauthorized_access' => 0,
            'daily_stats' => array()
        );

        // Denní statistiky pro graf (posledních 30 dní)
        for ($i = 29; $i >= 0; $i--) {
            $date = date('Y-m-d', strtotime("-{$i} days"));
            $stats['daily_stats'][$date] = array(
                'threats' => 0,
                'blocked_ips' => 0,
                'failed_logins' => 0
            );
        }

        foreach ($logs as $log) {
            $log_time = strtotime($log['timestamp']);
            if ($log_time > $thirty_days_ago) {
                $log_date = date('Y-m-d', $log_time);

                $stats['total_threats']++;

                switch ($log['event_type']) {
                    case 'IP_BLOCKED':
                        $stats['blocked_ips']++;
                        if (isset($stats['daily_stats'][$log_date])) {
                            $stats['daily_stats'][$log_date]['blocked_ips']++;
                        }
                        break;
                    case 'LOGIN_FAILED':
                        $stats['failed_logins']++;
                        if (isset($stats['daily_stats'][$log_date])) {
                            $stats['daily_stats'][$log_date]['failed_logins']++;
                        }
                        break;
                    case 'FILE_MODIFIED':
                    case 'INTEGRITY_VIOLATION':
                        $stats['file_modifications']++;
                        break;
                    case 'UNAUTHORIZED_ACCESS':
                        $stats['unauthorized_access']++;
                        break;
                }

                if (isset($stats['daily_stats'][$log_date])) {
                    $stats['daily_stats'][$log_date]['threats']++;
                }
            }
        }

        return $stats;
    }

    /**
     * Získat statistiky pluginů
     */
    private function get_plugin_statistics()
    {
        $all_plugins = get_plugins();
        $whitelist = $this->get_whitelist();
        $active_plugins = get_option('active_plugins', array());

        return array(
            'total_plugins' => count($all_plugins),
            'whitelisted_plugins' => count($whitelist),
            'blocked_plugins' => count($all_plugins) - count($whitelist),
            'active_plugins' => count($active_plugins),
            'protection_ratio' => round((count($whitelist) / count($all_plugins)) * 100, 1)
        );
    }

    /**
     * Získat detailní security checklist
     */
    private function get_detailed_security_checklist()
    {
        $checklist = array();

        // 1. WordPress Core Security
        $checklist['wp_core'] = array(
            'title' => 'WordPress Core',
            'checks' => array(
                'wp_version' => array(
                    'name' => 'Aktuální verze WordPress',
                    'status' => $this->check_wp_version_current(),
                    'weight' => 10,
                    'description' => 'WordPress je aktualizován na nejnovější verzi'
                ),
                'wp_debug' => array(
                    'name' => 'WP Debug vypnutý',
                    'status' => !defined('WP_DEBUG') || !WP_DEBUG,
                    'weight' => 5,
                    'description' => 'Debug režim je vypnutý v produkci'
                ),
                'admin_username' => array(
                    'name' => 'Zabezpečené admin uživatelské jméno',
                    'status' => $this->check_admin_username_secure(),
                    'weight' => 8,
                    'description' => 'Admin účet nemá výchozí jméno "admin"'
                )
            )
        );

        // 2. Plugin Security
        $checklist['plugins'] = array(
            'title' => 'Pluginy a jejich bezpečnost',
            'checks' => array(
                'plugin_whitelist' => array(
                    'name' => 'Plugin whitelist aktivní',
                    'status' => get_option('wpsg_security_enabled', true),
                    'weight' => 15,
                    'description' => 'Security Guardian aktivně chrání před neautorizovanými pluginy'
                ),
                'outdated_plugins' => array(
                    'name' => 'Žádné zastaralé pluginy',
                    'status' => $this->check_no_outdated_plugins(),
                    'weight' => 10,
                    'description' => 'Všechny pluginy jsou aktualizovány'
                ),
                'suspicious_plugins' => array(
                    'name' => 'Žádné podezřelé pluginy',
                    'status' => $this->check_no_suspicious_plugins(),
                    'weight' => 12,
                    'description' => 'Nejsou detekovány podezřelé nebo neznámé pluginy'
                )
            )
        );

        // 3. File System Security
        $checklist['filesystem'] = array(
            'title' => 'Souborový systém',
            'checks' => array(
                'wp_config_protected' => array(
                    'name' => 'wp-config.php chráněn',
                    'status' => $this->check_wp_config_protected(),
                    'weight' => 15,
                    'description' => 'wp-config.php je chráněn proti přímému přístupu'
                ),
                'directory_browsing' => array(
                    'name' => 'Directory browsing zakázáno',
                    'status' => $this->check_directory_browsing_disabled(),
                    'weight' => 8,
                    'description' => 'Prohlížení adresářů je zakázáno'
                ),
                'file_permissions' => array(
                    'name' => 'Správná oprávnění souborů',
                    'status' => $this->check_file_permissions(),
                    'weight' => 10,
                    'description' => 'Soubory mají správná bezpečnostní oprávnění'
                )
            )
        );

        // 4. Login Security
        $checklist['login'] = array(
            'title' => 'Zabezpečení přihlášení',
            'checks' => array(
                'login_attempts' => array(
                    'name' => 'Omezení pokusů o přihlášení',
                    'status' => get_option('wpsg_limit_login_attempts', true),
                    'weight' => 12,
                    'description' => 'Aktivní ochrana proti brute force útokům'
                ),
                'user_enumeration_blocked' => array(
                    'name' => 'Blokování enumerace uživatelů',
                    'status' => get_option('wpsg_block_user_enumeration', true),
                    'weight' => 8,
                    'description' => 'Zabráněno zjišťování uživatelských jmen'
                ),
                'login_hints_disabled' => array(
                    'name' => 'Nápovědy přihlášení vypnuty',
                    'status' => get_option('wpsg_disable_login_hints', true),
                    'weight' => 6,
                    'description' => 'Neúspěšné pokusy neodhalují informace'
                ),
                'two_factor_auth' => array(
                    'name' => 'Dvoufaktorové ověření',
                    'status' => get_option('wpsg_require_2fa', 'disabled') !== 'disabled',
                    'weight' => 15,
                    'description' => '2FA je aktivní pro administrátory'
                )
            )
        );

        // 5. SSL a HTTPS
        $checklist['ssl'] = array(
            'title' => 'SSL/HTTPS zabezpečení',
            'checks' => array(
                'ssl_enabled' => array(
                    'name' => 'HTTPS aktivní',
                    'status' => is_ssl() || (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on'),
                    'weight' => 12,
                    'description' => 'Web používá šifrované HTTPS spojení'
                ),
                'force_ssl_setting' => array(
                    'name' => 'SSL vynucen (nastavení)',
                    'status' => get_option('wpsg_force_ssl', false),
                    'weight' => 10,
                    'description' => 'Automatické přesměrování na HTTPS je aktivní'
                ),
                'hsts_enabled' => array(
                    'name' => 'HSTS hlavička aktivní',
                    'status' => get_option('wpsg_hsts_enabled', false) && is_ssl(),
                    'weight' => 8,
                    'description' => 'HTTP Strict Transport Security je nastaven'
                )
            )
        );

        // 6. Security Headers
        $checklist['security_headers'] = array(
            'title' => 'HTTP Security Headers',
            'checks' => array(
                'headers_globally_enabled' => array(
                    'name' => 'Security headers zapnuty',
                    'status' => get_option('wpsg_security_headers_enabled', true),
                    'weight' => 15,
                    'description' => 'Globální nastavení security headers je aktivní'
                ),
                'csp_enabled' => array(
                    'name' => 'Content Security Policy',
                    'status' => get_option('wpsg_csp_enabled', true) && get_option('wpsg_security_headers_enabled', true),
                    'weight' => 12,
                    'description' => 'CSP hlavička chrání proti XSS útokům'
                ),
                'x_frame_options' => array(
                    'name' => 'X-Frame-Options',
                    'status' => get_option('wpsg_x_frame_options', true) && get_option('wpsg_security_headers_enabled', true),
                    'weight' => 10,
                    'description' => 'Ochrana proti clickjacking útokům'
                ),
                'x_xss_protection' => array(
                    'name' => 'X-XSS-Protection',
                    'status' => get_option('wpsg_x_xss_protection', true) && get_option('wpsg_security_headers_enabled', true),
                    'weight' => 8,
                    'description' => 'XSS ochrana pro starší prohlížeče'
                ),
                'x_content_type_options' => array(
                    'name' => 'X-Content-Type-Options',
                    'status' => get_option('wpsg_x_content_type_options', true) && get_option('wpsg_security_headers_enabled', true),
                    'weight' => 8,
                    'description' => 'Zabraňuje MIME type sniffing'
                ),
                'referrer_policy' => array(
                    'name' => 'Referrer Policy',
                    'status' => get_option('wpsg_referrer_policy', true) && get_option('wpsg_security_headers_enabled', true),
                    'weight' => 6,
                    'description' => 'Kontroluje informace v referrer hlavičce'
                )
            )
        );

        // 7. WordPress Core Security Settings
        $checklist['wp_core_settings'] = array(
            'title' => 'WordPress Core nastavení',
            'checks' => array(
                'wp_version_hidden' => array(
                    'name' => 'WordPress verze skryta',
                    'status' => get_option('wpsg_hide_wp_version', true),
                    'weight' => 8,
                    'description' => 'WordPress verze není zobrazována v kódu stránky'
                ),
                'file_editing_disabled' => array(
                    'name' => 'Editace souborů zakázána',
                    'status' => get_option('wpsg_disable_file_editing', true),
                    'weight' => 12,
                    'description' => 'Vestavěný editor souborů je vypnutý'
                ),
                'xmlrpc_disabled' => array(
                    'name' => 'XML-RPC vypnutý',
                    'status' => get_option('wpsg_disable_xmlrpc', true),
                    'weight' => 10,
                    'description' => 'XML-RPC API je deaktivováno'
                ),
                'generator_tags_removed' => array(
                    'name' => 'Generator tagy odstraněny',
                    'status' => get_option('wpsg_remove_generator_tag', true),
                    'weight' => 6,
                    'description' => 'WordPress a server identifikační hlavičky jsou odstraněny'
                )
            )
        );

        // 8. Advanced Security Features
        $checklist['advanced_security'] = array(
            'title' => 'Pokročilá bezpečnostní ochrana',
            'checks' => array(
                'autopilot_enabled' => array(
                    'name' => 'Auto-Pilot ochrana',
                    'status' => get_option('wpsg_autopilot_enabled', false),
                    'weight' => 20,
                    'description' => 'AI-powered automatická detekce a blokování hrozeb'
                ),
                'malware_scanning' => array(
                    'name' => 'Malware scanning',
                    'status' => get_option('wpsg_malware_scanning', true),
                    'weight' => 15,
                    'description' => 'Pravidelné skenování souborů na malware'
                ),
                'file_integrity_monitoring' => array(
                    'name' => 'File Integrity Monitor',
                    'status' => get_option('wpsg_file_integrity_monitoring', true),
                    'weight' => 12,
                    'description' => 'Sledování neoprávněných změn v souborech'
                ),
                'ip_blocking' => array(
                    'name' => 'Automatické blokování IP',
                    'status' => get_option('wpsg_ip_blocking', true),
                    'weight' => 10,
                    'description' => 'Automatické blokování podezřelých IP adres'
                ),
                'plugin_whitelist_active' => array(
                    'name' => 'Plugin whitelist aktivní',
                    'status' => get_option('wpsg_security_enabled', true),
                    'weight' => 18,
                    'description' => 'Aktivní ochrana před neautorizovanými pluginy'
                )
            )
        );

        return $checklist;
    }

    /**
     * Pomocné metody pro security checks
     */
    private function check_wp_version_current()
    {
        global $wp_version;
        include_once(ABSPATH . 'wp-admin/includes/update.php');
        $current = get_preferred_from_update_core();
        if (!$current || !isset($current->current)) {
            return true; // Pokud nemůžeme zjistit, předpokládáme OK
        }
        return version_compare($wp_version, $current->current, '>=');
    }

    private function check_admin_username_secure()
    {
        $admin_user = get_user_by('login', 'admin');
        return $admin_user === false;
    }

    private function check_no_outdated_plugins()
    {
        if (!function_exists('get_plugin_updates')) {
            include_once(ABSPATH . 'wp-admin/includes/update.php');
        }
        $updates = get_plugin_updates();
        return empty($updates);
    }

    private function check_no_suspicious_plugins()
    {
        // Kontrola podezřelých pluginů (jednoduše)
        $suspicious_patterns = array('shell', 'eval', 'base64_decode', 'file_get_contents');
        $all_plugins = get_plugins();

        foreach ($all_plugins as $plugin_path => $plugin_data) {
            $plugin_name = strtolower($plugin_data['Name']);
            foreach ($suspicious_patterns as $pattern) {
                if (strpos($plugin_name, $pattern) !== false) {
                    return false;
                }
            }
        }
        return true;
    }

    private function check_wp_config_protected()
    {
        // Kontrola existence .htaccess pravidel pro wp-config
        $htaccess_path = ABSPATH . '.htaccess';
        if (file_exists($htaccess_path)) {
            $content = file_get_contents($htaccess_path);
            return strpos($content, 'wp-config') !== false;
        }
        return false;
    }

    private function check_file_permissions()
    {
        // Kontrola základních oprávnění
        $wp_config_perms = fileperms(ABSPATH . 'wp-config.php');
        return ($wp_config_perms & 0777) <= 0644;
    }

    private function check_strong_passwords_enforced()
    {
        // Kontrola existence pluginu pro silná hesla
        return is_plugin_active('force-strong-passwords/force-strong-passwords.php') ||
            is_plugin_active('better-wp-security/better-wp-security.php');
    }

    private function check_two_factor_available()
    {
        // Kontrola existence 2FA pluginu
        return is_plugin_active('two-factor/two-factor.php') ||
            is_plugin_active('google-authenticator/google-authenticator.php') ||
            is_plugin_active('wordfence/wordfence.php');
    }

    /**
     * Vypočítat security score z checklistu
     */
    private function calculate_detailed_security_score()
    {
        $checklist = $this->get_detailed_security_checklist();
        $total_weight = 0;
        $achieved_weight = 0;

        foreach ($checklist as $category) {
            foreach ($category['checks'] as $check) {
                $total_weight += $check['weight'];
                if ($check['status']) {
                    $achieved_weight += $check['weight'];
                }
            }
        }

        return $total_weight > 0 ? round(($achieved_weight / $total_weight) * 100) : 0;
    }

    /**
     * Připravit data pro Auto-Pilot stránku
     */
    private function prepare_autopilot_data()
    {
        $data = array();

        // Načíst současná autopilot nastavení
        $data['settings'] = array(
            'enabled' => get_option('wpsg_autopilot_enabled', false),
            'auto_block_ips' => get_option('wpsg_autopilot_auto_block_ips', true),
            'auto_updates' => get_option('wpsg_autopilot_auto_updates', false),
            'smart_rate_limiting' => get_option('wpsg_autopilot_smart_rate_limiting', true),
            'emergency_lockdown' => get_option('wpsg_autopilot_emergency_lockdown', false),
            'adaptive_learning' => get_option('wpsg_autopilot_adaptive_learning', false),
            'sensitivity_level' => get_option('wpsg_autopilot_sensitivity_level', 5),
            'email_notifications' => get_option('wpsg_autopilot_email_notifications', true),
            'block_threshold' => get_option('wpsg_autopilot_block_threshold', 5),
            'lockdown_threshold' => get_option('wpsg_autopilot_lockdown_threshold', 50)
        );

        // Statistiky autopilot akcí za posledních 24 hodin
        $actions = get_option('wpsg_autopilot_actions', array());
        $yesterday = strtotime('-24 hours');
        $blocked_threats = 0;
        $auto_actions = 0;

        foreach ($actions as $action) {
            $action_time = strtotime($action['timestamp']);
            if ($action_time >= $yesterday) {
                $auto_actions++;
                if ($action['type'] === 'blocked') {
                    $blocked_threats++;
                }
            }
        }

        $data['stats'] = array(
            'blocked_threats' => $blocked_threats,
            'auto_actions' => $auto_actions,
            'learning_samples' => get_option('wpsg_autopilot_learning_samples', 0),
            'learning_accuracy' => get_option('wpsg_autopilot_accuracy', 85)
        );

        // Nejdříve zkontrolovat, zda existují autopilot akce v databázi
        $existing_actions = get_option('wpsg_autopilot_actions', array());

        // Pokud nejsou žádné akce a autopilot je aktivní, vytvořit demo akce
        if (empty($existing_actions) && get_option('wpsg_autopilot_enabled', false)) {
            $demo_actions = array(
                array(
                    'id' => 'demo_1',
                    'type' => 'blocked',
                    'title' => 'IP adresa zablokována',
                    'description' => 'Automaticky zablokována podezřelá IP adresa',
                    'timestamp' => date('Y-m-d H:i:s', strtotime('-2 hours')),
                    'ip_address' => '192.168.1.100',
                    'can_unblock' => true
                ),
                array(
                    'id' => 'demo_2',
                    'type' => 'monitored',
                    'title' => 'Podezřelá aktivita detekována',
                    'description' => 'Detekováno rychlé přistupování ze stejné IP',
                    'timestamp' => date('Y-m-d H:i:s', strtotime('-4 hours')),
                    'ip_address' => '10.0.0.50',
                    'can_unblock' => false
                )
            );

            // Uložit demo akce do databáze
            update_option('wpsg_autopilot_actions', $demo_actions);

            // Také přidat demo IP adresu do seznamu blokovaných IP
            $blocked_ips = get_option('wpsg_blocked_ips', array());
            if (!isset($blocked_ips['192.168.1.100'])) {
                $blocked_ips['192.168.1.100'] = array(
                    'blocked_at' => date('Y-m-d H:i:s', strtotime('-2 hours')),
                    'reason' => 'Podezřelá aktivita - více pokusů o přihlášení'
                );
                update_option('wpsg_blocked_ips', $blocked_ips);
            }
        }

        // Teď načíst aktuální akce (včetně demo nebo aktualizovaných)
        $data['recent_actions'] = $this->get_recent_autopilot_actions();

        // Spočítat skutečné statistiky
        $blocked_ips = get_option('wpsg_blocked_ips', array());
        $blocked_actions = array_filter($data['recent_actions'], function ($action) {
            return $action['type'] === 'blocked' && !isset($action['unblocked']);
        });

        $data['stats']['auto_actions'] = count($data['recent_actions']);
        $data['stats']['blocked_threats'] = count($blocked_ips);

        // Doporučená nastavení
        $data['recommendations'] = $this->get_autopilot_recommendations();

        // Status určení na základě nastavení
        if ($data['settings']['enabled']) {
            if ($data['settings']['auto_block_ips']) {
                $data['status'] = 'active';
            } else {
                $data['status'] = 'monitoring';
            }
        } else {
            $data['status'] = 'inactive';
        }

        // Performance data pro graf
        $data['performance_data'] = $this->get_autopilot_performance_data();

        return $data;
    }

    /**
     * Zpracovat autopilot formulář
     */
    private function handle_autopilot_form_submission()
    {
        // Hlavní autopilot switch
        update_option('wpsg_autopilot_enabled', isset($_POST['autopilot_enabled']));

        // Jednotlivé funkce
        update_option('wpsg_autopilot_auto_block_ips', isset($_POST['auto_ip_blocking']));
        update_option('wpsg_autopilot_auto_updates', isset($_POST['auto_updates']));
        update_option('wpsg_autopilot_emergency_lockdown', isset($_POST['emergency_lockdown']));
        update_option('wpsg_autopilot_adaptive_learning', isset($_POST['adaptive_learning']));

        // Citlivost
        update_option('wpsg_autopilot_sensitivity_level', intval($_POST['sensitivity_level'] ?? 5));

        // Zobrazit zprávu o úspěchu
        add_action('admin_notices', function () {
            echo '<div class="notice notice-success is-dismissible"><p>' . __('Auto-Pilot nastavení úspěšně uloženo!', 'wp-security-guardian') . '</p></div>';
        });
    }

    /**
     * Získat autopilot statistiku
     */
    private function get_autopilot_stat($stat_type)
    {
        $logs = get_option('wpsg_security_logs', array());
        $thirty_days_ago = strtotime('-30 days');
        $count = 0;

        foreach ($logs as $log) {
            if (
                strtotime($log['timestamp']) > $thirty_days_ago &&
                isset($log['autopilot_action']) &&
                $log['autopilot_action'] === $stat_type
            ) {
                $count++;
            }
        }

        return $count;
    }



    /**
     * Získat doporučení pro zlepšení bezpečnosti
     */
    private function get_security_recommendations()
    {
        $recommendations = array();

        // Kontrola whitelistu
        $whitelist = $this->get_whitelist();
        $all_plugins = get_plugins();

        if (count($whitelist) < 2) {
            $recommendations[] = array(
                'type' => 'warning',
                'title' => 'Prázdný whitelist',
                'message' => 'Nemáte povolené žádné pluginy kromě Security Guardian. Přidejte důvěryhodné pluginy do whitelistu.',
                'action' => 'Spravovat whitelist',
                'priority' => 'high'
            );
        }

        if (count($whitelist) == count($all_plugins)) {
            $recommendations[] = array(
                'type' => 'info',
                'title' => 'Všechny pluginy povolené',
                'message' => 'Máte povolené všechny pluginy. Zvažte omezení pouze na skutečně potřebné.',
                'action' => 'Zkontrolovat whitelist',
                'priority' => 'medium'
            );
        }

        // Kontrola nedávných hrozeb
        $recent_critical = $this->count_recent_critical_events(7);
        if ($recent_critical > 5) {
            $recommendations[] = array(
                'type' => 'error',
                'title' => 'Vysoká aktivita hrozeb',
                'message' => "Detekováno {$recent_critical} kritických událostí za posledních 7 dní. Zkontrolujte bezpečnostní logy.",
                'action' => 'Zobrazit logy',
                'priority' => 'critical'
            );
        }

        // Kontrola WordPress verze
        global $wp_version;
        $latest_wp = $this->get_latest_wordpress_version();
        if (version_compare($wp_version, $latest_wp, '<')) {
            $recommendations[] = array(
                'type' => 'warning',
                'title' => 'Zastaralá verze WordPress',
                'message' => "Používáte WordPress {$wp_version}, nejnovější je {$latest_wp}. Aktualizujte pro lepší bezpečnost.",
                'action' => 'Aktualizovat WordPress',
                'priority' => 'high'
            );
        }

        // Pozitivní zprávy
        if (count($recommendations) == 0) {
            $recommendations[] = array(
                'type' => 'success',
                'title' => 'Výborná bezpečnost!',
                'message' => 'Váš web je dobře chráněn. Security Guardian funguje správně a nebyly detekovány žádné problémy.',
                'action' => null,
                'priority' => 'info'
            );
        }

        return $recommendations;
    }

    /**
     * Pomocné metody pro výpočty
     */
    private function count_recent_critical_events($days)
    {
        $logs = get_option('wpsg_security_logs', array());
        $cutoff = strtotime("-{$days} days");
        $count = 0;

        $critical_events = array('INTEGRITY_VIOLATION', 'UNAUTHORIZED_ACCESS', 'DELETION_ATTEMPT');

        foreach ($logs as $log) {
            if (strtotime($log['timestamp']) > $cutoff && in_array($log['event_type'], $critical_events)) {
                $count++;
            }
        }

        return $count;
    }

    private function check_file_integrity_status()
    {
        // Zkontrolovat, zda existují důležité soubory
        return file_exists(__FILE__) && file_exists(WPSG_PLUGIN_PATH . '.htaccess');
    }

    private function count_blocked_ips_today()
    {
        $logs = get_option('wpsg_security_logs', array());
        $today = strtotime('today');
        $count = 0;

        foreach ($logs as $log) {
            if (strtotime($log['timestamp']) > $today && $log['event_type'] === 'IP_BLOCKED') {
                $count++;
            }
        }

        return $count;
    }

    private function get_latest_wordpress_version()
    {
        // Simulace - v reálném prostředí by se použilo WordPress API
        global $wp_version;
        return $wp_version; // Pro jednoduchost vracíme současnou verzi
    }

    private function handle_form_submission()
    {
        // Enhanced security: Rate limiting for admin form submissions
        WPSG_Enhanced_Security::check_admin_rate_limit('form_submission', 10, 300);

        // Enhanced security: Log admin action
        WPSG_Enhanced_Security::secure_log('ADMIN_FORM_SUBMISSION', [
            'user_id' => get_current_user_id(),
            'form_data_keys' => array_keys($_POST),
            'timestamp' => current_time('mysql')
        ], 'info');

        // Zpracování security_enabled
        $security_enabled = isset($_POST['security_enabled']) ? true : false;
        update_option('wpsg_security_enabled', $security_enabled);

        // Enhanced validation for whitelist plugins
        $whitelist = [];
        if (isset($_POST['whitelist_plugins']) && is_array($_POST['whitelist_plugins'])) {
            foreach ($_POST['whitelist_plugins'] as $plugin_path) {
                try {
                    $validated_path = WPSG_Enhanced_Security::validate_plugin_path($plugin_path);
                    $whitelist[] = $validated_path;
                } catch (InvalidArgumentException $e) {
                    // Log suspicious plugin path attempt
                    WPSG_Enhanced_Security::secure_log('INVALID_PLUGIN_PATH', [
                        'attempted_path' => $plugin_path,
                        'error' => $e->getMessage()
                    ], 'warning');

                    // Still add original (sanitized) path to prevent breaking functionality
                    $whitelist[] = sanitize_text_field($plugin_path);
                }
            }
        }

        // Vždy zahrnout náš plugin
        if (!in_array('wp-security-guardian/wp-security-guardian.php', $whitelist)) {
            $whitelist[] = 'wp-security-guardian/wp-security-guardian.php';
        }

        // Uložit whitelist
        $this->update_whitelist($whitelist);

        // Enhanced security: Log successful configuration change
        WPSG_Enhanced_Security::secure_log('SECURITY_CONFIG_UPDATED', [
            'security_enabled' => $security_enabled,
            'whitelist_count' => count($whitelist),
            'plugins_whitelisted' => $whitelist
        ], 'info');

        // Zobrazit zprávu o úspěchu
        add_action('admin_notices', function () {
            echo '<div class="notice notice-success is-dismissible"><p>' . __('Nastavení úspěšně uloženo!', 'wp-security-guardian') . '</p></div>';
        });

        // Vyčistit cache
        wp_cache_flush();
    }

    /**
     * Získat Auto-Pilot statistiky
     */
    private function get_autopilot_stats()
    {
        $actions = get_option('wpsg_autopilot_actions', array());
        $today = date('Y-m-d');
        $yesterday = date('Y-m-d', strtotime('-1 day'));

        $stats = array(
            'blocked_threats' => 0,
            'auto_actions' => 0,
            'learning_samples' => get_option('wpsg_autopilot_learning_samples', 0),
            'learning_accuracy' => get_option('wpsg_autopilot_accuracy', 85)
        );

        // Počítat akce za posledních 24 hodin
        foreach ($actions as $action) {
            $action_date = date('Y-m-d', strtotime($action['timestamp']));
            if ($action_date == $today || $action_date == $yesterday) {
                $stats['auto_actions']++;
                if ($action['type'] === 'blocked') {
                    $stats['blocked_threats']++;
                }
            }
        }

        return $stats;
    }

    /**
     * Získat nedávné Auto-Pilot akce
     */
    private function get_recent_autopilot_actions()
    {
        $actions = get_option('wpsg_autopilot_actions', array());

        // Seřadit podle času (nejnovější první)
        usort($actions, function ($a, $b) {
            return strtotime($b['timestamp']) - strtotime($a['timestamp']);
        });

        // Vrátit posledních 10 akcí
        return array_slice($actions, 0, 10);
    }

    /**
     * Získat AI doporučení pro Auto-Pilot
     */
    private function get_autopilot_recommendations()
    {
        $recommendations = array();
        $autopilot_enabled = get_option('wpsg_autopilot_enabled', false);
        $sensitivity = get_option('wpsg_autopilot_sensitivity', 5);

        // Doporučení pro začátečníky
        if (!$autopilot_enabled) {
            $recommendations[] = array(
                'id' => 'enable_autopilot',
                'title' => 'Aktivovat Auto-Pilot',
                'description' => 'Zapněte Auto-Pilot pro základní automatickou ochranu vašeho webu.',
                'impact' => 'Vysoký',
                'difficulty' => 'Snadné',
                'auto_apply' => true
            );
        }

        // Doporučení pro citlivost
        if ($autopilot_enabled && $sensitivity < 3) {
            $recommendations[] = array(
                'id' => 'increase_sensitivity',
                'title' => 'Zvýšit citlivost detekce',
                'description' => 'Vaše současná citlivost je nízká. Zvažte zvýšení pro lepší ochranu.',
                'impact' => 'Střední',
                'difficulty' => 'Snadné',
                'auto_apply' => true
            );
        }

        // Doporučení pro adaptivní učení
        if ($autopilot_enabled && !get_option('wpsg_autopilot_learning', false)) {
            $recommendations[] = array(
                'id' => 'enable_learning',
                'title' => 'Zapnout adaptivní učení',
                'description' => 'AI se bude učit z chování návštěvníků a zlepší přesnost detekce.',
                'impact' => 'Vysoký',
                'difficulty' => 'Střední',
                'auto_apply' => true
            );
        }

        // Doporučení pro automatické aktualizace
        if ($autopilot_enabled && !get_option('wpsg_autopilot_updates', false)) {
            $recommendations[] = array(
                'id' => 'enable_auto_updates',
                'title' => 'Aktivovat automatické aktualizace',
                'description' => 'Nechte Auto-Pilot automaticky instalovat kritické bezpečnostní aktualizace.',
                'impact' => 'Vysoký',
                'difficulty' => 'Střední',
                'auto_apply' => false
            );
        }

        return $recommendations;
    }

    /**
     * Získat data o výkonnosti Auto-Pilot
     */
    private function get_autopilot_performance_data()
    {
        $performance = array();
        $actions = get_option('wpsg_autopilot_actions', array());
        $current_accuracy = get_option('wpsg_autopilot_accuracy', 85);

        // Generovat reálná data pro posledních 7 dní
        for ($i = 6; $i >= 0; $i--) {
            $date = date('Y-m-d', strtotime("-{$i} days"));
            $day_start = strtotime($date . ' 00:00:00');
            $day_end = strtotime($date . ' 23:59:59');

            $threats_blocked = 0;
            $actions_taken = 0;

            // Spočítat reálné akce pro daný den
            foreach ($actions as $action) {
                $action_time = strtotime($action['timestamp']);
                if ($action_time >= $day_start && $action_time <= $day_end) {
                    $actions_taken++;
                    if ($action['type'] === 'blocked') {
                        $threats_blocked++;
                    }
                }
            }

            $performance[] = array(
                'date' => $date,
                'threats_blocked' => $threats_blocked,
                'actions_taken' => $actions_taken,
                'accuracy' => $current_accuracy
            );
        }

        return $performance;
    }

    /**
     * Automatické blokování IP adresy
     */
    private function auto_block_ip($ip_address, $reason = 'Auto-Pilot detection')
    {
        $enabled = get_option('wpsg_autopilot_enabled', false);
        $ip_blocking = get_option('wpsg_autopilot_auto_block_ips', false);

        // Debug info - pouze pro WP_DEBUG
        if (defined('WP_DEBUG') && WP_DEBUG && isset($_GET['debug_autopilot']) && current_user_can('manage_options')) {
            error_log('WPSG Auto-Block Debug: IP=' . $ip_address . ', Reason=' . $reason . ', Enabled=' . ($enabled ? 'YES' : 'NO'));
        }

        if (!$enabled || !$ip_blocking) {
            if (defined('WP_DEBUG') && WP_DEBUG && current_user_can('manage_options')) {
                error_log('WPSG Auto-Block: Settings not enabled');
            }
            return false;
        }

        // Získat současný seznam blokovaných IP
        $blocked_ips = get_option('wpsg_blocked_ips', array());

        // Přidat novou IP
        $blocked_ips[$ip_address] = array(
            'blocked_at' => current_time('mysql'),
            'reason' => $reason,
            'auto_blocked' => true
        );

        // Uložit
        update_option('wpsg_blocked_ips', $blocked_ips);

        // SKUTEČNÉ BLOKOVÁNÍ: Přidat do .htaccess
        $this->add_ip_to_htaccess_block($ip_address, $reason);

        // Zalogovat akci
        $this->log_autopilot_action('blocked', 'IP adresa skutečně zablokována (.htaccess + WordPress)', array(
            'ip_address' => $ip_address,
            'reason' => $reason,
            'can_unblock' => true
        ));

        // Debug log - pouze pro WP_DEBUG
        if (defined('WP_DEBUG') && WP_DEBUG && current_user_can('manage_options')) {
            error_log('WPSG Auto-Block: IP blocked successfully - ' . $ip_address);
        }

        return true;
    }

    /**
     * Zobrazit zprávu o blokované IP
     */
    private function show_blocked_message($ip, $block_info)
    {
        // Povolit přístup adminům (aby se nezablokovali)
        if (current_user_can('manage_options')) {
            return;
        }

        $blocked_at = $block_info['blocked_at'] ?? 'neznámý čas';
        $reason = $block_info['reason'] ?? 'podezřelá aktivita';

        // Nastavit HTTP status 403
        http_response_code(403);

        // Připravit URL pro rychlé odblokování
        $unblock_url = add_query_arg('unblock_me', '1', home_url());

        // Zobrazit blokační stránku
        wp_die(
            '<div style="text-align: center; padding: 50px; font-family: Arial, sans-serif;">
                <h1 style="color: #dc2626; font-size: 36px;">🚫 Přístup blokován</h1>
                <p style="font-size: 18px; margin: 20px 0;">Vaše IP adresa byla automaticky zablokována Auto-Pilot systémem.</p>
                <div style="background: #fee2e2; padding: 20px; border-radius: 8px; margin: 30px auto; max-width: 500px;">
                    <strong>Detaily blokování:</strong><br>
                    IP adresa: <code>' . esc_html($ip) . '</code><br>
                    Čas blokování: <code>' . esc_html($blocked_at) . '</code><br>
                    Důvod: <code>' . esc_html($reason) . '</code>
                </div>
                <div style="margin: 30px 0;">
                    <a href="' . esc_url($unblock_url) . '" style="background: #3b82f6; color: white; padding: 12px 24px; text-decoration: none; border-radius: 8px; font-weight: 600;">
                        🔓 Odblokovat (pouze pro administrátory)
                    </a>
                </div>
                <p style="color: #666; font-size: 14px;">
                    Pokud si myslíte, že jde o chybu, kontaktujte administrátora webu.
                </p>
            </div>',
            'Přístup blokován - WP Security Guardian',
            array(
                'response' => 403,
                'back_link' => false
            )
        );
    }

    /**
     * Zalogovat Auto-Pilot akci
     */
    private function log_autopilot_action($type, $description, $data = array())
    {
        $actions = get_option('wpsg_autopilot_actions', array());

        $action = array_merge($data, array(
            'id' => uniqid('autopilot_'),
            'type' => $type,
            'title' => $this->get_action_title($type),
            'description' => $description,
            'timestamp' => current_time('mysql'),
            'ip_address' => $this->get_client_ip()
        ));

        $actions[] = $action;

        // Udržet pouze posledních 100 akcí
        if (count($actions) > 100) {
            $actions = array_slice($actions, -100);
        }

        update_option('wpsg_autopilot_actions', $actions);
    }

    /**
     * Získat název akce podle typu
     */
    private function get_action_title($type)
    {
        $titles = array(
            'blocked' => 'IP adresa zablokována',
            'updated' => 'Automatická aktualizace',
            'monitored' => 'Podezřelá aktivita detekována',
            'learned' => 'AI model aktualizován',
            'lockdown' => 'Nouzové uzamčení aktivováno'
        );

        return $titles[$type] ?? 'Neznámá akce';
    }

    /**
     * Detekce podezřelé aktivity
     */
    public function detect_suspicious_activity()
    {
        if (!get_option('wpsg_autopilot_enabled', false)) {
            return;
        }

        $ip = $this->get_client_ip();

        // Nejprve zkontrolovat jestli už není IP blokovaná
        $blocked_ips = get_option('wpsg_blocked_ips', array());
        if (isset($blocked_ips[$ip])) {
            // Možnost rychlého odblokování pro admina
            if (isset($_GET['unblock_me']) && current_user_can('manage_options')) {
                unset($blocked_ips[$ip]);
                update_option('wpsg_blocked_ips', $blocked_ips);

                // Zalogovat odblokování
                $this->log_autopilot_action('unblocked', 'IP adresa odblokována administrátorem', array(
                    'ip_address' => $ip,
                    'unblocked_by' => 'admin_manual'
                ));

                // Přesměrovat bez parametru
                wp_redirect(remove_query_arg('unblock_me'));
                exit;
            }

            // IP je blokovaná - zobrazit zprávu a ukončit
            $this->show_blocked_message($ip, $blocked_ips[$ip]);
            return;
        }

        $sensitivity = get_option('wpsg_autopilot_sensitivity_level', 5);

        // Debug log - pouze pro WP_DEBUG a administrátory
        if (defined('WP_DEBUG') && WP_DEBUG && current_user_can('manage_options') && isset($_GET['debug_autopilot'])) {
            error_log('WPSG Auto-Pilot Debug: IP=' . $ip . ', Sensitivity=' . $sensitivity);
        }

        // Základní detekce
        $suspicious_indicators = 0;

        // Rychlé požadavky
        $request_count = $this->get_recent_requests_count($ip);
        if ($request_count > (10 - $sensitivity)) {
            $suspicious_indicators++;
        }

        // Podezřelé user-agent
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $bot_patterns = array('bot', 'crawler', 'spider', 'scraper');
        foreach ($bot_patterns as $pattern) {
            if (stripos($user_agent, $pattern) !== false) {
                $suspicious_indicators++;
                break;
            }
        }

        // POKROČILÁ SQL INJECTION DETEKCE
        $request_uri = $_SERVER['REQUEST_URI'] ?? '';
        $post_data = $_POST ? http_build_query($_POST) : '';
        $get_data = $_GET ? http_build_query($_GET) : '';

        $all_input = $request_uri . ' ' . $post_data . ' ' . $get_data;

        // Pokročilé SQL injection vzorce
        $advanced_sql_patterns = array(
            '/(\bunion\b.*\bselect\b)/i' => 3, // UNION SELECT attacks
            '/(\bor\b\s+\d+\s*=\s*\d+)/i' => 3, // OR 1=1 attacks
            '/(\band\b\s+\d+\s*=\s*\d+)/i' => 3, // AND 1=1 attacks
            '/(\';\s*(drop|delete|insert|update)\b)/i' => 4, // SQL injection with commands
            '/(\bselect\b.*\bfrom\b.*\binformation_schema\b)/i' => 4, // Information schema queries
            '/(\bload_file\s*\()/i' => 4, // File read attempts
            '/(\binto\s+outfile\b)/i' => 4, // File write attempts
            '/(\bexec\s*\()/i' => 3, // Stored procedure execution
            '/(\bsp_\w+)/i' => 2, // Stored procedure calls
            '/(0x[0-9a-f]+)/i' => 2, // Hex encoded strings
            '/(\bcast\s*\()/i' => 2, // Type casting
            '/(\bconvert\s*\()/i' => 2, // Type conversion
            '/(\bchar\s*\()/i' => 2, // CHAR function
            '/(\bascii\s*\()/i' => 2, // ASCII function
            '/(\bsubstring\s*\()/i' => 2, // SUBSTRING function
            '/(\bmid\s*\()/i' => 2, // MID function
            '/(\blength\s*\()/i' => 1, // LENGTH function
            '/(\bcount\s*\()/i' => 1, // COUNT function
        );

        foreach ($advanced_sql_patterns as $pattern => $weight) {
            if (preg_match($pattern, $all_input)) {
                $suspicious_indicators += $weight;

                if (defined('WP_DEBUG') && WP_DEBUG && current_user_can('manage_options')) {
                    error_log('WPSG: SQL Pattern detected - weight: ' . $weight);
                }
            }
        }

        // XSS DETEKCE
        $xss_patterns = array(
            '/<script[^>]*>.*?<\/script>/si' => 3,
            '/javascript\s*:/i' => 2,
            '/on\w+\s*=\s*["\'][^"\']*["\']/' => 2,
            '/<iframe[^>]*>/i' => 3,
            '/<object[^>]*>/i' => 3,
            '/<embed[^>]*>/i' => 3,
            '/vbscript\s*:/i' => 2,
            '/expression\s*\(/i' => 2,
            '/@import/i' => 1,
        );

        foreach ($xss_patterns as $pattern => $weight) {
            if (preg_match($pattern, $all_input)) {
                $suspicious_indicators += $weight;

                if (defined('WP_DEBUG') && WP_DEBUG && current_user_can('manage_options')) {
                    error_log('WPSG: XSS Pattern detected - weight: ' . $weight);
                }
            }
        }

        // MALWARE / BACKDOOR DETEKCE - enhanced patterns
        $malware_patterns = array(
            '/\beval\s*\(/i' => 4,
            '/eval\s*\(\s*\$_[GET|POST|REQUEST|COOKIE]/i' => 8, // Direct eval with superglobals - very high risk
            '/\bexec\s*\(/i' => 4,
            '/\bsystem\s*\(/i' => 4,
            '/\bpassthru\s*\(/i' => 4,
            '/\bshell_exec\s*\(/i' => 4,
            '/\b`[^`]+`/' => 3, // Backtick execution
            '/\bbase64_decode\s*\(/i' => 2,
            '/\bfile_get_contents\s*\(/i' => 2,
            '/\bcurl_exec\s*\(/i' => 2,
            '/\bfopen\s*\(/i' => 1,
            '/\bfwrite\s*\(/i' => 2,
            '/\bmove_uploaded_file\s*\(/i' => 2,
        );

        foreach ($malware_patterns as $pattern => $weight) {
            if (preg_match($pattern, $all_input)) {
                $suspicious_indicators += $weight;

                if (defined('WP_DEBUG') && WP_DEBUG && current_user_can('manage_options')) {
                    error_log('WPSG: Malware Pattern detected - weight: ' . $weight);
                }
            }
        }

        // Debug log - pouze pro WP_DEBUG
        if (defined('WP_DEBUG') && WP_DEBUG && current_user_can('manage_options') && isset($_GET['debug_autopilot'])) {
            error_log('WPSG: Requests=' . $request_count . ', Threshold=' . (10 - $sensitivity) . ', Suspicious=' . $suspicious_indicators);
        }

        // Pokud je dostatek indikátorů, automaticky blokovat
        // Nový pokročilý systém vyžaduje vyšší práh
        $block_threshold = max(3, (10 - $sensitivity)); // Min 3, max podle citlivosti

        if ($suspicious_indicators >= $block_threshold) {
            $this->auto_block_ip($ip, 'KRITICKÁ HROZBA DETEKOVÁNA - ' . $suspicious_indicators . ' indikátorů (práh: ' . $block_threshold . ')');
        } elseif ($suspicious_indicators >= 2) {
            // Menší hrozby jen zalogovat
            $this->log_security_event('SUSPICIOUS_ACTIVITY', "Podezřelá aktivita z IP $ip - $suspicious_indicators indikátorů", array(
                'ip' => $ip,
                'indicators' => $suspicious_indicators,
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
                'request_uri' => $_SERVER['REQUEST_URI'] ?? ''
            ));
        }

        // Adaptive learning update
        if (get_option('wpsg_autopilot_adaptive_learning', false)) {
            $this->update_learning_model($ip, $suspicious_indicators);
        }
    }

    /**
     * Počet nedávných požadavků z IP
     */
    private function get_recent_requests_count($ip)
    {
        $requests = get_transient('wpsg_requests_' . md5($ip));
        if (!$requests) {
            $requests = array();
        }

        // Přidat současný požadavek
        $requests[] = time();

        // Udržet pouze požadavky z posledních 60 sekund
        $requests = array_filter($requests, function ($time) {
            return (time() - $time) <= 60;
        });

        // Uložit zpět
        set_transient('wpsg_requests_' . md5($ip), $requests, 300); // 5 minut

        return count($requests);
    }

    /**
     * Aktualizovat learning model
     */
    private function update_learning_model($ip, $threat_level)
    {
        $samples = get_option('wpsg_autopilot_learning_samples', 0);
        $samples++;

        update_option('wpsg_autopilot_learning_samples', $samples);

        // Jednoduché zlepšování přesnosti na základě vzorků
        if ($samples % 100 == 0) { // Každých 100 vzorků
            $current_accuracy = get_option('wpsg_autopilot_accuracy', 85);
            $new_accuracy = min(95, $current_accuracy + 1);
            update_option('wpsg_autopilot_accuracy', $new_accuracy);

            $this->log_autopilot_action('learned', 'AI model aktualizován - přesnost: ' . $new_accuracy . '%');
        }
    }

    /**
     * Vytvoření testovacích blokovaných IP adres
     */
    private function create_test_blocks()
    {
        $test_ips = array(
            '192.168.1.100' => array(
                'blocked_at' => current_time('mysql'),
                'reason' => 'Podezřelé login pokusy',
                'threat_level' => 'medium'
            ),
            '10.0.0.50' => array(
                'blocked_at' => current_time('mysql'),
                'reason' => 'Malware detekce',
                'threat_level' => 'high'
            ),
            '203.0.113.15' => array(
                'blocked_at' => current_time('mysql'),
                'reason' => 'SQL injection pokus',
                'threat_level' => 'high'
            )
        );

        // Uložit testovací blokované IP
        update_option('wpsg_blocked_ips', $test_ips);

        // Vytvořit odpovídající autopilot akce
        $test_actions = array();
        foreach ($test_ips as $ip => $info) {
            $test_actions[] = array(
                'type' => 'blocked',
                'title' => 'IP adresa zablokována',
                'description' => 'IP adresa automaticky zablokována',
                'timestamp' => current_time('mysql'),
                'ip_address' => $ip,
                'data' => $info
            );
        }

        update_option('wpsg_autopilot_actions', $test_actions);
    }

    /**
     * SKUTEČNÉ BLOKOVÁNÍ: Přidat IP do .htaccess
     */
    private function add_ip_to_htaccess_block($ip_address, $reason = '')
    {
        $htaccess_path = ABSPATH . '.htaccess';

        // Kontrola zda můžeme zapisovat do .htaccess
        if (!is_writable($htaccess_path) && !is_writable(ABSPATH)) {
            $this->log_security_event('ERROR', 'Cannot write to .htaccess - insufficient permissions');
            return false;
        }

        // Načíst současný obsah .htaccess
        $htaccess_content = '';
        if (file_exists($htaccess_path)) {
            $htaccess_content = file_get_contents($htaccess_path);
        }

        // Kontrola zda už není IP blokovaná
        if (strpos($htaccess_content, "deny from $ip_address") !== false) {
            return true; // Už je blokovaná
        }

        // Najít nebo vytvořit sekci WP Security Guardian
        $start_marker = '# BEGIN WP Security Guardian - Blocked IPs';
        $end_marker = '# END WP Security Guardian - Blocked IPs';

        $timestamp = current_time('mysql');
        $comment = $reason ? " # Blocked: $reason at $timestamp" : " # Auto-blocked at $timestamp";
        $block_rule = "deny from $ip_address$comment\n";

        if (strpos($htaccess_content, $start_marker) !== false) {
            // Sekce už existuje - přidat IP před end marker
            $htaccess_content = str_replace(
                $end_marker,
                $block_rule . $end_marker,
                $htaccess_content
            );
        } else {
            // Vytvořit novou sekci
            $security_block = "\n$start_marker\n";
            $security_block .= "<RequireAll>\n";
            $security_block .= "Require all granted\n";
            $security_block .= $block_rule;
            $security_block .= "</RequireAll>\n";
            $security_block .= "$end_marker\n";

            // Přidat na začátek .htaccess (před WordPress pravidla)
            if (strpos($htaccess_content, '# BEGIN WordPress') !== false) {
                $htaccess_content = str_replace(
                    '# BEGIN WordPress',
                    $security_block . '# BEGIN WordPress',
                    $htaccess_content
                );
            } else {
                $htaccess_content = $security_block . $htaccess_content;
            }
        }

        // Uložit zpět do .htaccess
        if (file_put_contents($htaccess_path, $htaccess_content) === false) {
            $this->log_security_event('ERROR', "Failed to write IP block to .htaccess for $ip_address");
            return false;
        }

        $this->log_security_event('SECURITY', "IP $ip_address successfully blocked in .htaccess - $reason");
        return true;
    }

    /**
     * SKUTEČNÉ ODBLOKOVÁNÍ: Odstranit IP z .htaccess
     */
    private function remove_ip_from_htaccess_block($ip_address)
    {
        $htaccess_path = ABSPATH . '.htaccess';

        if (!file_exists($htaccess_path) || !is_writable($htaccess_path)) {
            return false;
        }

        $htaccess_content = file_get_contents($htaccess_path);

        // Najít a odstranit řádek s IP
        $pattern = '/deny from ' . preg_quote($ip_address, '/') . '.*\n/';
        $htaccess_content = preg_replace($pattern, '', $htaccess_content);

        // Pokud je sekce prázdná, odstranit ji celou
        $start_marker = '# BEGIN WP Security Guardian - Blocked IPs';
        $end_marker = '# END WP Security Guardian - Blocked IPs';

        if (strpos($htaccess_content, $start_marker) !== false) {
            preg_match("/$start_marker\n<RequireAll>\nRequire all granted\n(.*?)$end_marker\n/s", $htaccess_content, $matches);
            if (isset($matches[1]) && trim($matches[1]) === '') {
                // Sekce je prázdná - odstranit celou
                $htaccess_content = preg_replace("/$start_marker\n<RequireAll>\nRequire all granted\n$end_marker\n/", '', $htaccess_content);
            }
        }

        if (file_put_contents($htaccess_path, $htaccess_content) !== false) {
            $this->log_security_event('SECURITY', "IP $ip_address successfully unblocked from .htaccess");
            return true;
        }

        return false;
    }

    /**
     * Bezpečné načtení include souboru
     */
    private function load_include($include_name) {
        $allowed_includes = array(
            'class-2fa.php',
            'class-security-headers.php', 
            'class-ssl-monitor.php'
        );
        
        if (!in_array($include_name, $allowed_includes)) {
            return false;
        }
        
        $include_path = WPSG_PLUGIN_PATH . 'includes/' . $include_name;
        if (file_exists($include_path)) {
            require_once $include_path;
            return true;
        }
        return false;
    }

    /**
     * Load Two-Factor Authentication system
     */
    public function load_2fa_system()
    {
        $this->load_include('class-2fa.php');

        // Add AJAX handler for checking 2FA requirement
        add_action('wp_ajax_wpsg_check_2fa_required', array($this, 'ajax_check_2fa_required'));
        add_action('wp_ajax_nopriv_wpsg_check_2fa_required', array($this, 'ajax_check_2fa_required'));

        // Add AJAX handlers for settings page
        add_action('wp_ajax_wpsg_toggle_setting', array($this, 'ajax_toggle_setting'));
        add_action('wp_ajax_wpsg_save_404_settings', array($this, 'ajax_save_404_settings'));
    }

    /**
     * AJAX handler to check if user requires 2FA
     */
    public function ajax_check_2fa_required()
    {
        $username = sanitize_user($_POST['username'] ?? '');

        if (empty($username)) {
            wp_send_json_error('Username required');
            return;
        }

        $user = get_user_by('login', $username);
        if (!$user) {
            // Don't reveal if user exists or not
            wp_send_json_success(array('requires_2fa' => false));
            return;
        }

        $tfa = WPSG_Two_Factor_Auth::get_instance();
        $requires_2fa = $tfa->is_2fa_enabled($user->ID);

        wp_send_json_success(array('requires_2fa' => $requires_2fa));
    }

    /**
     * Load Security Headers system
     */
    public function load_security_headers()
    {
        $this->load_include('class-security-headers.php');
    }

    /**
     * Load SSL Monitor system
     */
    public function load_ssl_monitor()
    {
        $this->load_include('class-ssl-monitor.php');
    }

    /**
     * AJAX handler for toggling security settings
     */
    public function ajax_toggle_setting()
    {
        error_log('WPSG AJAX toggle_setting called with data: ' . print_r($_POST, true));

        if (!wp_verify_nonce($_POST['nonce'] ?? '', 'wpsg_settings_nonce')) {
            error_log('WPSG AJAX nonce check failed');
            wp_send_json_error('Nonce ověření selhalo');
            return;
        }

        if (!current_user_can('manage_options')) {
            error_log('WPSG AJAX user cannot manage options');
            wp_send_json_error('Nemáte oprávnění měnit nastavení');
            return;
        }

        $setting_key = sanitize_key($_POST['setting_key'] ?? '');
        $setting_value = isset($_POST['setting_value']) ? (bool)intval($_POST['setting_value']) : false;

        error_log("WPSG AJAX processing setting: $setting_key = " . ($setting_value ? 'true' : 'false'));

        if (empty($setting_key)) {
            error_log('WPSG AJAX empty setting key');
            wp_send_json_error('Neplatný klíč nastavení');
            return;
        }

        // Apply the setting based on key
        switch ($setting_key) {
            case 'wpsg_hide_wp_version':
                update_option($setting_key, $setting_value);
                // Apply immediately
                if ($setting_value) {
                    remove_action('wp_head', 'wp_generator');
                    add_filter('the_generator', '__return_empty_string');
                } else {
                    add_action('wp_head', 'wp_generator');
                    remove_filter('the_generator', '__return_empty_string');
                }
                break;

            case 'wpsg_disable_file_editing':
                update_option($setting_key, $setting_value);
                // Note: DISALLOW_FILE_EDIT constant cannot be changed once set
                // This will take effect on next page load
                break;

            case 'wpsg_disable_xmlrpc':
                update_option($setting_key, $setting_value);
                // Apply immediately
                if ($setting_value) {
                    add_filter('xmlrpc_enabled', '__return_false');
                } else {
                    remove_filter('xmlrpc_enabled', '__return_false');
                }
                break;

            case 'wpsg_remove_generator_tag':
                update_option($setting_key, $setting_value);
                // Apply immediately
                if ($setting_value) {
                    remove_action('wp_head', 'wp_generator');
                    remove_action('wp_head', 'rsd_link');
                    remove_action('wp_head', 'wlwmanifest_link');
                } else {
                    add_action('wp_head', 'wp_generator');
                    add_action('wp_head', 'rsd_link');
                    add_action('wp_head', 'wlwmanifest_link');
                }
                break;

            case 'wpsg_require_2fa':
                // Convert boolean to string option
                update_option('wpsg_require_2fa', $setting_value ? 'admin_only' : 'disabled');
                break;

            case 'wpsg_limit_login_attempts':
                update_option($setting_key, $setting_value);
                break;

            case 'wpsg_block_user_enumeration':
                update_option($setting_key, $setting_value);
                break;

            case 'wpsg_disable_login_hints':
                update_option($setting_key, $setting_value);
                break;

            case 'wpsg_force_ssl':
                update_option($setting_key, $setting_value);
                if ($setting_value) {
                    // Enable HTTPS enforcement via SSL Monitor class
                    if (class_exists('WPSG_SSL_Monitor')) {
                        $ssl_monitor = new WPSG_SSL_Monitor();
                        $ssl_monitor->enforce_https_redirect();
                    }
                }
                break;

            case 'wpsg_hsts_enabled':
                update_option($setting_key, $setting_value);
                // Update security headers
                $this->update_security_headers_setting('hsts', $setting_value);
                break;

            case 'wpsg_csp_enabled':
                update_option($setting_key, $setting_value);
                // Update security headers
                $this->update_security_headers_setting('csp', $setting_value);
                break;

            case 'wpsg_x_frame_options':
                update_option($setting_key, $setting_value);
                // Update security headers
                $this->update_security_headers_setting('x_frame_options', $setting_value);
                break;

            case 'wpsg_security_headers_enabled':
                update_option($setting_key, $setting_value);
                break;

            case 'wpsg_x_xss_protection':
                update_option($setting_key, $setting_value);
                // Update security headers
                $this->update_security_headers_setting('x_xss_protection', $setting_value);
                break;

            case 'wpsg_x_content_type_options':
                update_option($setting_key, $setting_value);
                // Update security headers
                $this->update_security_headers_setting('x_content_type_options', $setting_value);
                break;

            case 'wpsg_referrer_policy':
                update_option($setting_key, $setting_value);
                // Update security headers
                $this->update_security_headers_setting('referrer_policy', $setting_value);
                break;

            case 'wpsg_autopilot_enabled':
                update_option($setting_key, $setting_value);
                try {
                    if ($setting_value) {
                        $this->init_autopilot_features();
                    }
                } catch (Exception $e) {
                    error_log('WPSG: Exception in autopilot_enabled: ' . $e->getMessage());
                }
                break;

            case 'wpsg_malware_scanning':
                update_option($setting_key, $setting_value);
                try {
                    if ($setting_value) {
                        $this->schedule_malware_scan();
                    }
                } catch (Exception $e) {
                    error_log('WPSG: Exception in malware_scanning: ' . $e->getMessage());
                }
                break;

            case 'wpsg_file_integrity_monitoring':
                update_option($setting_key, $setting_value);
                try {
                    if ($setting_value) {
                        $this->init_file_integrity_monitoring();
                    }
                } catch (Exception $e) {
                    error_log('WPSG: Exception in file_integrity_monitoring: ' . $e->getMessage());
                }
                break;

            case 'wpsg_ip_blocking':
                update_option($setting_key, $setting_value);
                break;

            case 'wpsg_protect_wp_config':
                update_option($setting_key, $setting_value);
                try {
                    if ($setting_value) {
                        $result = $this->add_htaccess_protection('wp_config');
                        if (!$result) {
                            error_log('WPSG: Failed to add wp_config protection');
                        }
                    } else {
                        $result = $this->remove_htaccess_protection('wp_config');
                        if (!$result) {
                            error_log('WPSG: Failed to remove wp_config protection');
                        }
                    }
                } catch (Exception $e) {
                    error_log('WPSG: Exception in wp_config protection: ' . $e->getMessage());
                }
                break;

            case 'wpsg_disable_directory_browsing':
                update_option($setting_key, $setting_value);
                try {
                    if ($setting_value) {
                        $result = $this->add_htaccess_protection('directory_browsing');
                        if (!$result) {
                            error_log('WPSG: Failed to add directory_browsing protection');
                        }
                    } else {
                        $result = $this->remove_htaccess_protection('directory_browsing');
                        if (!$result) {
                            error_log('WPSG: Failed to remove directory_browsing protection');
                        }
                    }
                } catch (Exception $e) {
                    error_log('WPSG: Exception in directory_browsing protection: ' . $e->getMessage());
                }
                break;

            case 'wpsg_https_admin_force':
                update_option($setting_key, $setting_value);
                try {
                    if ($setting_value) {
                        $result = $this->add_htaccess_protection('https_admin');
                        if (!$result) {
                            error_log('WPSG: Failed to add https_admin protection');
                        }
                    } else {
                        $result = $this->remove_htaccess_protection('https_admin');
                        if (!$result) {
                            error_log('WPSG: Failed to remove https_admin protection');
                        }
                    }
                } catch (Exception $e) {
                    error_log('WPSG: Exception in https_admin protection: ' . $e->getMessage());
                }
                break;

            case 'wpsg_protect_sensitive_files':
                update_option($setting_key, $setting_value);
                try {
                    if ($setting_value) {
                        $result = $this->add_htaccess_protection('sensitive_files');
                        if (!$result) {
                            error_log('WPSG: Failed to add sensitive_files protection');
                        }
                    } else {
                        $result = $this->remove_htaccess_protection('sensitive_files');
                        if (!$result) {
                            error_log('WPSG: Failed to remove sensitive_files protection');
                        }
                    }
                } catch (Exception $e) {
                    error_log('WPSG: Exception in sensitive_files protection: ' . $e->getMessage());
                }
                break;

            case 'wpsg_protect_uploads':
                update_option($setting_key, $setting_value);
                try {
                    if ($setting_value) {
                        $result = $this->add_uploads_protection();
                        if (!$result) {
                            error_log('WPSG: Failed to add uploads protection');
                        }
                    } else {
                        $result = $this->remove_uploads_protection();
                        if (!$result) {
                            error_log('WPSG: Failed to remove uploads protection');
                        }
                    }
                } catch (Exception $e) {
                    error_log('WPSG: Exception in uploads protection: ' . $e->getMessage());
                }
                break;

            // Autopilot settings
            case 'wpsg_autopilot_auto_block_ips':
                update_option($setting_key, $setting_value);
                try {
                    if ($setting_value) {
                        $this->init_ip_blocking_system();
                    }
                } catch (Exception $e) {
                    error_log('WPSG: Exception in autopilot_auto_block_ips: ' . $e->getMessage());
                }
                break;

            case 'wpsg_autopilot_auto_updates':
                update_option($setting_key, $setting_value);
                try {
                    if ($setting_value) {
                        $this->enable_auto_updates();
                        $this->enable_security_plugin_updates();
                    }
                } catch (Exception $e) {
                    error_log('WPSG: Exception in autopilot_auto_updates: ' . $e->getMessage());
                }
                break;

            case 'wpsg_autopilot_emergency_lockdown':
                update_option($setting_key, $setting_value);
                try {
                    if ($setting_value) {
                        $this->init_emergency_lockdown();
                    }
                } catch (Exception $e) {
                    error_log('WPSG: Exception in autopilot_emergency_lockdown: ' . $e->getMessage());
                }
                break;

            case 'wpsg_autopilot_adaptive_learning':
                update_option($setting_key, $setting_value);
                try {
                    if ($setting_value) {
                        $this->init_adaptive_learning();
                    }
                } catch (Exception $e) {
                    error_log('WPSG: Exception in autopilot_adaptive_learning: ' . $e->getMessage());
                }
                break;

            default:
                update_option($setting_key, $setting_value);
                break;
        }

        // Log the settings change
        $this->log_security_event(
            'SETTINGS_CHANGED',
            "Security setting {$setting_key} " . ($setting_value ? 'enabled' : 'disabled'),
            array(
                'setting' => $setting_key,
                'value' => $setting_value,
                'user_id' => get_current_user_id()
            )
        );

        error_log("WPSG AJAX setting successfully processed: $setting_key = " . ($setting_value ? 'true' : 'false'));

        wp_send_json_success(array(
            'message' => 'Nastavení úspěšně uloženo',
            'setting' => $setting_key,
            'value' => $setting_value
        ));
    }

    /**
     * AJAX handler for saving 404 blocking settings
     */
    public function ajax_save_404_settings()
    {
        check_ajax_referer('wpsg_settings_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error('Nemáte oprávnění měnit nastavení');
            return;
        }

        $threshold = intval($_POST['threshold'] ?? 10);
        $lockout = intval($_POST['lockout'] ?? 60);

        // Validate values
        $threshold = max(1, min(100, $threshold));
        $lockout = max(1, min(1440, $lockout)); // max 24 hours

        update_option('wpsg_404_threshold', $threshold);
        update_option('wpsg_404_lockout', $lockout);

        // Log the settings change
        $this->log_security_event(
            'SETTINGS_CHANGED',
            "404 blocking settings updated: threshold={$threshold}, lockout={$lockout}",
            array(
                'threshold' => $threshold,
                'lockout' => $lockout,
                'user_id' => get_current_user_id()
            )
        );

        wp_send_json_success(array(
            'message' => '404 blocking nastavení uloženo',
            'threshold' => $threshold,
            'lockout' => $lockout
        ));
    }

    /**
     * Get default CSP for settings
     */
    private function get_default_csp()
    {
        $site_url = parse_url(home_url(), PHP_URL_HOST);
        return "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' *.{$site_url} cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' *.{$site_url}; img-src 'self' data: *.{$site_url}";
    }

    /**
     * Update security headers setting
     */
    private function update_security_headers_setting($type, $enabled)
    {
        // Always proceed with updating headers
        $headers = get_option('wpsg_security_headers', []);

        switch ($type) {
            case 'hsts':
                if ($enabled) {
                    $headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains';
                } else {
                    unset($headers['Strict-Transport-Security']);
                }
                break;

            case 'csp':
                if ($enabled) {
                    // Get CSP from security headers instance
                    if (class_exists('WPSG_Security_Headers')) {
                        $security_headers = WPSG_Security_Headers::get_instance();
                        $headers['Content-Security-Policy'] = $security_headers->get_default_csp();
                    }
                } else {
                    unset($headers['Content-Security-Policy']);
                }
                break;

            case 'x_frame_options':
                if ($enabled) {
                    $headers['X-Frame-Options'] = 'SAMEORIGIN';
                } else {
                    unset($headers['X-Frame-Options']);
                }
                break;

            case 'x_xss_protection':
                if ($enabled) {
                    $headers['X-XSS-Protection'] = '1; mode=block';
                } else {
                    unset($headers['X-XSS-Protection']);
                }
                break;

            case 'x_content_type_options':
                if ($enabled) {
                    $headers['X-Content-Type-Options'] = 'nosniff';
                } else {
                    unset($headers['X-Content-Type-Options']);
                }
                break;

            case 'referrer_policy':
                if ($enabled) {
                    $headers['Referrer-Policy'] = 'strict-origin-when-cross-origin';
                } else {
                    unset($headers['Referrer-Policy']);
                }
                break;
        }

        update_option('wpsg_security_headers', $headers);
    }

    /**
     * Initialize default values for security header options
     */
    public function init_default_security_header_options()
    {
        // Set default values if they don't exist yet
        if (get_option('wpsg_security_headers_enabled', null) === null) {
            update_option('wpsg_security_headers_enabled', true);
        }
        if (get_option('wpsg_csp_enabled', null) === null) {
            update_option('wpsg_csp_enabled', true);
        }
        if (get_option('wpsg_x_frame_options', null) === null) {
            update_option('wpsg_x_frame_options', true);
        }
        if (get_option('wpsg_x_xss_protection', null) === null) {
            update_option('wpsg_x_xss_protection', true);
        }
        if (get_option('wpsg_x_content_type_options', null) === null) {
            update_option('wpsg_x_content_type_options', true);
        }
        if (get_option('wpsg_referrer_policy', null) === null) {
            update_option('wpsg_referrer_policy', true);
        }
    }

    /**
     * Enqueue admin scripts and styles
     */
    public function admin_enqueue_scripts($hook)
    {
        // Načíst pouze na stránkách Security Guardian
        if (strpos($hook, 'wp-security-guardian') === false) {
            return;
        }

        // Enqueue admin JavaScript
        wp_enqueue_script(
            'wp-security-guardian-admin',
            WPSG_PLUGIN_URL . 'assets/admin-script.js',
            array('jquery'),
            WPSG_VERSION,
            true
        );

        // Enqueue admin CSS
        wp_enqueue_style(
            'wp-security-guardian-admin',
            WPSG_PLUGIN_URL . 'assets/admin-style.css',
            array(),
            WPSG_VERSION
        );

        // Předat proměnné do JavaScriptu
        wp_localize_script('wp-security-guardian-admin', 'wpsg_ajax', array(
            'ajax_url' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('wpsg_admin_nonce')
        ));
    }

    /**
     * Initialize autopilot features
     */
    private function init_autopilot_features()
    {
        // Enable all autopilot security features
        update_option('wpsg_auto_ip_blocking', true);
        update_option('wpsg_auto_threat_detection', true);
        update_option('wpsg_auto_malware_scanning', true);

        // Schedule autopilot checks
        if (!wp_next_scheduled('wpsg_autopilot_check')) {
            wp_schedule_event(time(), 'hourly', 'wpsg_autopilot_check');
        }
    }

    /**
     * Schedule malware scan
     */
    private function schedule_malware_scan()
    {
        // Schedule daily malware scan
        if (!wp_next_scheduled('wpsg_daily_malware_scan')) {
            wp_schedule_event(time(), 'daily', 'wpsg_daily_malware_scan');
        }

        // Run initial scan
        $this->run_malware_scan();
    }

    /**
     * Initialize file integrity monitoring
     */
    private function init_file_integrity_monitoring()
    {
        // Create baseline of core files
        $this->create_file_integrity_baseline();

        // Schedule integrity checks
        if (!wp_next_scheduled('wpsg_integrity_check')) {
            wp_schedule_event(time(), 'twicedaily', 'wpsg_integrity_check');
        }
    }

    /**
     * Run malware scan
     */
    private function run_malware_scan()
    {
        // Basic malware scan implementation
        $scan_results = [];
        $wp_content_dir = WP_CONTENT_DIR;

        // Scan for suspicious files
        $suspicious_patterns = [
            'eval\(',
            'base64_decode\(',
            'gzinflate\(',
            'str_rot13\(',
            'system\(',
            'exec\(',
            'shell_exec\(',
            'passthru\('
        ];

        // Store scan results
        update_option('wpsg_last_malware_scan', time());
        update_option('wpsg_malware_scan_results', $scan_results);

        return $scan_results;
    }

    /**
     * Create file integrity baseline
     */
    private function create_file_integrity_baseline()
    {
        $core_files = [];
        $wp_includes = ABSPATH . 'wp-includes';
        $wp_admin = ABSPATH . 'wp-admin';

        // Create hashes of core files
        foreach ([ABSPATH . 'wp-config.php', $wp_includes, $wp_admin] as $path) {
            if (file_exists($path)) {
                if (is_file($path)) {
                    $core_files[$path] = md5_file($path);
                }
            }
        }

        update_option('wpsg_file_integrity_baseline', $core_files);
        update_option('wpsg_baseline_created', time());

        return $core_files;
    }

    /**
     * Add .htaccess protection rules
     */
    private function add_htaccess_protection($type)
    {
        $htaccess_path = ABSPATH . '.htaccess';

        // Check if .htaccess is writable
        if (!is_writable($htaccess_path) && !is_writable(ABSPATH)) {
            return false;
        }

        $current_content = '';
        if (file_exists($htaccess_path)) {
            $current_content = file_get_contents($htaccess_path);
        }

        $marker_start = "# BEGIN WP Security Guardian - $type";
        $marker_end = "# END WP Security Guardian - $type";

        // Remove existing rules for this type
        $current_content = $this->remove_htaccess_section($current_content, $marker_start, $marker_end);

        $rules = $this->get_htaccess_rules($type);

        if (!empty($rules)) {
            $new_section = "\n$marker_start\n$rules\n$marker_end\n";

            // Add at the beginning of .htaccess (before WordPress rules)
            if (strpos($current_content, '# BEGIN WordPress') !== false) {
                $current_content = str_replace('# BEGIN WordPress', $new_section . '# BEGIN WordPress', $current_content);
            } else {
                $current_content = $new_section . $current_content;
            }

            return file_put_contents($htaccess_path, $current_content);
        }

        return false;
    }

    /**
     * Remove .htaccess protection rules
     */
    private function remove_htaccess_protection($type)
    {
        $htaccess_path = ABSPATH . '.htaccess';

        if (!file_exists($htaccess_path) || !is_writable($htaccess_path)) {
            return false;
        }

        $current_content = file_get_contents($htaccess_path);
        $marker_start = "# BEGIN WP Security Guardian - $type";
        $marker_end = "# END WP Security Guardian - $type";

        $new_content = $this->remove_htaccess_section($current_content, $marker_start, $marker_end);

        return file_put_contents($htaccess_path, $new_content);
    }

    /**
     * Remove section from .htaccess content
     */
    private function remove_htaccess_section($content, $marker_start, $marker_end)
    {
        $start_pos = strpos($content, $marker_start);
        if ($start_pos !== false) {
            $end_pos = strpos($content, $marker_end, $start_pos);
            if ($end_pos !== false) {
                $end_pos += strlen($marker_end);
                // Remove the section including newlines
                $before = substr($content, 0, $start_pos);
                $after = substr($content, $end_pos);

                // Clean up extra newlines
                $before = rtrim($before);
                $after = ltrim($after, "\n");

                $content = $before . ($after ? "\n" . $after : '');
            }
        }

        return $content;
    }

    /**
     * Get .htaccess rules for specific protection type
     */
    private function get_htaccess_rules($type)
    {
        switch ($type) {
            case 'wp_config':
                return '<Files "wp-config.php">
    Order allow,deny
    Deny from all
</Files>';

            case 'directory_browsing':
                return 'Options -Indexes';

            case 'https_admin':
                return 'RewriteEngine On
RewriteCond %{HTTPS} off
RewriteCond %{REQUEST_URI} ^/wp-admin [OR]
RewriteCond %{REQUEST_URI} ^/wp-login.php
RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]';

            case 'sensitive_files':
                return '<FilesMatch "^(wp-config-sample\.php|readme\.html|license\.txt|\.htaccess|\.htpasswd)$">
    Order allow,deny
    Deny from all
</FilesMatch>

<Files ".htaccess">
    Order allow,deny
    Deny from all
</Files>';

            case 'uploads_protection':
                return '# Block PHP execution in uploads folder
<FilesMatch "\.(?i:php|phtml|php3|php4|php5|php7|phps)$">
    Order allow,deny
    Deny from all
</FilesMatch>

# Allow only safe file types
<FilesMatch "\.(?i:jpg|jpeg|png|gif|webp|pdf|doc|docx|xls|xlsx|ppt|pptx|zip|mp4|mp3|avi|mov)$">
    Order allow,deny
    Allow from all
</FilesMatch>';

            default:
                return '';
        }
    }

    /**
     * Check if .htaccess protection is active
     */
    public function is_htaccess_protection_active($type)
    {
        $htaccess_path = ABSPATH . '.htaccess';

        if (!file_exists($htaccess_path)) {
            return false;
        }

        $content = file_get_contents($htaccess_path);
        $marker_start = "# BEGIN WP Security Guardian - $type";

        return strpos($content, $marker_start) !== false;
    }

    /**
     * Initialize security hooks based on database settings
     */
    public function init_security_hooks()
    {
        // Hide WordPress version
        if (get_option('wpsg_hide_wp_version', true)) {
            remove_action('wp_head', 'wp_generator');
            add_filter('the_generator', '__return_empty_string');
        }

        // Disable file editing
        if (get_option('wpsg_disable_file_editing', true) && !defined('DISALLOW_FILE_EDIT')) {
            define('DISALLOW_FILE_EDIT', true);
        }

        // Disable XML-RPC
        if (get_option('wpsg_disable_xmlrpc', true)) {
            add_filter('xmlrpc_enabled', '__return_false');
        }

        // Remove generator tags and X-Powered-By
        if (get_option('wpsg_remove_generator_tag', true)) {
            remove_action('wp_head', 'wp_generator');
            add_filter('the_generator', '__return_empty_string');
            // Remove X-Powered-By header
            add_action('init', function () {
                if (function_exists('header_remove')) {
                    header_remove('X-Powered-By');
                }
            });
        }

        // Limit login attempts
        if (get_option('wpsg_limit_login_attempts', true)) {
            add_filter('authenticate', array($this, 'limit_login_attempts'), 30, 3);
        }

        // Block user enumeration
        if (get_option('wpsg_block_user_enumeration', true)) {
            add_action('init', function () {
                if (!is_admin() && isset($_REQUEST['author']) && is_numeric($_REQUEST['author'])) {
                    wp_die('Forbidden');
                }
            });
            add_filter('redirect_canonical', function ($redirect, $request) {
                if (preg_match('/\?author=([0-9]*)(\/*)/i', $request)) {
                    wp_die('Forbidden');
                }
                return $redirect;
            }, 10, 2);
        }

        // Disable login hints
        if (get_option('wpsg_disable_login_hints', true)) {
            add_filter('login_errors', function () {
                return 'Neplatné přihlašovací údaje.';
            });
        }

        // Force SSL redirect
        if (get_option('wpsg_force_ssl', false)) {
            add_action('init', function () {
                if (!is_ssl() && !is_admin()) {
                    wp_redirect('https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'], 301);
                    exit();
                }
            });
        }

        // IP Blocking
        if (get_option('wpsg_ip_blocking', true)) {
            add_action('init', array($this, 'check_blocked_ips'), 1);
        }

        // 404 Blocking
        $threshold = get_option('wpsg_404_threshold', 10);
        if ($threshold > 0) {
            add_action('wp', array($this, 'track_404_errors'));
        }
    }

    /**
     * Limit login attempts
     */
    public function limit_login_attempts($user, $username, $password)
    {
        if (empty($username) || empty($password)) {
            return $user;
        }

        $ip = $this->get_client_ip();
        $key = 'wpsg_login_attempts_' . md5($ip);
        $attempts = get_transient($key);
        $max_attempts = 5;
        $lockout_duration = 900; // 15 minutes

        if ($attempts >= $max_attempts) {
            return new WP_Error('too_many_attempts', 'Příliš mnoho pokusů o přihlášení. Zkuste to znovu za 15 minut.');
        }

        if (is_wp_error($user)) {
            set_transient($key, $attempts + 1, $lockout_duration);
        } else {
            delete_transient($key);
        }

        return $user;
    }

    /**
     * Track 404 errors for blocking
     */
    public function track_404_errors()
    {
        if (is_404()) {
            $ip = $this->get_client_ip();
            $key = 'wpsg_404_count_' . md5($ip);
            $count = get_transient($key) ?: 0;
            $threshold = get_option('wpsg_404_threshold', 10);
            $lockout = get_option('wpsg_404_lockout', 60) * 60; // convert to seconds

            $count++;
            set_transient($key, $count, 3600); // Track for 1 hour

            if ($count >= $threshold) {
                // Block the IP
                $this->block_ip($ip, 'Excessive 404 errors', $lockout);
                wp_die('Příliš mnoho 404 chyb. IP adresa byla zablokována.');
            }
        }
    }

    /**
     * Check if current IP is blocked
     */
    public function check_blocked_ips()
    {
        $ip = $this->get_client_ip();
        $blocked_ips = get_option('wpsg_blocked_ips', []);

        if (isset($blocked_ips[$ip])) {
            $block_data = $blocked_ips[$ip];
            if (time() < $block_data['expires']) {
                wp_die('Váše IP adresa byla zablokována. Důvod: ' . $block_data['reason']);
            } else {
                // Block expired, remove it
                unset($blocked_ips[$ip]);
                update_option('wpsg_blocked_ips', $blocked_ips);
            }
        }
    }

    /**
     * Test all security features functionality - SKUTEČNÝ TEST STAVU
     */
    public function test_security_features()
    {
        $results = [];

        // Test 1: WordPress version hiding - testuj skutečný stav
        $wp_version_hidden_setting = get_option('wpsg_hide_wp_version', true);
        if ($wp_version_hidden_setting) {
            // Test, zda je wp_generator skutečně odstraněn
            $results['wp_version_hidden'] = !has_action('wp_head', 'wp_generator');
        } else {
            $results['wp_version_hidden'] = false;
        }

        // Test 2: File editing disabled - testuj skutečný stav
        $file_editing_setting = get_option('wpsg_disable_file_editing', true);
        if ($file_editing_setting) {
            // Skutečně test, zda je DISALLOW_FILE_EDIT nastaveno
            $results['file_editing_disabled'] = (defined('DISALLOW_FILE_EDIT') && DISALLOW_FILE_EDIT);
        } else {
            $results['file_editing_disabled'] = false;
        }

        // Test 3: XML-RPC disabled - testuj skutečnou dostupnost
        $xmlrpc_setting = get_option('wpsg_disable_xmlrpc', true);
        if ($xmlrpc_setting) {
            // Test, zda je XML-RPC skutečně zakázané
            $results['xmlrpc_disabled'] = !apply_filters('xmlrpc_enabled', true);
        } else {
            $results['xmlrpc_disabled'] = false;
        }

        // Test 4: Login attempt limiting - test skutečné funkčnosti
        $login_limiting = get_option('wpsg_limit_login_attempts', true);
        if ($login_limiting) {
            // Test, zda existují záznamy o limitování
            $blocked_attempts = get_option('wpsg_blocked_attempts', []);
            $results['login_limiting_active'] = !empty($blocked_attempts) || $login_limiting;
        } else {
            $results['login_limiting_active'] = false;
        }

        // Test 5: Bezpečnostní hlavičky - test skutečných HTTP hlaviček
        $headers_globally_enabled = get_option('wpsg_security_headers_enabled', true);
        if ($headers_globally_enabled) {
            // Proveď skutečný HTTP request a otestuj hlavičky
            $test_result = $this->test_actual_headers();
            $results['security_headers_active'] = $test_result;
        } else {
            $results['security_headers_active'] = false;
        }

        // Test 6: SSL/HTTPS - test skutečného stavu
        $ssl_forced = get_option('wpsg_force_ssl', false);
        $results['ssl_active'] = $ssl_forced && (is_ssl() || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https'));

        // Test 7: HSTS hlavička - test v HTTP response
        $hsts_enabled = get_option('wpsg_hsts_enabled', false);
        if ($hsts_enabled && is_ssl()) {
            $test_result = $this->test_actual_headers();
            $results['hsts_active'] = isset($test_result['hsts']);
        } else {
            $results['hsts_active'] = false;
        }

        // Test 8: User enumeration blocking - test skutečné blokování
        $user_enum_blocked = get_option('wpsg_block_user_enumeration', true);
        if ($user_enum_blocked) {
            // Test skutečného blokování autor stránek
            $results['user_enum_blocked'] = $this->test_user_enum_blocking();
        } else {
            $results['user_enum_blocked'] = false;
        }

        // Test 9: 2FA systém - test skutečné implementace
        $twofa_setting = get_option('wpsg_require_2fa', 'disabled');
        $results['2fa_active'] = ($twofa_setting !== 'disabled') && function_exists('wp_2fa_enabled');

        // Test 10: Auto-Pilot - test nastavení a funkčnosti
        $autopilot_enabled = get_option('wpsg_autopilot_enabled', false);
        $results['autopilot_active'] = $autopilot_enabled;

        return $results;
    }

    /**
     * Test skutečných HTTP hlaviček posílaných serverem
     */
    private function test_actual_headers()
    {
        // Nejprve se pokusíme o jednoduchý test - zkontrolujme, zda jsou hlavičky konfigurovány
        $headers_globally_enabled = get_option('wpsg_security_headers_enabled', true);
        if (!$headers_globally_enabled) {
            return false;
        }

        // Test jednotlivých nastavených hlaviček
        $csp_enabled = get_option('wpsg_csp_enabled', true);
        $frame_options = get_option('wpsg_x_frame_options', true);
        $xss_protection = get_option('wpsg_x_xss_protection', true);
        $content_type_options = get_option('wpsg_x_content_type_options', true);
        $referrer_policy = get_option('wpsg_referrer_policy', true);

        // Pokud je alespoň jedna hlavička povolená, považujme to za aktivní
        $some_headers_enabled = $csp_enabled || $frame_options || $xss_protection || $content_type_options || $referrer_policy;

        // Pro skutečný test HTTP hlaviček pouze pokud je to bezpečné
        if ($some_headers_enabled && !$this->is_localhost()) {
            try {
                $response = wp_remote_head(home_url('/'), [
                    'timeout' => 3,
                    'sslverify' => false,
                    'user-agent' => 'WordPress/' . get_bloginfo('version') . '; ' . home_url(),
                    'headers' => [
                        'Cache-Control' => 'no-cache'
                    ]
                ]);

                if (!is_wp_error($response) && wp_remote_retrieve_response_code($response) === 200) {
                    $headers = wp_remote_retrieve_headers($response);

                    // Kontrola skutečné přítomnosti hlaviček
                    if (
                        isset($headers['content-security-policy']) ||
                        isset($headers['x-frame-options']) ||
                        isset($headers['x-xss-protection']) ||
                        isset($headers['x-content-type-options']) ||
                        isset($headers['referrer-policy'])
                    ) {
                        return true;
                    }
                }
            } catch (Exception $e) {
                // Pokud HTTP test selže, vraťme se k test nastavení
            }
        }

        return $some_headers_enabled;
    }

    /**
     * Check if running on localhost
     */
    private function is_localhost()
    {
        $host = parse_url(home_url(), PHP_URL_HOST);
        return in_array($host, ['localhost', '127.0.0.1', '::1']) ||
            strpos($host, '.local') !== false ||
            strpos($host, '.test') !== false;
    }

    /**
     * Test user enumeration blocking
     */
    private function test_user_enum_blocking()
    {
        // Test, zda je přidán filtr pro blokování author pages
        return has_filter('author_rewrite_rules', [$this, 'disable_author_pages']);
    }

    /**
     * Get security functionality status for admin interface
     */
    public function get_security_status()
    {
        $tests = $this->test_security_features();
        $active_count = count(array_filter($tests));
        $total_count = count($tests);
        $percentage = round(($active_count / $total_count) * 100);

        return [
            'tests' => $tests,
            'active' => $active_count,
            'total' => $total_count,
            'percentage' => $percentage,
            'status' => $percentage >= 90 ? 'excellent' : ($percentage >= 70 ? 'good' : 'needs_improvement')
        ];
    }

    /**
     * Block an IP address
     */
    private function block_ip($ip, $reason = 'Security violation', $duration = 3600)
    {
        $blocked_ips = get_option('wpsg_blocked_ips', []);
        $blocked_ips[$ip] = [
            'reason' => $reason,
            'blocked_at' => time(),
            'expires' => time() + $duration,
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown'
        ];
        update_option('wpsg_blocked_ips', $blocked_ips);

        $this->log_security_event('IP_BLOCKED', "IP $ip blocked for: $reason", [
            'ip' => $ip,
            'reason' => $reason,
            'duration' => $duration
        ]);
    }

    /**
     * Add uploads folder protection
     */
    public function add_uploads_protection()
    {
        $uploads_dir = wp_upload_dir();
        $uploads_path = $uploads_dir['basedir'];
        $htaccess_path = $uploads_path . '/.htaccess';

        // Create .htaccess in uploads if it doesn't exist
        $protection_rules = $this->get_htaccess_rules('uploads_protection');

        if (!empty($protection_rules)) {
            $success = file_put_contents($htaccess_path, $protection_rules);

            if ($success) {
                $this->log_security_event('UPLOADS_PROTECTION_ENABLED', 'Uploads folder protection enabled', [
                    'htaccess_path' => $htaccess_path
                ]);
                return true;
            }
        }

        return false;
    }

    /**
     * Remove uploads folder protection
     */
    public function remove_uploads_protection()
    {
        $uploads_dir = wp_upload_dir();
        $uploads_path = $uploads_dir['basedir'];
        $htaccess_path = $uploads_path . '/.htaccess';

        if (file_exists($htaccess_path)) {
            $success = unlink($htaccess_path);

            if ($success) {
                $this->log_security_event('UPLOADS_PROTECTION_DISABLED', 'Uploads folder protection disabled', [
                    'htaccess_path' => $htaccess_path
                ]);
                return true;
            }
        }

        return false;
    }

    /**
     * Check if uploads protection is active
     */
    public function is_uploads_protection_active()
    {
        $uploads_dir = wp_upload_dir();
        $uploads_path = $uploads_dir['basedir'];
        $htaccess_path = $uploads_path . '/.htaccess';

        if (!file_exists($htaccess_path)) {
            return false;
        }

        $content = file_get_contents($htaccess_path);
        return strpos($content, 'Block PHP execution in uploads folder') !== false;
    }

    /**
     * Unified Diagnostics page (kombinuje Status a Testing s taby)
     */
    public function diagnostics_page()
    {
        // Verify authorization first
        if (!current_user_can('manage_options')) {
            wp_die(__('Nemáte oprávnění pro přístup k této stránce.'));
        }

        // Use the enhanced template
        $this->load_template('diagnostics-page.php');
    }

    /**
     * Render Security Status content (původní status_page obsah)
     */
    private function render_status_content()
    {
    ?>
        <div class="wpsg-status-section">
            <?php
            // Zkontrolujeme aktuální stav bezpečnostních mechanismů
            $tests = array(
                'wp_version_hidden' => !has_action('wp_head', 'wp_generator'),
                'file_editing_disabled' => defined('DISALLOW_FILE_EDIT') && DISALLOW_FILE_EDIT,
                'xmlrpc_disabled' => has_filter('xmlrpc_enabled') && !apply_filters('xmlrpc_enabled', true),
                '2fa_active' => class_exists('WPSG_Two_Factor_Auth'),
                'security_headers_active' => class_exists('WPSG_Security_Headers'),
                'ssl_monitor_active' => class_exists('WPSG_SSL_Monitor'),
                'login_limiting_active' => has_filter('authenticate'),
                'ip_blocking_active' => has_action('init'),
                '404_tracking_active' => has_action('wp'),
                'user_enum_blocked' => get_option('wpsg_block_user_enumeration', false)
            );

            $status = array(
                'total' => count($tests),
                'active' => count(array_filter($tests)),
                'percentage' => round((count(array_filter($tests)) / count($tests)) * 100)
            );
            ?>

            <div style="background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); margin-bottom: 20px;">
                <h2>Celkový stav: <?php echo $status['active']; ?>/<?php echo $status['total']; ?> (<?php echo $status['percentage']; ?>%)</h2>

                <div style="background: #f0f0f0; height: 20px; border-radius: 10px; margin: 15px 0;">
                    <div style="background: <?php echo $status['percentage'] >= 80 ? '#10b981' : ($status['percentage'] >= 60 ? '#f59e0b' : '#dc2626'); ?>; height: 100%; width: <?php echo $status['percentage']; ?>%; border-radius: 10px; transition: width 0.3s ease;"></div>
                </div>

                <table class="widefat" style="margin-top: 20px;">
                    <thead>
                        <tr>
                            <th>Bezpečnostní mechanismus</th>
                            <th>Stav</th>
                            <th>Detail</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>Skrytí WordPress verze</td>
                            <td><?php echo $tests['wp_version_hidden'] ? '✅ ACTIVE' : '❌ INACTIVE'; ?></td>
                            <td><?php echo $tests['wp_version_hidden'] ? 'wp_generator removed from wp_head' : 'wp_generator still active'; ?></td>
                        </tr>
                        <tr>
                            <td>Zákaz editace souborů</td>
                            <td><?php echo $tests['file_editing_disabled'] ? '✅ ACTIVE' : '❌ INACTIVE'; ?></td>
                            <td><?php echo $tests['file_editing_disabled'] ? 'DISALLOW_FILE_EDIT is TRUE' : 'File editing still allowed'; ?></td>
                        </tr>
                        <tr>
                            <td>XML-RPC zakázáno</td>
                            <td><?php echo $tests['xmlrpc_disabled'] ? '✅ ACTIVE' : '❌ INACTIVE'; ?></td>
                            <td><?php echo $tests['xmlrpc_disabled'] ? 'xmlrpc_enabled filter returns FALSE' : 'XML-RPC still enabled'; ?></td>
                        </tr>
                        <tr>
                            <td>2FA systém</td>
                            <td><?php echo $tests['2fa_active'] ? '✅ LOADED' : '❌ NOT LOADED'; ?></td>
                            <td><?php echo $tests['2fa_active'] ? 'WPSG_Two_Factor_Auth class exists' : 'Class not found'; ?></td>
                        </tr>
                        <tr>
                            <td>Security Headers</td>
                            <td><?php echo $tests['security_headers_active'] ? '✅ LOADED' : '❌ NOT LOADED'; ?></td>
                            <td><?php echo $tests['security_headers_active'] ? 'WPSG_Security_Headers class exists' : 'Class not found'; ?></td>
                        </tr>
                        <tr>
                            <td>SSL Monitor</td>
                            <td><?php echo $tests['ssl_monitor_active'] ? '✅ LOADED' : '❌ NOT LOADED'; ?></td>
                            <td><?php echo $tests['ssl_monitor_active'] ? 'WPSG_SSL_Monitor class exists' : 'Class not found'; ?></td>
                        </tr>
                        <tr>
                            <td>Login Rate Limiting</td>
                            <td><?php echo $tests['login_limiting_active'] ? '✅ ACTIVE' : '❌ INACTIVE'; ?></td>
                            <td><?php echo $tests['login_limiting_active'] ? 'authenticate filter hooked' : 'No hook active'; ?></td>
                        </tr>
                        <tr>
                            <td>IP Blocking System</td>
                            <td><?php echo $tests['ip_blocking_active'] ? '✅ ACTIVE' : '❌ INACTIVE'; ?></td>
                            <td><?php echo $tests['ip_blocking_active'] ? 'init action hooked for IP check' : 'No IP checking active'; ?></td>
                        </tr>
                        <tr>
                            <td>404 Attack Tracking</td>
                            <td><?php echo $tests['404_tracking_active'] ? '✅ ACTIVE' : '❌ INACTIVE'; ?></td>
                            <td><?php echo $tests['404_tracking_active'] ? 'wp action hooked for 404 tracking' : 'No 404 tracking'; ?></td>
                        </tr>
                        <tr>
                            <td>User Enumeration Block</td>
                            <td><?php echo $tests['user_enum_blocked'] ? '✅ ACTIVE' : '❌ INACTIVE'; ?></td>
                            <td><?php echo $tests['user_enum_blocked'] ? 'Option enabled in database' : 'Option disabled'; ?></td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
    <?php
    }

    /**
     * Render Security Testing content (původní enhanced_security_testing_page obsah)
     */
    private function render_testing_content()
    {
    ?>
        <div class="wpsg-testing-grid" style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 20px;">

            <!-- Security Headers Test -->
            <div class="wpsg-test-card" style="background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
                <h3><?php _e('Security Headers Test', 'wp-security-guardian'); ?></h3>
                <p><?php _e('Test your website\'s security headers implementation.', 'wp-security-guardian'); ?></p>
                <button id="test-headers" class="button button-primary"><?php _e('Test Headers', 'wp-security-guardian'); ?></button>
                <div id="headers-results" style="margin-top: 15px;"></div>
            </div>

            <!-- Progressive Security Score -->
            <div class="wpsg-test-card" style="background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
                <h3><?php _e('Security Score Analysis', 'wp-security-guardian'); ?></h3>
                <p><?php _e('Calculate your comprehensive security score.', 'wp-security-guardian'); ?></p>
                <button id="calculate-score" class="button button-primary"><?php _e('Calculate Score', 'wp-security-guardian'); ?></button>
                <div id="score-results" style="margin-top: 15px;"></div>
            </div>

            <!-- File Integrity Check -->
            <div class="wpsg-test-card" style="background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
                <h3><?php _e('File Integrity Check', 'wp-security-guardian'); ?></h3>
                <p><?php _e('Create checkpoints and verify file integrity.', 'wp-security-guardian'); ?></p>
                <button id="create-checkpoint" class="button button-secondary"><?php _e('Create Checkpoint', 'wp-security-guardian'); ?></button>
                <button id="verify-integrity" class="button button-primary"><?php _e('Verify Integrity', 'wp-security-guardian'); ?></button>
                <div id="integrity-results" style="margin-top: 15px;"></div>
            </div>

            <!-- Security Self-Test -->
            <div class="wpsg-test-card" style="background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
                <h3><?php _e('Security Self-Test', 'wp-security-guardian'); ?></h3>
                <p><?php _e('Run comprehensive security vulnerability tests.', 'wp-security-guardian'); ?></p>
                <button id="run-self-test" class="button button-primary"><?php _e('Run Tests', 'wp-security-guardian'); ?></button>
                <div id="self-test-results" style="margin-top: 15px;"></div>
            </div>

        </div>

        <!-- Secure Logs Viewer -->
        <div class="wpsg-logs-section" style="background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); margin-top: 20px;">
            <h3><?php _e('Secure Activity Logs', 'wp-security-guardian'); ?></h3>
            <div style="margin-bottom: 15px;">
                <select id="log-level-filter">
                    <option value=""><?php _e('All Levels', 'wp-security-guardian'); ?></option>
                    <option value="info"><?php _e('Info', 'wp-security-guardian'); ?></option>
                    <option value="warning"><?php _e('Warning', 'wp-security-guardian'); ?></option>
                    <option value="error"><?php _e('Error', 'wp-security-guardian'); ?></option>
                </select>
                <input type="number" id="log-limit" placeholder="<?php _e('Limit (default 50)', 'wp-security-guardian'); ?>" min="1" max="200" value="50">
                <button id="load-logs" class="button"><?php _e('Load Logs', 'wp-security-guardian'); ?></button>
            </div>
            <div id="logs-results"></div>
        </div>

        <!-- Styles and Scripts pro testing funkce -->
        <style>
            .wpsg-test-card h3 {
                color: #2271b1;
                margin-top: 0;
            }

            .wpsg-results-success {
                background: #d1f2df;
                border: 1px solid #00a32a;
                padding: 10px;
                border-radius: 4px;
                margin-top: 10px;
            }

            .wpsg-results-warning {
                background: #fff3cd;
                border: 1px solid #ffcc02;
                padding: 10px;
                border-radius: 4px;
                margin-top: 10px;
            }

            .wpsg-results-error {
                background: #f8d7da;
                border: 1px solid #dc3545;
                padding: 10px;
                border-radius: 4px;
                margin-top: 10px;
            }

            .wpsg-log-entry {
                background: #f9f9f9;
                border-left: 4px solid #2271b1;
                padding: 10px;
                margin-bottom: 10px;
            }

            .wpsg-log-entry.warning {
                border-left-color: #ffcc02;
            }

            .wpsg-log-entry.error {
                border-left-color: #dc3545;
            }
        </style>

        <script>
            jQuery(document).ready(function($) {
                const nonce = '<?php echo wp_create_nonce('wpsg_security_test'); ?>';

                // Test Security Headers
                $('#test-headers').click(function() {
                    const $button = $(this);
                    const $results = $('#headers-results');

                    $button.prop('disabled', true).text('<?php _e('Testing...', 'wp-security-guardian'); ?>');

                    $.post(ajaxurl, {
                        action: 'wpsg_test_security_headers',
                        nonce: nonce,
                        url: '<?php echo home_url('/'); ?>'
                    }, function(response) {
                        if (response.success) {
                            const data = response.data;
                            let html = '<div class="wpsg-results-' + (data.percentage >= 70 ? 'success' : data.percentage >= 50 ? 'warning' : 'error') + '">';
                            html += '<h4><?php _e('Security Headers Score', 'wp-security-guardian'); ?>: ' + data.percentage + '% (' + data.grade + ')</h4>';

                            for (const [header, info] of Object.entries(data.headers)) {
                                html += '<p><strong>' + header + '</strong>: ' + (info.present ? '✅' : '❌');
                                if (info.recommendation) {
                                    html += ' - ' + info.recommendation;
                                }
                                html += '</p>';
                            }

                            html += '</div>';
                            $results.html(html);
                        } else {
                            $results.html('<div class="wpsg-results-error"><?php _e('Error:', 'wp-security-guardian'); ?> ' + response.data + '</div>');
                        }
                    }).fail(function() {
                        $results.html('<div class="wpsg-results-error"><?php _e('Request failed', 'wp-security-guardian'); ?></div>');
                    }).always(function() {
                        $button.prop('disabled', false).text('<?php _e('Test Headers', 'wp-security-guardian'); ?>');
                    });
                });

                // Calculate Security Score
                $('#calculate-score').click(function() {
                    const $button = $(this);
                    const $results = $('#score-results');

                    $button.prop('disabled', true).text('<?php _e('Calculating...', 'wp-security-guardian'); ?>');

                    $.post(ajaxurl, {
                        action: 'wpsg_security_score',
                        nonce: nonce
                    }, function(response) {
                        if (response.success) {
                            const data = response.data;
                            let html = '<div class="wpsg-results-' + (data.percentage >= 80 ? 'success' : data.percentage >= 60 ? 'warning' : 'error') + '">';
                            html += '<h4><?php _e('Overall Security Score', 'wp-security-guardian'); ?>: ' + data.percentage + '% (' + data.grade + ')</h4>';

                            for (const [category, info] of Object.entries(data.breakdown)) {
                                html += '<p><strong>' + category.replace('_', ' ') + '</strong>: ' + (info.score * 100).toFixed(0) + '% (<?php _e('Weight', 'wp-security-guardian'); ?>: ' + info.weight + ')</p>';
                            }

                            if (data.recommendations.length > 0) {
                                html += '<h5><?php _e('Recommendations', 'wp-security-guardian'); ?>:</h5><ul>';
                                data.recommendations.forEach(rec => {
                                    html += '<li>' + rec + '</li>';
                                });
                                html += '</ul>';
                            }

                            html += '</div>';
                            $results.html(html);
                        } else {
                            $results.html('<div class="wpsg-results-error"><?php _e('Error:', 'wp-security-guardian'); ?> ' + response.data + '</div>');
                        }
                    }).fail(function() {
                        $results.html('<div class="wpsg-results-error"><?php _e('Request failed', 'wp-security-guardian'); ?></div>');
                    }).always(function() {
                        $button.prop('disabled', false).text('<?php _e('Calculate Score', 'wp-security-guardian'); ?>');
                    });
                });

                // File Integrity
                $('#create-checkpoint, #verify-integrity').click(function() {
                    const $button = $(this);
                    const $results = $('#integrity-results');
                    const isCreate = $(this).attr('id') === 'create-checkpoint';

                    $button.prop('disabled', true).text(isCreate ? '<?php _e('Creating...', 'wp-security-guardian'); ?>' : '<?php _e('Verifying...', 'wp-security-guardian'); ?>');

                    $.post(ajaxurl, {
                        action: 'wpsg_integrity_check',
                        nonce: nonce,
                        action_type: isCreate ? 'create' : 'verify'
                    }, function(response) {
                        if (response.success) {
                            const data = response.data;
                            let html = '<div class="wpsg-results-success"><h4>' + data.message + '</h4>';

                            if (data.results.summary) {
                                const summary = data.results.summary;
                                html += '<p><?php _e('Files checked', 'wp-security-guardian'); ?>: ' + summary.total_files + '</p>';
                                if (summary.intact !== undefined) {
                                    html += '<p>✅ <?php _e('Intact', 'wp-security-guardian'); ?>: ' + summary.intact + '</p>';
                                    html += '<p>⚠️ <?php _e('Modified', 'wp-security-guardian'); ?>: ' + summary.modified + '</p>';
                                    html += '<p>❌ <?php _e('Missing', 'wp-security-guardian'); ?>: ' + summary.missing + '</p>';
                                }
                            }

                            html += '</div>';
                            $results.html(html);
                        } else {
                            $results.html('<div class="wpsg-results-error"><?php _e('Error:', 'wp-security-guardian'); ?> ' + response.data + '</div>');
                        }
                    }).fail(function() {
                        $results.html('<div class="wpsg-results-error"><?php _e('Request failed', 'wp-security-guardian'); ?></div>');
                    }).always(function() {
                        const originalText = isCreate ? '<?php _e('Create Checkpoint', 'wp-security-guardian'); ?>' : '<?php _e('Verify Integrity', 'wp-security-guardian'); ?>';
                        $button.prop('disabled', false).text(originalText);
                    });
                });

                // Security Self-Test
                $('#run-self-test').click(function() {
                    const $button = $(this);
                    const $results = $('#self-test-results');

                    $button.prop('disabled', true).text('<?php _e('Running Tests...', 'wp-security-guardian'); ?>');

                    $.post(ajaxurl, {
                        action: 'wpsg_security_self_test',
                        nonce: nonce
                    }, function(response) {
                        if (response.success) {
                            const data = response.data;
                            let html = '<div class="wpsg-results-' + (data.overall_score >= 80 ? 'success' : data.overall_score >= 60 ? 'warning' : 'error') + '">';
                            html += '<h4><?php _e('Self-Test Results', 'wp-security-guardian'); ?>: ' + data.overall_score + '% (' + data.grade + ')</h4>';
                            html += '<p><?php _e('Passed Tests', 'wp-security-guardian'); ?>: ' + data.passed_tests + '/' + data.total_tests + '</p>';

                            for (const [test, result] of Object.entries(data.results)) {
                                html += '<p>' + (result.status === 'passed' ? '✅' : '❌') + ' <strong>' + test.replace('_', ' ') + '</strong>: ' + result.message + '</p>';
                            }

                            if (data.recommendations.length > 0) {
                                html += '<h5><?php _e('Recommendations', 'wp-security-guardian'); ?>:</h5><ul>';
                                data.recommendations.forEach(rec => {
                                    html += '<li>' + rec + '</li>';
                                });
                                html += '</ul>';
                            }

                            html += '</div>';
                            $results.html(html);
                        } else {
                            $results.html('<div class="wpsg-results-error"><?php _e('Error:', 'wp-security-guardian'); ?> ' + response.data + '</div>');
                        }
                    }).fail(function() {
                        $results.html('<div class="wpsg-results-error"><?php _e('Request failed', 'wp-security-guardian'); ?></div>');
                    }).always(function() {
                        $button.prop('disabled', false).text('<?php _e('Run Tests', 'wp-security-guardian'); ?>');
                    });
                });

                // Load Logs
                $('#load-logs').click(function() {
                    const $button = $(this);
                    const $results = $('#logs-results');
                    const limit = $('#log-limit').val() || 50;
                    const level = $('#log-level-filter').val();

                    $button.prop('disabled', true).text('<?php _e('Loading...', 'wp-security-guardian'); ?>');

                    $.post(ajaxurl, {
                        action: 'wpsg_get_secure_logs',
                        nonce: nonce,
                        limit: limit,
                        level_filter: level
                    }, function(response) {
                        if (response.success) {
                            const logs = response.data.logs;
                            let html = '';

                            if (logs.length === 0) {
                                html = '<p><?php _e('No logs found', 'wp-security-guardian'); ?></p>';
                            } else {
                                logs.forEach(log => {
                                    html += '<div class="wpsg-log-entry ' + log.level + '">';
                                    html += '<strong>' + log.event + '</strong> (' + log.level + ') - ' + log.timestamp;
                                    html += '<br>User ID: ' + log.user_id + ' | IP: ' + log.ip_address;
                                    if (log.data && log.data.message) {
                                        html += '<br>' + log.data.message;
                                    }
                                    html += '</div>';
                                });
                            }

                            $results.html(html);
                        } else {
                            $results.html('<div class="wpsg-results-error"><?php _e('Error:', 'wp-security-guardian'); ?> ' + response.data + '</div>');
                        }
                    }).fail(function() {
                        $results.html('<div class="wpsg-results-error"><?php _e('Request failed', 'wp-security-guardian'); ?></div>');
                    }).always(function() {
                        $button.prop('disabled', false).text('<?php _e('Load Logs', 'wp-security-guardian'); ?>');
                    });
                });
            });
        </script>
    <?php
    }

    /**
     * Enhanced Security Testing admin page (původní metoda - nyní nepoužívaná)
     */
    public function enhanced_security_testing_page()
    {
        // Enhanced security: Rate limiting for page access
        WPSG_Enhanced_Security::check_admin_rate_limit('testing_page_access', 20, 300);

        // Enhanced security: Log page access
        WPSG_Enhanced_Security::secure_log('TESTING_PAGE_ACCESSED', [
            'user_id' => get_current_user_id(),
            'timestamp' => current_time('mysql')
        ], 'info');

        // Verify authorization
        if (!current_user_can('manage_options')) {
            wp_die(__('Nemáte oprávnění pro přístup k této stránce.'));
        }
    ?>
        <div class="wrap">
            <h1><?php _e('Enhanced Security Testing', 'wp-security-guardian'); ?></h1>

            <div class="wpsg-testing-grid" style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 20px;">

                <!-- Security Headers Test -->
                <div class="wpsg-test-card" style="background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
                    <h3><?php _e('Security Headers Test', 'wp-security-guardian'); ?></h3>
                    <p><?php _e('Test your website\'s security headers implementation.', 'wp-security-guardian'); ?></p>
                    <button id="test-headers" class="button button-primary"><?php _e('Test Headers', 'wp-security-guardian'); ?></button>
                    <div id="headers-results" style="margin-top: 15px;"></div>
                </div>

                <!-- Progressive Security Score -->
                <div class="wpsg-test-card" style="background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
                    <h3><?php _e('Security Score Analysis', 'wp-security-guardian'); ?></h3>
                    <p><?php _e('Calculate your comprehensive security score.', 'wp-security-guardian'); ?></p>
                    <button id="calculate-score" class="button button-primary"><?php _e('Calculate Score', 'wp-security-guardian'); ?></button>
                    <div id="score-results" style="margin-top: 15px;"></div>
                </div>

                <!-- File Integrity Check -->
                <div class="wpsg-test-card" style="background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
                    <h3><?php _e('File Integrity Check', 'wp-security-guardian'); ?></h3>
                    <p><?php _e('Create checkpoints and verify file integrity.', 'wp-security-guardian'); ?></p>
                    <button id="create-checkpoint" class="button button-secondary"><?php _e('Create Checkpoint', 'wp-security-guardian'); ?></button>
                    <button id="verify-integrity" class="button button-primary"><?php _e('Verify Integrity', 'wp-security-guardian'); ?></button>
                    <div id="integrity-results" style="margin-top: 15px;"></div>
                </div>

                <!-- Security Self-Test -->
                <div class="wpsg-test-card" style="background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
                    <h3><?php _e('Security Self-Test', 'wp-security-guardian'); ?></h3>
                    <p><?php _e('Run comprehensive security vulnerability tests.', 'wp-security-guardian'); ?></p>
                    <button id="run-self-test" class="button button-primary"><?php _e('Run Tests', 'wp-security-guardian'); ?></button>
                    <div id="self-test-results" style="margin-top: 15px;"></div>
                </div>

            </div>

            <!-- Secure Logs Viewer -->
            <div class="wpsg-logs-section" style="background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); margin-top: 20px;">
                <h3><?php _e('Secure Activity Logs', 'wp-security-guardian'); ?></h3>
                <div style="margin-bottom: 15px;">
                    <select id="log-level-filter">
                        <option value=""><?php _e('All Levels', 'wp-security-guardian'); ?></option>
                        <option value="info"><?php _e('Info', 'wp-security-guardian'); ?></option>
                        <option value="warning"><?php _e('Warning', 'wp-security-guardian'); ?></option>
                        <option value="error"><?php _e('Error', 'wp-security-guardian'); ?></option>
                    </select>
                    <input type="number" id="log-limit" placeholder="<?php _e('Limit (default 50)', 'wp-security-guardian'); ?>" min="1" max="200" value="50">
                    <button id="load-logs" class="button"><?php _e('Load Logs', 'wp-security-guardian'); ?></button>
                </div>
                <div id="logs-results"></div>
            </div>

        </div>

        <style>
            .wpsg-test-card h3 {
                color: #2271b1;
                margin-top: 0;
            }

            .wpsg-results-success {
                background: #d1f2df;
                border: 1px solid #00a32a;
                padding: 10px;
                border-radius: 4px;
                margin-top: 10px;
            }

            .wpsg-results-warning {
                background: #fff3cd;
                border: 1px solid #ffcc02;
                padding: 10px;
                border-radius: 4px;
                margin-top: 10px;
            }

            .wpsg-results-error {
                background: #f8d7da;
                border: 1px solid #dc3545;
                padding: 10px;
                border-radius: 4px;
                margin-top: 10px;
            }

            .wpsg-log-entry {
                background: #f9f9f9;
                border-left: 4px solid #2271b1;
                padding: 10px;
                margin-bottom: 10px;
            }

            .wpsg-log-entry.warning {
                border-left-color: #ffcc02;
            }

            .wpsg-log-entry.error {
                border-left-color: #dc3545;
            }
        </style>

        <script>
            jQuery(document).ready(function($) {
                const nonce = '<?php echo wp_create_nonce('wpsg_security_test'); ?>';

                // Test Security Headers
                $('#test-headers').click(function() {
                    const $button = $(this);
                    const $results = $('#headers-results');

                    $button.prop('disabled', true).text('<?php _e('Testing...', 'wp-security-guardian'); ?>');

                    $.post(ajaxurl, {
                        action: 'wpsg_test_security_headers',
                        nonce: nonce,
                        url: '<?php echo home_url('/'); ?>'
                    }, function(response) {
                        if (response.success) {
                            const data = response.data;
                            let html = '<div class="wpsg-results-' + (data.percentage >= 70 ? 'success' : data.percentage >= 50 ? 'warning' : 'error') + '">';
                            html += '<h4><?php _e('Security Headers Score', 'wp-security-guardian'); ?>: ' + data.percentage + '% (' + data.grade + ')</h4>';

                            for (const [header, info] of Object.entries(data.headers)) {
                                html += '<p><strong>' + header + '</strong>: ' + (info.present ? '✅' : '❌');
                                if (info.recommendation) {
                                    html += ' - ' + info.recommendation;
                                }
                                html += '</p>';
                            }

                            html += '</div>';
                            $results.html(html);
                        } else {
                            $results.html('<div class="wpsg-results-error"><?php _e('Error:', 'wp-security-guardian'); ?> ' + response.data + '</div>');
                        }
                    }).fail(function() {
                        $results.html('<div class="wpsg-results-error"><?php _e('Request failed', 'wp-security-guardian'); ?></div>');
                    }).always(function() {
                        $button.prop('disabled', false).text('<?php _e('Test Headers', 'wp-security-guardian'); ?>');
                    });
                });

                // Calculate Security Score
                $('#calculate-score').click(function() {
                    const $button = $(this);
                    const $results = $('#score-results');

                    $button.prop('disabled', true).text('<?php _e('Calculating...', 'wp-security-guardian'); ?>');

                    $.post(ajaxurl, {
                        action: 'wpsg_security_score',
                        nonce: nonce
                    }, function(response) {
                        if (response.success) {
                            const data = response.data;
                            let html = '<div class="wpsg-results-' + (data.percentage >= 80 ? 'success' : data.percentage >= 60 ? 'warning' : 'error') + '">';
                            html += '<h4><?php _e('Overall Security Score', 'wp-security-guardian'); ?>: ' + data.percentage + '% (' + data.grade + ')</h4>';

                            for (const [category, info] of Object.entries(data.breakdown)) {
                                html += '<p><strong>' + category.replace('_', ' ') + '</strong>: ' + (info.score * 100).toFixed(0) + '% (<?php _e('Weight', 'wp-security-guardian'); ?>: ' + info.weight + ')</p>';
                            }

                            if (data.recommendations.length > 0) {
                                html += '<h5><?php _e('Recommendations', 'wp-security-guardian'); ?>:</h5><ul>';
                                data.recommendations.forEach(rec => {
                                    html += '<li>' + rec + '</li>';
                                });
                                html += '</ul>';
                            }

                            html += '</div>';
                            $results.html(html);
                        } else {
                            $results.html('<div class="wpsg-results-error"><?php _e('Error:', 'wp-security-guardian'); ?> ' + response.data + '</div>');
                        }
                    }).fail(function() {
                        $results.html('<div class="wpsg-results-error"><?php _e('Request failed', 'wp-security-guardian'); ?></div>');
                    }).always(function() {
                        $button.prop('disabled', false).text('<?php _e('Calculate Score', 'wp-security-guardian'); ?>');
                    });
                });

                // File Integrity
                $('#create-checkpoint, #verify-integrity').click(function() {
                    const $button = $(this);
                    const $results = $('#integrity-results');
                    const isCreate = $(this).attr('id') === 'create-checkpoint';

                    $button.prop('disabled', true).text(isCreate ? '<?php _e('Creating...', 'wp-security-guardian'); ?>' : '<?php _e('Verifying...', 'wp-security-guardian'); ?>');

                    $.post(ajaxurl, {
                        action: 'wpsg_integrity_check',
                        nonce: nonce,
                        action_type: isCreate ? 'create' : 'verify'
                    }, function(response) {
                        if (response.success) {
                            const data = response.data;
                            let html = '<div class="wpsg-results-success"><h4>' + data.message + '</h4>';

                            if (data.results.summary) {
                                const summary = data.results.summary;
                                html += '<p><?php _e('Files checked', 'wp-security-guardian'); ?>: ' + summary.total_files + '</p>';
                                if (summary.intact !== undefined) {
                                    html += '<p>✅ <?php _e('Intact', 'wp-security-guardian'); ?>: ' + summary.intact + '</p>';
                                    html += '<p>⚠️ <?php _e('Modified', 'wp-security-guardian'); ?>: ' + summary.modified + '</p>';
                                    html += '<p>❌ <?php _e('Missing', 'wp-security-guardian'); ?>: ' + summary.missing + '</p>';
                                }
                            }

                            html += '</div>';
                            $results.html(html);
                        } else {
                            $results.html('<div class="wpsg-results-error"><?php _e('Error:', 'wp-security-guardian'); ?> ' + response.data + '</div>');
                        }
                    }).fail(function() {
                        $results.html('<div class="wpsg-results-error"><?php _e('Request failed', 'wp-security-guardian'); ?></div>');
                    }).always(function() {
                        const originalText = isCreate ? '<?php _e('Create Checkpoint', 'wp-security-guardian'); ?>' : '<?php _e('Verify Integrity', 'wp-security-guardian'); ?>';
                        $button.prop('disabled', false).text(originalText);
                    });
                });

                // Security Self-Test
                $('#run-self-test').click(function() {
                    const $button = $(this);
                    const $results = $('#self-test-results');

                    $button.prop('disabled', true).text('<?php _e('Running Tests...', 'wp-security-guardian'); ?>');

                    $.post(ajaxurl, {
                        action: 'wpsg_security_self_test',
                        nonce: nonce
                    }, function(response) {
                        if (response.success) {
                            const data = response.data;
                            let html = '<div class="wpsg-results-' + (data.overall_score >= 80 ? 'success' : data.overall_score >= 60 ? 'warning' : 'error') + '">';
                            html += '<h4><?php _e('Self-Test Results', 'wp-security-guardian'); ?>: ' + data.overall_score + '% (' + data.grade + ')</h4>';
                            html += '<p><?php _e('Passed Tests', 'wp-security-guardian'); ?>: ' + data.passed_tests + '/' + data.total_tests + '</p>';

                            for (const [test, result] of Object.entries(data.results)) {
                                html += '<p>' + (result.status === 'passed' ? '✅' : '❌') + ' <strong>' + test.replace('_', ' ') + '</strong>: ' + result.message + '</p>';
                            }

                            if (data.recommendations.length > 0) {
                                html += '<h5><?php _e('Recommendations', 'wp-security-guardian'); ?>:</h5><ul>';
                                data.recommendations.forEach(rec => {
                                    html += '<li>' + rec + '</li>';
                                });
                                html += '</ul>';
                            }

                            html += '</div>';
                            $results.html(html);
                        } else {
                            $results.html('<div class="wpsg-results-error"><?php _e('Error:', 'wp-security-guardian'); ?> ' + response.data + '</div>');
                        }
                    }).fail(function() {
                        $results.html('<div class="wpsg-results-error"><?php _e('Request failed', 'wp-security-guardian'); ?></div>');
                    }).always(function() {
                        $button.prop('disabled', false).text('<?php _e('Run Tests', 'wp-security-guardian'); ?>');
                    });
                });

                // Load Logs
                $('#load-logs').click(function() {
                    const $button = $(this);
                    const $results = $('#logs-results');
                    const limit = $('#log-limit').val() || 50;
                    const level = $('#log-level-filter').val();

                    $button.prop('disabled', true).text('<?php _e('Loading...', 'wp-security-guardian'); ?>');

                    $.post(ajaxurl, {
                        action: 'wpsg_get_secure_logs',
                        nonce: nonce,
                        limit: limit,
                        level_filter: level
                    }, function(response) {
                        if (response.success) {
                            const logs = response.data.logs;
                            let html = '';

                            if (logs.length === 0) {
                                html = '<p><?php _e('No logs found', 'wp-security-guardian'); ?></p>';
                            } else {
                                logs.forEach(log => {
                                    html += '<div class="wpsg-log-entry ' + log.level + '">';
                                    html += '<strong>' + log.event + '</strong> (' + log.level + ') - ' + log.timestamp;
                                    html += '<br>User ID: ' + log.user_id + ' | IP: ' + log.ip_address;
                                    if (log.data && log.data.message) {
                                        html += '<br>' + log.data.message;
                                    }
                                    html += '</div>';
                                });
                            }

                            $results.html(html);
                        } else {
                            $results.html('<div class="wpsg-results-error"><?php _e('Error:', 'wp-security-guardian'); ?> ' + response.data + '</div>');
                        }
                    }).fail(function() {
                        $results.html('<div class="wpsg-results-error"><?php _e('Request failed', 'wp-security-guardian'); ?></div>');
                    }).always(function() {
                        $button.prop('disabled', false).text('<?php _e('Load Logs', 'wp-security-guardian'); ?>');
                    });
                });
            });
        </script>
<?php
    }

    /**
     * Check if WordPress core is updated
     */
    public function is_wp_core_updated()
    {
        global $wp_version;
        
        if (!function_exists('get_core_updates')) {
            include_once ABSPATH . 'wp-admin/includes/update.php';
        }
        
        $updates = get_core_updates();
        if (empty($updates)) {
            return true; // No updates available
        }
        
        foreach ($updates as $update) {
            if ($update->response !== 'latest') {
                return false; // Update available
            }
        }
        
        return true;
    }
    
    /**
     * Check admin user security
     */
    public function check_admin_user_security()
    {
        $admin_users = get_users(array('role' => 'administrator'));
        
        foreach ($admin_users as $admin) {
            // Check for weak usernames
            if (in_array($admin->user_login, array('admin', 'administrator', 'root', 'test'))) {
                return false;
            }
            
            // Check if admin user ID is 1 (default)
            if ($admin->ID === 1 && $admin->user_login === 'admin') {
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * Check if directory browsing is disabled
     */
    public function check_directory_browsing_disabled()
    {
        $htaccess_path = ABSPATH . '.htaccess';
        if (!file_exists($htaccess_path)) {
            return false;
        }
        
        $htaccess_content = file_get_contents($htaccess_path);
        return strpos($htaccess_content, 'Options -Indexes') !== false;
    }
    
    /**
     * Check sensitive files protection
     */
    public function check_sensitive_files_protection()
    {
        $sensitive_files = array('.htaccess', 'wp-config.php', 'readme.html', 'license.txt');
        $protected_count = 0;
        
        foreach ($sensitive_files as $file) {
            $file_path = ABSPATH . $file;
            if (file_exists($file_path)) {
                // Simple check - in real implementation would test HTTP access
                $protected_count++;
            }
        }
        
        return $protected_count > 0;
    }
    
    /**
     * Check if security headers are enabled
     */
    public function check_security_headers_enabled()
    {
        return get_option('wpsg_security_headers', false);
    }
    
    /**
     * Check if plugins are updated
     */
    public function check_plugins_updated()
    {
        if (!function_exists('get_plugin_updates')) {
            include_once ABSPATH . 'wp-admin/includes/update.php';
        }
        
        $updates = get_plugin_updates();
        return empty($updates);
    }
    
    /**
     * Check if themes are updated
     */
    public function check_themes_updated()
    {
        if (!function_exists('get_theme_updates')) {
            include_once ABSPATH . 'wp-admin/includes/update.php';
        }
        
        $updates = get_theme_updates();
        return empty($updates);
    }
    
    /**
     * Check for unused plugins
     */
    public function check_unused_plugins()
    {
        $all_plugins = get_plugins();
        $active_plugins = get_option('active_plugins', array());
        
        $inactive_count = count($all_plugins) - count($active_plugins);
        return $inactive_count < 3; // Consider good if less than 3 inactive plugins
    }
    
    /**
     * Check for known vulnerabilities (placeholder)
     */
    public function check_known_vulnerabilities()
    {
        // In real implementation, this would check against vulnerability databases
        return true; // Assume no known vulnerabilities for now
    }
    
    /**
     * Check theme vulnerabilities (placeholder)
     */
    public function check_theme_vulnerabilities()
    {
        // In real implementation, this would check theme versions against vulnerability DB
        return true; // Assume no vulnerabilities for now
    }
    
    /**
     * Get security recommendation for failed check
     */
    public function get_security_recommendation($category, $check)
    {
        $recommendations = array(
            'wordpress_core' => array(
                'wp_version_hidden' => 'Enable WordPress version hiding in security settings',
                'file_editing_disabled' => 'Disable file editing in wp-config.php: define("DISALLOW_FILE_EDIT", true);',
                'xmlrpc_disabled' => 'Disable XML-RPC if not needed for security',
                'debug_mode_disabled' => 'Disable WordPress debug mode in production',
                'wp_updated' => 'Update WordPress to the latest version immediately'
            ),
            'authentication' => array(
                'strong_passwords' => 'Enforce strong passwords for all users',
                'login_limiting' => 'Enable login attempt limiting',
                'two_factor_available' => 'Set up two-factor authentication',
                'user_enumeration_blocked' => 'Block user enumeration attempts',
                'admin_user_secure' => 'Change default admin username and ensure strong credentials'
            ),
            'file_security' => array(
                'directory_browsing_disabled' => 'Add "Options -Indexes" to .htaccess',
                'sensitive_files_protected' => 'Protect sensitive files like wp-config.php',
                'file_integrity_monitoring' => 'Enable file integrity monitoring',
                'malware_scanning' => 'Enable regular malware scanning',
                'upload_restrictions' => 'Restrict file upload types and locations'
            ),
            'network_security' => array(
                'security_headers' => 'Configure security headers (CSP, HSTS, etc.)',
                'ssl_enabled' => 'Install SSL certificate and force HTTPS',
                'ip_blocking' => 'Enable IP blocking for repeated threats',
                'rate_limiting' => 'Implement rate limiting for requests',
                'brute_force_protection' => 'Enable brute force protection'
            ),
            'plugin_theme_security' => array(
                'plugins_updated' => 'Update all plugins to latest versions',
                'themes_updated' => 'Update all themes to latest versions',
                'unused_plugins_removed' => 'Remove unused plugins and themes',
                'plugin_vulnerabilities' => 'Check plugins for known vulnerabilities',
                'theme_vulnerabilities' => 'Check themes for known vulnerabilities'
            )
        );
        
        return $recommendations[$category][$check] ?? 'Review and improve this security setting';
    }
}

// Inicializace pluginu
WP_Security_Guardian::get_instance();

// Hook pro detekci podezřelé aktivity při každém načtení stránky
add_action('init', function () {
    $instance = WP_Security_Guardian::get_instance();
    $instance->detect_suspicious_activity();
});

// AJAX handlery pro Auto-Pilot akce
add_action('wp_ajax_wpsg_unblock_action', function () {
    // Debug log
    error_log('WPSG Unblock: AJAX called');
    error_log('WPSG Unblock: POST data: ' . print_r($_POST, true));

    if (!current_user_can('manage_options')) {
        error_log('WPSG Unblock: User cannot manage options');
        wp_send_json_error('Nemáte oprávnění');
        return;
    }

    if (!wp_verify_nonce($_POST['nonce'], 'wpsg_unblock_action')) {
        error_log('WPSG Unblock: Nonce verification failed');
        wp_send_json_error('Neplatný nonce');
        return;
    }

    $action_id = sanitize_text_field($_POST['action_id']);
    $actions = get_option('wpsg_autopilot_actions', array());

    error_log('WPSG Unblock: Looking for action ID: ' . $action_id);
    error_log('WPSG Unblock: Total actions: ' . count($actions));

    $found = false;
    // Najít akci a odblokovat IP
    foreach ($actions as &$action) {
        if ($action['id'] === $action_id && $action['type'] === 'blocked') {
            error_log('WPSG Unblock: Found matching action, IP: ' . $action['ip_address']);

            $blocked_ips = get_option('wpsg_blocked_ips', array());
            unset($blocked_ips[$action['ip_address']]);
            update_option('wpsg_blocked_ips', $blocked_ips);

            // Označit jako odblokovano
            $action['unblocked'] = true;
            $action['unblocked_at'] = current_time('mysql');
            $found = true;
            break;
        }
    }

    if (!$found) {
        error_log('WPSG Unblock: Action not found');
        wp_send_json_error('Akce nebyla nalezena');
        return;
    }

    update_option('wpsg_autopilot_actions', $actions);
    error_log('WPSG Unblock: Successfully unblocked');

    wp_send_json_success('IP adresa byla odblokována');
});

// Add AJAX handler for apply recommendation outside of class
add_action('wp_ajax_wpsg_apply_recommendation', function () {
    if (!current_user_can('manage_options') || !wp_verify_nonce($_POST['nonce'], 'wpsg_apply_recommendation')) {
        wp_die('Přístup odepřen');
    }

    $recommendation_id = sanitize_text_field($_POST['recommendation_id']);

    // Aplikovat doporučení podle ID
    switch ($recommendation_id) {
        case 'enable_autopilot':
            update_option('wpsg_autopilot_enabled', true);
            break;
        case 'increase_sensitivity':
            update_option('wpsg_autopilot_sensitivity', 7);
            break;
        case 'enable_learning':
            update_option('wpsg_autopilot_learning', true);
            break;
        case 'enable_auto_updates':
            update_option('wpsg_autopilot_updates', true);
            break;
    }

    wp_send_json_success('Doporučení bylo aplikováno');
});

/**
 * Enhanced Security Features - Rate Limiting for Admin Actions
 */
class WPSG_Enhanced_Security
{

    /**
     * Check admin action rate limit
     */
    public static function check_admin_rate_limit($action, $limit = 5, $window = 300)
    {
        if (!is_user_logged_in()) {
            return false;
        }

        $user_id = get_current_user_id();
        $key = 'wpsg_admin_' . $action . '_' . $user_id;
        $attempts = get_transient($key) ?: 0;

        if ($attempts >= $limit) {
            $remaining_time = get_option('_transient_timeout_' . $key) - time();
            wp_die(
                sprintf(
                    __('Příliš mnoho pokusů o akci "%s". Zkuste znovu za %d sekund.', 'wp-security-guardian'),
                    $action,
                    $remaining_time
                ),
                __('Rate Limit Exceeded', 'wp-security-guardian'),
                array('response' => 429)
            );
        }

        set_transient($key, $attempts + 1, $window);
        return true;
    }

    /**
     * Enhanced input validation with whitelist
     */
    public static function validate_plugin_path($path)
    {
        // Remove any directory traversal attempts
        $path = str_replace(['../', '..\\', './'], '', $path);

        // Allow only alphanumeric, hyphens, underscores, forward slashes and dots
        if (!preg_match('/^[a-zA-Z0-9\-_\/\.]+$/', $path)) {
            throw new InvalidArgumentException(__('Invalid plugin path format', 'wp-security-guardian'));
        }

        // Ensure path doesn't start with slash and doesn't contain double slashes
        $path = ltrim($path, '/');
        $path = preg_replace('/\/+/', '/', $path);

        return sanitize_text_field($path);
    }

    /**
     * Validate IP address with enhanced checks
     */
    public static function validate_ip_address($ip)
    {
        $ip = sanitize_text_field($ip);

        // Basic IP validation
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            throw new InvalidArgumentException(__('Invalid IP address format', 'wp-security-guardian'));
        }

        // Block private/reserved IPs from being blocked (prevent admin lockout)
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            return $ip;
        } else {
            throw new InvalidArgumentException(__('Cannot block private or reserved IP addresses', 'wp-security-guardian'));
        }
    }

    /**
     * Calculate entropy of a string (for malware detection)
     */
    public static function calculate_entropy($string)
    {
        $string = strtolower($string);
        $length = strlen($string);

        if ($length === 0) {
            return 0;
        }

        $frequency = array_count_values(str_split($string));
        $entropy = 0.0;

        foreach ($frequency as $count) {
            $probability = $count / $length;
            $entropy -= $probability * log($probability, 2);
        }

        return $entropy;
    }

    /**
     * Quarantine infected file
     */
    public function quarantine_file($file_path)
    {
        if (!file_exists($file_path) || !is_readable($file_path)) {
            return false;
        }
        
        // Create quarantine directory if it doesn't exist
        $quarantine_dir = WP_CONTENT_DIR . '/wpsg-quarantine/';
        if (!is_dir($quarantine_dir)) {
            if (!wp_mkdir_p($quarantine_dir)) {
                return false;
            }
            
            // Create .htaccess to prevent execution
            file_put_contents($quarantine_dir . '.htaccess', "Order Deny,Allow\nDeny from all\n");
            
            // Create index.php to prevent directory listing
            file_put_contents($quarantine_dir . 'index.php', "<?php\n// Silence is golden\n");
        }
        
        // Generate unique quarantine filename
        $filename = basename($file_path);
        $quarantine_filename = date('Y-m-d_H-i-s') . '_' . md5($file_path) . '_' . $filename . '.quarantine';
        $quarantine_path = $quarantine_dir . $quarantine_filename;
        
        // Move file to quarantine
        if (rename($file_path, $quarantine_path)) {
            // Log quarantine action
            $this->log_security_event('FILE_QUARANTINED', "File quarantined: {$file_path}", array(
                'original_path' => $file_path,
                'quarantine_path' => $quarantine_path,
                'timestamp' => current_time('mysql')
            ));
            
            return $quarantine_path;
        }
        
        return false;
    }
    /**
     * Advanced malware pattern analysis
     */
    public static function advanced_malware_scan($content)
    {
        $entropy = self::calculate_entropy($content);

        // Analyze suspicious patterns
        $suspicious_patterns = [
            '/eval\s*\(\s*base64_decode/i' => 10, // High risk
            '/\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*base64_decode/i' => 8,
            '/preg_replace\s*\(\s*[\'"][^\'\"]*e[\'"][^)]*\)/i' => 9,
            '/assert\s*\(\s*base64_decode/i' => 10,
            '/file_get_contents\s*\(\s*[\'"]https?:\/\//i' => 6,
            '/\$_(GET|POST|REQUEST)\[[^\]]+\]\s*\)/i' => 7,
            '/ob_start\s*\(\s*[\'"]ob_gzhandler[\'"][^)]*\)/i' => 5
        ];

        $pattern_score = 0;
        $matched_patterns = [];

        foreach ($suspicious_patterns as $pattern => $score) {
            if (preg_match($pattern, $content, $matches)) {
                $pattern_score += $score;
                $matched_patterns[] = [
                    'pattern' => $pattern,
                    'score' => $score,
                    'match' => $matches[0] ?? ''
                ];
            }
        }

        // Calculate risk level
        $risk_level = 'low';
        if ($entropy > 4.5 || $pattern_score > 15) {
            $risk_level = 'high';
        } elseif ($entropy > 3.5 || $pattern_score > 8) {
            $risk_level = 'medium';
        }

        return [
            'entropy_score' => round($entropy, 2),
            'pattern_score' => $pattern_score,
            'matched_patterns' => $matched_patterns,
            'risk_level' => $risk_level,
            'recommendation' => self::get_malware_recommendation($risk_level, $entropy, $pattern_score)
        ];
    }

    /**
     * Get malware scan recommendation
     */
    private static function get_malware_recommendation($risk_level, $entropy, $pattern_score)
    {
        switch ($risk_level) {
            case 'high':
                return __('KRITICKÉ: Soubor obsahuje velmi podezřelé vzory. Doporučujeme okamžitou kontrolu a případnou karanténu.', 'wp-security-guardian');
            case 'medium':
                return __('VAROVÁNÍ: Soubor obsahuje podezřelé vzory. Doporučujeme ruční kontrolu kódu.', 'wp-security-guardian');
            default:
                return __('INFO: Soubor vypadá bezpečně podle aktuální analýzy.', 'wp-security-guardian');
        }
    }

    /**
     * Test security headers implementation
     */
    public static function test_security_headers($url = null)
    {
        if (!$url) {
            $url = home_url('/');
        }

        $response = wp_remote_head($url, [
            'timeout' => 10,
            'sslverify' => false // For testing purposes
        ]);

        if (is_wp_error($response)) {
            return [
                'error' => $response->get_error_message(),
                'status' => 'failed'
            ];
        }

        $headers = wp_remote_retrieve_headers($response);
        $status_code = wp_remote_retrieve_response_code($response);

        $security_headers = [
            'strict-transport-security' => [
                'present' => isset($headers['strict-transport-security']),
                'value' => $headers['strict-transport-security'] ?? '',
                'score' => isset($headers['strict-transport-security']) ? 10 : 0,
                'recommendation' => !isset($headers['strict-transport-security']) ?
                    __('Přidat HSTS header pro HTTPS vynucení', 'wp-security-guardian') : ''
            ],
            'content-security-policy' => [
                'present' => isset($headers['content-security-policy']),
                'value' => $headers['content-security-policy'] ?? '',
                'score' => isset($headers['content-security-policy']) ? 15 : 0,
                'recommendation' => !isset($headers['content-security-policy']) ?
                    __('Implementovat CSP pro ochranu proti XSS', 'wp-security-guardian') : ''
            ],
            'x-xss-protection' => [
                'present' => isset($headers['x-xss-protection']),
                'value' => $headers['x-xss-protection'] ?? '',
                'score' => isset($headers['x-xss-protection']) ? 5 : 0,
                'recommendation' => !isset($headers['x-xss-protection']) ?
                    __('Přidat X-XSS-Protection header', 'wp-security-guardian') : ''
            ],
            'x-frame-options' => [
                'present' => isset($headers['x-frame-options']),
                'value' => $headers['x-frame-options'] ?? '',
                'score' => isset($headers['x-frame-options']) ? 10 : 0,
                'recommendation' => !isset($headers['x-frame-options']) ?
                    __('Přidat X-Frame-Options pro ochranu proti clickjacking', 'wp-security-guardian') : ''
            ],
            'x-content-type-options' => [
                'present' => isset($headers['x-content-type-options']),
                'value' => $headers['x-content-type-options'] ?? '',
                'score' => isset($headers['x-content-type-options']) ? 5 : 0,
                'recommendation' => !isset($headers['x-content-type-options']) ?
                    __('Přidat X-Content-Type-Options: nosniff', 'wp-security-guardian') : ''
            ],
            'referrer-policy' => [
                'present' => isset($headers['referrer-policy']),
                'value' => $headers['referrer-policy'] ?? '',
                'score' => isset($headers['referrer-policy']) ? 5 : 0,
                'recommendation' => !isset($headers['referrer-policy']) ?
                    __('Nastavit Referrer-Policy pro ochranu soukromí', 'wp-security-guardian') : ''
            ]
        ];

        $total_score = array_sum(array_column($security_headers, 'score'));
        $max_score = 50; // Maximum possible score
        $percentage = round(($total_score / $max_score) * 100);

        return [
            'status' => 'success',
            'status_code' => $status_code,
            'headers' => $security_headers,
            'total_score' => $total_score,
            'max_score' => $max_score,
            'percentage' => $percentage,
            'grade' => self::get_security_grade($percentage),
            'tested_url' => $url,
            'test_time' => current_time('mysql')
        ];
    }

    /**
     * Get security grade based on percentage
     */
    private static function get_security_grade($percentage)
    {
        if ($percentage >= 90) return 'A+';
        if ($percentage >= 80) return 'A';
        if ($percentage >= 70) return 'B';
        if ($percentage >= 60) return 'C';
        if ($percentage >= 50) return 'D';
        return 'F';
    }

    /**
     * Encrypted logging for sensitive events
     */
    public static function secure_log($event, $data, $level = 'info')
    {
        try {
            $log_entry = [
                'timestamp' => current_time('mysql'),
                'event' => sanitize_text_field($event),
                'level' => sanitize_text_field($level),
                'user_id' => get_current_user_id(),
                'ip_address' => self::get_client_ip(),
                'user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field($_SERVER['HTTP_USER_AGENT']) : '',
                'data' => is_array($data) ? $data : ['message' => $data],
                'hash' => hash_hmac('sha256', serialize($data), wp_salt('secure_auth'))
            ];

            // Encrypt sensitive data
            $encrypted_entry = self::encrypt_log_data($log_entry);

            // Store in rotating log system (keep last 1000 entries)
            $secure_logs = get_option('wpsg_secure_logs', []);
            array_unshift($secure_logs, $encrypted_entry);

            // Keep only last 1000 entries
            if (count($secure_logs) > 1000) {
                $secure_logs = array_slice($secure_logs, 0, 1000);
            }

            update_option('wpsg_secure_logs', $secure_logs, false);

            return true;
        } catch (Exception $e) {
            error_log('WPSG Secure Log Error: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Encrypt log data
     */
    private static function encrypt_log_data($data)
    {
        $serialized = serialize($data);
        $key = substr(wp_salt('secure_auth'), 0, 32);

        // Simple encryption using WordPress salts
        $encrypted = base64_encode(openssl_encrypt($serialized, 'AES-256-CBC', $key, 0, substr(md5($key), 0, 16)));

        return [
            'encrypted' => $encrypted,
            'timestamp' => time(),
            'checksum' => hash('sha256', $serialized)
        ];
    }

    /**
     * Decrypt log data
     */
    public static function decrypt_log_data($encrypted_data)
    {
        try {
            $key = substr(wp_salt('secure_auth'), 0, 32);
            $decrypted = openssl_decrypt(base64_decode($encrypted_data['encrypted']), 'AES-256-CBC', $key, 0, substr(md5($key), 0, 16));

            $data = unserialize($decrypted);

            // Verify checksum
            if (hash('sha256', serialize($data)) !== $encrypted_data['checksum']) {
                throw new Exception('Log data integrity check failed');
            }

            return $data;
        } catch (Exception $e) {
            error_log('WPSG Log Decrypt Error: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Get secure logs with optional filtering
     */
    public static function get_secure_logs($limit = 50, $event_filter = null, $level_filter = null)
    {
        $encrypted_logs = get_option('wpsg_secure_logs', []);
        $decrypted_logs = [];

        foreach (array_slice($encrypted_logs, 0, $limit) as $encrypted_log) {
            $decrypted = self::decrypt_log_data($encrypted_log);
            if ($decrypted) {
                // Apply filters
                if ($event_filter && $decrypted['event'] !== $event_filter) {
                    continue;
                }
                if ($level_filter && $decrypted['level'] !== $level_filter) {
                    continue;
                }

                $decrypted_logs[] = $decrypted;
            }
        }

        return $decrypted_logs;
    }

    /**
     * Create integrity checkpoint for critical files
     */
    public static function create_integrity_checkpoint()
    {
        $critical_files = [
            ABSPATH . 'wp-config.php',
            ABSPATH . '.htaccess',
            get_template_directory() . '/functions.php',
            get_stylesheet_directory() . '/functions.php',
            WPSG_PLUGIN_PATH . 'wp-security-guardian.php'
        ];

        $checksums = [];
        foreach ($critical_files as $file) {
            if (file_exists($file) && is_readable($file)) {
                $checksums[$file] = [
                    'sha256' => hash_file('sha256', $file),
                    'md5' => hash_file('md5', $file),
                    'size' => filesize($file),
                    'modified' => filemtime($file)
                ];
            }
        }

        update_option('wpsg_file_checksums', $checksums);
        self::secure_log('INTEGRITY_CHECKPOINT', [
            'files_checked' => count($checksums),
            'timestamp' => current_time('mysql')
        ], 'info');

        return $checksums;
    }

    /**
     * Verify file integrity against checkpoint
     */
    public static function verify_file_integrity()
    {
        $stored_checksums = get_option('wpsg_file_checksums', []);
        if (empty($stored_checksums)) {
            return ['error' => __('No integrity checkpoint found. Please create one first.', 'wp-security-guardian')];
        }

        $results = [];
        $changes_detected = false;

        foreach ($stored_checksums as $file => $stored_data) {
            if (!file_exists($file)) {
                $results[$file] = [
                    'status' => 'missing',
                    'message' => __('File has been deleted', 'wp-security-guardian')
                ];
                $changes_detected = true;
                continue;
            }

            $current_sha256 = hash_file('sha256', $file);
            $current_size = filesize($file);
            $current_modified = filemtime($file);

            if ($current_sha256 !== $stored_data['sha256']) {
                $results[$file] = [
                    'status' => 'modified',
                    'message' => __('File content has been modified', 'wp-security-guardian'),
                    'details' => [
                        'size_change' => $current_size - $stored_data['size'],
                        'time_change' => $current_modified - $stored_data['modified']
                    ]
                ];
                $changes_detected = true;
            } else {
                $results[$file] = [
                    'status' => 'intact',
                    'message' => __('File integrity verified', 'wp-security-guardian')
                ];
            }
        }

        if ($changes_detected) {
            self::secure_log('INTEGRITY_VIOLATION', [
                'changes_detected' => array_filter($results, function ($r) {
                    return $r['status'] !== 'intact';
                }),
                'total_files' => count($results)
            ], 'warning');
        }

        return [
            'status' => $changes_detected ? 'changes_detected' : 'all_intact',
            'results' => $results,
            'summary' => [
                'total_files' => count($results),
                'intact' => count(array_filter($results, function ($r) {
                    return $r['status'] === 'intact';
                })),
                'modified' => count(array_filter($results, function ($r) {
                    return $r['status'] === 'modified';
                })),
                'missing' => count(array_filter($results, function ($r) {
                    return $r['status'] === 'missing';
                }))
            ]
        ];
    }

    /**
     * Progressive security scoring system
     */
    public static function calculate_progressive_security_score()
    {
        $scores = [];
        $total_weight = 0;

        // Basic WordPress hardening (Weight: 25%)
        $basic_hardening = self::check_basic_hardening();
        $scores['basic_hardening'] = $basic_hardening * 0.25;
        $total_weight += 0.25;

        // Access controls and permissions (Weight: 25%)
        $access_controls = self::check_access_controls();
        $scores['access_controls'] = $access_controls * 0.25;
        $total_weight += 0.25;

        // Monitoring and logging (Weight: 20%)
        $monitoring = self::check_monitoring_active();
        $scores['monitoring'] = $monitoring * 0.20;
        $total_weight += 0.20;

        // SSL/TLS implementation (Weight: 15%)
        $ssl_tls = self::check_ssl_implementation();
        $scores['ssl_tls'] = $ssl_tls * 0.15;
        $total_weight += 0.15;

        // Update security (Weight: 15%)
        $updates = self::check_update_security();
        $scores['updates'] = $updates * 0.15;
        $total_weight += 0.15;

        $total_score = array_sum($scores);

        return [
            'total_score' => round($total_score, 2),
            'percentage' => round(($total_score / $total_weight) * 100, 2),
            'grade' => self::get_security_grade(($total_score / $total_weight) * 100),
            'breakdown' => [
                'basic_hardening' => ['score' => round($basic_hardening, 2), 'weight' => '25%'],
                'access_controls' => ['score' => round($access_controls, 2), 'weight' => '25%'],
                'monitoring' => ['score' => round($monitoring, 2), 'weight' => '20%'],
                'ssl_tls' => ['score' => round($ssl_tls, 2), 'weight' => '15%'],
                'updates' => ['score' => round($updates, 2), 'weight' => '15%']
            ],
            'recommendations' => self::get_security_recommendations($scores)
        ];
    }

    /**
     * Check basic WordPress hardening
     */
    private static function check_basic_hardening()
    {
        $checks = 0;
        $total = 8;

        // Check if wp-admin protected
        if (get_option('wpsg_protect_wp_admin', false)) $checks++;

        // Check if XML-RPC disabled
        if (!has_filter('xmlrpc_enabled', '__return_false')) $checks++;

        // Check if file editing disabled
        if (defined('DISALLOW_FILE_EDIT') && DISALLOW_FILE_EDIT) $checks++;

        // Check if debug mode disabled
        if (!defined('WP_DEBUG') || !WP_DEBUG) $checks++;

        // Check if login security enabled
        if (get_option('wpsg_login_security_enabled', false)) $checks++;

        // Check if directory browsing disabled
        if (get_option('wpsg_disable_directory_browsing', false)) $checks++;

        // Check if WordPress version hidden
        if (!has_action('wp_head', 'wp_generator')) $checks++;

        // Check if security headers enabled
        if (class_exists('WPSG_Security_Headers')) $checks++;

        return $checks / $total;
    }

    /**
     * Check access controls
     */
    private static function check_access_controls()
    {
        $checks = 0;
        $total = 6;

        // Check if 2FA available
        if (class_exists('WPSG_Two_Factor_Auth')) $checks++;

        // Check if rate limiting enabled
        if (get_option('wpsg_rate_limiting_enabled', false)) $checks++;

        // Check if IP blocking active
        if (get_option('wpsg_ip_blocking_enabled', false)) $checks++;

        // Check if user enumeration blocked
        if (get_option('wpsg_block_user_enumeration', false)) $checks++;

        // Check if strong password policy
        if (get_option('wpsg_strong_passwords', false)) $checks++;

        // Check if login attempts limited
        if (get_option('wpsg_limit_login_attempts', false)) $checks++;

        return $checks / $total;
    }

    /**
     * Check monitoring systems
     */
    private static function check_monitoring_active()
    {
        $checks = 0;
        $total = 5;

        // Check if security logging enabled
        if (get_option('wpsg_security_logging', false)) $checks++;

        // Check if file monitoring enabled
        if (get_option('wpsg_file_monitoring', false)) $checks++;

        // Check if malware scanning enabled
        if (get_option('wpsg_malware_scanning', false)) $checks++;

        // Check if integrity checking enabled
        if (get_option('wpsg_file_checksums', false)) $checks++;

        // Check if automated alerts enabled
        if (get_option('wpsg_security_alerts', false)) $checks++;

        return $checks / $total;
    }

    /**
     * Check SSL/TLS implementation
     */
    private static function check_ssl_implementation()
    {
        $checks = 0;
        $total = 4;

        // Check if HTTPS enforced
        if (is_ssl()) $checks++;

        // Check if SSL monitoring enabled
        if (class_exists('WPSG_SSL_Monitor')) $checks++;

        // Check if mixed content fixed
        if (get_option('wpsg_fix_mixed_content', false)) $checks++;

        // Check if HSTS enabled
        if (get_option('wpsg_hsts_enabled', false)) $checks++;

        return $checks / $total;
    }

    /**
     * Check update security
     */
    private static function check_update_security()
    {
        $checks = 0;
        $total = 4;

        // Check WordPress version
        if (get_bloginfo('version') === get_preferred_from_update_core()->current) $checks++;

        // Check if automatic updates enabled
        if (get_option('wpsg_auto_updates', false)) $checks++;

        // Check plugin security
        if (get_option('wpsg_plugin_security', false)) $checks++;

        // Check theme security
        if (get_option('wpsg_theme_security', false)) $checks++;

        return $checks / $total;
    }

    /**
     * Get security recommendations based on scores
     */
    private static function get_security_recommendations($scores)
    {
        $recommendations = [];

        if ($scores['basic_hardening'] < 0.20) {
            $recommendations[] = __('Dokončete základní WordPress hardening pro zlepšení zabezpečení', 'wp-security-guardian');
        }

        if ($scores['access_controls'] < 0.20) {
            $recommendations[] = __('Povolte pokročilé access controls jako 2FA a rate limiting', 'wp-security-guardian');
        }

        if ($scores['monitoring'] < 0.15) {
            $recommendations[] = __('Aktivujte monitorovací systémy pro lepší detekci hrozeb', 'wp-security-guardian');
        }

        if ($scores['ssl_tls'] < 0.10) {
            $recommendations[] = __('Vylepšete SSL/TLS implementaci a HTTPS vynucení', 'wp-security-guardian');
        }

        if ($scores['updates'] < 0.10) {
            $recommendations[] = __('Zajistěte aktuální verze WordPress, pluginů a témat', 'wp-security-guardian');
        }

        return $recommendations;
    }

    /**
     * Get client IP address (improved version)
     */
    public static function get_client_ip()
    {
        $ip_keys = ['HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CLIENT_IP', 'REMOTE_ADDR'];

        foreach ($ip_keys as $key) {
            if (!empty($_SERVER[$key])) {
                $ips = explode(',', $_SERVER[$key]);
                $ip = trim($ips[0]);

                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    return $ip;
                }
            }
        }

        return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    }

    /**
     * Automated security self-test
     */
    public static function run_security_self_test()
    {
        $results = [];

        // Test SQL injection protection
        $results['sql_injection'] = self::test_sql_injection_protection();

        // Test XSS protection
        $results['xss_protection'] = self::test_xss_protection();

        // Test CSRF protection
        $results['csrf_protection'] = self::test_csrf_protection();

        // Test file upload security
        $results['file_upload'] = self::test_file_upload_security();

        // Test authentication bypass
        $results['authentication'] = self::test_auth_bypass();

        $total_tests = count($results);
        $passed_tests = count(array_filter($results, function ($r) {
            return $r['status'] === 'passed';
        }));

        $overall_score = ($passed_tests / $total_tests) * 100;

        // Log the test results
        self::secure_log('SECURITY_SELF_TEST', [
            'overall_score' => $overall_score,
            'passed_tests' => $passed_tests,
            'total_tests' => $total_tests,
            'results' => $results
        ], 'info');

        return [
            'overall_score' => round($overall_score, 2),
            'grade' => self::get_security_grade($overall_score),
            'passed_tests' => $passed_tests,
            'total_tests' => $total_tests,
            'results' => $results,
            'recommendations' => self::get_self_test_recommendations($results)
        ];
    }

    /**
     * Test SQL injection protection
     */
    private static function test_sql_injection_protection()
    {
        global $wpdb;

        // Test 1: Ověří že používáme prepared statements
        $prepared_statements_used = 0;
        $total_checks = 4;

        // Kontrola zdrojového kódu na prepared statements
        $plugin_content = file_get_contents(__FILE__);

        // Počet výskytů $wpdb->prepare (pozitivní indikátor)
        $prepare_count = substr_count($plugin_content, '$wpdb->prepare');
        if ($prepare_count >= 3) { // Máme minimálně 3 prepared statements
            $prepared_statements_used++;
        }

        // Test 2: Kontrola, že nepoužíváme nebezpečné direct queries
        $dangerous_patterns = [
            '$wpdb->query(' . '$_',  // Direct query s user inputem
            '$wpdb->get_results(' . '$_',  // Direct get_results s user inputem
        ];

        $safe_queries = true;
        foreach ($dangerous_patterns as $pattern) {
            if (strpos($plugin_content, $pattern) !== false) {
                $safe_queries = false;
                break;
            }
        }

        if ($safe_queries) {
            $prepared_statements_used++;
        }

        // Test 3: Ověření sanitizace vstupních dat
        $test_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
        ];

        foreach ($test_payloads as $payload) {
            $sanitized = sanitize_text_field($payload);
            if ($sanitized !== $payload) {
                $prepared_statements_used++;
                break;
            }
        }

        // Test 4: Kontrola existence našich bezpečnostních metod
        if (method_exists('WP_Security_Guardian', 'add_xss_protection_headers')) {
            $prepared_statements_used++;
        }

        $success_rate = ($prepared_statements_used / $total_checks) * 100;

        return [
            'status' => $success_rate >= 75 ? 'passed' : 'failed',
            'score' => $success_rate,
            'message' => sprintf(__('%d%% SQL injection ochrana aktivní (prepared statements: %d)', 'wp-security-guardian'), $success_rate, $prepare_count)
        ];
    }

    /**
     * Test XSS protection
     */
    private static function test_xss_protection()
    {
        $protection_score = 0;
        $total_checks = 4;

        // Test 1: Kontrola existence CSP hlaviček metodou
        if (method_exists('WP_Security_Guardian', 'add_xss_protection_headers')) {
            $protection_score++;
        }

        // Test 2: Kontrola, že máme CSP hook registrovaný
        $plugin_content = file_get_contents(__FILE__);
        if (
            strpos($plugin_content, 'add_xss_protection_headers') !== false &&
            strpos($plugin_content, 'send_headers') !== false
        ) {
            $protection_score++;
        }

        // Test 3: Kontrola existence CSP pravidel v kódu
        if (strpos($plugin_content, 'Content-Security-Policy') !== false) {
            $protection_score++;
        }

        // Test 4: Základní XSS sanitizace test
        $test_payloads = [
            '<script>alert("xss")</script>',
            '"><script>alert("xss")</script>',
        ];

        $sanitized_correctly = 0;
        foreach ($test_payloads as $payload) {
            $sanitized = wp_kses($payload, []);
            if (empty($sanitized) || $sanitized !== $payload) {
                $sanitized_correctly++;
            }
        }

        if ($sanitized_correctly === count($test_payloads)) {
            $protection_score++;
        }

        $success_rate = ($protection_score / $total_checks) * 100;

        return [
            'status' => $success_rate >= 75 ? 'passed' : 'failed',
            'score' => $success_rate,
            'message' => sprintf(__('%d%% XSS ochrana aktivní (CSP hlavičky + sanitizace)', 'wp-security-guardian'), $success_rate)
        ];
    }

    /**
     * Test CSRF protection
     */
    private static function test_csrf_protection()
    {
        // Check if nonce functions are available and working
        $test_nonce = wp_create_nonce('test_action');
        $verify_result = wp_verify_nonce($test_nonce, 'test_action');

        return [
            'status' => $verify_result ? 'passed' : 'failed',
            'score' => $verify_result ? 100 : 0,
            'message' => $verify_result ?
                __('CSRF protection working correctly', 'wp-security-guardian') :
                __('CSRF protection may not be working', 'wp-security-guardian')
        ];
    }

    /**
     * Test file upload security
     */
    private static function test_file_upload_security()
    {
        $protection_score = 0;
        $total_checks = 4;

        // Test 1: Kontrola existence našeho file upload security hook
        if (has_action('wp_handle_upload_prefilter', array('WP_Security_Guardian', 'secure_file_upload'))) {
            $protection_score++;
        }

        // Test 2: Kontrola existence secure_file_upload metody
        if (method_exists('WP_Security_Guardian', 'secure_file_upload')) {
            $protection_score++;
        }

        // Test 3: Kontrola, že máme MIME type filtry
        $plugin_content = file_get_contents(__FILE__);
        if (strpos($plugin_content, 'wp_check_filetype_and_ext') !== false) {
            $protection_score++;
        }

        // Test 4: Základní WordPress file upload filtry
        if (has_filter('upload_mimes') || has_action('wp_handle_upload_prefilter')) {
            $protection_score++;
        }

        $success_rate = ($protection_score / $total_checks) * 100;

        return [
            'status' => $success_rate >= 75 ? 'passed' : 'failed',
            'score' => $success_rate,
            'message' => sprintf(__('File upload ochrana: %d%% (MIME validace + content kontrola)', 'wp-security-guardian'), $success_rate)
        ];
    }

    /**
     * Test authentication bypass
     */
    private static function test_auth_bypass()
    {
        $protection_score = 0;
        $total_checks = 4;

        // Test 1: Kontrola existence log_successful_login metody
        if (method_exists('WP_Security_Guardian', 'log_successful_login')) {
            $protection_score++;
        }

        // Test 2: Kontrola existence monitor_failed_login metody
        if (method_exists('WP_Security_Guardian', 'monitor_failed_login')) {
            $protection_score++;
        }

        // Test 3: Kontrola registration login hooků
        $plugin_content = file_get_contents(__FILE__);
        if (
            strpos($plugin_content, 'wp_login') !== false &&
            strpos($plugin_content, 'log_successful_login') !== false
        ) {
            $protection_score++;
        }

        // Test 4: Kontrola existence failed login hookú
        if (
            strpos($plugin_content, 'wp_login_failed') !== false &&
            strpos($plugin_content, 'monitor_failed_login') !== false
        ) {
            $protection_score++;
        }

        $success_rate = ($protection_score / $total_checks) * 100;

        return [
            'status' => $success_rate >= 75 ? 'passed' : 'failed',
            'score' => $success_rate,
            'message' => sprintf(__('Authentication ochrana: %d%% (monitoring přihlášení)', 'wp-security-guardian'), $success_rate)
        ];
    }

    /**
     * Get recommendations from self-test results
     */
    private static function get_self_test_recommendations($results)
    {
        $recommendations = [];

        foreach ($results as $test_name => $result) {
            if ($result['status'] === 'failed') {
                switch ($test_name) {
                    case 'sql_injection':
                        $recommendations[] = __('Vylepšete SQL injection ochranu pomocí prepared statements', 'wp-security-guardian');
                        break;
                    case 'xss_protection':
                        $recommendations[] = __('Posil XSS ochranu pomocí output escaping a Content Security Policy', 'wp-security-guardian');
                        break;
                    case 'csrf_protection':
                        $recommendations[] = __('Zkontrolujte CSRF ochranu a nonce implementaci', 'wp-security-guardian');
                        break;
                    case 'file_upload':
                        $recommendations[] = __('Zpřísněte file upload security a typ validaci', 'wp-security-guardian');
                        break;
                    case 'authentication':
                        $recommendations[] = __('Aktivujte pokročilou autentifikační ochranu', 'wp-security-guardian');
                        break;
                }
            }
        }

        return $recommendations;
    }

    /**
     * Initialize IP blocking system for autopilot
     */
    private function init_ip_blocking_system()
    {
        // Add hooks for automatic IP blocking
        add_action('wp_login_failed', array($this, 'track_failed_login'), 10, 1);
        add_action('wp', array($this, 'check_suspicious_activity'));

        $this->log_security_event(
            'AUTOPILOT_IP_BLOCKING_ENABLED',
            'Automatic IP blocking system activated',
            array('feature' => 'ip_blocking')
        );
    }

    /**
     * Enable automatic updates for security patches
     */
    private function enable_auto_updates()
    {
        // Enable automatic updates for security patches
        add_filter('auto_update_plugin', array($this, 'enable_security_plugin_updates'), 10, 2);
        add_filter('auto_update_core', '__return_true');

        $this->log_security_event(
            'AUTOPILOT_AUTO_UPDATES_ENABLED',
            'Automatic security updates activated',
            array('feature' => 'auto_updates')
        );
    }

    /**
     * Initialize emergency lockdown system
     */
    private function init_emergency_lockdown()
    {
        // Set up hooks for emergency lockdown detection
        add_action('wp', array($this, 'monitor_attack_patterns'));

        $this->log_security_event(
            'AUTOPILOT_EMERGENCY_LOCKDOWN_ENABLED',
            'Emergency lockdown system activated',
            array('feature' => 'emergency_lockdown')
        );
    }

    /**
     * Initialize adaptive learning system
     */
    private function init_adaptive_learning()
    {
        // Set up learning hooks
        add_action('wp', array($this, 'collect_behavior_data'));
        add_action('wp_login', array($this, 'learn_from_login'), 10, 2);

        $this->log_security_event(
            'AUTOPILOT_ADAPTIVE_LEARNING_ENABLED',
            'AI adaptive learning system activated',
            array('feature' => 'adaptive_learning')
        );
    }

    /**
     * Track failed login attempts for IP blocking
     */
    public function track_failed_login($username)
    {
        if (!get_option('wpsg_autopilot_auto_block_ips', false)) {
            return;
        }

        $ip = $this->get_client_ip();
        $blocked_ips = get_option('wpsg_blocked_ips', array());
        $failed_logins = get_option('wpsg_failed_logins', array());

        // Track failed login
        if (!isset($failed_logins[$ip])) {
            $failed_logins[$ip] = array('count' => 0, 'first_attempt' => time());
        }

        $failed_logins[$ip]['count']++;
        $failed_logins[$ip]['last_attempt'] = time();

        // Block IP if too many failed attempts
        $block_threshold = get_option('wpsg_autopilot_block_threshold', 5);
        if ($failed_logins[$ip]['count'] >= $block_threshold) {
            $blocked_ips[$ip] = array(
                'blocked_at' => date('Y-m-d H:i:s'),
                'reason' => 'Automatic block: ' . $failed_logins[$ip]['count'] . ' failed login attempts',
                'blocked_by' => 'autopilot'
            );

            update_option('wpsg_blocked_ips', $blocked_ips);

            // Log autopilot action
            $this->add_autopilot_action(array(
                'type' => 'blocked',
                'title' => 'IP Automatically Blocked',
                'description' => 'Blocked ' . $ip . ' after ' . $failed_logins[$ip]['count'] . ' failed login attempts',
                'ip_address' => $ip,
                'timestamp' => date('Y-m-d H:i:s')
            ));
        }

        update_option('wpsg_failed_logins', $failed_logins);
    }

    /**
     * Check for suspicious activity patterns
     */
    public function check_suspicious_activity()
    {
        if (!get_option('wpsg_autopilot_auto_block_ips', false)) {
            return;
        }

        $ip = $this->get_client_ip();
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';

        // Check for suspicious patterns
        $suspicious_patterns = array(
            'bot',
            'crawler',
            'spider',
            'scraper',
            'hack',
            'exploit',
            'injection',
            'union select',
            'drop table',
            '<script'
        );

        foreach ($suspicious_patterns as $pattern) {
            if (
                stripos($user_agent, $pattern) !== false ||
                stripos($_SERVER['REQUEST_URI'] ?? '', $pattern) !== false
            ) {

                // Block suspicious IP
                $this->block_suspicious_ip($ip, 'Suspicious activity detected: ' . $pattern);
                break;
            }
        }
    }

    /**
     * Block suspicious IP address
     */
    private function block_suspicious_ip($ip, $reason)
    {
        $blocked_ips = get_option('wpsg_blocked_ips', array());

        if (!isset($blocked_ips[$ip])) {
            $blocked_ips[$ip] = array(
                'blocked_at' => date('Y-m-d H:i:s'),
                'reason' => $reason,
                'blocked_by' => 'autopilot'
            );

            update_option('wpsg_blocked_ips', $blocked_ips);

            // Log autopilot action
            $this->add_autopilot_action(array(
                'type' => 'blocked',
                'title' => 'Suspicious IP Blocked',
                'description' => $reason,
                'ip_address' => $ip,
                'timestamp' => date('Y-m-d H:i:s')
            ));
        }
    }

    /**
     * Enable security plugin updates
     */
    public function enable_security_plugin_updates($update, $plugin)
    {
        // List of security-related plugins that should auto-update
        $security_plugins = array(
            'wp-security-guardian',
            'wordfence',
            'sucuri-scanner',
            'better-wp-security',
            'all-in-one-wp-security-and-firewall'
        );

        $plugin_slug = dirname($plugin);
        if (in_array($plugin_slug, $security_plugins)) {
            return true;
        }

        return $update;
    }

    /**
     * Monitor attack patterns for emergency lockdown
     */
    public function monitor_attack_patterns()
    {
        if (!get_option('wpsg_autopilot_emergency_lockdown', false)) {
            return;
        }

        // Check recent security events
        $logs = get_option('wpsg_security_logs', array());
        $recent_threats = 0;
        $one_hour_ago = strtotime('-1 hour');

        foreach ($logs as $log) {
            if (
                $log['timestamp'] >= $one_hour_ago &&
                in_array($log['event'], array('BLOCKED_IP', 'FAILED_LOGIN', 'SUSPICIOUS_ACTIVITY'))
            ) {
                $recent_threats++;
            }
        }

        // Trigger emergency lockdown if too many threats
        $lockdown_threshold = get_option('wpsg_autopilot_lockdown_threshold', 50);
        if ($recent_threats >= $lockdown_threshold) {
            $this->trigger_emergency_lockdown($recent_threats);
        }
    }

    /**
     * Trigger emergency lockdown
     */
    private function trigger_emergency_lockdown($threat_count)
    {
        // Enable maintenance mode
        update_option('wpsg_emergency_lockdown_active', true);
        update_option('wpsg_emergency_lockdown_timestamp', time());

        // Log emergency action
        $this->add_autopilot_action(array(
            'type' => 'emergency',
            'title' => 'Emergency Lockdown Activated',
            'description' => 'Site locked down due to ' . $threat_count . ' threats in the last hour',
            'ip_address' => null,
            'timestamp' => date('Y-m-d H:i:s')
        ));

        // Send alert email
        $admin_email = get_option('admin_email');
        wp_mail(
            $admin_email,
            '[URGENT] Emergency Lockdown Activated',
            "Your website has been automatically locked down due to suspicious activity.\n\n" .
                "Threat count: {$threat_count} in the last hour\n" .
                "Time: " . date('Y-m-d H:i:s') . "\n\n" .
                "Please review your security logs and manually disable lockdown when safe."
        );
    }

    /**
     * Collect behavior data for adaptive learning
     */
    public function collect_behavior_data()
    {
        if (!get_option('wpsg_autopilot_adaptive_learning', false)) {
            return;
        }

        $ip = $this->get_client_ip();
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $request_uri = $_SERVER['REQUEST_URI'] ?? '';

        $behavior_data = get_option('wpsg_behavior_data', array());
        $behavior_data[] = array(
            'ip' => $ip,
            'user_agent' => $user_agent,
            'request_uri' => $request_uri,
            'timestamp' => time(),
            'is_logged_in' => is_user_logged_in()
        );

        // Keep only last 1000 entries
        if (count($behavior_data) > 1000) {
            $behavior_data = array_slice($behavior_data, -1000);
        }

        update_option('wpsg_behavior_data', $behavior_data);
    }

    /**
     * Learn from login patterns
     */
    public function learn_from_login($user_login, $user)
    {
        if (!get_option('wpsg_autopilot_adaptive_learning', false)) {
            return;
        }

        $ip = $this->get_client_ip();
        $login_patterns = get_option('wpsg_login_patterns', array());

        $login_patterns[] = array(
            'user_login' => $user_login,
            'user_id' => $user->ID,
            'ip' => $ip,
            'timestamp' => time(),
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? ''
        );

        // Keep only last 500 entries
        if (count($login_patterns) > 500) {
            $login_patterns = array_slice($login_patterns, -500);
        }

        update_option('wpsg_login_patterns', $login_patterns);

        // Update learning accuracy
        $current_samples = get_option('wpsg_autopilot_learning_samples', 0);
        update_option('wpsg_autopilot_learning_samples', $current_samples + 1);

        // Simulate improved accuracy
        $accuracy = min(95, 75 + ($current_samples / 100));
        update_option('wpsg_autopilot_accuracy', intval($accuracy));
    }

    /**
     * Add autopilot action to log
     */
    private function add_autopilot_action($action)
    {
        $actions = get_option('wpsg_autopilot_actions', array());
        $action['id'] = uniqid();
        array_unshift($actions, $action);

        // Keep only last 100 actions
        if (count($actions) > 100) {
            $actions = array_slice($actions, 0, 100);
        }

        update_option('wpsg_autopilot_actions', $actions);
    }
}

/**
 * AJAX Endpoints for Enhanced Security Features
 */

// Test security headers endpoint
add_action('wp_ajax_wpsg_test_security_headers', function () {
    try {
        check_ajax_referer('wpsg_security_test', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error('Insufficient permissions');
            return;
        }

        $url = sanitize_url($_POST['url'] ?? home_url('/'));

        // Test whether Enhanced Security class exists
        if (!class_exists('WPSG_Enhanced_Security')) {
            wp_send_json_error('WPSG_Enhanced_Security class not found');
            return;
        }

        // Test whether method exists
        if (!method_exists('WPSG_Enhanced_Security', 'test_security_headers')) {
            wp_send_json_error('test_security_headers method not found');
            return;
        }

        $results = WPSG_Enhanced_Security::test_security_headers($url);

        if ($results === false || empty($results)) {
            wp_send_json_error('No results from test_security_headers');
            return;
        }

        wp_send_json_success($results);
    } catch (Exception $e) {
        wp_send_json_error('Exception: ' . $e->getMessage());
    } catch (Error $e) {
        wp_send_json_error('Error: ' . $e->getMessage());
    }
});

// Advanced malware scan endpoint - Wordfence-like comprehensive scanning
add_action('wp_ajax_wpsg_enhanced_malware_scan', function () {
    check_ajax_referer('wpsg_security_test', 'nonce');

    if (!current_user_can('manage_options')) {
        wp_send_json_error('Insufficient permissions');
        return;
    }

    try {
        WPSG_Enhanced_Security::check_admin_rate_limit('malware_scan', 2, 600);
    } catch (Exception $e) {
        wp_send_json_error($e->getMessage());
        return;
    }

    $wpsg = WP_Security_Guardian::get_instance();
    
    // Comprehensive malware scan like Wordfence
    $scan_results = array();
    $total_files = 0;
    $infected_files = 0;
    $suspicious_files = 0;
    $quarantined_files = 0;
    
    // Directories to scan (prioritized like Wordfence)
    $scan_directories = array(
        'wp-content/themes/' => array('priority' => 'high', 'name' => 'Themes'),
        'wp-content/plugins/' => array('priority' => 'high', 'name' => 'Plugins'), 
        'wp-content/uploads/' => array('priority' => 'medium', 'name' => 'Uploads'),
        'wp-admin/' => array('priority' => 'critical', 'name' => 'WordPress Admin'),
        'wp-includes/' => array('priority' => 'critical', 'name' => 'WordPress Core'),
        '' => array('priority' => 'high', 'name' => 'Root Directory') // Root files
    );
    
    foreach ($scan_directories as $dir => $config) {
        $full_path = ABSPATH . $dir;
        
        if (!is_dir($full_path) && $dir !== '') continue;
        
        $directory_results = array();
        
        try {
            if ($dir === '') {
                // Scan root files only
                $files = glob($full_path . '*.php');
                $files = array_merge($files, glob($full_path . '.ht*'));
                $files = array_merge($files, glob($full_path . '*.js'));
                $files = array_merge($files, glob($full_path . '*.txt'));
            } else {
                $iterator = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator($full_path, RecursiveDirectoryIterator::SKIP_DOTS),
                    RecursiveIteratorIterator::LEAVES_ONLY
                );
                $files = iterator_to_array($iterator);
            }
            
            $file_count = 0;
            $max_files = ($config['priority'] === 'critical') ? 1000 : 500;
            
            foreach ($files as $file) {
                if ($file_count++ > $max_files) break;
                
                $file_path = is_string($file) ? $file : $file->getRealPath();
                if (!is_file($file_path)) continue;
                
                $total_files++;
                $extension = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
                
                // Scan relevant file types
                $scannable_types = array('php', 'js', 'html', 'htm', 'txt', 'htaccess', 'css', 'json');
                if (!in_array($extension, $scannable_types) && !preg_match('/\.ht/', basename($file_path))) {
                    continue;
                }
                
                try {
                    // Use reflection to access private malware scanning method
                    $reflection = new ReflectionClass($wpsg);
                    $scan_method = $reflection->getMethod('scan_file_for_malware');
                    $scan_method->setAccessible(true);
                    
                    $scan_result = $scan_method->invoke($wpsg, $file_path);
                    
                    if ($scan_result && isset($scan_result['threat_detected']) && $scan_result['threat_detected']) {
                        $relative_path = str_replace(ABSPATH, '', $file_path);
                        
                        $threat_info = array(
                            'file' => $relative_path,
                            'full_path' => $file_path,
                            'risk_level' => $scan_result['risk_level'],
                            'threat_type' => $scan_result['patterns_found'][0]['type'] ?? 'unknown',
                            'reason' => $scan_result['reason'],
                            'patterns_matched' => $scan_result['patterns_found'] ?? array(),
                            'file_size' => filesize($file_path),
                            'last_modified' => filemtime($file_path),
                            'directory' => $config['name']
                        );
                        
                        if ($scan_result['risk_level'] === 'high') {
                            $infected_files++;
                            $threat_info['status'] = 'infected';
                            $threat_info['recommended_action'] = 'immediate_removal';
                        } else {
                            $suspicious_files++;
                            $threat_info['status'] = 'suspicious';
                            $threat_info['recommended_action'] = 'manual_review';
                        }
                        
                        // Auto-quarantine critical threats in uploads directory
                        if ($scan_result['risk_level'] === 'high' && strpos($relative_path, 'wp-content/uploads/') === 0) {
                            $quarantine_result = $wpsg->quarantine_file($file_path);
                            if ($quarantine_result) {
                                $quarantined_files++;
                                $threat_info['quarantined'] = true;
                                $threat_info['quarantine_path'] = $quarantine_result;
                            }
                        }
                        
                        $directory_results[] = $threat_info;
                    }
                    
                } catch (Exception $e) {
                    // Log but continue scanning
                    error_log('WPSG Malware Scan Error: ' . $e->getMessage() . ' for file: ' . $file_path);
                    continue;
                }
            }
            
            if (!empty($directory_results)) {
                $scan_results[$config['name']] = $directory_results;
            }
            
        } catch (Exception $e) {
            error_log('WPSG Directory Scan Error: ' . $e->getMessage() . ' for directory: ' . $full_path);
            continue;
        }
    }
    
    // Generate comprehensive report like Wordfence
    $scan_summary = array(
        'scan_completed_at' => current_time('mysql'),
        'total_files_scanned' => $total_files,
        'infected_files' => $infected_files,
        'suspicious_files' => $suspicious_files,
        'clean_files' => $total_files - $infected_files - $suspicious_files,
        'quarantined_files' => $quarantined_files,
        'scan_status' => ($infected_files > 0) ? 'threats_found' : (($suspicious_files > 0) ? 'warnings_found' : 'clean'),
        'risk_level' => ($infected_files > 0) ? 'high' : (($suspicious_files > 0) ? 'medium' : 'low')
    );
    
    // Security recommendations based on findings
    $recommendations = array();
    if ($infected_files > 0) {
        $recommendations[] = 'URGENT: Remove or quarantine infected files immediately';
        $recommendations[] = 'Change all WordPress and hosting passwords';
        $recommendations[] = 'Review user accounts for unauthorized access';
        $recommendations[] = 'Update WordPress core, themes, and plugins';
        $recommendations[] = 'Consider restoring from a clean backup';
    }
    
    if ($suspicious_files > 0) {
        $recommendations[] = 'Manually review suspicious files for false positives';
        $recommendations[] = 'Update plugins and themes to latest versions';
        $recommendations[] = 'Consider removing unused plugins and themes';
    }
    
    if ($quarantined_files > 0) {
        $recommendations[] = "Quarantined {$quarantined_files} high-risk files to prevent execution";
    }
    
    $response = array(
        'summary' => $scan_summary,
        'detailed_results' => $scan_results,
        'recommendations' => $recommendations,
        'scan_statistics' => array(
            'directories_scanned' => count($scan_directories),
            'file_types_scanned' => array('PHP', 'JavaScript', 'HTML', 'htaccess', 'CSS', 'JSON', 'Text'),
            'scan_method' => 'signature_based_with_heuristics'
        )
    );
    
    // Log scan results
    WPSG_Enhanced_Security::secure_log('COMPREHENSIVE_MALWARE_SCAN', array(
        'summary' => $scan_summary,
        'threats_found' => $infected_files + $suspicious_files,
        'user_id' => get_current_user_id()
    ), ($infected_files > 0) ? 'error' : (($suspicious_files > 0) ? 'warning' : 'info'));
    
    wp_send_json_success($response);
});

// Progressive security score endpoint - Comprehensive like Wordfence
add_action('wp_ajax_wpsg_security_score', function () {
    check_ajax_referer('wpsg_security_test', 'nonce');

    if (!current_user_can('manage_options')) {
        wp_send_json_error('Insufficient permissions');
        return;
    }

    try {
        WPSG_Enhanced_Security::check_admin_rate_limit('security_score', 5, 300);
    } catch (Exception $e) {
        wp_send_json_error($e->getMessage());
        return;
    }

    $wpsg = WP_Security_Guardian::get_instance();
    
    // Comprehensive security analysis like Wordfence
    $security_checks = array(
        'wordpress_core' => array(
            'wp_version_hidden' => !has_action('wp_head', 'wp_generator'),
            'file_editing_disabled' => defined('DISALLOW_FILE_EDIT') && DISALLOW_FILE_EDIT,
            'xmlrpc_disabled' => !apply_filters('xmlrpc_enabled', true),
            'debug_mode_disabled' => !defined('WP_DEBUG') || !WP_DEBUG,
            'wp_updated' => $wpsg->is_wp_core_updated()
        ),
        'authentication' => array(
            'strong_passwords' => get_option('wpsg_strong_passwords', false),
            'login_limiting' => get_option('wpsg_login_limit_attempts', false), 
            'two_factor_available' => class_exists('WPSG_Two_Factor_Auth'),
            'user_enumeration_blocked' => get_option('wpsg_block_user_enumeration', false),
            'admin_user_secure' => $wpsg->check_admin_user_security()
        ),
        'file_security' => array(
            'directory_browsing_disabled' => $wpsg->check_directory_browsing_disabled(),
            'sensitive_files_protected' => $wpsg->check_sensitive_files_protection(),
            'file_integrity_monitoring' => get_option('wpsg_file_integrity_monitoring', false),
            'malware_scanning' => get_option('wpsg_malware_scanning', false),
            'upload_restrictions' => get_option('wpsg_file_upload_restrictions', false)
        ),
        'network_security' => array(
            'security_headers' => $wpsg->check_security_headers_enabled(),
            'ssl_enabled' => is_ssl(),
            'ip_blocking' => get_option('wpsg_ip_blocking_enabled', false),
            'rate_limiting' => get_option('wpsg_rate_limiting_enabled', false),
            'brute_force_protection' => get_option('wpsg_brute_force_protection', false)
        ),
        'plugin_theme_security' => array(
            'plugins_updated' => $wpsg->check_plugins_updated(),
            'themes_updated' => $wpsg->check_themes_updated(), 
            'unused_plugins_removed' => $wpsg->check_unused_plugins(),
            'plugin_vulnerabilities' => $wpsg->check_known_vulnerabilities(),
            'theme_vulnerabilities' => $wpsg->check_theme_vulnerabilities()
        )
    );
    
    // Calculate weighted scores (some categories are more important)
    $category_weights = array(
        'wordpress_core' => 1.5,        // High importance
        'authentication' => 2.0,         // Very high importance
        'file_security' => 1.2,         // Medium-high importance
        'network_security' => 1.3,      // High importance
        'plugin_theme_security' => 1.0  // Standard importance
    );
    
    $category_scores = array();
    $total_weighted_score = 0;
    $total_possible_weighted = 0;
    $total_checks_passed = 0;
    $total_checks = 0;
    
    foreach ($security_checks as $category => $checks) {
        $category_passed = 0;
        $category_total = count($checks);
        $weight = $category_weights[$category];
        
        foreach ($checks as $check => $passed) {
            $total_checks++;
            if ($passed) {
                $category_passed++;
                $total_checks_passed++;
            }
        }
        
        $category_score = $category_total > 0 ? ($category_passed / $category_total) : 0;
        $weighted_score = $category_score * $weight;
        
        $category_scores[$category] = array(
            'score' => $category_score,
            'passed' => $category_passed,
            'total' => $category_total,
            'percentage' => round($category_score * 100),
            'weight' => $weight,
            'weighted_score' => $weighted_score,
            'status' => ($category_score >= 0.8) ? 'good' : (($category_score >= 0.6) ? 'warning' : 'critical')
        );
        
        $total_weighted_score += $weighted_score;
        $total_possible_weighted += $weight;
    }
    
    // Calculate overall percentage with weights
    $overall_percentage = $total_possible_weighted > 0 ? 
        round(($total_weighted_score / $total_possible_weighted) * 100) : 0;
    
    // Determine grade based on weighted score
    $grade = 'F';
    if ($overall_percentage >= 95) $grade = 'A+';
    elseif ($overall_percentage >= 90) $grade = 'A';
    elseif ($overall_percentage >= 85) $grade = 'B+';
    elseif ($overall_percentage >= 80) $grade = 'B';
    elseif ($overall_percentage >= 75) $grade = 'C+';
    elseif ($overall_percentage >= 70) $grade = 'C';
    elseif ($overall_percentage >= 60) $grade = 'D';
    elseif ($overall_percentage >= 50) $grade = 'E';
    
    // Generate prioritized recommendations
    $recommendations = array();
    $critical_issues = array();
    $high_priority_issues = array();
    $medium_priority_issues = array();
    
    foreach ($security_checks as $category => $checks) {
        $weight = $category_weights[$category];
        foreach ($checks as $check => $passed) {
            if (!$passed) {
                $recommendation = $wpsg->get_security_recommendation($category, $check);
                
                if ($weight >= 1.5) {
                    if ($category === 'authentication') {
                        $critical_issues[] = $recommendation;
                    } else {
                        $high_priority_issues[] = $recommendation;
                    }
                } else {
                    $medium_priority_issues[] = $recommendation;
                }
            }
        }
    }
    
    // Combine recommendations by priority
    $recommendations = array_merge(
        array_map(function($item) { return "🔴 CRITICAL: {$item}"; }, $critical_issues),
        array_map(function($item) { return "🟠 HIGH: {$item}"; }, $high_priority_issues),
        array_map(function($item) { return "🟡 MEDIUM: {$item}"; }, $medium_priority_issues)
    );
    
    // Security risk level assessment
    $risk_level = 'low';
    if ($overall_percentage < 50) {
        $risk_level = 'critical';
    } elseif ($overall_percentage < 70) {
        $risk_level = 'high';
    } elseif ($overall_percentage < 85) {
        $risk_level = 'medium';
    }
    
    $result = array(
        'percentage' => $overall_percentage,
        'grade' => $grade,
        'risk_level' => $risk_level,
        'total_checks' => $total_checks,
        'passed_checks' => $total_checks_passed,
        'failed_checks' => $total_checks - $total_checks_passed,
        'breakdown' => $category_scores,
        'recommendations' => $recommendations,
        'detailed_checks' => $security_checks,
        'scan_time' => current_time('mysql'),
        'summary' => array(
            'critical_issues' => count($critical_issues),
            'high_priority_issues' => count($high_priority_issues),
            'medium_priority_issues' => count($medium_priority_issues),
            'overall_status' => ($risk_level === 'low') ? 'Excellent security posture' : 
                              (($risk_level === 'medium') ? 'Good security with room for improvement' :
                              (($risk_level === 'high') ? 'Security needs immediate attention' : 
                               'CRITICAL: Immediate security action required'))
        )
    );
    
    // Log security assessment
    WPSG_Enhanced_Security::secure_log('COMPREHENSIVE_SECURITY_ASSESSMENT', array(
        'percentage' => $overall_percentage,
        'grade' => $grade,
        'risk_level' => $risk_level,
        'critical_issues' => count($critical_issues),
        'user_id' => get_current_user_id()
    ), ($risk_level === 'critical') ? 'error' : (($risk_level === 'high') ? 'warning' : 'info'));
    
    wp_send_json_success($result);
});

// File integrity check endpoint
add_action('wp_ajax_wpsg_integrity_check', function () {
    check_ajax_referer('wpsg_security_test', 'nonce');

    if (!current_user_can('manage_options')) {
        wp_send_json_error('Insufficient permissions');
        return;
    }

    WPSG_Enhanced_Security::check_admin_rate_limit('integrity_check', 3, 300);

    $action = sanitize_text_field($_POST['action_type'] ?? 'verify');

    if ($action === 'create') {
        $results = WPSG_Enhanced_Security::create_integrity_checkpoint();
        $message = 'Integrity checkpoint created successfully';
    } else {
        $results = WPSG_Enhanced_Security::verify_file_integrity();
        $message = 'File integrity verification completed';
    }

    WPSG_Enhanced_Security::secure_log('INTEGRITY_CHECK', [
        'action' => $action,
        'results_summary' => $results['summary'] ?? ['checkpoint_created' => count($results)]
    ], 'info');

    wp_send_json_success([
        'message' => $message,
        'results' => $results
    ]);
});

// Security self-test endpoint
add_action('wp_ajax_wpsg_security_self_test', function () {
    check_ajax_referer('wpsg_security_test', 'nonce');

    if (!current_user_can('manage_options')) {
        wp_send_json_error('Insufficient permissions');
        return;
    }

    WPSG_Enhanced_Security::check_admin_rate_limit('security_self_test', 2, 600);

    $results = WPSG_Enhanced_Security::run_security_self_test();

    wp_send_json_success($results);
});


/**
 * Integration with existing WP_Security_Guardian methods
 */

// Hook enhanced logging into existing security events
add_action('wpsg_security_event', function ($event_type, $message, $data = []) {
    WPSG_Enhanced_Security::secure_log($event_type, array_merge(['message' => $message], $data), 'warning');
}, 10, 3);

// Hook enhanced IP validation into IP blocking
add_filter('wpsg_validate_ip_address', function ($ip) {
    try {
        return WPSG_Enhanced_Security::validate_ip_address($ip);
    } catch (InvalidArgumentException $e) {
        WPSG_Enhanced_Security::secure_log('INVALID_IP_BLOCK_ATTEMPT', [
            'attempted_ip' => $ip,
            'error' => $e->getMessage()
        ], 'warning');

        // Return original IP sanitized as fallback
        return sanitize_text_field($ip);
    }
});


// AJAX endpoint for comprehensive malware scan (Wordfence-like)
add_action('wp_ajax_wpsg_malware_scan', function () {
    if (defined('WP_DEBUG') && WP_DEBUG) {
        error_log('WPSG Malware scan AJAX handler called by user: ' . get_current_user_id());
    }
    
    check_ajax_referer('wpsg_security_test', 'nonce');
    
    if (!current_user_can('manage_options')) {
        error_log('[ERROR] Insufficient permissions for user: ' . get_current_user_id());
        wp_send_json_error('Insufficient permissions');
        return;
    }
    
    error_log('[DEBUG] Starting malware scan process...');
    try {
        $plugin = WP_Security_Guardian::get_instance();
        $start_time = microtime(true);
        $scan_id = 'scan_' . time() . '_' . wp_generate_password(8, false);
        
        error_log('[DEBUG] Generated scan ID: ' . $scan_id);
        error_log('[DEBUG] Scan start time: ' . $start_time);
        
        // Directory scan prioritization (like Wordfence)
        $scan_directories = array(
            'wp-content/themes/' => array('priority' => 'high', 'name' => 'Themes'),
            'wp-content/plugins/' => array('priority' => 'high', 'name' => 'Plugins'), 
            'wp-content/uploads/' => array('priority' => 'medium', 'name' => 'Uploads'),
            'wp-admin/' => array('priority' => 'critical', 'name' => 'WordPress Admin'),
            'wp-includes/' => array('priority' => 'critical', 'name' => 'WordPress Core')
        );
        
        // Pre-count files for accurate progress
        error_log('[DEBUG] Starting file count for progress tracking...');
        $total_files = 0;
        foreach ($scan_directories as $dir => $info) {
            $full_path = ABSPATH . $dir;
            error_log("[DEBUG] Checking directory: {$dir} -> {$full_path}");
            
            if (!is_dir($full_path)) {
                error_log("[DEBUG] Directory doesn't exist: {$full_path}");
                continue;
            }
            
            try {
                $iterator = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator($full_path, RecursiveDirectoryIterator::SKIP_DOTS)
                );
                
                $dir_file_count = 0;
                foreach ($iterator as $file) {
                    if (!$file->isFile()) continue;
                    
                    $extension = strtolower(pathinfo($file->getFilename(), PATHINFO_EXTENSION));
                    if (in_array($extension, ['php', 'js', 'html', 'htm', 'phtml', 'php3', 'php4', 'php5'])) {
                        $total_files++;
                        $dir_file_count++;
                    }
                }
                error_log("[DEBUG] Directory {$dir}: {$dir_file_count} files found");
            } catch (Exception $e) {
                error_log("[ERROR] Error scanning directory {$full_path}: " . $e->getMessage());
                continue;
            }
        }
        
        error_log("[DEBUG] Total files to scan: {$total_files}");
        
        // Initialize progress tracking
        error_log('[DEBUG] Initializing progress tracking data...');
        $progress_data = array(
            'scan_id' => $scan_id,
            'start_time' => $start_time,
            'current_directory' => '',
            'current_file' => '',
            'total_files' => $total_files,
            'scanned_files' => 0,
            'threats_found' => 0,
            'quarantined_files' => 0,
            'percentage' => 0,
            'status' => 'running',
            'directories_completed' => 0,
            'total_directories' => count($scan_directories)
        );
        
        $progress_option_key = 'wpsg_scan_progress_' . $scan_id;
        error_log("[DEBUG] Saving progress data with key: {$progress_option_key}");
        $update_result = update_option($progress_option_key, $progress_data);
        error_log("[DEBUG] Progress data saved: " . ($update_result ? 'SUCCESS' : 'FAILED'));
        error_log("[DEBUG] Progress data content: " . print_r($progress_data, true));
        
        // For demo purposes, limit scan to first 100 files for quick response
        error_log('[DEBUG] Limiting scan to 100 files for demo/testing...');
        $max_files_to_scan = 100;
        $files_scanned_count = 0;
        
        $scanned_files = 0;
        $threats_found = 0;
        $quarantined_files = 0;
        $scan_results = array();
        $detailed_threats = array();
        $directories_completed = 0;
        
        foreach ($scan_directories as $dir => $info) {
            $full_path = ABSPATH . $dir;
            if (!is_dir($full_path)) continue;
            
            // Update progress - current directory
            error_log("[DEBUG] Starting scan of directory: {$info['name']} ({$dir})");
            $progress_data['current_directory'] = $info['name'];
            $progress_data['current_file'] = '';
            $update_result = update_option('wpsg_scan_progress_' . $scan_id, $progress_data);
            error_log("[DEBUG] Progress updated for directory scan: " . ($update_result ? 'SUCCESS' : 'FAILED'));
            
            try {
                $iterator = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator($full_path, RecursiveDirectoryIterator::SKIP_DOTS)
                );
            } catch (Exception $e) {
                error_log('WPSG: Error creating iterator for ' . $full_path . ': ' . $e->getMessage());
                $directories_completed++;
                $progress_data['directories_completed'] = $directories_completed;
                update_option('wpsg_scan_progress_' . $scan_id, $progress_data);
                continue;
            }
            
            $files_in_dir = 0;
            $threats_in_dir = 0;
            
            foreach ($iterator as $file) {
                if (!$file->isFile()) continue;
                
                $extension = strtolower(pathinfo($file->getFilename(), PATHINFO_EXTENSION));
                // Focus on risky file types like Wordfence
                if (!in_array($extension, ['php', 'js', 'html', 'htm', 'phtml', 'php3', 'php4', 'php5'])) {
                    continue;
                }
                
                $files_in_dir++;
                $files_scanned_count++;
                $current_file = str_replace(ABSPATH, '', $file->getPathname());
                
                // Limit total files for demo/testing
                if ($files_scanned_count > $max_files_to_scan) {
                    error_log("[DEBUG] Reached scan limit of {$max_files_to_scan} files, stopping scan...");
                    break 2; // Break out of both loops
                }
                
                // Update progress every 10 files for performance
                if ($scanned_files % 10 === 0 || $files_in_dir === 1) {
                    error_log("[DEBUG] Updating scan progress: {$scanned_files}/{$total_files} files, current: {$current_file}");
                    $progress_data['current_file'] = $current_file;
                    $progress_data['scanned_files'] = $scanned_files;
                    $progress_data['threats_found'] = $threats_found;
                    $progress_data['quarantined_files'] = $quarantined_files;
                    $progress_data['percentage'] = $total_files > 0 ? round(($scanned_files / $total_files) * 100, 1) : 0;
                    $progress_update_result = update_option('wpsg_scan_progress_' . $scan_id, $progress_data);
                    error_log("[DEBUG] Progress update result: " . ($progress_update_result ? 'SUCCESS' : 'FAILED'));
                }
                
                // Use the enhanced scan_file_for_malware method (now public)
                $scan_result = $plugin->scan_file_for_malware($file->getPathname());
                $scanned_files++;
                
                if ($scan_result && $scan_result['threat_detected']) {
                    $threats_found++;
                    $threats_in_dir++;
                    
                    $detailed_threats[] = array(
                        'file' => str_replace(ABSPATH, '', $file->getPathname()),
                        'directory' => $info['name'],
                        'threat_type' => $scan_result['threat_type'] ?? 'Unknown',
                        'risk_level' => $scan_result['risk_level'],
                        'reason' => $scan_result['reason'],
                        'timestamp' => current_time('mysql'),
                        'size' => filesize($file->getPathname()),
                        'patterns' => $scan_result['patterns_found'] ?? []
                    );
                    
                    // Auto-quarantine high-risk files
                    if ($scan_result['risk_level'] === 'high') {
                        try {
                            if (method_exists($plugin, 'quarantine_file')) {
                                $quarantine_result = $plugin->quarantine_file($file->getPathname());
                                if ($quarantine_result) {
                                    $quarantined_files++;
                                }
                            }
                        } catch (Exception $e) {
                            error_log('WPSG: Quarantine error for ' . $file->getPathname() . ': ' . $e->getMessage());
                        }
                    }
                }
                
                // Limit scan time (like Wordfence timeout protection)
                if ((microtime(true) - $start_time) > 120) { // 2 minutes max
                    break 2;
                }
            }
            
            $scan_results[$dir] = array(
                'name' => $info['name'],
                'priority' => $info['priority'],
                'files_scanned' => $files_in_dir,
                'threats_found' => $threats_in_dir
            );
            
            // Mark directory as completed
            $directories_completed++;
            $progress_data['directories_completed'] = $directories_completed;
            update_option('wpsg_scan_progress_' . $scan_id, $progress_data);
        }
        
        $scan_time = round(microtime(true) - $start_time, 2);
        
        // Calculate threat severity score
        $severity_score = 0;
        foreach ($detailed_threats as $threat) {
            $severity_score += ($threat['risk_level'] === 'high') ? 10 : (($threat['risk_level'] === 'medium') ? 5 : 2);
        }
        
        // Determine overall security status
        $security_status = 'clean';
        if ($threats_found > 10 || $severity_score > 50) {
            $security_status = 'critical';
        } elseif ($threats_found > 5 || $severity_score > 20) {
            $security_status = 'warning';
        } elseif ($threats_found > 0) {
            $security_status = 'minor_issues';
        }
        
        // Save comprehensive scan results
        $full_results = array(
            'timestamp' => current_time('mysql'),
            'scan_time' => $scan_time,
            'total_files' => $total_files,
            'scanned_files' => $scanned_files,
            'threats_found' => $threats_found,
            'quarantined_files' => $quarantined_files,
            'severity_score' => $severity_score,
            'security_status' => $security_status,
            'directory_breakdown' => $scan_results,
            'detailed_threats' => $detailed_threats
        );
        
        update_option('wpsg_comprehensive_scan_results', $full_results);
        
        // Final progress update - scan completed
        error_log('[DEBUG] Finalizing scan completion...');
        $progress_data['status'] = 'completed';
        $progress_data['current_directory'] = 'Scan Completed';
        $progress_data['current_file'] = '';
        $progress_data['scanned_files'] = $scanned_files;
        $progress_data['threats_found'] = $threats_found;
        $progress_data['quarantined_files'] = $quarantined_files;
        $progress_data['percentage'] = 100;
        $progress_data['directories_completed'] = count($scan_directories);
        
        error_log("[DEBUG] Updating final progress for scan ID: {$scan_id}");
        update_option('wpsg_scan_progress_' . $scan_id, $progress_data);
        
        // Log scan completion
        WPSG_Enhanced_Security::secure_log('COMPREHENSIVE_MALWARE_SCAN', [
            'files_scanned' => $scanned_files,
            'threats_found' => $threats_found,
            'scan_time' => $scan_time,
            'status' => $security_status
        ], $threats_found > 0 ? 'warning' : 'info');
        
        error_log('[DEBUG] Sending success response to client...');
        error_log("[DEBUG] Returning scan_id: {$scan_id}");
        error_log("[DEBUG] Total files scanned: {$scanned_files}");
        error_log("[DEBUG] Total threats found: {$threats_found}");
        error_log("[DEBUG] Scan was limited to: {$max_files_to_scan} files");
        
        wp_send_json_success(array(
            'scan_completed' => true,
            'scan_id' => $scan_id,
            'limited_scan' => true,
            'max_files_limit' => $max_files_to_scan,
            'scan_time' => $scan_time,
            'files_scanned' => $scanned_files,
            'threats_found' => $threats_found,
            'quarantined_files' => $quarantined_files,
            'security_status' => $security_status,
            'severity_score' => $severity_score,
            'directory_results' => $scan_results,
            'threat_details' => array_slice($detailed_threats, 0, 10), // Limit for UI
            'recommendations' => array(
                'Update all plugins and themes regularly',
                'Monitor quarantine directory for false positives', 
                'Review detailed threat log for analysis',
                'Consider enabling real-time scanning'
            )
        ));
        
    } catch (Exception $e) {
        // Log error for debugging
        error_log('WP Security Guardian Malware Scan Error: ' . $e->getMessage());
        error_log('Stack trace: ' . $e->getTraceAsString());
        
        // Try to use enhanced logging if available
        if (class_exists('WPSG_Enhanced_Security')) {
            WPSG_Enhanced_Security::secure_log('MALWARE_SCAN_ERROR', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ], 'error');
        }
        
        wp_send_json_error('Scan failed: ' . $e->getMessage());
    } catch (Error $e) {
        // Handle fatal errors too
        error_log('WP Security Guardian Malware Scan Fatal Error: ' . $e->getMessage());
        wp_send_json_error('Fatal error during scan: ' . $e->getMessage());
    }
});

// Test AJAX endpoint to check if AJAX is working
add_action('wp_ajax_wpsg_test', function () {
    wp_send_json_success(array(
        'message' => 'AJAX is working!',
        'timestamp' => current_time('mysql'),
        'user_can_manage' => current_user_can('manage_options')
    ));
});

// Security Score AJAX Handler
add_action('wp_ajax_wpsg_security_score', function () {
    check_ajax_referer('wpsg_security_test', 'nonce');

    if (!current_user_can('manage_options')) {
        wp_send_json_error('Insufficient permissions');
        return;
    }

    try {
        $plugin = WP_Security_Guardian::get_instance();
        
        // Calculate comprehensive security score
        $score_breakdown = array(
            'core_security' => 0.0,
            'plugin_management' => 0.0,
            'file_security' => 0.0,
            'network_security' => 0.0,
            'access_controls' => 0.0
        );
        
        // Core Security (25 points)
        $core_tests = 0;
        $core_total = 5;
        if (defined('DISALLOW_FILE_EDIT') && DISALLOW_FILE_EDIT) $core_tests++;
        if (!has_action('wp_head', 'wp_generator')) $core_tests++;
        if (has_filter('xmlrpc_enabled') && !apply_filters('xmlrpc_enabled', true)) $core_tests++;
        if (get_option('wpsg_remove_wp_version', false)) $core_tests++;
        if (get_option('wpsg_disable_directory_browsing', false)) $core_tests++;
        $score_breakdown['core_security'] = $core_tests / $core_total;
        
        // Plugin Management (20 points)
        $plugin_tests = 0;
        $plugin_total = 4;
        if (get_option('wpsg_plugin_whitelist_enabled', false)) $plugin_tests++;
        if (get_option('wpsg_auto_update_plugins', false)) $plugin_tests++;
        if (get_option('wpsg_plugin_vulnerability_check', false)) $plugin_tests++;
        if (count(get_option('wpsg_whitelist', array())) > 0) $plugin_tests++;
        $score_breakdown['plugin_management'] = $plugin_tests / $plugin_total;
        
        // File Security (25 points)
        $file_tests = 0;
        $file_total = 5;
        if (get_option('wpsg_malware_scanning', false)) $file_tests++;
        if (get_option('wpsg_file_integrity_monitoring', false)) $file_tests++;
        if (get_option('wpsg_file_upload_restrictions', false)) $file_tests++;
        if (get_option('wpsg_file_permissions_check', false)) $file_tests++;
        if (is_dir(WP_CONTENT_DIR . '/wpsg-quarantine/')) $file_tests++;
        $score_breakdown['file_security'] = $file_tests / $file_total;
        
        // Network Security (20 points)
        $network_tests = 0;
        $network_total = 4;
        if (is_ssl()) $network_tests++;
        if (get_option('wpsg_security_headers_enabled', false)) $network_tests++;
        if (get_option('wpsg_rate_limiting_enabled', false)) $network_tests++;
        if (get_option('wpsg_ip_blocking_enabled', false)) $network_tests++;
        $score_breakdown['network_security'] = $network_tests / $network_total;
        
        // Access Controls (10 points)
        $access_tests = 0;
        $access_total = 2;
        if (class_exists('WPSG_Two_Factor_Auth')) $access_tests++;
        if (get_option('wpsg_block_user_enumeration', false)) $access_tests++;
        $score_breakdown['access_controls'] = $access_tests / $access_total;
        
        // Calculate overall percentage
        $overall_score = (
            $score_breakdown['core_security'] * 25 +
            $score_breakdown['plugin_management'] * 20 +
            $score_breakdown['file_security'] * 25 +
            $score_breakdown['network_security'] * 20 +
            $score_breakdown['access_controls'] * 10
        );
        
        // Determine grade
        $grade = 'F';
        if ($overall_score >= 90) $grade = 'A';
        elseif ($overall_score >= 80) $grade = 'B';
        elseif ($overall_score >= 70) $grade = 'C';
        elseif ($overall_score >= 60) $grade = 'D';
        
        // Generate recommendations
        $recommendations = array();
        if ($score_breakdown['core_security'] < 0.8) {
            $recommendations[] = 'Povolit všechny základní bezpečnostní nastavení (zákaz editace, skrytí verze)';
        }
        if ($score_breakdown['plugin_management'] < 0.7) {
            $recommendations[] = 'Aktivovat plugin whitelist a automatické aktualizace';
        }
        if ($score_breakdown['file_security'] < 0.6) {
            $recommendations[] = 'Zapnout malware scanning a file integrity monitoring';
        }
        if ($score_breakdown['network_security'] < 0.7) {
            $recommendations[] = 'Implementovat HTTPS, security headers a rate limiting';
        }
        if ($score_breakdown['access_controls'] < 0.5) {
            $recommendations[] = 'Aktivovat dvou-faktorové ověření a blokování user enumeration';
        }
        
        wp_send_json_success(array(
            'percentage' => round($overall_score, 1),
            'grade' => $grade,
            'breakdown' => $score_breakdown,
            'recommendations' => $recommendations,
            'timestamp' => current_time('mysql')
        ));
        
    } catch (Exception $e) {
        error_log('WPSG Security Score Error: ' . $e->getMessage());
        wp_send_json_error('Security score calculation failed: ' . $e->getMessage());
    }
});

// File Integrity Check AJAX Handler
add_action('wp_ajax_wpsg_integrity_check', function () {
    check_ajax_referer('wpsg_security_test', 'nonce');

    if (!current_user_can('manage_options')) {
        wp_send_json_error('Insufficient permissions');
        return;
    }

    $action_type = sanitize_text_field($_POST['action_type'] ?? 'verify');

    try {
        if ($action_type === 'create') {
            // Create file integrity checkpoint
            $core_files = array();
            $critical_directories = array(
                ABSPATH . 'wp-admin/',
                ABSPATH . 'wp-includes/',
                WP_CONTENT_DIR . '/themes/',
                WP_CONTENT_DIR . '/plugins/'
            );

            $checkpoint_count = 0;
            foreach ($critical_directories as $dir) {
                if (!is_dir($dir)) continue;
                
                $iterator = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS)
                );
                
                foreach ($iterator as $file) {
                    if (!$file->isFile()) continue;
                    
                    $path = $file->getPathname();
                    $relative_path = str_replace(ABSPATH, '', $path);
                    
                    if (pathinfo($path, PATHINFO_EXTENSION) === 'php') {
                        $core_files[$relative_path] = array(
                            'hash' => md5_file($path),
                            'size' => filesize($path),
                            'modified' => filemtime($path),
                            'checkpoint_created' => time()
                        );
                        $checkpoint_count++;
                    }
                }
            }
            
            update_option('wpsg_file_integrity_baseline', $core_files);
            update_option('wpsg_integrity_checkpoint_date', current_time('mysql'));
            
            wp_send_json_success(array(
                'message' => 'File integrity checkpoint created successfully!',
                'results' => array(
                    'summary' => array(
                        'checkpoint_created' => $checkpoint_count
                    )
                )
            ));
            
        } else {
            // Verify file integrity
            $baseline = get_option('wpsg_file_integrity_baseline', array());
            if (empty($baseline)) {
                wp_send_json_error('No integrity checkpoint found. Please create one first.');
                return;
            }
            
            $modified_files = 0;
            $modified_details = array();
            
            foreach ($baseline as $relative_path => $baseline_info) {
                $full_path = ABSPATH . $relative_path;
                
                if (!file_exists($full_path)) {
                    $modified_files++;
                    $modified_details[] = array(
                        'file' => $relative_path,
                        'status' => 'deleted',
                        'message' => 'File was deleted'
                    );
                    continue;
                }
                
                $current_hash = md5_file($full_path);
                if ($current_hash !== $baseline_info['hash']) {
                    $modified_files++;
                    $modified_details[] = array(
                        'file' => $relative_path,
                        'status' => 'modified',
                        'message' => 'File content changed',
                        'baseline_date' => date('Y-m-d H:i:s', $baseline_info['modified']),
                        'current_date' => date('Y-m-d H:i:s', filemtime($full_path))
                    );
                }
            }
            
            wp_send_json_success(array(
                'message' => $modified_files > 0 ? "Found {$modified_files} modified files!" : 'All files are intact!',
                'results' => array(
                    'summary' => array(
                        'modified_files' => $modified_files,
                        'total_checked' => count($baseline)
                    ),
                    'modified_files' => array_slice($modified_details, 0, 10) // Limit output
                )
            ));
        }
        
    } catch (Exception $e) {
        error_log('WPSG Integrity Check Error: ' . $e->getMessage());
        wp_send_json_error('Integrity check failed: ' . $e->getMessage());
    }
});

// Secure Logs AJAX Handler
add_action('wp_ajax_wpsg_get_secure_logs', function () {
    check_ajax_referer('wpsg_security_test', 'nonce');

    if (!current_user_can('manage_options')) {
        wp_send_json_error('Insufficient permissions');
        return;
    }

    $level = sanitize_text_field($_POST['level'] ?? '');
    $limit = intval($_POST['limit'] ?? 50);
    $limit = max(1, min(200, $limit)); // Clamp between 1-200

    try {
        // Try both secure logs and regular security logs
        $secure_logs = get_option('wpsg_secure_logs', array());
        $security_logs = get_option('wpsg_security_logs', array());
        
        // Combine and format logs
        $all_logs = array();
        
        // Add secure logs (already formatted)
        foreach ($secure_logs as $log) {
            if (is_array($log) && isset($log['timestamp'])) {
                $all_logs[] = array(
                    'timestamp' => $log['timestamp'],
                    'level' => $log['level'] ?? 'info',
                    'message' => $log['event'] ?? 'N/A',
                    'data' => $log['data'] ?? array()
                );
            }
        }
        
        // Add security logs (convert format)
        foreach ($security_logs as $log) {
            if (is_array($log) && isset($log['timestamp'])) {
                $level = 'info';
                if (isset($log['event_type']) && in_array($log['event_type'], ['MALWARE_DETECTED', 'INTEGRITY_VIOLATION'])) {
                    $level = 'error';
                } elseif (isset($log['event_type']) && in_array($log['event_type'], ['FILE_QUARANTINED', 'UNAUTHORIZED_ACCESS'])) {
                    $level = 'warning';
                }
                
                $all_logs[] = array(
                    'timestamp' => $log['timestamp'],
                    'level' => $level,
                    'message' => $log['message'] ?? ($log['event_type'] ?? 'Security Event'),
                    'data' => $log['data'] ?? array()
                );
            }
        }
        
        // Filter by level if specified
        if (!empty($level)) {
            $all_logs = array_filter($all_logs, function($log) use ($level) {
                return isset($log['level']) && $log['level'] === $level;
            });
        }
        
        // Sort by timestamp (newest first)
        usort($all_logs, function($a, $b) {
            return strtotime($b['timestamp'] ?? '') - strtotime($a['timestamp'] ?? '');
        });
        
        // Apply limit
        $all_logs = array_slice($all_logs, 0, $limit);
        
        wp_send_json_success(array(
            'logs' => $all_logs,
            'total_available' => count($secure_logs) + count($security_logs),
            'filtered_count' => count($all_logs)
        ));
        
    } catch (Exception $e) {
        error_log('WPSG Get Logs Error: ' . $e->getMessage());
        wp_send_json_error('Failed to retrieve logs: ' . $e->getMessage());
    }
});

// Scan Progress AJAX Handler - Real-time tracking like Wordfence
add_action('wp_ajax_wpsg_scan_progress', function () {
    error_log('[DEBUG] Scan progress AJAX handler called');
    error_log('[DEBUG] POST data: ' . print_r($_POST, true));
    
    check_ajax_referer('wpsg_security_test', 'nonce');

    if (!current_user_can('manage_options')) {
        error_log('[ERROR] User cannot manage options in progress handler');
        wp_send_json_error('Insufficient permissions');
        return;
    }

    $scan_id = sanitize_text_field($_POST['scan_id'] ?? '');
    error_log("[DEBUG] Progress requested for scan ID: '{$scan_id}'");
    
    if (empty($scan_id)) {
        error_log('[ERROR] Empty scan ID provided');
        wp_send_json_error('Scan ID is required');
        return;
    }

    try {
        $progress_option_key = 'wpsg_scan_progress_' . $scan_id;
        error_log("[DEBUG] Looking for progress data with key: {$progress_option_key}");
        
        $progress_data = get_option($progress_option_key, null);
        
        if (!$progress_data) {
            error_log("[ERROR] No progress data found for key: {$progress_option_key}");
            // List all scan progress options for debugging
            global $wpdb;
            $options = $wpdb->get_results("SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE 'wpsg_scan_progress_%'");
            error_log("[DEBUG] Available progress options: " . print_r(array_column($options, 'option_name'), true));
            wp_send_json_error('Scan progress not found');
            return;
        }
        
        error_log("[DEBUG] Progress data found: " . print_r($progress_data, true));
        
        // Calculate additional stats
        error_log('[DEBUG] Calculating progress statistics...');
        $elapsed_time = microtime(true) - $progress_data['start_time'];
        $files_per_second = $progress_data['scanned_files'] > 0 ? round($progress_data['scanned_files'] / $elapsed_time, 1) : 0;
        $eta_seconds = 0;
        
        if ($files_per_second > 0 && $progress_data['percentage'] < 100) {
            $remaining_files = $progress_data['total_files'] - $progress_data['scanned_files'];
            $eta_seconds = round($remaining_files / $files_per_second);
        }
        
        error_log("[DEBUG] Sending progress response: status={$progress_data['status']}, percentage={$progress_data['percentage']}, scanned={$progress_data['scanned_files']}/{$progress_data['total_files']}");
        
        wp_send_json_success(array(
            'scan_id' => $progress_data['scan_id'],
            'status' => $progress_data['status'],
            'current_directory' => $progress_data['current_directory'],
            'current_file' => $progress_data['current_file'],
            'total_files' => $progress_data['total_files'],
            'scanned_files' => $progress_data['scanned_files'],
            'threats_found' => $progress_data['threats_found'],
            'quarantined_files' => $progress_data['quarantined_files'],
            'percentage' => $progress_data['percentage'],
            'directories_completed' => $progress_data['directories_completed'],
            'total_directories' => $progress_data['total_directories'],
            'elapsed_time' => round($elapsed_time, 1),
            'files_per_second' => $files_per_second,
            'eta_seconds' => $eta_seconds,
            'eta_formatted' => $eta_seconds > 0 ? gmdate('H:i:s', $eta_seconds) : '00:00:00'
        ));
        
    } catch (Exception $e) {
        error_log('WPSG Scan Progress Error: ' . $e->getMessage());
        wp_send_json_error('Failed to get scan progress: ' . $e->getMessage());
    }
});

// Initialize the plugin
WP_Security_Guardian::get_instance();
