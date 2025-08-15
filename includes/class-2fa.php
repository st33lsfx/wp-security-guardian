<?php

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Two-Factor Authentication System
 * Provides TOTP/Google Authenticator support with backup codes
 */
class WPSG_Two_Factor_Auth
{
    private static $instance = null;
    private $secret_length = 16;

    public static function get_instance()
    {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct()
    {
        add_action('init', array($this, 'init'));
    }

    public function init()
    {
        // Login hooks
        add_action('wp_login', array($this, 'handle_login'), 10, 2);
        add_action('wp_authenticate_user', array($this, 'authenticate_2fa'), 30, 2);
        add_filter('authenticate', array($this, 'check_2fa_requirement'), 50, 3);

        // Profile hooks for 2FA setup
        add_action('show_user_profile', array($this, 'show_2fa_profile_fields'));
        add_action('edit_user_profile', array($this, 'show_2fa_profile_fields'));
        add_action('personal_options_update', array($this, 'save_2fa_profile_fields'));
        add_action('edit_user_profile_update', array($this, 'save_2fa_profile_fields'));

        // AJAX handlers
        add_action('wp_ajax_wpsg_generate_2fa_secret', array($this, 'ajax_generate_secret'));
        add_action('wp_ajax_wpsg_verify_2fa_setup', array($this, 'ajax_verify_setup'));
        add_action('wp_ajax_wpsg_disable_2fa', array($this, 'ajax_disable_2fa'));
        add_action('wp_ajax_wpsg_generate_backup_codes', array($this, 'ajax_generate_backup_codes'));

        // Login form modifications
        add_action('login_form', array($this, 'add_2fa_login_fields'));
        add_action('login_enqueue_scripts', array($this, 'enqueue_login_scripts'));
    }

    /**
     * Generate a new secret key for TOTP
     */
    public function generate_secret()
    {
        $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $secret = '';
        for ($i = 0; $i < $this->secret_length; $i++) {
            $secret .= $chars[random_int(0, strlen($chars) - 1)];
        }
        return $secret;
    }

    /**
     * Generate TOTP based on secret and time
     */
    public function generate_totp($secret, $time = null)
    {
        if ($time === null) {
            $time = time();
        }

        $time = floor($time / 30);
        $secret = $this->base32_decode($secret);

        $time = pack('N*', 0) . pack('N*', $time);
        $hash = hash_hmac('sha1', $time, $secret, true);

        $offset = ord($hash[19]) & 0xf;
        $code = (
            ((ord($hash[$offset]) & 0x7f) << 24) |
            ((ord($hash[$offset + 1]) & 0xff) << 16) |
            ((ord($hash[$offset + 2]) & 0xff) << 8) |
            (ord($hash[$offset + 3]) & 0xff)
        ) % 1000000;

        return sprintf('%06d', $code);
    }

    /**
     * Verify TOTP code with time tolerance
     */
    public function verify_totp($secret, $code, $tolerance = 2)
    {
        $current_time = time();

        // Check current time and tolerance window
        for ($i = -$tolerance; $i <= $tolerance; $i++) {
            $time = $current_time + ($i * 30);
            if ($this->generate_totp($secret, $time) === $code) {
                return true;
            }
        }

        return false;
    }

    /**
     * Base32 decode for TOTP secret
     */
    private function base32_decode($input)
    {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $output = '';
        $v = 0;
        $vbits = 0;

        for ($i = 0, $j = strlen($input); $i < $j; $i++) {
            $v <<= 5;
            $v += strpos($alphabet, $input[$i]);
            $vbits += 5;

            if ($vbits >= 8) {
                $output .= chr(($v >> ($vbits - 8)) & 255);
                $vbits -= 8;
            }
        }

        return $output;
    }

    /**
     * Check if user has 2FA enabled
     */
    public function is_2fa_enabled($user_id)
    {
        $secret = get_user_meta($user_id, 'wpsg_2fa_secret', true);
        $enabled = get_user_meta($user_id, 'wpsg_2fa_enabled', true);

        return !empty($secret) && $enabled === '1';
    }

    /**
     * Check if 2FA is required for user
     */
    public function is_2fa_required($user_id)
    {
        $user = get_user_by('id', $user_id);

        // Force 2FA for administrators
        if (user_can($user, 'administrator')) {
            return true;
        }

        // Check global setting
        $require_2fa = get_option('wpsg_require_2fa', 'admin_only');

        switch ($require_2fa) {
            case 'all_users':
                return true;
            case 'admin_only':
                return user_can($user, 'administrator');
            case 'disabled':
            default:
                return false;
        }
    }

    /**
     * Handle login process - check if 2FA verification is needed
     */
    public function check_2fa_requirement($user, $username, $password)
    {
        if (is_wp_error($user)) {
            return $user;
        }

        // Skip 2FA for automated processes
        if (defined('XMLRPC_REQUEST') || defined('REST_REQUEST') || wp_doing_cron()) {
            return $user;
        }

        if (!$this->is_2fa_enabled($user->ID)) {
            // If 2FA is required but not set up, redirect to setup
            if ($this->is_2fa_required($user->ID)) {
                return new WP_Error('2fa_required', 'Two-factor authentication is required for your account. Please set it up first.');
            }
            return $user;
        }

        // Check if 2FA code was provided
        $totp_code = sanitize_text_field($_POST['wpsg_2fa_code'] ?? '');

        if (empty($totp_code)) {
            // Store partial login state
            set_transient('wpsg_partial_login_' . $user->ID, array(
                'user_id' => $user->ID,
                'timestamp' => time()
            ), 300); // 5 minutes

            return new WP_Error('2fa_required', 'Please enter your two-factor authentication code.');
        }

        // Verify 2FA code
        if (!$this->verify_user_2fa_code($user->ID, $totp_code)) {
            // Log failed 2FA attempt
            $this->log_2fa_attempt($user->ID, 'failed', $totp_code);

            return new WP_Error('2fa_invalid', 'Invalid two-factor authentication code.');
        }

        // Log successful 2FA
        $this->log_2fa_attempt($user->ID, 'success', $totp_code);

        // Clear partial login state
        delete_transient('wpsg_partial_login_' . $user->ID);

        return $user;
    }

    /**
     * Verify 2FA code for user
     */
    public function verify_user_2fa_code($user_id, $code)
    {
        $secret = get_user_meta($user_id, 'wpsg_2fa_secret', true);

        if (empty($secret)) {
            return false;
        }

        // First try TOTP verification
        if ($this->verify_totp($secret, $code)) {
            return true;
        }

        // Try backup codes if TOTP failed
        return $this->verify_backup_code($user_id, $code);
    }

    /**
     * Generate backup codes for user
     */
    public function generate_backup_codes($user_id, $count = 8)
    {
        $codes = array();

        for ($i = 0; $i < $count; $i++) {
            $codes[] = sprintf('%04d-%04d', random_int(1000, 9999), random_int(1000, 9999));
        }

        // Hash codes before storing
        $hashed_codes = array_map(function ($code) {
            return array(
                'code' => wp_hash_password($code),
                'used' => false,
                'created' => time()
            );
        }, $codes);

        update_user_meta($user_id, 'wpsg_2fa_backup_codes', $hashed_codes);

        // Log backup code generation
        $this->log_2fa_event($user_id, 'backup_codes_generated', array('count' => $count));

        return $codes; // Return unhashed codes for display
    }

    /**
     * Verify backup code
     */
    public function verify_backup_code($user_id, $code)
    {
        $backup_codes = get_user_meta($user_id, 'wpsg_2fa_backup_codes', true);

        if (empty($backup_codes) || !is_array($backup_codes)) {
            return false;
        }

        foreach ($backup_codes as $index => $backup_code) {
            if ($backup_code['used']) {
                continue;
            }

            if (wp_check_password($code, $backup_code['code'])) {
                // Mark code as used
                $backup_codes[$index]['used'] = true;
                $backup_codes[$index]['used_at'] = time();
                update_user_meta($user_id, 'wpsg_2fa_backup_codes', $backup_codes);

                // Log backup code usage
                $this->log_2fa_event($user_id, 'backup_code_used', array('code_index' => $index));

                return true;
            }
        }

        return false;
    }

    /**
     * Get QR code URL for Google Authenticator
     */
    public function get_qr_code_url($user_id, $secret)
    {
        $user = get_user_by('id', $user_id);
        $site_name = get_bloginfo('name');
        $account_name = urlencode("{$user->user_login}@{$site_name}");

        $qr_code_url = "otpauth://totp/{$account_name}?secret={$secret}&issuer=" . urlencode($site_name);

        // Use Google Charts API for QR code generation
        return "https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl=" . urlencode($qr_code_url);
    }

    /**
     * Show 2FA profile fields
     */
    public function show_2fa_profile_fields($user)
    {
        $is_enabled = $this->is_2fa_enabled($user->ID);
        $is_required = $this->is_2fa_required($user->ID);
        $secret = get_user_meta($user->ID, 'wpsg_2fa_secret', true);

?>
        <h3><?php _e('Two-Factor Authentication', 'wp-security-guardian'); ?></h3>
        <table class="form-table">
            <tr>
                <th><label for="wpsg_2fa_status"><?php _e('2FA Status', 'wp-security-guardian'); ?></label></th>
                <td>
                    <?php if ($is_enabled): ?>
                        <span class="dashicons dashicons-yes-alt" style="color: #46b450;"></span>
                        <strong style="color: #46b450;"><?php _e('Enabled', 'wp-security-guardian'); ?></strong>
                        <p class="description">
                            <?php _e('Two-factor authentication is active for your account.', 'wp-security-guardian'); ?>
                            <?php if ($is_required): ?>
                                <br><em><?php _e('2FA is required for your account level.', 'wp-security-guardian'); ?></em>
                            <?php endif; ?>
                        </p>
                    <?php else: ?>
                        <span class="dashicons dashicons-dismiss" style="color: #dc3232;"></span>
                        <strong style="color: #dc3232;"><?php _e('Disabled', 'wp-security-guardian'); ?></strong>
                        <p class="description">
                            <?php _e('Two-factor authentication is not set up.', 'wp-security-guardian'); ?>
                            <?php if ($is_required): ?>
                                <br><em style="color: #dc3232;"><?php _e('2FA is required for your account level. Please set it up immediately.', 'wp-security-guardian'); ?></em>
                            <?php endif; ?>
                        </p>
                    <?php endif; ?>
                </td>
            </tr>

            <?php if (!$is_enabled): ?>
                <tr>
                    <th><label><?php _e('Setup 2FA', 'wp-security-guardian'); ?></label></th>
                    <td>
                        <div id="wpsg-2fa-setup">
                            <button type="button" id="wpsg-generate-2fa" class="button button-primary">
                                <?php _e('Generate Secret Key', 'wp-security-guardian'); ?>
                            </button>
                            <p class="description">
                                <?php _e('Click to generate a new secret key and set up two-factor authentication.', 'wp-security-guardian'); ?>
                            </p>

                            <div id="wpsg-2fa-setup-form" style="display: none;">
                                <h4><?php _e('Setup Instructions', 'wp-security-guardian'); ?></h4>
                                <ol>
                                    <li><?php _e('Install Google Authenticator or another TOTP app on your phone', 'wp-security-guardian'); ?></li>
                                    <li><?php _e('Scan the QR code below or manually enter the secret key', 'wp-security-guardian'); ?></li>
                                    <li><?php _e('Enter the 6-digit code from your app to verify setup', 'wp-security-guardian'); ?></li>
                                </ol>

                                <div id="wpsg-qr-code"></div>
                                <div id="wpsg-secret-key"></div>

                                <p>
                                    <label for="wpsg-2fa-verify"><?php _e('Enter verification code:', 'wp-security-guardian'); ?></label><br>
                                    <input type="text" id="wpsg-2fa-verify" maxlength="6" placeholder="123456" style="width: 100px;">
                                    <button type="button" id="wpsg-verify-2fa" class="button button-primary">
                                        <?php _e('Verify & Enable 2FA', 'wp-security-guardian'); ?>
                                    </button>
                                </p>
                            </div>
                        </div>
                    </td>
                </tr>
            <?php else: ?>
                <tr>
                    <th><label><?php _e('Backup Codes', 'wp-security-guardian'); ?></label></th>
                    <td>
                        <?php
                        $backup_codes = get_user_meta($user->ID, 'wpsg_2fa_backup_codes', true);
                        $unused_codes = 0;
                        if (is_array($backup_codes)) {
                            foreach ($backup_codes as $code) {
                                if (!$code['used']) {
                                    $unused_codes++;
                                }
                            }
                        }
                        ?>
                        <p>
                            <?php printf(__('You have %d unused backup codes.', 'wp-security-guardian'), $unused_codes); ?>
                            <button type="button" id="wpsg-generate-backup-codes" class="button">
                                <?php _e('Generate New Codes', 'wp-security-guardian'); ?>
                            </button>
                        </p>
                        <div id="wpsg-backup-codes-display" style="display: none;"></div>
                    </td>
                </tr>

                <tr>
                    <th><label><?php _e('Disable 2FA', 'wp-security-guardian'); ?></label></th>
                    <td>
                        <?php if (!$is_required): ?>
                            <button type="button" id="wpsg-disable-2fa" class="button button-secondary">
                                <?php _e('Disable Two-Factor Authentication', 'wp-security-guardian'); ?>
                            </button>
                            <p class="description">
                                <?php _e('This will disable 2FA and remove all backup codes. You will need to set it up again if you want to re-enable it.', 'wp-security-guardian'); ?>
                            </p>
                        <?php else: ?>
                            <p><em><?php _e('2FA cannot be disabled as it is required for your account level.', 'wp-security-guardian'); ?></em></p>
                        <?php endif; ?>
                    </td>
                </tr>
            <?php endif; ?>
        </table>

        <script>
            jQuery(document).ready(function($) {
                $('#wpsg-generate-2fa').click(function() {
                    $.post(ajaxurl, {
                        action: 'wpsg_generate_2fa_secret',
                        nonce: '<?php echo wp_create_nonce('wpsg_2fa_setup'); ?>',
                        user_id: <?php echo $user->ID; ?>
                    }, function(response) {
                        if (response.success) {
                            $('#wpsg-qr-code').html('<img src="' + response.data.qr_code + '" alt="QR Code">');
                            $('#wpsg-secret-key').html('<p><strong>Secret Key:</strong> <code>' + response.data.secret + '</code></p>');
                            $('#wpsg-2fa-setup-form').show();
                            $('#wpsg-generate-2fa').hide();
                        } else {
                            alert('Error generating secret: ' + response.data);
                        }
                    });
                });

                $('#wpsg-verify-2fa').click(function() {
                    var code = $('#wpsg-2fa-verify').val();
                    if (!code || code.length !== 6) {
                        alert('Please enter a 6-digit code');
                        return;
                    }

                    $.post(ajaxurl, {
                        action: 'wpsg_verify_2fa_setup',
                        nonce: '<?php echo wp_create_nonce('wpsg_2fa_verify'); ?>',
                        user_id: <?php echo $user->ID; ?>,
                        code: code
                    }, function(response) {
                        if (response.success) {
                            alert('2FA has been enabled successfully! Backup codes: ' + response.data.backup_codes.join(', '));
                            location.reload();
                        } else {
                            alert('Verification failed: ' + response.data);
                        }
                    });
                });

                $('#wpsg-generate-backup-codes').click(function() {
                    if (!confirm('This will invalidate all existing backup codes. Continue?')) {
                        return;
                    }

                    $.post(ajaxurl, {
                        action: 'wpsg_generate_backup_codes',
                        nonce: '<?php echo wp_create_nonce('wpsg_2fa_backup'); ?>',
                        user_id: <?php echo $user->ID; ?>
                    }, function(response) {
                        if (response.success) {
                            var codes = response.data.codes.join('<br>');
                            $('#wpsg-backup-codes-display').html('<div class="notice notice-success"><p><strong>New Backup Codes (save these securely):</strong><br>' + codes + '</p></div>').show();
                        } else {
                            alert('Error generating backup codes: ' + response.data);
                        }
                    });
                });

                $('#wpsg-disable-2fa').click(function() {
                    if (!confirm('Are you sure you want to disable two-factor authentication? This action cannot be undone.')) {
                        return;
                    }

                    $.post(ajaxurl, {
                        action: 'wpsg_disable_2fa',
                        nonce: '<?php echo wp_create_nonce('wpsg_2fa_disable'); ?>',
                        user_id: <?php echo $user->ID; ?>
                    }, function(response) {
                        if (response.success) {
                            alert('2FA has been disabled.');
                            location.reload();
                        } else {
                            alert('Error disabling 2FA: ' + response.data);
                        }
                    });
                });
            });
        </script>
    <?php
    }

    /**
     * AJAX: Generate new 2FA secret
     */
    public function ajax_generate_secret()
    {
        check_ajax_referer('wpsg_2fa_setup', 'nonce');

        $user_id = intval($_POST['user_id']);

        if (!current_user_can('edit_user', $user_id)) {
            wp_die(__('Insufficient permissions.', 'wp-security-guardian'));
        }

        $secret = $this->generate_secret();
        update_user_meta($user_id, 'wpsg_2fa_secret_temp', $secret);

        $qr_code_url = $this->get_qr_code_url($user_id, $secret);

        wp_send_json_success(array(
            'secret' => $secret,
            'qr_code' => $qr_code_url
        ));
    }

    /**
     * AJAX: Verify 2FA setup
     */
    public function ajax_verify_setup()
    {
        check_ajax_referer('wpsg_2fa_verify', 'nonce');

        $user_id = intval($_POST['user_id']);
        $code = sanitize_text_field($_POST['code']);

        if (!current_user_can('edit_user', $user_id)) {
            wp_die(__('Insufficient permissions.', 'wp-security-guardian'));
        }

        $temp_secret = get_user_meta($user_id, 'wpsg_2fa_secret_temp', true);

        if (empty($temp_secret)) {
            wp_send_json_error(__('No temporary secret found. Please generate a new one.', 'wp-security-guardian'));
        }

        if (!$this->verify_totp($temp_secret, $code)) {
            wp_send_json_error(__('Invalid verification code.', 'wp-security-guardian'));
        }

        // Move temp secret to permanent and enable 2FA
        update_user_meta($user_id, 'wpsg_2fa_secret', $temp_secret);
        update_user_meta($user_id, 'wpsg_2fa_enabled', '1');
        delete_user_meta($user_id, 'wpsg_2fa_secret_temp');

        // Generate backup codes
        $backup_codes = $this->generate_backup_codes($user_id);

        // Log 2FA activation
        $this->log_2fa_event($user_id, '2fa_enabled');

        wp_send_json_success(array(
            'message' => __('2FA has been enabled successfully!', 'wp-security-guardian'),
            'backup_codes' => $backup_codes
        ));
    }

    /**
     * AJAX: Generate backup codes
     */
    public function ajax_generate_backup_codes()
    {
        check_ajax_referer('wpsg_2fa_backup', 'nonce');

        $user_id = intval($_POST['user_id']);

        if (!current_user_can('edit_user', $user_id)) {
            wp_die(__('Insufficient permissions.', 'wp-security-guardian'));
        }

        if (!$this->is_2fa_enabled($user_id)) {
            wp_send_json_error(__('2FA is not enabled for this user.', 'wp-security-guardian'));
        }

        $codes = $this->generate_backup_codes($user_id);

        wp_send_json_success(array('codes' => $codes));
    }

    /**
     * AJAX: Disable 2FA
     */
    public function ajax_disable_2fa()
    {
        check_ajax_referer('wpsg_2fa_disable', 'nonce');

        $user_id = intval($_POST['user_id']);

        if (!current_user_can('edit_user', $user_id)) {
            wp_die(__('Insufficient permissions.', 'wp-security-guardian'));
        }

        if ($this->is_2fa_required($user_id)) {
            wp_send_json_error(__('2FA cannot be disabled as it is required for your account level.', 'wp-security-guardian'));
        }

        // Remove all 2FA data
        delete_user_meta($user_id, 'wpsg_2fa_secret');
        delete_user_meta($user_id, 'wpsg_2fa_secret_temp');
        delete_user_meta($user_id, 'wpsg_2fa_enabled');
        delete_user_meta($user_id, 'wpsg_2fa_backup_codes');

        // Log 2FA deactivation
        $this->log_2fa_event($user_id, '2fa_disabled');

        wp_send_json_success();
    }

    /**
     * Add 2FA fields to login form
     */
    public function add_2fa_login_fields()
    {
    ?>
        <p id="wpsg-2fa-field" style="display: none;">
            <label for="wpsg_2fa_code"><?php _e('Authentication Code', 'wp-security-guardian'); ?><br>
                <input type="text" name="wpsg_2fa_code" id="wpsg_2fa_code" class="input" value="" size="6" maxlength="6" autocomplete="off" placeholder="123456" />
            </label>
            <br>
            <small><?php _e('Enter the 6-digit code from your authenticator app or use a backup code.', 'wp-security-guardian'); ?></small>
        </p>

        <script>
            // Show 2FA field if needed
            document.addEventListener('DOMContentLoaded', function() {
                var loginForm = document.getElementById('loginform');
                var submitButton = document.getElementById('wp-submit');
                var tfaField = document.getElementById('wpsg-2fa-field');

                if (loginForm && submitButton && tfaField) {
                    var originalSubmit = submitButton.onclick;

                    loginForm.addEventListener('submit', function(e) {
                        var username = document.getElementById('user_login').value;
                        var password = document.getElementById('user_pass').value;
                        var tfaCode = document.getElementById('wpsg_2fa_code').value;

                        // If no username/password, let normal validation handle it
                        if (!username || !password) {
                            return true;
                        }

                        // If 2FA field is visible but empty, prevent submission
                        if (tfaField.style.display !== 'none' && !tfaCode) {
                            alert('<?php _e('Please enter your two-factor authentication code.', 'wp-security-guardian'); ?>');
                            e.preventDefault();
                            return false;
                        }

                        // If 2FA field is not visible, check if user needs 2FA
                        if (tfaField.style.display === 'none') {
                            // Make AJAX call to check if user needs 2FA
                            e.preventDefault();

                            fetch('<?php echo admin_url('admin-ajax.php'); ?>', {
                                    method: 'POST',
                                    headers: {
                                        'Content-Type': 'application/x-www-form-urlencoded',
                                    },
                                    body: 'action=wpsg_check_2fa_required&username=' + encodeURIComponent(username)
                                })
                                .then(response => response.json())
                                .then(data => {
                                    if (data.success && data.data.requires_2fa) {
                                        tfaField.style.display = 'block';
                                        document.getElementById('wpsg_2fa_code').focus();
                                    } else {
                                        // Submit form normally
                                        loginForm.submit();
                                    }
                                })
                                .catch(error => {
                                    // On error, allow normal submission
                                    loginForm.submit();
                                });

                            return false;
                        }

                        return true;
                    });
                }
            });
        </script>
<?php
    }

    /**
     * Log 2FA attempt
     */
    private function log_2fa_attempt($user_id, $status, $code)
    {
        $user = get_user_by('id', $user_id);

        if (class_exists('WP_Security_Guardian')) {
            $guardian = WP_Security_Guardian::get_instance();
            if (method_exists($guardian, 'log_security_event')) {
                $guardian->log_security_event(
                    '2FA_' . strtoupper($status),
                    "2FA authentication {$status} for user {$user->user_login}",
                    array(
                        'user_id' => $user_id,
                        'username' => $user->user_login,
                        'code_prefix' => substr($code, 0, 2) . '****',
                        'ip' => $guardian->get_client_ip()
                    )
                );
            }
        }
    }

    /**
     * Log 2FA event
     */
    private function log_2fa_event($user_id, $event, $data = array())
    {
        $user = get_user_by('id', $user_id);

        if (class_exists('WP_Security_Guardian')) {
            $guardian = WP_Security_Guardian::get_instance();
            if (method_exists($guardian, 'log_security_event')) {
                $guardian->log_security_event(
                    strtoupper($event),
                    "2FA event: {$event} for user {$user->user_login}",
                    array_merge(array(
                        'user_id' => $user_id,
                        'username' => $user->user_login,
                        'ip' => $guardian->get_client_ip()
                    ), $data)
                );
            }
        }
    }
}

// Initialize 2FA
WPSG_Two_Factor_Auth::get_instance();
