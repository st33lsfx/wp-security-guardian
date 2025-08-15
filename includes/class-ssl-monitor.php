<?php

if (!defined('ABSPATH')) {
    exit;
}

/**
 * SSL/HTTPS Monitoring and Enforcement System
 * Monitors SSL certificates, enforces HTTPS, and provides SSL security features
 */
class WPSG_SSL_Monitor
{
    private static $instance = null;

    public static function get_instance()
    {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct()
    {
        add_action('init', [$this, 'init']);
    }

    public function init()
    {
        // SSL certificate monitoring
        add_action('wpsg_daily_ssl_check', [$this, 'check_ssl_certificate']);

        // Schedule daily SSL checks if not already scheduled
        if (!wp_next_scheduled('wpsg_daily_ssl_check')) {
            wp_schedule_event(time(), 'daily', 'wpsg_daily_ssl_check');
        }

        // HTTPS enforcement hooks
        add_action('template_redirect', [$this, 'enforce_https_redirect'], 1);
        add_action('wp_loaded', [$this, 'check_mixed_content']);

        // Admin hooks
        add_action('wp_ajax_wpsg_test_ssl', [$this, 'ajax_test_ssl']);
        add_action('wp_ajax_wpsg_fix_mixed_content', [$this, 'ajax_fix_mixed_content']);
        add_action('wp_ajax_wpsg_force_ssl_redirect', [$this, 'ajax_force_ssl_redirect']);

        // Content filtering for HTTPS
        add_filter('the_content', [$this, 'fix_content_mixed_content']);
        add_filter('widget_text', [$this, 'fix_content_mixed_content']);

        // URL rewriting for HTTPS
        if (get_option('wpsg_fix_mixed_content', false)) {
            add_action('init', [$this, 'start_output_buffer']);
        }
    }

    /**
     * Check SSL certificate status and expiration
     */
    public function check_ssl_certificate()
    {
        $site_url = get_site_url();
        $parsed_url = parse_url($site_url);

        if ($parsed_url['scheme'] !== 'https') {
            $this->log_ssl_event('SSL_NOT_ENABLED', 'Site is not using HTTPS');
            return false;
        }

        $host = $parsed_url['host'];
        $port = $parsed_url['port'] ?? 443;

        // Get SSL certificate information
        $ssl_info = $this->get_ssl_certificate_info($host, $port);

        if (!$ssl_info) {
            $this->log_ssl_event('SSL_CHECK_FAILED', 'Failed to retrieve SSL certificate information');
            return false;
        }

        // Check certificate validity
        $current_time = time();
        $valid_from = $ssl_info['validFrom_time_t'];
        $valid_to = $ssl_info['validTo_time_t'];

        // Certificate status
        $status = 'valid';
        $days_until_expiry = ceil(($valid_to - $current_time) / (60 * 60 * 24));

        if ($current_time < $valid_from) {
            $status = 'not_yet_valid';
        } elseif ($current_time > $valid_to) {
            $status = 'expired';
        } elseif ($days_until_expiry <= 30) {
            $status = 'expiring_soon';
        }

        // Update SSL status in database
        update_option('wpsg_ssl_status', [
            'status' => $status,
            'issuer' => $ssl_info['issuer']['CN'] ?? 'Unknown',
            'subject' => $ssl_info['subject']['CN'] ?? 'Unknown',
            'valid_from' => $valid_from,
            'valid_to' => $valid_to,
            'days_until_expiry' => $days_until_expiry,
            'signature_algorithm' => $ssl_info['signatureTypeSN'] ?? 'Unknown',
            'last_checked' => $current_time
        ]);

        // Send alerts based on status
        $this->handle_ssl_status_alerts($status, $days_until_expiry, $ssl_info);

        return true;
    }

    /**
     * Get SSL certificate information
     */
    private function get_ssl_certificate_info($host, $port = 443)
    {
        $context = stream_context_create([
            'ssl' => [
                'capture_peer_cert' => true,
                'verify_peer' => false,
                'verify_peer_name' => false,
            ],
        ]);

        $socket = @stream_socket_client(
            "ssl://{$host}:{$port}",
            $errno,
            $errstr,
            30,
            STREAM_CLIENT_CONNECT,
            $context
        );

        if (!$socket) {
            return false;
        }

        $params = stream_context_get_params($socket);
        fclose($socket);

        if (!isset($params['options']['ssl']['peer_certificate'])) {
            return false;
        }

        $cert = $params['options']['ssl']['peer_certificate'];
        return openssl_x509_parse($cert);
    }

    /**
     * Handle SSL status alerts
     */
    private function handle_ssl_status_alerts($status, $days_until_expiry, $ssl_info)
    {
        $alert_recipients = get_option('wpsg_ssl_alert_recipients', [get_option('admin_email')]);

        switch ($status) {
            case 'expired':
                $this->send_ssl_alert(
                    'SSL Certificate Expired',
                    'Your SSL certificate has expired. Please renew it immediately to maintain site security.',
                    $alert_recipients,
                    'critical'
                );
                $this->log_ssl_event('SSL_EXPIRED', 'SSL certificate has expired');
                break;

            case 'expiring_soon':
                if ($days_until_expiry <= 7) {
                    $urgency = 'critical';
                } elseif ($days_until_expiry <= 14) {
                    $urgency = 'high';
                } else {
                    $urgency = 'medium';
                }

                $this->send_ssl_alert(
                    "SSL Certificate Expiring in {$days_until_expiry} Days",
                    "Your SSL certificate will expire in {$days_until_expiry} days. Please renew it to avoid service interruption.",
                    $alert_recipients,
                    $urgency
                );
                $this->log_ssl_event('SSL_EXPIRING_SOON', "SSL certificate expires in {$days_until_expiry} days");
                break;

            case 'not_yet_valid':
                $this->log_ssl_event('SSL_NOT_YET_VALID', 'SSL certificate is not yet valid');
                break;

            case 'valid':
                // Check for weak encryption
                if (
                    isset($ssl_info['signatureTypeSN']) &&
                    in_array($ssl_info['signatureTypeSN'], ['md5WithRSAEncryption', 'sha1WithRSAEncryption'])
                ) {
                    $this->log_ssl_event('SSL_WEAK_ENCRYPTION', 'SSL certificate uses weak encryption algorithm');
                }
                break;
        }
    }

    /**
     * Send SSL alert email
     */
    private function send_ssl_alert($subject, $message, $recipients, $urgency = 'medium')
    {
        $site_name = get_bloginfo('name');
        $site_url = get_site_url();

        $full_subject = "[{$urgency}] {$site_name}: {$subject}";

        $full_message = "
{$message}

Site: {$site_name}
URL: {$site_url}
Time: " . current_time('mysql') . "

Please take immediate action to resolve this SSL issue.

---
This alert was sent by WP Security Guardian
";

        $headers = [
            'Content-Type: text/plain; charset=UTF-8',
            'From: ' . get_option('admin_email'),
        ];

        foreach ($recipients as $recipient) {
            wp_mail($recipient, $full_subject, $full_message, $headers);
        }
    }

    /**
     * Enforce HTTPS redirects
     */
    public function enforce_https_redirect()
    {
        if (!get_option('wpsg_force_ssl', false)) {
            return;
        }

        // Skip for certain conditions
        if (is_ssl() || wp_doing_cron() || wp_doing_ajax() || (defined('WP_CLI') && WP_CLI)) {
            return;
        }

        // Skip for XML-RPC requests
        if (isset($GLOBALS['pagenow']) && $GLOBALS['pagenow'] === 'xmlrpc.php') {
            return;
        }

        $redirect_url = 'https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];

        // Log the redirect  
        $this->log_ssl_event('HTTPS_REDIRECT', 'HTTP request redirected to HTTPS', [
            'from' => $_SERVER['REQUEST_URI'],
            'to' => $redirect_url,
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? ''
        ]);

        wp_redirect($redirect_url, 301);
        exit;
    }

    /**
     * Check for mixed content issues
     */
    public function check_mixed_content()
    {
        if (!is_ssl() || !get_option('wpsg_scan_mixed_content', false)) {
            return;
        }

        // Only run on frontend pages
        if (is_admin() || wp_doing_ajax() || wp_doing_cron()) {
            return;
        }

        // Store current page for mixed content scanning
        add_action('wp_footer', [$this, 'inject_mixed_content_scanner']);
    }

    /**
     * Inject mixed content scanner JavaScript
     */
    public function inject_mixed_content_scanner()
    {
        if (current_user_can('manage_options')) {
?>
            <script>
                (function() {
                    var mixedContentItems = [];
                    var elements = document.querySelectorAll('img, script, link, iframe, object, embed');

                    elements.forEach(function(element) {
                        var src = element.src || element.href;
                        if (src && src.indexOf('http://') === 0) {
                            mixedContentItems.push({
                                tag: element.tagName.toLowerCase(),
                                src: src,
                                element: element
                            });
                        }
                    });

                    if (mixedContentItems.length > 0 && typeof console !== 'undefined') {
                        console.warn('WP Security Guardian: Mixed content detected:', mixedContentItems);

                        // Send to WordPress for logging
                        if (typeof fetch !== 'undefined') {
                            fetch('<?php echo admin_url('admin-ajax.php'); ?>', {
                                method: 'POST',
                                headers: {
                                    'Content-Type': 'application/x-www-form-urlencoded',
                                },
                                body: 'action=wpsg_log_mixed_content&nonce=<?php echo wp_create_nonce('wpsg_mixed_content'); ?>&items=' + encodeURIComponent(JSON.stringify(mixedContentItems)) + '&url=' + encodeURIComponent(window.location.href)
                            });
                        }
                    }
                })();
            </script>
<?php
        }
    }

    /**
     * Fix mixed content in content
     */
    public function fix_content_mixed_content($content)
    {
        if (!is_ssl() || !get_option('wpsg_fix_mixed_content', false)) {
            return $content;
        }

        // Replace HTTP URLs with HTTPS
        $content = preg_replace('/http:\/\//i', 'https://', $content);

        return $content;
    }

    /**
     * Start output buffer for full page HTTPS fixing
     */
    public function start_output_buffer()
    {
        if (is_ssl() && get_option('wpsg_fix_mixed_content', false)) {
            ob_start([$this, 'fix_mixed_content_buffer']);
        }
    }

    /**
     * Fix mixed content in output buffer
     */
    public function fix_mixed_content_buffer($buffer)
    {
        // Only fix if we're on HTTPS
        if (!is_ssl()) {
            return $buffer;
        }

        $site_url = parse_url(home_url(), PHP_URL_HOST);

        // Replace HTTP references to same domain with HTTPS
        $buffer = preg_replace(
            '/http:\/\/' . preg_quote($site_url, '/') . '/i',
            'https://' . $site_url,
            $buffer
        );

        // Replace protocol-relative URLs with HTTPS
        $buffer = preg_replace('/src=["\'](\/\/[^"\']*)["\']/', 'src="https:$1"', $buffer);
        $buffer = preg_replace('/href=["\'](\/\/[^"\']*)["\']/', 'href="https:$1"', $buffer);

        return $buffer;
    }

    /**
     * AJAX: Test SSL configuration
     */
    public function ajax_test_ssl()
    {
        check_ajax_referer('wpsg_test_ssl', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_die('Insufficient permissions');
        }

        $test_url = sanitize_url($_POST['url'] ?? get_site_url());
        $parsed_url = parse_url($test_url);

        if ($parsed_url['scheme'] !== 'https') {
            wp_send_json_error('URL must use HTTPS');
        }

        $host = $parsed_url['host'];
        $port = $parsed_url['port'] ?? 443;

        // Test SSL connection
        $ssl_info = $this->get_ssl_certificate_info($host, $port);

        if (!$ssl_info) {
            wp_send_json_error('Unable to retrieve SSL certificate information');
        }

        $current_time = time();
        $valid_from = $ssl_info['validFrom_time_t'];
        $valid_to = $ssl_info['validTo_time_t'];
        $days_until_expiry = ceil(($valid_to - $current_time) / (60 * 60 * 24));

        $status = 'valid';
        if ($current_time < $valid_from) {
            $status = 'not_yet_valid';
        } elseif ($current_time > $valid_to) {
            $status = 'expired';
        } elseif ($days_until_expiry <= 30) {
            $status = 'expiring_soon';
        }

        wp_send_json_success([
            'status' => $status,
            'issuer' => $ssl_info['issuer']['CN'] ?? 'Unknown',
            'subject' => $ssl_info['subject']['CN'] ?? 'Unknown',
            'valid_from' => date('Y-m-d H:i:s', $valid_from),
            'valid_to' => date('Y-m-d H:i:s', $valid_to),
            'days_until_expiry' => $days_until_expiry,
            'signature_algorithm' => $ssl_info['signatureTypeSN'] ?? 'Unknown'
        ]);
    }

    /**
     * AJAX: Log mixed content detection
     */
    public function ajax_log_mixed_content()
    {
        check_ajax_referer('wpsg_mixed_content', 'nonce');

        $items = json_decode(stripslashes($_POST['items'] ?? ''), true);
        $url = sanitize_url($_POST['url'] ?? '');

        if (empty($items) || !is_array($items)) {
            wp_send_json_error('No mixed content items provided');
        }

        $this->log_ssl_event('MIXED_CONTENT_DETECTED', 'Mixed content detected on page', [
            'page_url' => $url,
            'mixed_content_count' => count($items),
            'items' => array_slice($items, 0, 10) // Log max 10 items to avoid huge logs
        ]);

        wp_send_json_success();
    }

    /**
     * AJAX: Fix mixed content
     */
    public function ajax_fix_mixed_content()
    {
        check_ajax_referer('wpsg_fix_mixed_content', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_die('Insufficient permissions');
        }

        update_option('wpsg_fix_mixed_content', true);

        // Clear any caching
        if (function_exists('wp_cache_flush')) {
            wp_cache_flush();
        }

        $this->log_ssl_event('MIXED_CONTENT_FIX_ENABLED', 'Mixed content automatic fixing enabled');

        wp_send_json_success(['message' => 'Mixed content fixing enabled']);
    }

    /**
     * Get current SSL status
     */
    public function get_ssl_status()
    {
        return get_option('wpsg_ssl_status', [
            'status' => 'unknown',
            'last_checked' => 0
        ]);
    }

    /**
     * Get SSL security score
     */
    public function get_ssl_security_score()
    {
        if (!is_ssl()) {
            return 0;
        }

        $score = 60; // Base score for having SSL

        $ssl_status = $this->get_ssl_status();

        // Add points based on certificate status
        switch ($ssl_status['status']) {
            case 'valid':
                $score += 20;

                // Bonus for modern encryption
                if (
                    isset($ssl_status['signature_algorithm']) &&
                    in_array($ssl_status['signature_algorithm'], ['sha256WithRSAEncryption', 'ecdsa-with-SHA256'])
                ) {
                    $score += 10;
                }

                // Bonus for not expiring soon
                if (isset($ssl_status['days_until_expiry']) && $ssl_status['days_until_expiry'] > 30) {
                    $score += 5;
                }
                break;

            case 'expiring_soon':
                $score += 10;
                break;

            case 'expired':
            case 'not_yet_valid':
                $score -= 30;
                break;
        }

        // HSTS implementation
        if (get_option('wpsg_hsts_enabled', false)) {
            $score += 5;
        }

        return max(0, min(100, $score));
    }

    /**
     * Get client IP address
     */
    private function get_client_ip()
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
     * Log SSL-related events
     */
    private function log_ssl_event($event_type, $message, $data = [])
    {
        if (class_exists('WP_Security_Guardian')) {
            $guardian = WP_Security_Guardian::get_instance();
            if (method_exists($guardian, 'log_security_event')) {
                $guardian->log_security_event(
                    $event_type,
                    $message,
                    array_merge([
                        'ssl_monitor' => true,
                        'timestamp' => time()
                    ], $data)
                );
            }
        }
    }
}

// Initialize SSL Monitor
WPSG_SSL_Monitor::get_instance();
