<?php

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Security Headers System
 * Implements comprehensive HTTP security headers for WordPress protection
 */
class WPSG_Security_Headers
{
    private static $instance = null;
    private $default_headers = [];

    public static function get_instance()
    {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct()
    {
        $this->init_default_headers();
        add_action('init', [$this, 'init']);
    }

    private function init_default_headers()
    {
        $this->default_headers = [
            // Content Security Policy - najdůležitější header proti XSS
            'Content-Security-Policy' => $this->get_default_csp(),

            // X-Frame-Options - ochrana proti clickjacking
            'X-Frame-Options' => 'SAMEORIGIN',

            // X-XSS-Protection - starší XSS ochrana pro kompatibilitu
            'X-XSS-Protection' => '1; mode=block',

            // X-Content-Type-Options - zabraňuje MIME type sniffing
            'X-Content-Type-Options' => 'nosniff',

            // Referrer Policy - kontroluje kolik informací se posílá v referrer
            'Referrer-Policy' => 'strict-origin-when-cross-origin',

            // Permissions Policy - omezuje přístup k browser API
            'Permissions-Policy' => $this->get_default_permissions_policy(),

            // Cross-Origin-Embedder-Policy - ochrana proti spectre útokům
            'Cross-Origin-Embedder-Policy' => 'unsafe-none',

            // Cross-Origin-Opener-Policy - izolace browsing kontextu
            'Cross-Origin-Opener-Policy' => 'same-origin-allow-popups',

            // Cross-Origin-Resource-Policy - CORS ochrana
            'Cross-Origin-Resource-Policy' => 'same-site',
        ];
    }

    public function init()
    {
        // Apply headers on all requests
        add_action('send_headers', [$this, 'apply_security_headers']);

        // Additional headers for admin area
        add_action('admin_init', [$this, 'apply_admin_security_headers']);

        // Headers for login page
        add_action('login_init', [$this, 'apply_login_security_headers']);

        // HTTPS enforcement
        add_action('init', [$this, 'enforce_https']);

        // HSTS header (only over HTTPS)
        add_action('send_headers', [$this, 'apply_hsts_header']);

        // Remove WordPress version from headers
        add_filter('the_generator', '__return_empty_string');
        remove_action('wp_head', 'wp_generator');

        // Remove server signature
        add_action('init', [$this, 'remove_server_signature']);

        // Security headers admin page hooks
        add_action('wp_ajax_wpsg_test_csp', [$this, 'ajax_test_csp']);
        add_action('wp_ajax_wpsg_update_security_headers', [$this, 'ajax_update_headers']);
    }

    /**
     * Apply main security headers
     */
    public function apply_security_headers()
    {
        if (headers_sent()) {
            return;
        }

        // Check if security headers are globally enabled
        $headers_globally_enabled = get_option('wpsg_security_headers_enabled', true);
        if (!$headers_globally_enabled) {
            return;
        }

        // Allow temporary CSP disable for debugging
        if (get_option('wpsg_disable_csp_debug', false) && current_user_can('manage_options')) {
            return;
        }

        // Get enabled headers and apply them based on individual settings
        $default_headers = $this->default_headers;

        // Check individual settings for each header
        foreach ($default_headers as $header => $default_value) {
            $should_apply = false;

            switch ($header) {
                case 'Content-Security-Policy':
                    $should_apply = get_option('wpsg_csp_enabled', true);
                    break;
                case 'X-Frame-Options':
                    $should_apply = get_option('wpsg_x_frame_options', true);
                    break;
                case 'X-XSS-Protection':
                    $should_apply = get_option('wpsg_x_xss_protection', true);
                    break;
                case 'X-Content-Type-Options':
                    $should_apply = get_option('wpsg_x_content_type_options', true);
                    break;
                case 'Referrer-Policy':
                    $should_apply = get_option('wpsg_referrer_policy', true);
                    break;
                default:
                    $should_apply = true; // For other headers like Permissions Policy, etc.
                    break;
            }

            if ($should_apply && $this->should_apply_header($header)) {
                header($header . ': ' . $default_value);
            }
        }

        // Custom headers based on page type
        if (is_admin()) {
            $this->apply_admin_specific_headers();
        }

        if ($this->is_login_page()) {
            $this->apply_login_specific_headers();
        }
    }

    /**
     * Enhanced headers for admin area
     */
    public function apply_admin_security_headers()
    {
        if (!is_admin() || headers_sent()) {
            return;
        }

        // Check if security headers are globally enabled
        $headers_globally_enabled = get_option('wpsg_security_headers_enabled', true);
        if (!$headers_globally_enabled) {
            return;
        }

        // Stricter CSP for admin
        if (get_option('wpsg_csp_enabled', true)) {
            $admin_csp = $this->get_admin_csp();
            if ($admin_csp) {
                header('Content-Security-Policy: ' . $admin_csp);
            }
        }

        // Strict frame options for admin
        if (get_option('wpsg_x_frame_options', true)) {
            header('X-Frame-Options: DENY');
        }

        // Additional admin protection
        header('X-Robots-Tag: noindex, nofollow, noarchive, nosnippet');
    }

    /**
     * Security headers for login page
     */
    public function apply_login_security_headers()
    {
        if (headers_sent()) {
            return;
        }

        // Check if security headers are globally enabled
        $headers_globally_enabled = get_option('wpsg_security_headers_enabled', true);
        if (!$headers_globally_enabled) {
            return;
        }

        // Very strict CSP for login
        if (get_option('wpsg_csp_enabled', true)) {
            $login_csp = $this->get_login_csp();
            header('Content-Security-Policy: ' . $login_csp);
        }

        // No framing allowed on login
        if (get_option('wpsg_x_frame_options', true)) {
            header('X-Frame-Options: DENY');
        }

        // Cache control for login page
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
        header('Pragma: no-cache');
        header('Expires: 0');
    }

    /**
     * HTTPS enforcement
     */
    public function enforce_https()
    {
        $force_ssl = get_option('wpsg_force_ssl', false);

        if ($force_ssl && !is_ssl() && !wp_doing_cron() && !wp_doing_ajax()) {
            $redirect_url = 'https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];

            // Log HTTP access attempt
            if (class_exists('WP_Security_Guardian')) {
                $guardian = WP_Security_Guardian::get_instance();
                if (method_exists($guardian, 'log_security_event')) {
                    $guardian->log_security_event(
                        'HTTPS_REDIRECT',
                        'HTTP access redirected to HTTPS',
                        [
                            'original_url' => $_SERVER['REQUEST_URI'],
                            'ip' => $guardian->get_client_ip()
                        ]
                    );
                }
            }

            wp_redirect($redirect_url, 301);
            exit;
        }
    }

    /**
     * Apply HSTS header for HTTPS connections
     */
    public function apply_hsts_header()
    {
        if (!is_ssl() || headers_sent()) {
            return;
        }

        // Check if security headers are globally enabled
        $headers_globally_enabled = get_option('wpsg_security_headers_enabled', true);
        if (!$headers_globally_enabled) {
            return;
        }

        $hsts_enabled = get_option('wpsg_hsts_enabled', false);
        if (!$hsts_enabled) {
            return;
        }

        $max_age = get_option('wpsg_hsts_max_age', 31536000); // 1 year default
        $include_subdomains = get_option('wpsg_hsts_include_subdomains', true);
        $preload = get_option('wpsg_hsts_preload', false);

        $hsts_header = "max-age={$max_age}";

        if ($include_subdomains) {
            $hsts_header .= '; includeSubDomains';
        }

        if ($preload) {
            $hsts_header .= '; preload';
        }

        header('Strict-Transport-Security: ' . $hsts_header);
    }

    /**
     * Get default Content Security Policy
     */
    public function get_default_csp()
    {
        $site_url = parse_url(home_url(), PHP_URL_HOST);

        $csp_directives = [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' *.{$site_url} cdnjs.cloudflare.com cdn.jsdelivr.net code.jquery.com cdn.tailwindcss.com",
            "style-src 'self' 'unsafe-inline' *.{$site_url} fonts.googleapis.com cdnjs.cloudflare.com cdn.jsdelivr.net cdn.tailwindcss.com",
            "img-src 'self' data: *.{$site_url} *.gravatar.com *.wordpress.com chart.googleapis.com",
            "font-src 'self' fonts.gstatic.com fonts.googleapis.com",
            "connect-src 'self' *.{$site_url} api.wordpress.org",
            "frame-src 'self' *.{$site_url}",
            "object-src 'none'",
            "base-uri 'self'",
            "form-action 'self'",
            "upgrade-insecure-requests"
        ];

        return implode('; ', $csp_directives);
    }

    /**
     * Get stricter CSP for admin area
     */
    protected function get_admin_csp()
    {
        $site_url = parse_url(home_url(), PHP_URL_HOST);

        $admin_csp = [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' *.{$site_url} cdn.jsdelivr.net cdn.tailwindcss.com",
            "style-src 'self' 'unsafe-inline' *.{$site_url} fonts.googleapis.com cdn.tailwindcss.com",
            "img-src 'self' data: *.{$site_url} *.gravatar.com chart.googleapis.com",
            "font-src 'self' fonts.gstatic.com",
            "connect-src 'self' *.{$site_url} api.wordpress.org",
            "frame-src 'none'",
            "object-src 'none'",
            "base-uri 'self'",
            "form-action 'self'"
        ];

        return implode('; ', $admin_csp);
    }

    /**
     * Get very strict CSP for login page
     */
    protected function get_login_csp()
    {
        $site_url = parse_url(home_url(), PHP_URL_HOST);

        $login_csp = [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline' *.{$site_url}",
            "style-src 'self' 'unsafe-inline' *.{$site_url}",
            "img-src 'self' data: *.{$site_url}",
            "font-src 'self'",
            "connect-src 'self' *.{$site_url}",
            "frame-src 'none'",
            "object-src 'none'",
            "base-uri 'self'",
            "form-action 'self'"
        ];

        return implode('; ', $login_csp);
    }

    /**
     * Get default Permissions Policy
     */
    protected function get_default_permissions_policy()
    {
        $permissions = [
            'accelerometer=()' => true,
            'ambient-light-sensor=()' => true,
            'autoplay=()' => false, // Allow autoplay for videos
            'battery=()' => true,
            'camera=()' => true,
            'display-capture=()' => true,
            'document-domain=()' => true,
            'encrypted-media=(self)' => false,
            'execution-while-not-rendered=()' => true,
            'execution-while-out-of-viewport=()' => true,
            'fullscreen=(self)' => false,
            'geolocation=()' => true,
            'gyroscope=()' => true,
            'magnetometer=()' => true,
            'microphone=()' => true,
            'midi=()' => true,
            'navigation-override=()' => true,
            'payment=()' => true,
            'picture-in-picture=()' => false,
            'publickey-credentials-get=(self)' => false,
            'screen-wake-lock=()' => true,
            'sync-xhr=()' => true,
            'usb=()' => true,
            'web-share=()' => false,
            'xr-spatial-tracking=()' => true
        ];

        $enabled_permissions = get_option('wpsg_permissions_policy', $permissions);
        $policy_string = '';

        foreach ($enabled_permissions as $permission => $enabled) {
            if ($enabled) {
                $policy_string .= $permission . ', ';
            }
        }

        return rtrim($policy_string, ', ');
    }

    /**
     * Check if header should be applied
     */
    protected function should_apply_header($header_name)
    {
        // Don't override if already set
        $existing_headers = headers_list();
        foreach ($existing_headers as $existing_header) {
            if (stripos($existing_header, $header_name . ':') === 0) {
                return false;
            }
        }

        // Skip CSP on certain admin pages that need flexibility
        if ($header_name === 'Content-Security-Policy') {
            if (is_admin() && isset($_GET['page'])) {
                $skip_pages = ['plugin-editor', 'theme-editor', 'wp-security-guardian-dashboard'];
                if (in_array($_GET['page'], $skip_pages)) {
                    return false;
                }
            }
        }

        return true;
    }

    /**
     * Additional headers for admin area
     */
    protected function apply_admin_specific_headers()
    {
        // Admin-specific headers
        header('X-Download-Options: noopen');
        header('X-Permitted-Cross-Domain-Policies: none');
    }

    /**
     * Additional headers for login page
     */
    protected function apply_login_specific_headers()
    {
        // Login-specific headers
        header('X-Download-Options: noopen');
        header('X-Permitted-Cross-Domain-Policies: none');
        header('Clear-Site-Data: "cache", "cookies", "storage"');
    }

    /**
     * Remove server signature headers
     */
    public function remove_server_signature()
    {
        // Remove PHP version
        if (function_exists('header_remove')) {
            header_remove('X-Powered-By');
            header_remove('Server');
        }

        // Remove WordPress specific headers
        remove_action('wp_head', 'wp_shortlink_wp_head', 10);
        remove_action('wp_head', 'wp_generator');
        remove_action('wp_head', 'rsd_link');
        remove_action('wp_head', 'wlwmanifest_link');
        remove_action('wp_head', 'adjacent_posts_rel_link_wp_head', 10);

        // Remove REST API links from head
        remove_action('wp_head', 'rest_output_link_wp_head');
        remove_action('wp_head', 'wp_oembed_add_discovery_links');

        // Remove WordPress emoji scripts
        remove_action('wp_head', 'print_emoji_detection_script', 7);
        remove_action('wp_print_styles', 'print_emoji_styles');
    }

    /**
     * Check if current page is login page
     */
    protected function is_login_page()
    {
        return in_array($GLOBALS['pagenow'], ['wp-login.php', 'wp-register.php'], true);
    }

    /**
     * Test CSP compatibility
     */
    public function ajax_test_csp()
    {
        check_ajax_referer('wpsg_test_csp', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_die('Insufficient permissions');
        }

        $test_csp = sanitize_text_field($_POST['csp'] ?? '');

        if (empty($test_csp)) {
            wp_send_json_error('CSP policy is required');
        }

        // Validate CSP syntax
        $validation_result = $this->validate_csp_syntax($test_csp);

        if (!$validation_result['valid']) {
            wp_send_json_error('Invalid CSP syntax: ' . $validation_result['error']);
        }

        // Test CSP against current site
        $compatibility_issues = $this->test_csp_compatibility($test_csp);

        wp_send_json_success([
            'valid' => true,
            'compatibility_issues' => $compatibility_issues,
            'recommendation' => $this->generate_csp_recommendation($compatibility_issues)
        ]);
    }

    /**
     * Validate CSP syntax
     */
    protected function validate_csp_syntax($csp)
    {
        // Basic CSP syntax validation
        $valid_directives = [
            'default-src',
            'script-src',
            'style-src',
            'img-src',
            'font-src',
            'connect-src',
            'frame-src',
            'object-src',
            'media-src',
            'child-src',
            'form-action',
            'base-uri',
            'plugin-types',
            'sandbox',
            'report-uri',
            'report-to',
            'upgrade-insecure-requests',
            'block-all-mixed-content'
        ];

        $directives = explode(';', $csp);

        foreach ($directives as $directive) {
            $directive = trim($directive);
            if (empty($directive)) continue;

            $parts = explode(' ', $directive, 2);
            $directive_name = $parts[0];

            if (!in_array($directive_name, $valid_directives)) {
                return [
                    'valid' => false,
                    'error' => "Unknown directive: {$directive_name}"
                ];
            }
        }

        return ['valid' => true];
    }

    /**
     * Test CSP compatibility with WordPress
     */
    protected function test_csp_compatibility($csp)
    {
        $issues = [];

        // Check for common WordPress compatibility issues
        if (strpos($csp, 'unsafe-inline') === false) {
            if (strpos($csp, 'script-src') !== false) {
                $issues[] = [
                    'severity' => 'warning',
                    'message' => 'WordPress admin may require unsafe-inline for scripts',
                    'recommendation' => 'Consider adding unsafe-inline to script-src for admin pages'
                ];
            }

            if (strpos($csp, 'style-src') !== false) {
                $issues[] = [
                    'severity' => 'warning',
                    'message' => 'WordPress themes may require unsafe-inline for styles',
                    'recommendation' => 'Consider adding unsafe-inline to style-src'
                ];
            }
        }

        // Check for Gravatar images
        if (strpos($csp, 'img-src') !== false && strpos($csp, '*.gravatar.com') === false) {
            $issues[] = [
                'severity' => 'info',
                'message' => 'Gravatar images may be blocked',
                'recommendation' => 'Add *.gravatar.com to img-src if using Gravatars'
            ];
        }

        // Check for Google Fonts
        if (strpos($csp, 'font-src') !== false && strpos($csp, 'fonts.gstatic.com') === false) {
            $issues[] = [
                'severity' => 'info',
                'message' => 'Google Fonts may be blocked',
                'recommendation' => 'Add fonts.gstatic.com to font-src if using Google Fonts'
            ];
        }

        return $issues;
    }

    /**
     * Generate CSP recommendation
     */
    protected function generate_csp_recommendation($issues)
    {
        if (empty($issues)) {
            return 'CSP policy looks compatible with WordPress!';
        }

        $warnings = array_filter($issues, fn($issue) => $issue['severity'] === 'warning');

        if (!empty($warnings)) {
            return 'CSP policy may cause functionality issues. Review warnings before applying.';
        }

        return 'CSP policy is mostly compatible. Review minor issues if you encounter problems.';
    }

    /**
     * Update security headers via AJAX
     */
    public function ajax_update_headers()
    {
        check_ajax_referer('wpsg_update_headers', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_die('Insufficient permissions');
        }

        $headers_data = $_POST['headers'] ?? [];
        $validated_headers = [];

        foreach ($headers_data as $header => $value) {
            $header = sanitize_text_field($header);
            $value = sanitize_text_field($value);

            // Validate header names
            if (in_array($header, array_keys($this->default_headers))) {
                $validated_headers[$header] = $value;
            }
        }

        update_option('wpsg_security_headers', $validated_headers);

        // Log settings change
        if (class_exists('WP_Security_Guardian')) {
            $guardian = WP_Security_Guardian::get_instance();
            if (method_exists($guardian, 'log_security_event')) {
                $guardian->log_security_event(
                    'SECURITY_HEADERS_UPDATED',
                    'Security headers configuration updated',
                    [
                        'headers_count' => count($validated_headers),
                        'user_id' => get_current_user_id()
                    ]
                );
            }
        }

        wp_send_json_success(['message' => 'Security headers updated successfully']);
    }

    /**
     * Get current security headers configuration
     */
    public function get_current_headers()
    {
        return get_option('wpsg_security_headers', $this->default_headers);
    }

    /**
     * Get security score for headers
     */
    public function get_headers_security_score()
    {
        $current_headers = $this->get_current_headers();
        $total_possible = count($this->default_headers);
        $enabled_count = 0;

        foreach ($current_headers as $header => $value) {
            if (!empty($value)) {
                $enabled_count++;
            }
        }

        $base_score = ($enabled_count / $total_possible) * 70; // 70% max for just having headers

        // Bonus points for critical headers
        $bonus = 0;
        if (!empty($current_headers['Content-Security-Policy'])) {
            $bonus += 15;
        }
        if (!empty($current_headers['Strict-Transport-Security']) && is_ssl()) {
            $bonus += 10;
        }
        if (!empty($current_headers['X-Frame-Options'])) {
            $bonus += 5;
        }

        return min(100, round($base_score + $bonus));
    }
}

// Initialize Security Headers
WPSG_Security_Headers::get_instance();
