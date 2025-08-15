<?php
if (!defined('ABSPATH')) {
    exit;
}

// Dočasně vypnout CSP pro tuto stránku kvůli stylingům
if (function_exists('header_remove')) {
    header_remove('Content-Security-Policy');
}

// AJAX zpracování je v hlavním souboru pluginu

// Získat aktuální nastavení
$settings = [
    'basic_security' => [
        'title' => 'Základní zabezpečení',
        'items' => [
            'wpsg_hide_wp_version' => [
                'title' => 'Skrýt verzi WordPressu',
                'description' => 'Odstraní verzi WP z kódu stránky',
                'default' => true,
                'current' => get_option('wpsg_hide_wp_version', true)
            ],
            'wpsg_disable_file_editing' => [
                'title' => 'Zakázat úpravy souborů',
                'description' => 'Zakáže vestavěné editory souborů',
                'default' => true,
                'current' => get_option('wpsg_disable_file_editing', true)
            ],
            'wpsg_disable_xmlrpc' => [
                'title' => 'Zakázat XML-RPC',
                'description' => 'Vypne XML-RPC API pro bezpečnost',
                'default' => true,
                'current' => get_option('wpsg_disable_xmlrpc', true)
            ],
            'wpsg_remove_generator_tag' => [
                'title' => 'Unset X-Powered-By header',
                'description' => 'Odstraní server identifikační hlavičky',
                'default' => true,
                'current' => get_option('wpsg_remove_generator_tag', true)
            ]
        ]
    ],
    'login_security' => [
        'title' => 'Zabezpečení přihlašování',
        'items' => [
            'wpsg_require_2fa' => [
                'title' => 'Zabránit zpětné vazby na přihlášení',
                'description' => 'Vyžaduje 2FA pro administrátory',
                'default' => false,
                'current' => get_option('wpsg_require_2fa', 'admin_only') !== 'disabled'
            ],
            'wpsg_limit_login_attempts' => [
                'title' => 'Zakázat procházení adresářů',
                'description' => 'Omezí počet pokusů o přihlášení',
                'default' => true,
                'current' => get_option('wpsg_limit_login_attempts', true)
            ],
            'wpsg_block_user_enumeration' => [
                'title' => 'Zakázat výčet uživatelů',
                'description' => 'Blokuje pokusy o zjišťování uživatelských jmen',
                'default' => true,
                'current' => get_option('wpsg_block_user_enumeration', true)
            ],
            'wpsg_disable_login_hints' => [
                'title' => 'Blokovat uživatelské jméno "admin"',
                'description' => 'Odstraní nápovědy při neúspěšném přihlášení',
                'default' => true,
                'current' => get_option('wpsg_disable_login_hints', true)
            ]
        ]
    ],
    'headers_security' => [
        'title' => 'HTTP Security Headers',
        'items' => [
            'wpsg_security_headers_enabled' => [
                'title' => '🛡️ Aktivovat všechny bezpečnostní hlavičky',
                'description' => 'Globální zapnutí/vypnutí všech HTTP bezpečnostních hlaviček',
                'default' => true,
                'current' => get_option('wpsg_security_headers_enabled', true)
            ],
            'wpsg_force_ssl' => [
                'title' => 'Aktivovat SSL/HTTPS',
                'description' => 'Vynucuje HTTPS na celém webu',
                'default' => false,
                'current' => get_option('wpsg_force_ssl', false)
            ],
            'wpsg_hsts_enabled' => [
                'title' => 'Aktivovat HSTS',
                'description' => 'HTTP Strict Transport Security',
                'default' => false,
                'current' => get_option('wpsg_hsts_enabled', false)
            ],
            'wpsg_csp_enabled' => [
                'title' => 'Content Security Policy',
                'description' => 'Ochrana proti XSS útokům',
                'default' => true,
                'current' => get_option('wpsg_csp_enabled', true)
            ],
            'wpsg_x_frame_options' => [
                'title' => 'X-Frame-Options',
                'description' => 'Ochrana proti clickjacking',
                'default' => true,
                'current' => get_option('wpsg_x_frame_options', true)
            ],
            'wpsg_x_xss_protection' => [
                'title' => 'X-XSS-Protection',
                'description' => 'XSS ochrana pro starší prohlížeče',
                'default' => true,
                'current' => get_option('wpsg_x_xss_protection', true)
            ],
            'wpsg_x_content_type_options' => [
                'title' => 'X-Content-Type-Options',
                'description' => 'Zabraňuje MIME type sniffing',
                'default' => true,
                'current' => get_option('wpsg_x_content_type_options', true)
            ],
            'wpsg_referrer_policy' => [
                'title' => 'Referrer Policy',
                'description' => 'Kontroluje informace v referrer hlavičce',
                'default' => true,
                'current' => get_option('wpsg_referrer_policy', true)
            ]
        ]
    ],
    'server_security' => [
        'title' => 'Server Security',
        'items' => [
            'wpsg_protect_wp_config' => [
                'title' => 'wp-config.php chráněn proti přímému přístupu',
                'description' => 'Blokuje přímý přístup k wp-config.php přes HTTP',
                'default' => true,
                'current' => (class_exists('WP_Security_Guardian') && WP_Security_Guardian::get_instance()->is_htaccess_protection_active('wp_config')) && get_option('wpsg_protect_wp_config', false)
            ],
            'wpsg_disable_directory_browsing' => [
                'title' => 'Directory browsing zakázáno',
                'description' => 'Zabraňuje zobrazování obsahu adresářů',
                'default' => true,
                'current' => (class_exists('WP_Security_Guardian') && WP_Security_Guardian::get_instance()->is_htaccess_protection_active('directory_browsing')) && get_option('wpsg_disable_directory_browsing', false)
            ],
            'wpsg_https_admin_force' => [
                'title' => 'HTTPS pro admin',
                'description' => 'Vynucuje HTTPS pro admin oblast',
                'default' => false,
                'current' => (class_exists('WP_Security_Guardian') && WP_Security_Guardian::get_instance()->is_htaccess_protection_active('https_admin')) && get_option('wpsg_https_admin_force', false)
            ],
            'wpsg_protect_sensitive_files' => [
                'title' => 'Chránit citlivé soubory',
                'description' => 'Blokuje přístup k .htaccess, wp-config-sample.php, atd.',
                'default' => true,
                'current' => (class_exists('WP_Security_Guardian') && WP_Security_Guardian::get_instance()->is_htaccess_protection_active('sensitive_files')) && get_option('wpsg_protect_sensitive_files', false)
            ],
            'wpsg_protect_uploads' => [
                'title' => 'Uploads složka chráněna',
                'description' => 'Blokuje spouštění PHP souborů v uploads složce',
                'default' => true,
                'current' => (class_exists('WP_Security_Guardian') && WP_Security_Guardian::get_instance()->is_uploads_protection_active()) && get_option('wpsg_protect_uploads', false)
            ]
        ]
    ],
    'advanced_protection' => [
        'title' => 'Pokročilá ochrana',
        'items' => [
            'wpsg_autopilot_enabled' => [
                'title' => 'Auto-Pilot ochrana',
                'description' => 'AI-powered automatická detekce hrozeb',
                'default' => false,
                'current' => get_option('wpsg_autopilot_enabled', false)
            ],
            'wpsg_malware_scanning' => [
                'title' => 'Malware scanning',
                'description' => 'Pravidelné skenování souborů',
                'default' => true,
                'current' => get_option('wpsg_malware_scanning', true)
            ],
            'wpsg_file_integrity_monitoring' => [
                'title' => 'File Integrity Monitor',
                'description' => 'Sledování změn v souborech',
                'default' => true,
                'current' => get_option('wpsg_file_integrity_monitoring', true)
            ],
            'wpsg_ip_blocking' => [
                'title' => 'Automatické blokování IP',
                'description' => 'Blokuje podezřelé IP adresy',
                'default' => true,
                'current' => get_option('wpsg_ip_blocking', true)
            ]
        ]
    ]
];
?>

<script src="https://cdn.tailwindcss.com"></script>

<style>
    .wpsg-settings-wrap {
        margin: 20px 20px 0 2px;
        background: #f0f0f1;
        min-height: calc(100vh - 32px);
    }

    .wpsg-toggle-switch {
        position: relative;
        display: inline-block;
        width: 44px;
        height: 24px;
        margin-left: auto;
    }

    .wpsg-toggle-switch input {
        opacity: 0;
        width: 0;
        height: 0;
    }

    .wpsg-toggle-slider {
        position: absolute;
        cursor: pointer;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background-color: #cbd5e0;
        transition: .3s;
        border-radius: 24px;
    }

    .wpsg-toggle-slider:before {
        position: absolute;
        content: "";
        height: 18px;
        width: 18px;
        left: 3px;
        bottom: 3px;
        background-color: white;
        transition: .3s;
        border-radius: 50%;
    }

    input:checked+.wpsg-toggle-slider {
        background-color: #4299e1;
    }

    input:checked+.wpsg-toggle-slider:before {
        transform: translateX(20px);
    }

    .wpsg-settings-card {
        background: white;
        border-radius: 16px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
        margin-bottom: 20px;
        transition: all 0.3s ease;
    }

    .wpsg-settings-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
    }

    .wpsg-setting-item {
        padding: 16px 20px;
        border-bottom: 1px solid #f1f5f9;
        display: flex;
        align-items: center;
        justify-content: between;
    }

    .wpsg-setting-item:last-child {
        border-bottom: none;
    }

    .wpsg-setting-item:hover {
        background-color: #f8fafc;
    }

    .wpsg-setting-content {
        flex: 1;
        margin-right: 16px;
    }

    .wpsg-setting-title {
        font-weight: 600;
        color: #1e293b;
        font-size: 14px;
        margin-bottom: 4px;
    }

    .wpsg-setting-description {
        font-size: 13px;
        color: #64748b;
        line-height: 1.4;
    }

    .wpsg-section-header {
        background: #f8fafc;
        padding: 16px 20px;
        border-bottom: 1px solid #e5e7eb;
        font-weight: 600;
        color: #374151;
        font-size: 15px;
    }

    .wpsg-loading {
        opacity: 0.6;
        pointer-events: none;
    }

    .wpsg-pro-badge {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        font-size: 10px;
        font-weight: 600;
        padding: 2px 6px;
        border-radius: 10px;
        text-transform: uppercase;
        margin-left: 8px;
    }

    .wpsg-toast {
        position: fixed;
        top: 32px;
        right: 20px;
        background: #059669;
        color: white;
        padding: 12px 16px;
        border-radius: 6px;
        font-size: 14px;
        font-weight: 500;
        z-index: 999999;
        transform: translateX(400px);
        transition: transform 0.3s ease;
    }

    .wpsg-toast.show {
        transform: translateX(0);
    }

    @media (max-width: 1200px) {
        .wpsg-settings-main-grid {
            grid-template-columns: 1fr !important;
        }
    }

    @media (max-width: 768px) {
        .wpsg-settings-wrap {
            margin: 20px 10px 0 2px !important;
        }
    }
</style>

<script src="https://cdn.jsdelivr.net/npm/apexcharts"></script>

<div class="wrap">
    <h1>🔧 Security Settings</h1>

    <div class="wpsg-settings-wrap">
        <div style="max-width: 1400px; margin: 0 auto; padding: 20px;">

            <!-- Header Section -->
            <div class="wpsg-gradient-header" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);padding: 32px;border-radius: 16px;margin-bottom: 32px;position: relative;overflow: hidden;color: #fff;">
                <div style="display: flex; align-items: flex-end; justify-content: space-between; flex-wrap: wrap; gap: 16px;">
                    <div style="display: flex;flex-direction: column;gap: 1rem;">
                        <h2 style="font-size: 24px; font-weight: 700;color:#fff;margin: 0; text-shadow: 0 2px 4px rgba(0,0,0,0.3);">Bezpečnostní nastavení</h2>
                        <p style="font-size: 14px; opacity: 0.9; margin: 8px 0 0 0;">Zapněte nebo vypněte jednotlivé bezpečnostní funkce podle vašich potřeb</p>
                    </div>
                    <div style="text-align: right;">
                        <div style="font-size: 12px; opacity: 0.8;">Aktivní nastavení</div>
                        <div id="active-settings-count" style="font-size: 14px; font-weight: 600;">-</div>
                    </div>
                </div>
            </div>

            <!-- Main Grid Layout -->
            <div style="display: grid; grid-template-columns: 2fr 1fr; gap: 24px;" class="wpsg-settings-main-grid">

                <!-- Left Column - Settings Sections -->
                <div>
                    <?php foreach ($settings as $section_key => $section): ?>
                        <!-- <?php echo esc_html($section['title']); ?> -->
                        <div class="wpsg-settings-card">
                            <div class="wpsg-section-header">
                                <?php echo esc_html($section['title']); ?>
                            </div>

                            <?php foreach ($section['items'] as $setting_key => $setting): ?>
                                <div class="wpsg-setting-item" data-setting="<?php echo esc_attr($setting_key); ?>">
                                    <div class="wpsg-setting-content">
                                        <div class="wpsg-setting-title">
                                            <?php echo esc_html($setting['title']); ?>
                                            <?php if (in_array($setting_key, ['wpsg_autopilot_enabled', 'wpsg_malware_scanning'])): ?>
                                                <span class="wpsg-pro-badge">Pro</span>
                                            <?php endif; ?>
                                        </div>
                                        <div class="wpsg-setting-description">
                                            <?php echo esc_html($setting['description']); ?>
                                        </div>
                                    </div>
                                    <div class="wpsg-setting-toggle">
                                        <label class="wpsg-toggle-switch">
                                            <input type="checkbox"
                                                data-setting="<?php echo esc_attr($setting_key); ?>"
                                                <?php checked($setting['current']); ?>>
                                            <span class="wpsg-toggle-slider"></span>
                                        </label>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    <?php endforeach; ?>

                    <!-- 404 Blocking Section -->
                    <div class="wpsg-settings-card">
                        <div class="wpsg-section-header">
                            404 Blocking
                        </div>
                        <div style="padding: 20px; background: #f8fafc;">
                            <p style="color: #64748b; font-size: 14px; margin: 0 0 16px 0;">
                                Crawlers might scan your site looking for possible exploits. One way to detect this is the fact that they trigger more 404 (not found) errors than legitimate visitors would. Below you can set the threshold and lockout duration for 404 blocking.
                            </p>
                            <div style="display: flex; gap: 16px; align-items: center;">
                                <div>
                                    <label style="font-size: 13px; color: #374151; margin-bottom: 4px; display: block;">Threshold:</label>
                                    <input type="number" value="<?php echo get_option('wpsg_404_threshold', 10); ?>"
                                        style="width: 80px; padding: 6px; border: 1px solid #d1d5db; border-radius: 4px;">
                                </div>
                                <div>
                                    <label style="font-size: 13px; color: #374151; margin-bottom: 4px; display: block;">Lockout (minutes):</label>
                                    <input type="number" value="<?php echo get_option('wpsg_404_lockout', 60); ?>"
                                        style="width: 80px; padding: 6px; border: 1px solid #d1d5db; border-radius: 4px;">
                                </div>
                                <button class="button-primary" id="save-404-settings" style="margin-top: 16px;">
                                    Save Settings
                                </button>
                            </div>
                        </div>
                    </div>
                </div> <!-- End left column -->

                <!-- Right Column - Security Score & Info -->
                <div>
                    <!-- Security Score -->
                    <div class="wpsg-settings-card" style="padding: 24px; text-align: center;">
                        <h3 style="font-size: 20px; font-weight: 700; color: #1e293b; margin: 0 0 20px 0;">Security Score</h3>

                        <div style="position: relative; width: 200px; height: 200px; margin: 0 auto;">
                            <div id="securityScoreChart"></div>
                            <div style="position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); text-align: center;">
                                <div id="security-score" style="font-size: 36px; padding-bottom: 1rem; font-weight: 800; color: #16a34a;">
                                    <?php
                                    $score = 0;
                                    $total_settings = 0;
                                    foreach ($settings as $section) {
                                        foreach ($section['items'] as $setting) {
                                            $total_settings++;
                                            if ($setting['current']) $score++;
                                        }
                                    }
                                    $percentage = $total_settings > 0 ? round(($score / $total_settings) * 100) : 0;
                                    echo $percentage . '%';
                                    ?>
                                </div>
                                <div style="font-size: 16px; color: #64748b; font-weight: 600;">
                                    <?php
                                    if ($percentage >= 90) echo 'VYNIKAJÍCÍ';
                                    elseif ($percentage >= 80) echo 'VÝBORNÉ';
                                    elseif ($percentage >= 70) echo 'DOBRÉ';
                                    elseif ($percentage >= 50) echo 'STŘEDNÍ';
                                    else echo 'SLABÉ';
                                    ?>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Debug hodnoty z databáze -->
                    <div class="wpsg-settings-card" style="padding: 20px; margin-top: 24px; background: #fff3cd; border-left: 4px solid #ffc107;">
                        <h4 style="margin: 0 0 16px 0; color: #856404;">🐛 Debug hodnoty z databáze</h4>
                        <div style="font-family: monospace; font-size: 12px; line-height: 1.6;">
                            <strong>wpsg_disable_file_editing:</strong> <?php echo get_option('wpsg_disable_file_editing', 'not_set') ? 'true' : 'false'; ?> (<?php var_dump(get_option('wpsg_disable_file_editing', 'not_set')); ?>)<br>
                            <strong>wpsg_security_headers_enabled:</strong> <?php echo get_option('wpsg_security_headers_enabled', 'not_set') ? 'true' : 'false'; ?> (<?php var_dump(get_option('wpsg_security_headers_enabled', 'not_set')); ?>)<br>
                            <strong>wpsg_hide_wp_version:</strong> <?php echo get_option('wpsg_hide_wp_version', 'not_set') ? 'true' : 'false'; ?> (<?php var_dump(get_option('wpsg_hide_wp_version', 'not_set')); ?>)<br>
                        </div>
                    </div>

                    <!-- Real Status Check -->
                    <?php
                    $security_instance = WP_Security_Guardian::get_instance();
                    $real_status = $security_instance->get_security_status();
                    ?>
                    <div class="wpsg-settings-card" style="padding: 20px; margin-top: 24px;">
                        <h4 style="margin: 0 0 16px 0; color: #1e293b;">Real Status Check</h4>
                        <div style="display: flex; flex-direction: column; gap: 8px; font-size: 12px;">
                            <div style="display: flex; justify-content: space-between;">
                                <span>WP Version Hidden:</span>
                                <span style="color: <?php echo $real_status['tests']['wp_version_hidden'] ? '#16a34a' : '#dc2626'; ?>;">
                                    <?php echo $real_status['tests']['wp_version_hidden'] ? '✅' : '❌'; ?>
                                </span>
                            </div>
                            <div style="display: flex; justify-content: space-between;">
                                <span>File Editing Blocked:</span>
                                <span style="color: <?php echo $real_status['tests']['file_editing_disabled'] ? '#16a34a' : '#dc2626'; ?>;">
                                    <?php echo $real_status['tests']['file_editing_disabled'] ? '✅' : '❌'; ?>
                                </span>
                            </div>
                            <div style="display: flex; justify-content: space-between;">
                                <span>XML-RPC Disabled:</span>
                                <span style="color: <?php echo $real_status['tests']['xmlrpc_disabled'] ? '#16a34a' : '#dc2626'; ?>;">
                                    <?php echo $real_status['tests']['xmlrpc_disabled'] ? '✅' : '❌'; ?>
                                </span>
                            </div>
                            <div style="display: flex; justify-content: space-between;">
                                <span>Login Protection:</span>
                                <span style="color: <?php echo $real_status['tests']['login_limiting_active'] ? '#16a34a' : '#dc2626'; ?>;">
                                    <?php echo $real_status['tests']['login_limiting_active'] ? '✅' : '❌'; ?>
                                </span>
                            </div>
                        </div>
                    </div>

                    <!-- Quick Stats -->
                    <div class="wpsg-settings-card" style="padding: 20px; margin-top: 24px;">
                        <h4 style="margin: 0 0 16px 0; color: #1e293b;">Rychlé statistiky</h4>
                        <div style="display: flex; flex-direction: column; gap: 12px;">
                            <div style="display: flex; justify-content: space-between; align-items: center;">
                                <span style="color: #64748b; font-size: 14px;">Aktivní funkce:</span>
                                <span id="active-features-count" style="font-weight: 600; color: #16a34a;"><?php echo $score; ?>/<?php echo $total_settings; ?></span>
                            </div>
                            <div style="display: flex; justify-content: space-between; align-items: center;">
                                <span style="color: #64748b; font-size: 14px;">2FA systém:</span>
                                <span style="color: <?php echo get_option('wpsg_require_2fa', 'disabled') !== 'disabled' ? '#16a34a' : '#dc2626'; ?>;">
                                    <?php echo get_option('wpsg_require_2fa', 'disabled') !== 'disabled' ? 'Aktivní' : 'Neaktivní'; ?>
                                </span>
                            </div>
                            <div style="display: flex; justify-content: space-between; align-items: center;">
                                <span style="color: #64748b; font-size: 14px;">SSL/HTTPS:</span>
                                <span style="color: <?php echo get_option('wpsg_force_ssl', false) ? '#16a34a' : '#dc2626'; ?>;">
                                    <?php echo get_option('wpsg_force_ssl', false) ? 'Vynuceno' : 'Volitelné'; ?>
                                </span>
                            </div>
                            <div style="display: flex; justify-content: space-between; align-items: center;">
                                <span style="color: #64748b; font-size: 14px;">Auto-Pilot:</span>
                                <span style="color: <?php echo get_option('wpsg_autopilot_enabled', false) ? '#16a34a' : '#64748b'; ?>;">
                                    <?php echo get_option('wpsg_autopilot_enabled', false) ? 'Aktivní' : 'Neaktivní'; ?>
                                </span>
                            </div>
                        </div>
                    </div>
                </div>
            </div> <!-- End main grid -->

        </div>
    </div>
</div>

<!-- Toast notification -->
<div id="wpsg-toast" class="wpsg-toast">
    Nastavení úspěšně uloženo
</div>

<script>
    // Definovat ajaxurl pro WordPress AJAX
    var ajaxurl = '<?php echo admin_url('admin-ajax.php'); ?>';

    document.addEventListener('DOMContentLoaded', function() {
        const toggles = document.querySelectorAll('.wpsg-toggle-switch input[type="checkbox"]');
        const toast = document.getElementById('wpsg-toast');

        // Initialize Security Score Chart
        const securityScore = <?php echo $percentage; ?>;
        const scoreChart = new ApexCharts(document.querySelector("#securityScoreChart"), {
            series: [securityScore],
            chart: {
                type: 'radialBar',
                height: 200,
                sparkline: {
                    enabled: true
                }
            },
            plotOptions: {
                radialBar: {
                    startAngle: -90,
                    endAngle: 90,
                    track: {
                        background: "#f1f5f9",
                        strokeWidth: '100%',
                        margin: 5,
                    },
                    dataLabels: {
                        show: false
                    },
                    hollow: {
                        margin: 15,
                        size: '70%',
                    }
                }
            },
            fill: {
                type: 'gradient',
                gradient: {
                    shade: 'light',
                    shadeIntensity: 0.4,
                    inverseColors: false,
                    opacityFrom: 1,
                    opacityTo: 1,
                    stops: [0, 50, 53, 91]
                }
            },
            colors: [securityScore >= 80 ? '#16a34a' : securityScore >= 60 ? '#f59e0b' : '#dc2626'],
            stroke: {
                lineCap: 'round'
            }
        });
        scoreChart.render();

        // Update active settings count
        document.getElementById('active-settings-count').textContent = document.querySelectorAll('.wpsg-toggle-switch input[type="checkbox"]:checked').length + '/<?php echo $total_settings; ?>';

        // Function to show toast
        function showToast(message) {
            toast.textContent = message;
            toast.classList.add('show');
            setTimeout(() => {
                toast.classList.remove('show');
            }, 3000);
        }

        // Function to update security score
        function updateSecurityScore() {
            const totalToggles = toggles.length;
            const enabledToggles = document.querySelectorAll('.wpsg-toggle-switch input[type="checkbox"]:checked').length;
            const percentage = Math.round((enabledToggles / totalToggles) * 100);

            // Update score display
            document.getElementById('security-score').textContent = percentage + '%';
            document.getElementById('active-features-count').textContent = enabledToggles + '/' + totalToggles;
            document.getElementById('active-settings-count').textContent = enabledToggles + '/' + totalToggles;

            // Update chart
            scoreChart.updateSeries([percentage]);

            // Update score color and rating
            const scoreElement = document.getElementById('security-score');
            const ratingElement = scoreElement.nextElementSibling;
            if (percentage >= 90) {
                scoreElement.style.color = '#16a34a';
                ratingElement.textContent = 'VYNIKAJÍCÍ';
            } else if (percentage >= 80) {
                scoreElement.style.color = '#16a34a';
                ratingElement.textContent = 'VÝBORNÉ';
            } else if (percentage >= 70) {
                scoreElement.style.color = '#f59e0b';
                ratingElement.textContent = 'DOBRÉ';
            } else if (percentage >= 50) {
                scoreElement.style.color = '#f59e0b';
                ratingElement.textContent = 'STŘEDNÍ';
            } else {
                scoreElement.style.color = '#dc2626';
                ratingElement.textContent = 'SLABÉ';
            }
        }

        // Handle toggle changes
        toggles.forEach(toggle => {
            toggle.addEventListener('change', function() {
                const settingItem = this.closest('.wpsg-setting-item');
                const settingKey = this.getAttribute('data-setting');
                const settingValue = this.checked;
                const toggleEl = this;
                const originalValue = !settingValue; // Store original state (opposite of new value)

                // Add loading state
                settingItem.classList.add('wpsg-loading');
                // prevent double clicks during request
                toggleEl.disabled = true;

                // Map value(s) for special settings; fall back to 1/0
                const valueMap = {
                    'wpsg_require_2fa': settingValue ? 'admin_only' : 'disabled',
                };
                let valueToSend = Object.prototype.hasOwnProperty.call(valueMap, settingKey) ?
                    valueMap[settingKey] :
                    (settingValue ? '1' : '0');

                // Send AJAX request
                console.log('Sending AJAX request:', {
                    action: 'wpsg_toggle_setting',
                    setting_key: settingKey,
                    setting_value: valueToSend,
                    nonce: '<?php echo wp_create_nonce('wpsg_settings_nonce'); ?>'
                });

                fetch(ajaxurl, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded',
                        },
                        body: new URLSearchParams({
                            action: 'wpsg_toggle_setting',
                            setting_key: settingKey,
                            setting_value: valueToSend,
                            nonce: '<?php echo wp_create_nonce('wpsg_settings_nonce'); ?>'
                        })
                    })
                    .then(response => {
                        console.log('Response status:', response.status);
                        console.log('Response headers:', response.headers);
                        return response.text().then(text => {
                            console.log('Raw response:', text);
                            try {
                                return JSON.parse(text);
                            } catch (e) {
                                console.error('JSON parse error:', e);
                                throw new Error('Neplatná odpověď ze serveru: ' + text);
                            }
                        });
                    })
                    .then(data => {
                        console.log('Parsed data:', data);
                        settingItem.classList.remove('wpsg-loading');

                        if (data.success) {
                            showToast('Nastavení úspěšně uloženo');
                            updateSecurityScore();

                            // Special handling for some settings
                            if (settingKey === 'wpsg_force_ssl' && settingValue) {
                                showToast('HTTPS bude vynucen při příští návštěvě stránky');
                            }
                            if (settingKey === 'wpsg_autopilot_enabled' && settingValue) {
                                showToast('Auto-Pilot aktivován - AI ochrana je nyní aktivní');
                            }
                            if (settingKey === 'wpsg_disable_file_editing') {
                                showToast('Nastavení uloženo - bude aktivní při příštím načtení stránky');
                            }
                            if (settingKey === 'wpsg_security_headers_enabled') {
                                showToast('Bezpečnostní hlavičky ' + (settingValue ? 'zapnuty' : 'vypnuty') + ' - efekt při příštím načtení');
                            }
                        } else {
                            console.error('AJAX error:', data.data);
                            showToast('Chyba: ' + (data.data || 'Neznámá chyba'));
                            // Revert toggle state
                            this.checked = originalValue;
                        }
                    })
                    .catch(error => {
                        console.error('Network error:', error);
                        settingItem.classList.remove('wpsg-loading');
                        showToast('Chyba při ukládání nastavení: ' + error.message);
                        // Revert toggle state
                        this.checked = originalValue;
                    })
                    .finally(() => {
                        settingItem.classList.remove('wpsg-loading');
                        toggleEl.disabled = false;
                    });
            });
        });

        // Handle 404 settings
        document.getElementById('save-404-settings').addEventListener('click', function() {
            const threshold = document.querySelector('input[type="number"]').value;
            const lockout = document.querySelectorAll('input[type="number"]')[1].value;

            fetch(ajaxurl, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: new URLSearchParams({
                        action: 'wpsg_save_404_settings',
                        threshold: threshold,
                        lockout: lockout,
                        nonce: '<?php echo wp_create_nonce('wpsg_settings_nonce'); ?>'
                    })
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        showToast('404 blocking nastavení uloženo');
                    } else {
                        showToast('Chyba při ukládání 404 nastavení');
                    }
                });
        });
    });
</script>