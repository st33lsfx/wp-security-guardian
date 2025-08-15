<?php
if (!defined('ABSPATH')) {
    exit;
}

// Get security status
$security_instance = WP_Security_Guardian::get_instance();
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
    'user_enum_blocked' => get_option('wpsg_block_user_enumeration', false),
    'malware_scanning' => get_option('wpsg_malware_scanning', false),
    'file_integrity_monitoring' => get_option('wpsg_file_integrity_monitoring', false),
    'autopilot_enabled' => get_option('wpsg_autopilot_enabled', false)
);

$status = array(
    'total' => count($tests),
    'active' => count(array_filter($tests)),
    'percentage' => round((count(array_filter($tests)) / count($tests)) * 100)
);

// Determine security grade
$grade = 'F';
if ($status['percentage'] >= 95) $grade = 'A+';
elseif ($status['percentage'] >= 90) $grade = 'A';
elseif ($status['percentage'] >= 80) $grade = 'B';
elseif ($status['percentage'] >= 70) $grade = 'C';
elseif ($status['percentage'] >= 60) $grade = 'D';
elseif ($status['percentage'] >= 50) $grade = 'E';

$color = $status['percentage'] >= 80 ? 'green' : ($status['percentage'] >= 60 ? 'yellow' : 'red');
?>

<!-- Overall Security Score -->
<div class="wpsg-settings-card">
    <div class="wpsg-section-header">
        Celkový bezpečnostní stav
    </div>
    <div class="wpsg-setting-item">
        <div class="wpsg-setting-content">
            <div class="wpsg-setting-title" style="font-size: 18px; margin-bottom: 8px;">
                Aktuální stav zabezpečení vašeho webu
            </div>
            <div style="display: flex; align-items: center; gap: 20px; margin-top: 12px;">
                <div style="flex: 1;">
                    <div style="background: #f1f5f9; height: 20px; border-radius: 10px; overflow: hidden; position: relative;">
                        <div style="background: <?php echo $status['percentage'] >= 80 ? 'linear-gradient(90deg, #10b981, #065f46)' : ($status['percentage'] >= 60 ? 'linear-gradient(90deg, #f59e0b, #92400e)' : 'linear-gradient(90deg, #dc2626, #991b1b)'); ?>; height: 100%; width: <?php echo $status['percentage']; ?>%; border-radius: 10px; transition: width 0.8s ease;"></div>
                    </div>
                    <div style="display: flex; justify-content: space-between; margin-top: 8px; font-size: 12px; color: #64748b;">
                        <span><?php echo $status['active']; ?> z <?php echo $status['total']; ?> kontrol prošlo</span>
                        <span><?php echo $status['total'] - $status['active']; ?> vyžaduje pozornost</span>
                    </div>
                </div>
                <div style="text-align: right; min-width: 120px;">
                    <div style="font-size: 36px; font-weight: bold; color: <?php echo $status['percentage'] >= 80 ? '#10b981' : ($status['percentage'] >= 60 ? '#f59e0b' : '#dc2626'); ?>; line-height: 1;"><?php echo $status['percentage']; ?>%</div>
                    <div style="font-size: 14px; font-weight: 600; color: <?php echo $status['percentage'] >= 80 ? '#065f46' : ($status['percentage'] >= 60 ? '#92400e' : '#991b1b'); ?>; margin-top: 4px;">Grade <?php echo $grade; ?></div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Detailed Security Status Grid -->
<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-bottom: 32px;">

    <!-- WordPress Core Security -->
    <div class="wpsg-settings-card">
        <div class="wpsg-section-header">
            <div style="display: flex; align-items: center;">
                <div style="width: 40px; height: 40px; background: #dbeafe; border-radius: 8px; display: flex; align-items: center; justify-content: center; margin-right: 12px;">
                    <i class="fab fa-wordpress" style="color: #2563eb; font-size: 16px;"></i>
                </div>
                <h3 style="font-size: 16px; font-weight: 600; color: #1e293b; margin: 0;">WordPress Core</h3>
            </div>
        </div>

        <div class="wpsg-setting-item">
            <div class="wpsg-setting-content">
                <div style="display: flex; flex-direction: column; gap: 12px;">
                    <div style="display: flex; align-items: center; justify-content: space-between;">
                        <span style="font-size: 13px; color: #64748b;">Skrytí verze</span>
                        <span style="color: <?php echo $tests['wp_version_hidden'] ? '#10b981' : '#ef4444'; ?>;">
                            <i class="fas <?php echo $tests['wp_version_hidden'] ? 'fa-check-circle' : 'fa-times-circle'; ?>"></i>
                        </span>
                    </div>
                    <div style="display: flex; align-items: center; justify-content: space-between;">
                        <span style="font-size: 13px; color: #64748b;">Editace souborů</span>
                        <span style="color: <?php echo $tests['file_editing_disabled'] ? '#10b981' : '#ef4444'; ?>;">
                            <i class="fas <?php echo $tests['file_editing_disabled'] ? 'fa-check-circle' : 'fa-times-circle'; ?>"></i>
                        </span>
                    </div>
                    <div style="display: flex; align-items: center; justify-content: space-between;">
                        <span style="font-size: 13px; color: #64748b;">XML-RPC</span>
                        <span style="color: <?php echo $tests['xmlrpc_disabled'] ? '#10b981' : '#ef4444'; ?>;">
                            <i class="fas <?php echo $tests['xmlrpc_disabled'] ? 'fa-check-circle' : 'fa-times-circle'; ?>"></i>
                        </span>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Authentication & Access -->
    <div class="wpsg-settings-card">
        <div class="wpsg-section-header">
            <div style="display: flex; align-items: center;">
                <div style="width: 40px; height: 40px; background: #f3e8ff; border-radius: 8px; display: flex; align-items: center; justify-content: center; margin-right: 12px;">
                    <i class="fas fa-key" style="color: #9333ea; font-size: 16px;"></i>
                </div>
                <h3 style="font-size: 16px; font-weight: 600; color: #1e293b; margin: 0;">Autentifikace</h3>
            </div>
        </div>

        <div class="wpsg-setting-item">
            <div class="wpsg-setting-content">
                <div style="display: flex; flex-direction: column; gap: 12px;">
                    <div style="display: flex; align-items: center; justify-content: space-between;">
                        <span style="font-size: 13px; color: #64748b;">2FA systém</span>
                        <span style="color: <?php echo $tests['2fa_active'] ? '#10b981' : '#ef4444'; ?>;">
                            <i class="fas <?php echo $tests['2fa_active'] ? 'fa-check-circle' : 'fa-times-circle'; ?>"></i>
                        </span>
                    </div>
                    <div style="display: flex; align-items: center; justify-content: space-between;">
                        <span style="font-size: 13px; color: #64748b;">Omezení přihlášení</span>
                        <span style="color: <?php echo $tests['login_limiting_active'] ? '#10b981' : '#ef4444'; ?>;">
                            <i class="fas <?php echo $tests['login_limiting_active'] ? 'fa-check-circle' : 'fa-times-circle'; ?>"></i>
                        </span>
                    </div>
                    <div style="display: flex; align-items: center; justify-content: space-between;">
                        <span style="font-size: 13px; color: #64748b;">Blokování enumerace</span>
                        <span style="color: <?php echo $tests['user_enum_blocked'] ? '#10b981' : '#ef4444'; ?>;">
                            <i class="fas <?php echo $tests['user_enum_blocked'] ? 'fa-check-circle' : 'fa-times-circle'; ?>"></i>
                        </span>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Network & Headers -->
    <div class="wpsg-settings-card">
        <div class="wpsg-section-header">
            <div style="display: flex; align-items: center;">
                <div style="width: 40px; height: 40px; background: #dcfce7; border-radius: 8px; display: flex; align-items: center; justify-content: center; margin-right: 12px;">
                    <i class="fas fa-network-wired" style="color: #16a34a; font-size: 16px;"></i>
                </div>
                <h3 style="font-size: 16px; font-weight: 600; color: #1e293b; margin: 0;">Síť & Headers</h3>
            </div>
        </div>

        <div class="wpsg-setting-item">
            <div class="wpsg-setting-content">
                <div style="display: flex; flex-direction: column; gap: 12px;">
                    <div style="display: flex; align-items: center; justify-content: space-between;">
                        <span style="font-size: 13px; color: #64748b;">Security Headers</span>
                        <span style="color: <?php echo $tests['security_headers_active'] ? '#10b981' : '#ef4444'; ?>;">
                            <i class="fas <?php echo $tests['security_headers_active'] ? 'fa-check-circle' : 'fa-times-circle'; ?>"></i>
                        </span>
                    </div>
                    <div style="display: flex; align-items: center; justify-content: space-between;">
                        <span style="font-size: 13px; color: #64748b;">SSL Monitor</span>
                        <span style="color: <?php echo $tests['ssl_monitor_active'] ? '#10b981' : '#ef4444'; ?>;">
                            <i class="fas <?php echo $tests['ssl_monitor_active'] ? 'fa-check-circle' : 'fa-times-circle'; ?>"></i>
                        </span>
                    </div>
                    <div style="display: flex; align-items: center; justify-content: space-between;">
                        <span style="font-size: 13px; color: #64748b;">IP Blokování</span>
                        <span style="color: <?php echo $tests['ip_blocking_active'] ? '#10b981' : '#ef4444'; ?>;">
                            <i class="fas <?php echo $tests['ip_blocking_active'] ? 'fa-check-circle' : 'fa-times-circle'; ?>"></i>
                        </span>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Monitoring & Scanning -->
    <div class="wpsg-settings-card">
        <div class="wpsg-section-header">
            <div style="display: flex; align-items: center;">
                <div style="width: 40px; height: 40px; background: #fecaca; border-radius: 8px; display: flex; align-items: center; justify-content: center; margin-right: 12px;">
                    <i class="fas fa-search" style="color: #dc2626; font-size: 16px;"></i>
                </div>
                <h3 style="font-size: 16px; font-weight: 600; color: #1e293b; margin: 0;">Monitorování</h3>
            </div>
        </div>

        <div class="wpsg-setting-item">
            <div class="wpsg-setting-content">
                <div style="display: flex; flex-direction: column; gap: 12px;">
                    <div style="display: flex; align-items: center; justify-content: space-between;">
                        <span style="font-size: 13px; color: #64748b;">Malware scanning</span>
                        <span style="color: <?php echo $tests['malware_scanning'] ? '#10b981' : '#ef4444'; ?>;">
                            <i class="fas <?php echo $tests['malware_scanning'] ? 'fa-check-circle' : 'fa-times-circle'; ?>"></i>
                        </span>
                    </div>
                    <div style="display: flex; align-items: center; justify-content: space-between;">
                        <span style="font-size: 13px; color: #64748b;">Integrita souborů</span>
                        <span style="color: <?php echo $tests['file_integrity_monitoring'] ? '#10b981' : '#ef4444'; ?>;">
                            <i class="fas <?php echo $tests['file_integrity_monitoring'] ? 'fa-check-circle' : 'fa-times-circle'; ?>"></i>
                        </span>
                    </div>
                    <div style="display: flex; align-items: center; justify-content: space-between;">
                        <span style="font-size: 13px; color: #64748b;">404 Tracking</span>
                        <span style="color: <?php echo $tests['404_tracking_active'] ? '#10b981' : '#ef4444'; ?>;">
                            <i class="fas <?php echo $tests['404_tracking_active'] ? 'fa-check-circle' : 'fa-times-circle'; ?>"></i>
                        </span>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- AI & Automation -->
    <div class="wpsg-settings-card">
        <div class="wpsg-section-header">
            <div style="display: flex; align-items: center;">
                <div style="width: 40px; height: 40px; background: #e0e7ff; border-radius: 8px; display: flex; align-items: center; justify-content: center; margin-right: 12px;">
                    <i class="fas fa-robot" style="color: #4f46e5; font-size: 16px;"></i>
                </div>
                <h3 style="font-size: 16px; font-weight: 600; color: #1e293b; margin: 0;">AI Autopilot</h3>
            </div>
        </div>

        <div class="wpsg-setting-item">
            <div class="wpsg-setting-content">
                <div style="display: flex; flex-direction: column; gap: 12px;">
                    <div style="display: flex; align-items: center; justify-content: space-between;">
                        <span style="font-size: 13px; color: #64748b;">Autopilot aktivní</span>
                        <span style="color: <?php echo $tests['autopilot_enabled'] ? '#10b981' : '#ef4444'; ?>;">
                            <i class="fas <?php echo $tests['autopilot_enabled'] ? 'fa-check-circle' : 'fa-times-circle'; ?>"></i>
                        </span>
                    </div>
                    <div style="display: flex; align-items: center; justify-content: space-between;">
                        <span style="font-size: 13px; color: #64748b;">Auto blokování</span>
                        <span style="color: <?php echo get_option('wpsg_autopilot_auto_block_ips', false) ? '#10b981' : '#ef4444'; ?>;">
                            <i class="fas <?php echo get_option('wpsg_autopilot_auto_block_ips', false) ? 'fa-check-circle' : 'fa-times-circle'; ?>"></i>
                        </span>
                    </div>
                    <div style="display: flex; align-items: center; justify-content: space-between;">
                        <span style="font-size: 13px; color: #64748b;">Adaptivní učení</span>
                        <span style="color: <?php echo get_option('wpsg_autopilot_adaptive_learning', false) ? '#10b981' : '#ef4444'; ?>;">
                            <i class="fas <?php echo get_option('wpsg_autopilot_adaptive_learning', false) ? 'fa-check-circle' : 'fa-times-circle'; ?>"></i>
                        </span>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Quick Actions -->
    <div class="wpsg-settings-card" style="background: linear-gradient(135deg, rgba(59,130,246,0.1) 0%, rgba(139,92,246,0.1) 100%); border: 1px solid rgba(59,130,246,0.3);">
        <div class="wpsg-section-header" style="background: transparent; border-bottom: 1px solid rgba(59,130,246,0.2);">
            <div style="display: flex; align-items: center;">
                <div style="width: 40px; height: 40px; background: #3b82f6; border-radius: 8px; display: flex; align-items: center; justify-content: center; margin-right: 12px;">
                    <i class="fas fa-bolt" style="color: white; font-size: 16px;"></i>
                </div>
                <h3 style="font-size: 16px; font-weight: 600; color: #1e293b; margin: 0;">Rychlé akce</h3>
            </div>
        </div>

        <div class="wpsg-setting-item">
            <div class="wpsg-setting-content" style="margin-right: 0;">
                <div style="display: flex; flex-direction: column; gap: 12px;">
                    <button id="quick-security-scan" class="wpsg-test-button" style="width: 100%; background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%); font-size: 13px; padding: 10px 16px;">
                        <i class="fas fa-search" style="margin-right: 6px;"></i>
                        Rychlý scan
                    </button>
                    <button id="update-security-rules" class="wpsg-test-button" style="width: 100%; background: linear-gradient(135deg, #8b5cf6 0%, #7c3aed 100%); font-size: 13px; padding: 10px 16px;">
                        <i class="fas fa-sync" style="margin-right: 6px;"></i>
                        Aktualizovat pravidla
                    </button>
                    <button id="export-security-report" class="wpsg-test-button" style="width: 100%; background: linear-gradient(135deg, #10b981 0%, #059669 100%); font-size: 13px; padding: 10px 16px;">
                        <i class="fas fa-download" style="margin-right: 6px;"></i>
                        Export reportu
                    </button>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Recommendations Section -->
<?php if ($status['percentage'] < 90): ?>
    <div class="wpsg-settings-card" style="background: #fffbeb; border: 1px solid #fed7aa; margin-bottom: 32px;">
        <div class="wpsg-section-header" style="background: transparent; border-bottom: 1px solid #fbbf24; color: #92400e;">
            <div style="display: flex; align-items: flex-start;">
                <div style="width: 32px; height: 32px; background: #fef3c7; border-radius: 8px; display: flex; align-items: center; justify-content: center; margin-right: 12px; margin-top: 2px;">
                    <i class="fas fa-lightbulb" style="color: #d97706; font-size: 14px;"></i>
                </div>
                <div>
                    <h3 style="font-size: 16px; font-weight: 600; color: #92400e; margin: 0 0 12px 0;">Doporučení pro zlepšení zabezpečení</h3>
                    <ul style="display: flex; flex-direction: column; gap: 8px; margin: 0; padding: 0; list-style: none;">
                        <?php if (!$tests['wp_version_hidden']): ?>
                            <li style="display: flex; align-items: center; color: #a16207;">
                                <i class="fas fa-arrow-right" style="margin-right: 8px; color: #d97706; font-size: 12px;"></i>
                                Zapněte skrývání verze WordPressu v nastavení zabezpečení
                            </li>
                        <?php endif; ?>
                        <?php if (!$tests['file_editing_disabled']): ?>
                            <li style="display: flex; align-items: center; color: #a16207;">
                                <i class="fas fa-arrow-right" style="margin-right: 8px; color: #d97706; font-size: 12px;"></i>
                                Zakažte editaci souborů z admin rozhraní
                            </li>
                        <?php endif; ?>
                        <?php if (!$tests['2fa_active']): ?>
                            <li style="display: flex; align-items: center; color: #a16207;">
                                <i class="fas fa-arrow-right" style="margin-right: 8px; color: #d97706; font-size: 12px;"></i>
                                Aktivujte 2FA pro administrátorské účty
                            </li>
                        <?php endif; ?>
                        <?php if (!$tests['autopilot_enabled']): ?>
                            <li style="display: flex; align-items: center; color: #a16207;">
                                <i class="fas fa-arrow-right" style="margin-right: 8px; color: #d97706; font-size: 12px;"></i>
                                Zapněte AI Autopilot pro automatickou ochranu
                            </li>
                        <?php endif; ?>
                    </ul>
                </div>
            </div>
        </div>
    </div>
<?php endif; ?>

<script>
    jQuery(document).ready(function($) {
        // Quick actions handlers
        $('#quick-security-scan').click(function() {
            const $btn = $(this);
            const originalText = $btn.html();

            $btn.html('<i class="fas fa-spinner fa-spin mr-2"></i>Skenování...').prop('disabled', true);

            wpsgAjaxRequest('wpsg_security_score', {},
                function(data) {
                    $btn.html('<i class="fas fa-check mr-2"></i>Dokončeno!');
                    setTimeout(() => {
                        $btn.html(originalText).prop('disabled', false);
                        location.reload();
                    }, 2000);
                },
                function() {
                    $btn.html(originalText).prop('disabled', false);
                }
            );
        });

        $('#update-security-rules').click(function() {
            const $btn = $(this);
            const originalText = $btn.html();

            $btn.html('<i class="fas fa-spinner fa-spin mr-2"></i>Aktualizuji...').prop('disabled', true);

            // Simulate rule update - you can replace this with actual AJAX call
            setTimeout(() => {
                showToast('Bezpečnostní pravidla aktualizována!', 'success');
                $btn.html('<i class="fas fa-check mr-2"></i>Aktualizováno!');
                setTimeout(() => {
                    $btn.html(originalText).prop('disabled', false);
                }, 2000);
            }, 3000);
        });

        $('#export-security-report').click(function() {
            const $btn = $(this);
            const originalText = $btn.html();

            $btn.html('<i class="fas fa-spinner fa-spin mr-2"></i>Exportuji...').prop('disabled', true);

            // Create downloadable report
            const reportData = {
                timestamp: new Date().toISOString(),
                site: '<?php echo home_url(); ?>',
                score: <?php echo $status['percentage']; ?>,
                grade: '<?php echo $grade; ?>',
                tests: <?php echo json_encode($tests); ?>
            };

            const blob = new Blob([JSON.stringify(reportData, null, 2)], {
                type: 'application/json'
            });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'security-report-' + new Date().toISOString().split('T')[0] + '.json';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);

            $btn.html('<i class="fas fa-check mr-2"></i>Exportováno!');
            setTimeout(() => {
                $btn.html(originalText).prop('disabled', false);
            }, 2000);
        });
    });
</script>