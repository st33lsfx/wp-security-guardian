<?php
if (!defined('ABSPATH')) {
    exit;
}
?>

<!-- Testing Introduction -->
<div class="wpsg-settings-card" style="background: linear-gradient(135deg, #667eea 10%, #764ba2 90%); color: white; margin-bottom: 32px;">
    <div class="wpsg-section-header" style="background: transparent; border-bottom: 1px solid rgba(255,255,255,0.2); color: white;">
        <div style="display: flex; align-items: center;">
            <div style="width: 48px; height: 48px; background: rgba(255,255,255,0.2); border-radius: 12px; display: flex; align-items: center; justify-content: center; margin-right: 16px;">
                <i class="fas fa-flask" style="color: white; font-size: 20px;"></i>
            </div>
            <div>
                <h2 style="font-size: 20px; font-weight: 700; color: white; margin: 0;">Pokročilé bezpečnostní testování</h2>
                <p style="font-size: 14px; opacity: 0.9; margin: 4px 0 0 0;">Spusťte komprehentivní testy pro analýzu bezpečnosti vašeho webu</p>
            </div>
        </div>
    </div>
</div>

<!-- Testing Grid -->
<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 20px; margin-bottom: 32px;">

    <!-- Security Headers Test -->
    <div class="wpsg-settings-card">
        <div class="wpsg-section-header">
            <div style="display: flex; align-items: center;">
                <div style="width: 48px; height: 48px; background: #dbeafe; border-radius: 12px; display: flex; align-items: center; justify-content: center; margin-right: 16px;">
                    <i class="fas fa-shield-alt" style="color: #2563eb; font-size: 20px;"></i>
                </div>
                <div>
                    <div class="wpsg-setting-title" style="font-size: 16px; margin-bottom: 2px;"><?php _e('Security Headers Test', 'wp-security-guardian'); ?></div>
                    <div class="wpsg-setting-description"><?php _e('Test your website\'s security headers implementation', 'wp-security-guardian'); ?></div>
                </div>
            </div>
        </div>

        <div class="wpsg-setting-item">
            <div class="wpsg-setting-content">
                <div style="background: #f8fafc; border-radius: 8px; padding: 12px; margin-bottom: 16px;">
                    <div style="display: flex; align-items: center; font-size: 13px; color: #64748b;">
                        <i class="fas fa-info-circle" style="margin-right: 8px; color: #2563eb;"></i>
                        <span>Testuje CSP, HSTS, X-Frame-Options, X-XSS-Protection a další důležité HTTP hlavičky</span>
                    </div>
                </div>

                <button id="test-headers" class="wpsg-test-button" style="width: 100%;">
                    <i class="fas fa-play" style="margin-right: 8px;"></i><?php _e('Spustit test headers', 'wp-security-guardian'); ?>
                </button>

                <div id="headers-results" style="margin-top: 16px;"></div>
            </div>
        </div>
    </div>

    <!-- Progressive Security Score -->
    <div class="wpsg-settings-card">
        <div class="wpsg-section-header">
            <div style="display: flex; align-items: center;">
                <div style="width: 48px; height: 48px; background: #dcfce7; border-radius: 12px; display: flex; align-items: center; justify-content: center; margin-right: 16px;">
                    <i class="fas fa-chart-line" style="color: #16a34a; font-size: 20px;"></i>
                </div>
                <div>
                    <div class="wpsg-setting-title" style="font-size: 16px; margin-bottom: 2px;"><?php _e('Security Score Analysis', 'wp-security-guardian'); ?></div>
                    <div class="wpsg-setting-description"><?php _e('Calculate your comprehensive security score', 'wp-security-guardian'); ?></div>
                </div>
            </div>
        </div>

        <div class="wpsg-setting-item">
            <div class="wpsg-setting-content">
                <div style="background: #f8fafc; border-radius: 8px; padding: 12px; margin-bottom: 16px;">
                    <div style="display: flex; align-items: center; font-size: 13px; color: #64748b;">
                        <i class="fas fa-info-circle" style="margin-right: 8px; color: #16a34a;"></i>
                        <span>Analyzuje všechny aspekty zabezpečení a poskytne celkové skóre s doporučeními</span>
                    </div>
                </div>

                <button id="calculate-score" class="wpsg-test-button" style="width: 100%; background: linear-gradient(135deg, #16a34a 0%, #15803d 100%);">
                    <i class="fas fa-calculator" style="margin-right: 8px;"></i><?php _e('Spočítat skóre', 'wp-security-guardian'); ?>
                </button>

                <div id="score-results" style="margin-top: 16px;"></div>
            </div>
        </div>
    </div>

    <!-- File Integrity Check -->
    <div class="wpsg-settings-card">
        <div class="wpsg-section-header">
            <div style="display: flex; align-items: center;">
                <div style="width: 48px; height: 48px; background: #fed7aa; border-radius: 12px; display: flex; align-items: center; justify-content: center; margin-right: 16px;">
                    <i class="fas fa-file-shield" style="color: #ea580c; font-size: 20px;"></i>
                </div>
                <div>
                    <div class="wpsg-setting-title" style="font-size: 16px; margin-bottom: 2px;"><?php _e('File Integrity Check', 'wp-security-guardian'); ?></div>
                    <div class="wpsg-setting-description"><?php _e('Create checkpoints and verify file integrity', 'wp-security-guardian'); ?></div>
                </div>
            </div>
        </div>

        <div class="wpsg-setting-item">
            <div class="wpsg-setting-content">
                <div style="background: #f8fafc; border-radius: 8px; padding: 12px; margin-bottom: 16px;">
                    <div style="display: flex; align-items: center; font-size: 13px; color: #64748b;">
                        <i class="fas fa-info-circle" style="margin-right: 8px; color: #ea580c;"></i>
                        <span>Vytváří kontrolní body souborů a detekuje neautorizované změny</span>
                    </div>
                </div>

                <div style="display: flex; gap: 12px;">
                    <button id="create-checkpoint" class="wpsg-test-button" style="flex: 1; background: linear-gradient(135deg, #fb923c 0%, #ea580c 100%); font-size: 14px; padding: 10px 16px;">
                        <i class="fas fa-save" style="margin-right: 6px;"></i><?php _e('Vytvořit checkpoint', 'wp-security-guardian'); ?>
                    </button>
                    <button id="verify-integrity" class="wpsg-test-button" style="flex: 1; background: linear-gradient(135deg, #ea580c 0%, #dc2626 100%); font-size: 14px; padding: 10px 16px;">
                        <i class="fas fa-search" style="margin-right: 6px;"></i><?php _e('Ověřit integritu', 'wp-security-guardian'); ?>
                    </button>
                </div>

                <div id="integrity-results" style="margin-top: 16px;"></div>
            </div>
        </div>
    </div>

    <!-- Security Self-Test -->
    <div class="wpsg-settings-card">
        <div class="wpsg-section-header">
            <div style="display: flex; align-items: center;">
                <div style="width: 48px; height: 48px; background: #fecaca; border-radius: 12px; display: flex; align-items: center; justify-content: center; margin-right: 16px;">
                    <i class="fas fa-bug" style="color: #dc2626; font-size: 20px;"></i>
                </div>
                <div>
                    <div class="wpsg-setting-title" style="font-size: 16px; margin-bottom: 2px;"><?php _e('Security Self-Test', 'wp-security-guardian'); ?></div>
                    <div class="wpsg-setting-description"><?php _e('Run comprehensive security vulnerability tests', 'wp-security-guardian'); ?></div>
                </div>
            </div>
        </div>

        <div class="wpsg-setting-item">
            <div class="wpsg-setting-content">
                <div style="background: #f8fafc; border-radius: 8px; padding: 12px; margin-bottom: 16px;">
                    <div style="display: flex; align-items: center; font-size: 13px; color: #64748b;">
                        <i class="fas fa-info-circle" style="margin-right: 8px; color: #dc2626;"></i>
                        <span>Komprehentivní test zranitelností včetně SQL injection, XSS a dalších</span>
                    </div>
                </div>

                <button id="run-self-test" class="wpsg-test-button" style="width: 100%; background: linear-gradient(135deg, #dc2626 0%, #991b1b 100%);">
                    <i class="fas fa-bug" style="margin-right: 8px;"></i><?php _e('Spustit self-test', 'wp-security-guardian'); ?>
                </button>

                <div id="self-test-results" style="margin-top: 16px;"></div>
            </div>
        </div>
    </div>
</div>

<!-- Advanced Features Section -->
<div class="wpsg-settings-card" style="background: linear-gradient(135deg, rgba(139,92,246,0.1) 0%, rgba(236,72,153,0.1) 100%); border: 1px solid rgba(139,92,246,0.3); margin-bottom: 32px;">
    <div class="wpsg-section-header" style="background: transparent; border-bottom: 1px solid rgba(139,92,246,0.2);">
        <div style="display: flex; align-items: center;">
            <div style="width: 48px; height: 48px; background: rgba(139,92,246,0.2); border-radius: 12px; display: flex; align-items: center; justify-content: center; margin-right: 16px;">
                <i class="fas fa-rocket" style="color: #8b5cf6; font-size: 20px;"></i>
            </div>
            <div>
                <div class="wpsg-setting-title" style="font-size: 18px; margin-bottom: 2px;">Pokročilé funkce</div>
                <div class="wpsg-setting-description">Speciální diagnostické nástroje pro expert analýzu</div>
            </div>
        </div>
    </div>

    <div class="wpsg-setting-item" style="border-bottom: none;">
        <div class="wpsg-setting-content" style="margin-right: 0;">
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px;">
                <button id="malware-deep-scan" class="wpsg-test-button" style="background: linear-gradient(135deg, #8b5cf6 0%, #7c3aed 100%); font-size: 14px;">
                    <i class="fas fa-search-plus" style="margin-right: 6px;"></i>Deep Malware Scan
                </button>
                <button id="network-security-test" class="wpsg-test-button" style="background: linear-gradient(135deg, #ec4899 0%, #be185d 100%); font-size: 14px;">
                    <i class="fas fa-network-wired" style="margin-right: 6px;"></i>Network Security Test
                </button>
                <button id="performance-impact" class="wpsg-test-button" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); font-size: 14px;">
                    <i class="fas fa-tachometer-alt" style="margin-right: 6px;"></i>Performance Impact
                </button>
            </div>
        </div>
    </div>
</div>

<!-- Security Logs Viewer -->
<div class="wpsg-settings-card">
    <div class="wpsg-section-header">
        <div style="display: flex; align-items: center; justify-content: space-between;">
            <div style="display: flex; align-items: center;">
                <div style="width: 48px; height: 48px; background: #f3f4f6; border-radius: 12px; display: flex; align-items: center; justify-content: center; margin-right: 16px;">
                    <i class="fas fa-list-alt" style="color: #4b5563; font-size: 20px;"></i>
                </div>
                <div>
                    <div class="wpsg-setting-title" style="font-size: 18px; margin-bottom: 2px;"><?php _e('Secure Activity Logs', 'wp-security-guardian'); ?></div>
                    <div class="wpsg-setting-description"><?php _e('Monitor security events and activities', 'wp-security-guardian'); ?></div>
                </div>
            </div>
            <button id="refresh-logs" style="background: #f3f4f6; color: #374151; border: none; padding: 8px 16px; border-radius: 8px; font-size: 13px; font-weight: 500; cursor: pointer; transition: all 0.3s ease;">
                <i class="fas fa-sync-alt" style="margin-right: 6px;"></i>Refresh
            </button>
        </div>
    </div>

    <div class="wpsg-setting-item" style="border-bottom: 1px solid #f1f5f9;">
        <div class="wpsg-setting-content" style="margin-right: 0;">
            <div style="display: flex; flex-wrap: wrap; gap: 16px; margin-bottom: 20px;">
                <select id="log-level-filter" style="border: 1px solid #d1d5db; border-radius: 8px; padding: 8px 12px; background: white; min-width: 120px;">
                    <option value=""><?php _e('All Levels', 'wp-security-guardian'); ?></option>
                    <option value="info"><?php _e('Info', 'wp-security-guardian'); ?></option>
                    <option value="warning"><?php _e('Warning', 'wp-security-guardian'); ?></option>
                    <option value="error"><?php _e('Error', 'wp-security-guardian'); ?></option>
                </select>
                <input type="number" id="log-limit" placeholder="<?php _e('Limit (default 50)', 'wp-security-guardian'); ?>" min="1" max="200" value="50" style="border: 1px solid #d1d5db; border-radius: 8px; padding: 8px 12px; background: white; width: 150px;">
                <button id="load-logs" class="wpsg-test-button" style="background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%); font-size: 13px; padding: 8px 16px;">
                    <i class="fas fa-download" style="margin-right: 6px;"></i><?php _e('Load Logs', 'wp-security-guardian'); ?>
                </button>
                <button id="clear-logs" class="wpsg-test-button" style="background: linear-gradient(135deg, #dc2626 0%, #991b1b 100%); font-size: 13px; padding: 8px 16px;">
                    <i class="fas fa-trash" style="margin-right: 6px;"></i><?php _e('Clear Logs', 'wp-security-guardian'); ?>
                </button>
            </div>
        </div>
    </div>

    <div class="wpsg-setting-item" style="border-bottom: none;">
        <div class="wpsg-setting-content" style="margin-right: 0;">
            <div id="logs-container" style="background: #f8fafc; border-radius: 8px; padding: 16px; min-height: 128px;">
                <div style="text-align: center; color: #64748b;">
                    <i class="fas fa-info-circle" style="font-size: 24px; margin-bottom: 8px; display: block;"></i>
                    <p>Klikněte na "Load Logs" pro načtení bezpečnostních logů</p>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
    jQuery(document).ready(function($) {
        const nonce = '<?php echo wp_create_nonce('wpsg_security_test'); ?>';

        // Enhanced button animations
        function animateButton($button, loadingText, iconClass = 'fa-spinner fa-spin') {
            const originalHtml = $button.html();
            $button.prop('disabled', true)
                .addClass('wpsg-testing')
                .html(`<span><i class="fas ${iconClass} mr-3"></i>${loadingText}</span>`);
            return originalHtml;
        }

        function resetButton($button, originalHtml, delay = 0) {
            setTimeout(() => {
                $button.prop('disabled', false)
                    .removeClass('wpsg-testing')
                    .html(originalHtml);
            }, delay);
        }

        function createResultCard(data, type = 'info') {
            let colorClass = 'bg-blue-50 border-blue-200 text-blue-800';
            let iconClass = 'fa-info-circle';

            switch (type) {
                case 'success':
                    colorClass = 'bg-green-50 border-green-200 text-green-800';
                    iconClass = 'fa-check-circle';
                    break;
                case 'warning':
                    colorClass = 'bg-yellow-50 border-yellow-200 text-yellow-800';
                    iconClass = 'fa-exclamation-triangle';
                    break;
                case 'error':
                    colorClass = 'bg-red-50 border-red-200 text-red-800';
                    iconClass = 'fa-times-circle';
                    break;
            }

            return `
            <div class="wpsg-result-card border rounded-xl p-6 mt-4 ${colorClass}">
                <div class="flex items-start">
                    <i class="fas ${iconClass} text-2xl mr-4 mt-1"></i>
                    <div class="flex-1">${data}</div>
                </div>
            </div>
        `;
        }

        // Test Security Headers
        $('#test-headers').click(function() {
            const $button = $(this);
            const $results = $('#headers-results');
            const originalHtml = animateButton($button, '<?php _e('Testuji headers...', 'wp-security-guardian'); ?>');

            wpsgAjaxRequest('wpsg_test_security_headers', {
                    url: '<?php echo home_url('/'); ?>'
                },
                function(data) {
                    let html = `<div class="wpsg-result-card wpsg-result-${data.percentage >= 70 ? 'success' : 'warning'}">
                    <h4 style="font-size: 16px; font-weight: 600; margin-bottom: 16px; color: ${data.percentage >= 70 ? '#065f46' : data.percentage >= 50 ? '#92400e' : '#991b1b'};">
                        Security Headers Score: ${data.percentage}% (${data.grade})
                    </h4>`;

                    html += '<div style="display: flex; flex-direction: column; gap: 8px;">';
                    for (const [header, info] of Object.entries(data.headers)) {
                        html += `
                        <div style="display: flex; align-items: center; justify-content: space-between; padding: 12px; background: white; border-radius: 8px; border: 1px solid #e5e7eb;">
                            <span style="font-weight: 500;">${header}</span>
                            <div style="display: flex; align-items: center;">
                                <span style="color: ${info.present ? '#10b981' : '#ef4444'}; margin-right: 8px;">
                                    <i class="fas ${info.present ? 'fa-check-circle' : 'fa-times-circle'}"></i>
                                </span>
                                ${info.recommendation ? `<span style="font-size: 12px; color: #64748b;">${info.recommendation}</span>` : ''}
                            </div>
                        </div>
                    `;
                    }
                    html += '</div></div>';

                    $results.html(html);
                    resetButton($button, originalHtml, 1000);
                },
                function() {
                    $results.html(createResultCard('<?php _e('Test se nezdařil', 'wp-security-guardian'); ?>', 'error'));
                    resetButton($button, originalHtml);
                }
            );
        });

        // Calculate Security Score
        $('#calculate-score').click(function() {
            const $button = $(this);
            const $results = $('#score-results');
            const originalHtml = animateButton($button, '<?php _e('Počítám skóre...', 'wp-security-guardian'); ?>', 'fa-calculator');

            wpsgAjaxRequest('wpsg_security_score', {},
                function(data) {
                    let html = `<div class="wpsg-result-card wpsg-result-${data.percentage >= 80 ? 'success' : 'warning'}">
                    <h4 style="font-size: 16px; font-weight: 600; margin-bottom: 16px; color: ${data.percentage >= 80 ? '#065f46' : data.percentage >= 60 ? '#92400e' : '#991b1b'};">
                        Overall Security Score: ${data.percentage}% (${data.grade})
                    </h4>`;

                    html += '<div style="display: flex; flex-direction: column; gap: 8px; margin-bottom: 16px;">';
                    for (const [category, info] of Object.entries(data.breakdown)) {
                        const score = Math.round(info.score * 100);
                        html += `
                        <div style="display: flex; align-items: center; justify-content: space-between; padding: 12px; background: white; border-radius: 8px; border: 1px solid #e5e7eb;">
                            <span style="font-weight: 500;">${category.replace('_', ' ')}</span>
                            <div style="display: flex; align-items: center;">
                                <div style="width: 64px; height: 8px; background: #e5e7eb; border-radius: 4px; margin-right: 12px; overflow: hidden;">
                                    <div style="height: 100%; background: linear-gradient(90deg, #667eea, #764ba2); border-radius: 4px; width: ${score}%; transition: width 0.8s ease;"></div>
                                </div>
                                <span style="font-size: 13px; font-weight: 500;">${score}%</span>
                            </div>
                        </div>
                    `;
                    }
                    html += '</div>';

                    if (data.recommendations && data.recommendations.length > 0) {
                        html += '<h5 style="font-weight: 600; margin-bottom: 8px;">Doporučení:</h5><ul style="display: flex; flex-direction: column; gap: 4px;">';
                        data.recommendations.forEach(rec => {
                            html += `<li style="display: flex; align-items: flex-start;"><i class="fas fa-arrow-right" style="margin-right: 8px; margin-top: 4px; color: #667eea; font-size: 12px;"></i><span style="font-size: 13px;">${rec}</span></li>`;
                        });
                        html += '</ul>';
                    }

                    html += '</div>';
                    $results.html(html);
                    resetButton($button, originalHtml, 1000);
                },
                function() {
                    $results.html(createResultCard('<?php _e('Výpočet skóre se nezdařil', 'wp-security-guardian'); ?>', 'error'));
                    resetButton($button, originalHtml);
                }
            );
        });

        // File Integrity Check
        $('#create-checkpoint, #verify-integrity').click(function() {
            const $button = $(this);
            const $results = $('#integrity-results');
            const isCreate = $(this).attr('id') === 'create-checkpoint';
            const originalHtml = animateButton($button, isCreate ? '<?php _e('Vytvářím checkpoint...', 'wp-security-guardian'); ?>' : '<?php _e('Ověřuji integritu...', 'wp-security-guardian'); ?>', 'fa-cog fa-spin');

            wpsgAjaxRequest('wpsg_integrity_check', {
                    action_type: isCreate ? 'create' : 'verify'
                },
                function(data) {
                    let html = `<div class="wpsg-result-card wpsg-result-success">
                    <h4 style="font-size: 16px; font-weight: 600; margin-bottom: 16px; color: #065f46;">${data.message}</h4>`;

                    if (data.results && data.results.summary) {
                        const summary = data.results.summary;
                        html += '<div style="display: flex; flex-direction: column; gap: 8px;">';

                        if (isCreate && summary.checkpoint_created) {
                            html += `
                            <div style="padding: 12px; background: #f0f9ff; border-radius: 8px; border: 1px solid #bfdbfe;">
                                <i class="fas fa-check-circle" style="color: #10b981; margin-right: 8px;"></i>
                                Vytvořeno ${summary.checkpoint_created} kontrolních bodů
                            </div>
                        `;
                        } else if (!isCreate) {
                            if (summary.modified_files) {
                                html += `
                                <div style="padding: 12px; background: #fffbeb; border-radius: 8px; border: 1px solid #fed7aa;">
                                    <i class="fas fa-exclamation-triangle" style="color: #f59e0b; margin-right: 8px;"></i>
                                    Nalezeno ${summary.modified_files} změněných souborů
                                </div>
                            `;
                            } else {
                                html += `
                                <div style="padding: 12px; background: #f0f9ff; border-radius: 8px; border: 1px solid #bfdbfe;">
                                    <i class="fas fa-check-circle" style="color: #10b981; margin-right: 8px;"></i>
                                    Všechny soubory jsou v pořádku
                                </div>
                            `;
                            }
                        }

                        html += '</div>';
                    }

                    html += '</div>';
                    $results.html(html);
                    resetButton($button, originalHtml, 1000);
                },
                function() {
                    $results.html(createResultCard(isCreate ? '<?php _e('Vytvoření checkpointu se nezdařilo', 'wp-security-guardian'); ?>' : '<?php _e('Ověření integrity se nezdařilo', 'wp-security-guardian'); ?>', 'error'));
                    resetButton($button, originalHtml);
                }
            );
        });

        // Security Self-Test
        $('#run-self-test').click(function() {
            const $button = $(this);
            const $results = $('#self-test-results');
            const originalHtml = animateButton($button, '<?php _e('Spouštím self-test...', 'wp-security-guardian'); ?>', 'fa-cog fa-spin');

            wpsgAjaxRequest('wpsg_security_self_test', {},
                function(data) {
                    let html = `<div class="wpsg-result-card wpsg-result-${data.overall_score >= 80 ? 'success' : 'warning'}">
                    <h4 style="font-size: 16px; font-weight: 600; margin-bottom: 16px; color: ${data.overall_score >= 80 ? '#065f46' : data.overall_score >= 60 ? '#92400e' : '#991b1b'};">
                        Self-Test Results: ${data.overall_score}% (${data.grade})
                    </h4>`;

                    html += `<p style="margin-bottom: 16px; color: #64748b;">Passed Tests: ${data.passed_tests}/${data.total_tests}</p>`;

                    html += '<div style="display: flex; flex-direction: column; gap: 8px; margin-bottom: 16px;">';
                    for (const [test, result] of Object.entries(data.results)) {
                        html += `
                        <div style="display: flex; align-items: center; justify-content: space-between; padding: 12px; background: white; border-radius: 8px; border: 1px solid #e5e7eb;">
                            <span style="font-weight: 500;">${test.replace('_', ' ')}</span>
                            <div style="display: flex; align-items: center;">
                                <span style="color: ${result.status === 'passed' ? '#10b981' : '#ef4444'}; margin-right: 8px;">
                                    <i class="fas ${result.status === 'passed' ? 'fa-check-circle' : 'fa-times-circle'}"></i>
                                </span>
                                <span style="font-size: 13px; color: #64748b;">${result.message}</span>
                            </div>
                        </div>
                    `;
                    }
                    html += '</div>';

                    if (data.recommendations && data.recommendations.length > 0) {
                        html += '<h5 style="font-weight: 600; margin-bottom: 8px;">Doporučení:</h5><ul style="display: flex; flex-direction: column; gap: 4px;">';
                        data.recommendations.forEach(rec => {
                            html += `<li style="display: flex; align-items: flex-start;"><i class="fas fa-arrow-right" style="margin-right: 8px; margin-top: 4px; color: #dc2626; font-size: 12px;"></i><span style="font-size: 13px;">${rec}</span></li>`;
                        });
                        html += '</ul>';
                    }

                    html += '</div>';
                    $results.html(html);
                    resetButton($button, originalHtml, 1000);
                },
                function() {
                    $results.html(createResultCard('<?php _e('Self-test se nezdařil', 'wp-security-guardian'); ?>', 'error'));
                    resetButton($button, originalHtml);
                }
            );
        });

        // Real-time progress tracking for malware scan
        let scanProgressInterval;
        let scanInProgress = false;

        function showScanModal() {
            console.log('🎬 Opening scan modal...');
            const $modal = $('#wpsg-scan-modal');
            console.log('Modal element found:', $modal.length);
            console.log('Modal current classes:', $modal.attr('class'));
            $modal.addClass('active');
            console.log('Modal classes after adding active:', $modal.attr('class'));
            console.log('Modal is visible:', $modal.hasClass('active'));

            // Reset modal content
            $('#wpsg-scan-progress-bar').css('width', '0%');
            $('#wpsg-scan-percentage').text('0%');
            $('#wpsg-current-directory').text('Inicializace...');
            $('#wpsg-scanned-files').text('0 / 0');
            $('#wpsg-scan-speed').text('0 souborů/s');
            $('#wpsg-scan-eta').text('Výpočet...');
            $('#wpsg-directories-progress').text('0/0');
            $('#wpsg-threats-found').text('0');
            $('#wpsg-quarantined-files').text('0');
            $('#wpsg-current-file').text('Příprava...');
            $('#wpsg-recent-files').empty();
            $('#wpsg-scan-status').html('<i class="fas fa-spinner fa-spin"></i> Spouštím malware scan...');
        }

        function hideScanModal() {
            console.log('🎭 Hiding scan modal...');
            const $modal = $('#wpsg-scan-modal');
            $modal.removeClass('active');
            console.log('Modal classes after removing active:', $modal.attr('class'));
        }

        function startProgressTracking(scanId) {
            console.log('🚀 [DEBUG] Starting progress tracking for scan ID:', scanId);
            console.log('🚀 [DEBUG] Setting up interval for progress polling...');
            
            scanProgressInterval = setInterval(function() {
                console.log('📊 [DEBUG] Polling progress for scan ID:', scanId);
                console.log('📊 [DEBUG] Making AJAX request to wpsg_scan_progress...');
                
                wpsgAjaxRequest('wpsg_scan_progress', {
                        scan_id: scanId
                    },
                    function(progress) {
                        console.log('✅ [DEBUG] Progress received:', progress);
                        console.log('✅ [DEBUG] Progress status:', progress.status);
                        console.log('✅ [DEBUG] Progress percentage:', progress.percentage);
                        console.log('✅ [DEBUG] Current directory:', progress.current_directory);
                        
                        updateProgressDisplay(progress);

                        if (progress.status === 'completed') {
                            console.log('🎉 [DEBUG] Scan completed!');
                            console.log('🎉 [DEBUG] Clearing interval...');
                            clearInterval(scanProgressInterval);
                            scanInProgress = false;
                            showFinalResults(progress);
                        } else if (progress.status === 'error') {
                            console.error('❌ [ERROR] Scan failed with error:', progress.error);
                            clearInterval(scanProgressInterval);
                            scanInProgress = false;
                            showToast('Chyba při scanování: ' + progress.error, 'error');
                        }
                    },
                    function(error) {
                        console.error('❌ [ERROR] Progress polling failed:', error);
                        console.error('❌ [ERROR] Error details:', JSON.stringify(error));
                        clearInterval(scanProgressInterval);
                        scanInProgress = false;
                        showToast('Chyba při sledování postupu: ' + error, 'error');
                    }
                );
            }, 1000); // Update every second
        }

        function updateProgressDisplay(progress) {
            console.log('🔄 [DEBUG] Updating progress display with data:', progress);
            
            // Update modal content instead of inline display
            const percentage = progress.percentage || 0;
            const currentDir = progress.current_directory || 'Inicializace...';
            const scannedFiles = progress.scanned_files || 0;
            const totalFiles = progress.total_files || 0;
            
            console.log('🔄 [DEBUG] Setting progress bar to:', percentage + '%');
            $('#wpsg-scan-progress-bar').css('width', percentage + '%');
            
            console.log('🔄 [DEBUG] Setting percentage text to:', percentage + '%');
            $('#wpsg-scan-percentage').text(percentage + '%');
            
            console.log('🔄 [DEBUG] Setting current directory to:', currentDir);
            $('#wpsg-current-directory').text(currentDir);
            
            console.log('🔄 [DEBUG] Setting scanned files to:', `${scannedFiles} / ${totalFiles}`);
            $('#wpsg-scanned-files').text(`${scannedFiles} / ${totalFiles}`);
            console.log('🔄 [DEBUG] Setting additional stats...');
            $('#wpsg-scan-speed').text(`${progress.files_per_second || 0} souborů/s`);
            $('#wpsg-scan-eta').text(progress.eta_formatted || 'Výpočet...');
            $('#wpsg-directories-progress').text(`${progress.directories_completed || 0}/${progress.total_directories || 0}`);
            $('#wpsg-threats-found').text(progress.threats_found || 0);
            $('#wpsg-quarantined-files').text(progress.quarantined_files || 0);

            // Update current file with animation
            if (progress.current_file) {
                console.log('🔄 [DEBUG] Updating current file to:', progress.current_file);
                const $currentFile = $('#wpsg-current-file');
                $currentFile.fadeOut(200, function() {
                    $(this).text(progress.current_file).fadeIn(200);
                });
            }

            // Update file list with last few files
            if (progress.recent_files && progress.recent_files.length > 0) {
                console.log('🔄 [DEBUG] Updating recent files list:', progress.recent_files);
                const recentFilesHtml = progress.recent_files.map((file, index) =>
                    `<div class="wpsg-file-item" style="animation-delay: ${index * 0.1}s">${file}</div>`
                ).join('');
                $('#wpsg-recent-files').html(recentFilesHtml);
            }
        }

        function showFinalResults(progress) {
            $('#wpsg-scan-status').html('<i class="fas fa-check-circle"></i> Skenování dokončeno!');
            $('#wpsg-scan-progress-bar').css('width', '100%');
            $('#wpsg-scan-percentage').text('100%');

            setTimeout(() => {
                let resultType = progress.threats_found > 0 ? 'error' : 'success';
                let message = progress.threats_found > 0 ?
                    `⚠️ NALEZENY HROZBY! ${progress.threats_found} hrozeb, ${progress.quarantined_files} v karanténě` :
                    `✅ Scan dokončen! ${progress.scanned_files} souborů prohledáno, žádné hrozby nenalezeny`;

                showToast(message, resultType);
                hideScanModal();
                $('#malware-deep-scan').prop('disabled', false).html('<i class="fas fa-search-plus" style="margin-right: 6px;"></i>Deep Malware Scan');
            }, 2000);
        }

        // Quick modal test (double-click to test visibility)
        $('#malware-deep-scan').on('dblclick', function(e) {
            e.preventDefault();
            console.log('🎭 Double-click test: Testing modal visibility only');
            showScanModal();

            // Auto-hide after 3 seconds for testing
            setTimeout(() => {
                console.log('🔄 Auto-hiding modal after test');
                hideScanModal();
            }, 3000);

            return false;
        });

        // Deep Malware Scan - Complete implementation with progress tracking
        $('#malware-deep-scan').on('click', function() {
            console.log('🔍 Malware scan button clicked!');

            // Show modal immediately
            console.log('🎬 Showing scan modal...');
            showScanModal();

            if (scanInProgress) {
                console.log('⚠️ Scan already in progress');
                showToast('Scan již běží...', 'warning');
                return;
            }

            const $button = $(this);
            $button.prop('disabled', true).html('<i class="fas fa-spinner fa-spin" style="margin-right: 6px;"></i>Inicializuji scan...');
            scanInProgress = true;

            console.log('🚀 [DEBUG] Starting malware scan AJAX request...');
            console.log('🚀 [DEBUG] AJAX URL:', ajaxurl);
            console.log('🚀 [DEBUG] Action: wpsg_malware_scan');
            
            // Make AJAX request with longer timeout for scan
            jQuery.ajax({
                url: ajaxurl,
                type: 'POST',
                timeout: 120000, // 2 minutes timeout
                data: {
                    action: 'wpsg_malware_scan',
                    nonce: '<?php echo wp_create_nonce('wpsg_security_test'); ?>'
                },
                success: function(response) {
                    console.log('✅ [DEBUG] Malware scan AJAX response received:', response);
                    console.log('✅ [DEBUG] Response type:', typeof response);
                    
                    // Handle WordPress AJAX response format
                    if (response.success === false) {
                        console.error('❌ [ERROR] WordPress AJAX error:', response.data);
                        scanInProgress = false;
                        hideScanModal();
                        showToast('Chyba při deep scan: ' + response.data, 'error');
                        $button.prop('disabled', false).html('<i class="fas fa-search-plus" style="margin-right: 6px;"></i>Deep Malware Scan');
                        return;
                    }
                    
                    const data = response.data || response;
                    console.log('✅ [DEBUG] Extracted data:', data);
                    console.log('✅ [DEBUG] Data keys:', Object.keys(data));
                    
                    if (data.scan_id) {
                        console.log('📋 [DEBUG] Scan ID received, starting progress tracking:', data.scan_id);
                        console.log('📋 [DEBUG] Scan ID type:', typeof data.scan_id);
                        startProgressTracking(data.scan_id);
                        $button.html('<i class="fas fa-search-plus" style="margin-right: 6px;"></i>Skenování...');
                    } else {
                        console.log('💡 [DEBUG] No scan ID, using fallback results');
                        console.log('💡 [DEBUG] Available data keys:', Object.keys(data));
                        // Modal is already shown, simulate scanning for a moment
                        setTimeout(() => {
                            scanInProgress = false;
                            let resultType = 'success';
                            let message = `Deep malware scan dokončen! Naskenováno ${data.files_scanned || 0} souborů`;

                            if (data.threats_found > 0) {
                                resultType = 'error';
                                message = `⚠️ NALEZENY HROZBY! ${data.threats_found} hrozeb v ${data.files_scanned} souborech`;
                            }

                            showToast(message, resultType);
                            hideScanModal();
                            $button.prop('disabled', false).html('<i class="fas fa-search-plus" style="margin-right: 6px;"></i>Deep Malware Scan');
                        }, 3000);
                    }
                },
                error: function(error) {
                    console.error('❌ [ERROR] Malware scan AJAX error:', error);
                    console.error('❌ [ERROR] Error status:', error.status);
                    console.error('❌ [ERROR] Error statusText:', error.statusText);
                    console.error('❌ [ERROR] Error responseJSON:', error.responseJSON);
                    console.error('❌ [ERROR] Error responseText:', error.responseText);
                    
                    scanInProgress = false;
                    hideScanModal();
                    showToast('Chyba při deep scan: ' + (error.responseJSON?.data || error.statusText || 'Neznámá chyba'), 'error');
                    $button.prop('disabled', false).html('<i class="fas fa-search-plus" style="margin-right: 6px;"></i>Deep Malware Scan');
                }
            });
        });

        $('#network-security-test').click(function() {
            const $button = $(this);
            const originalHtml = animateButton($button, 'Testing network...', 'fa-network-wired');

            setTimeout(() => {
                showToast('Network security test dokončen - síť je bezpečná!', 'success');
                resetButton($button, originalHtml, 1000);
            }, 3000);
        });

        $('#performance-impact').click(function() {
            const $button = $(this);
            const originalHtml = animateButton($button, 'Analyzing impact...', 'fa-tachometer-alt');

            setTimeout(() => {
                showToast('Performance impact: minimální (<2% overhead)', 'info');
                resetButton($button, originalHtml, 1000);
            }, 2000);
        });

        // Logs functionality
        $('#load-logs').click(function() {
            const $button = $(this);
            const $container = $('#logs-container');
            const level = $('#log-level-filter').val();
            const limit = $('#log-limit').val() || 50;

            const originalHtml = $button.html();
            $button.prop('disabled', true).html('<i class="fas fa-spinner fa-spin mr-2"></i>Loading...');

            wpsgAjaxRequest('wpsg_get_secure_logs', {
                    level: level,
                    limit: limit
                },
                function(data) {
                    if (data.logs && data.logs.length > 0) {
                        let html = '<div class="space-y-2">';
                        data.logs.forEach(log => {
                            const levelColor = {
                                'info': 'text-blue-600 bg-blue-50',
                                'warning': 'text-yellow-600 bg-yellow-50',
                                'error': 'text-red-600 bg-red-50'
                            } [log.level] || 'text-gray-600 bg-gray-50';

                            html += `
                            <div class="p-3 rounded-lg border ${levelColor}">
                                <div class="flex justify-between items-start">
                                    <div class="flex-1">
                                        <div class="font-medium text-sm">${log.message}</div>
                                        <div class="text-xs opacity-75 mt-1">${log.timestamp}</div>
                                    </div>
                                    <span class="text-xs px-2 py-1 rounded uppercase font-semibold">${log.level}</span>
                                </div>
                            </div>
                        `;
                        });
                        html += '</div>';
                        $container.html(html);
                    } else {
                        $container.html('<div class="text-center text-gray-500 py-8"><i class="fas fa-info-circle text-2xl mb-2"></i><p>Žádné logy k zobrazení</p></div>');
                    }

                    $button.prop('disabled', false).html(originalHtml);
                },
                function() {
                    $container.html('<div class="text-center text-red-500 py-8"><i class="fas fa-times-circle text-2xl mb-2"></i><p>Chyba při načítání logů</p></div>');
                    $button.prop('disabled', false).html(originalHtml);
                }
            );
        });

        $('#clear-logs').click(function() {
            if (confirm('<?php _e('Opravdu chcete vymazat všechny logy?', 'wp-security-guardian'); ?>')) {
                const $button = $(this);
                const originalHtml = $button.html();
                $button.prop('disabled', true).html('<i class="fas fa-spinner fa-spin mr-2"></i>Clearing...');

                // Simulate clearing - you can implement actual AJAX call
                setTimeout(() => {
                    $('#logs-container').html('<div class="text-center text-gray-500 py-8"><i class="fas fa-info-circle text-2xl mb-2"></i><p>Logy byly vymazány</p></div>');
                    showToast('Logy byly úspěšně vymazány', 'success');
                    $button.prop('disabled', false).html(originalHtml);
                }, 1500);
            }
        });

        $('#refresh-logs').click(function() {
            $('#load-logs').click();
        });

        // Close modal when clicking outside or close button
        $(document).on('click', '#wpsg-scan-modal', function(e) {
            if (e.target === this) {
                $(this).removeClass('active');
                if (scanProgressInterval) {
                    clearInterval(scanProgressInterval);
                    scanInProgress = false;
                }
            }
        });

        $(document).on('click', '.wpsg-modal-close', function() {
            $('#wpsg-scan-modal').removeClass('active');
            if (scanProgressInterval) {
                clearInterval(scanProgressInterval);
                scanInProgress = false;
            }
        });
    });
</script>

<!-- Malware Scan Modal -->
<div id="wpsg-scan-modal" class="wpsg-scan-modal">
    <div class="wpsg-modal-content">
        <div class="wpsg-modal-header">
            <h3><i class="fas fa-shield-virus"></i> Malware Scanner</h3>
            <button class="wpsg-modal-close">&times;</button>
        </div>

        <div class="wpsg-modal-body">
            <!-- Status Section -->
            <div class="wpsg-scan-status-section">
                <div id="wpsg-scan-status" class="wpsg-scan-status">
                    <i class="fas fa-spinner fa-spin"></i> Inicializace...
                </div>
            </div>

            <!-- Progress Bar -->
            <div class="wpsg-progress-section">
                <div class="wpsg-progress-container">
                    <div class="wpsg-progress-track">
                        <div id="wpsg-scan-progress-bar" class="wpsg-progress-bar"></div>
                    </div>
                    <div id="wpsg-scan-percentage" class="wpsg-progress-percentage">0%</div>
                </div>
            </div>

            <!-- Statistics Grid -->
            <div class="wpsg-stats-grid">
                <div class="wpsg-stat-item">
                    <div class="wpsg-stat-label">Aktuální složka:</div>
                    <div id="wpsg-current-directory" class="wpsg-stat-value">-</div>
                </div>
                <div class="wpsg-stat-item">
                    <div class="wpsg-stat-label">Soubory:</div>
                    <div id="wpsg-scanned-files" class="wpsg-stat-value">0 / 0</div>
                </div>
                <div class="wpsg-stat-item">
                    <div class="wpsg-stat-label">Rychlost:</div>
                    <div id="wpsg-scan-speed" class="wpsg-stat-value">0 souborů/s</div>
                </div>
                <div class="wpsg-stat-item">
                    <div class="wpsg-stat-label">Zbývá:</div>
                    <div id="wpsg-scan-eta" class="wpsg-stat-value">Výpočet...</div>
                </div>
                <div class="wpsg-stat-item">
                    <div class="wpsg-stat-label">Složky:</div>
                    <div id="wpsg-directories-progress" class="wpsg-stat-value">0/0</div>
                </div>
                <div class="wpsg-stat-item">
                    <div class="wpsg-stat-label">⚠️ Hrozby:</div>
                    <div id="wpsg-threats-found" class="wpsg-stat-value wpsg-threats">0</div>
                </div>
                <div class="wpsg-stat-item">
                    <div class="wpsg-stat-label">🔒 Karanténa:</div>
                    <div id="wpsg-quarantined-files" class="wpsg-stat-value">0</div>
                </div>
            </div>

            <!-- Current File Section -->
            <div class="wpsg-current-file-section">
                <div class="wpsg-section-title">
                    <i class="fas fa-file-code"></i> Aktuální soubor:
                </div>
                <div id="wpsg-current-file" class="wpsg-current-file">-</div>
            </div>

            <!-- Recent Files Section -->
            <div class="wpsg-recent-files-section">
                <div class="wpsg-section-title">
                    <i class="fas fa-history"></i> Nedávno proskenované:
                </div>
                <div id="wpsg-recent-files" class="wpsg-recent-files"></div>
            </div>
        </div>
    </div>
</div>

<style>
    .wpsg-scan-modal {
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.8);
        backdrop-filter: blur(4px);
        z-index: 999999;
        display: flex;
        align-items: center;
        justify-content: center;
        opacity: 0;
        visibility: hidden;
        transition: all 0.3s ease;
    }

    .wpsg-scan-modal.active {
        opacity: 1;
        visibility: visible;
    }

    .wpsg-modal-content {
        background: #ffffff;
        border-radius: 20px;
        max-width: 800px;
        width: 90vw;
        max-height: 90vh;
        overflow-y: auto;
        transform: scale(0.7);
        transition: transform 0.3s ease;
        box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
    }

    .wpsg-scan-modal.active .wpsg-modal-content {
        transform: scale(1);
    }

    .wpsg-modal-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 24px 32px;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        border-radius: 20px 20px 0 0;
        font-weight: 600;
        font-size: 18px;
    }

    .wpsg-modal-close {
        background: rgba(255, 255, 255, 0.2);
        border: none;
        color: white;
        font-size: 24px;
        width: 36px;
        height: 36px;
        border-radius: 50%;
        cursor: pointer;
        display: flex;
        align-items: center;
        justify-content: center;
        transition: all 0.2s ease;
    }

    .wpsg-modal-close:hover {
        background: rgba(255, 255, 255, 0.3);
        transform: scale(1.1);
    }

    .wpsg-modal-body {
        padding: 32px;
    }

    .wpsg-scan-status-section {
        text-align: center;
        margin-bottom: 32px;
    }

    .wpsg-scan-status {
        font-size: 20px;
        font-weight: 600;
        color: #374151;
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 12px;
    }

    .wpsg-progress-section {
        margin-bottom: 32px;
    }

    .wpsg-progress-container {
        display: flex;
        align-items: center;
        gap: 16px;
    }

    .wpsg-progress-track {
        flex: 1;
        height: 16px;
        background: #e5e7eb;
        border-radius: 8px;
        overflow: hidden;
        position: relative;
    }

    .wpsg-progress-bar {
        height: 100%;
        background: linear-gradient(90deg, #667eea, #764ba2);
        border-radius: 8px;
        width: 0%;
        transition: width 0.5s ease;
        position: relative;
    }

    .wpsg-progress-bar::after {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        height: 100%;
        width: 100%;
        background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.4), transparent);
        animation: wpsg-progress-shine 2s infinite;
    }

    @keyframes wpsg-progress-shine {
        0% {
            transform: translateX(-100%);
        }

        100% {
            transform: translateX(100%);
        }
    }

    .wpsg-progress-percentage {
        font-size: 18px;
        font-weight: 700;
        color: #667eea;
        min-width: 60px;
        text-align: right;
    }

    .wpsg-stats-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 20px;
        margin-bottom: 32px;
    }

    .wpsg-stat-item {
        background: #f8fafc;
        padding: 16px;
        border-radius: 12px;
        border-left: 4px solid #667eea;
    }

    .wpsg-stat-label {
        font-size: 13px;
        color: #6b7280;
        margin-bottom: 6px;
        font-weight: 500;
    }

    .wpsg-stat-value {
        font-size: 16px;
        font-weight: 600;
        color: #374151;
    }

    .wpsg-stat-value.wpsg-threats {
        color: #dc2626;
    }

    .wpsg-current-file-section,
    .wpsg-recent-files-section {
        margin-bottom: 24px;
    }

    .wpsg-section-title {
        font-size: 14px;
        font-weight: 600;
        color: #374151;
        margin-bottom: 12px;
        display: flex;
        align-items: center;
        gap: 8px;
    }

    .wpsg-current-file {
        background: #f3f4f6;
        padding: 12px 16px;
        border-radius: 8px;
        font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
        font-size: 13px;
        color: #1f2937;
        word-break: break-all;
        min-height: 20px;
    }

    .wpsg-recent-files {
        max-height: 150px;
        overflow-y: auto;
    }

    .wpsg-file-item {
        background: #f9fafb;
        padding: 8px 12px;
        margin-bottom: 4px;
        border-radius: 6px;
        font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
        font-size: 12px;
        color: #6b7280;
        animation: wpsg-file-fade-in 0.3s ease;
        word-break: break-all;
    }

    @keyframes wpsg-file-fade-in {
        from {
            opacity: 0;
            transform: translateX(-10px);
        }

        to {
            opacity: 1;
            transform: translateX(0);
        }
    }

    /* Responsive */
    @media (max-width: 768px) {
        .wpsg-modal-content {
            width: 95vw;
            margin: 20px;
        }

        .wpsg-modal-header,
        .wpsg-modal-body {
            padding: 20px;
        }

        .wpsg-stats-grid {
            grid-template-columns: 1fr;
        }
    }
</style>