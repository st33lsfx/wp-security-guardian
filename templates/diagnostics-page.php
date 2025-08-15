<?php
if (!defined('ABSPATH')) {
    exit;
}

// Get current tab
$current_tab = isset($_GET['tab']) ? sanitize_text_field($_GET['tab']) : 'status';

// Enhanced security: Rate limiting for page access
if (class_exists('WPSG_Enhanced_Security')) {
    try {
        WPSG_Enhanced_Security::check_admin_rate_limit('diagnostics_page_access', 20, 300);
        WPSG_Enhanced_Security::secure_log('DIAGNOSTICS_PAGE_ACCESSED', [
            'user_id' => get_current_user_id(),
            'timestamp' => current_time('mysql')
        ], 'info');
    } catch (Exception $e) {
        // Rate limit exceeded or other error - continue but log
        error_log('WPSG Enhanced Security check failed: ' . $e->getMessage());
    }
}
?>

<script src="https://cdn.jsdelivr.net/npm/apexcharts"></script>

<style>
    .wpsg-settings-wrap {
        margin: 20px 20px 0 2px;
        background: #f0f0f1;
        min-height: calc(100vh - 32px);
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

    .wpsg-section-header {
        background: #f8fafc;
        padding: 16px 20px;
        border-bottom: 1px solid #e5e7eb;
        font-weight: 600;
        color: #374151;
        font-size: 15px;
        border-radius: 16px 16px 0 0;
    }

    .wpsg-setting-item {
        padding: 16px 20px;
        border-bottom: 1px solid #f1f5f9;
        display: flex;
        align-items: center;
        justify-content: space-between;
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

    .wpsg-loading {
        opacity: 0.6;
        pointer-events: none;
    }

    /* Enhanced animations for diagnostics */
    @keyframes pulse-glow {

        0%,
        100% {
            box-shadow: 0 0 5px rgba(102, 126, 234, 0.5);
        }

        50% {
            box-shadow: 0 0 20px rgba(102, 126, 234, 0.8), 0 0 30px rgba(102, 126, 234, 0.6);
        }
    }

    @keyframes spin {
        0% {
            transform: rotate(0deg);
        }

        100% {
            transform: rotate(360deg);
        }
    }

    @keyframes bounce-in {
        0% {
            transform: scale(0.3);
            opacity: 0;
        }

        50% {
            transform: scale(1.05);
        }

        70% {
            transform: scale(0.9);
        }

        100% {
            transform: scale(1);
            opacity: 1;
        }
    }

    .wpsg-testing {
        animation: pulse-glow 2s infinite;
    }

    .wpsg-loader {
        display: inline-block;
        width: 20px;
        height: 20px;
        border: 2px solid #f3f4f6;
        border-top: 2px solid #667eea;
        border-radius: 50%;
        animation: spin 1s linear infinite;
        margin-right: 8px;
    }

    .wpsg-result-card {
        animation: bounce-in 0.8s ease-out;
        margin-top: 16px;
        padding: 16px;
        border-radius: 8px;
        border-left: 4px solid #667eea;
    }

    .wpsg-result-success {
        background: #f0f9ff;
        border-left-color: #10b981;
        color: #065f46;
    }

    .wpsg-result-warning {
        background: #fffbeb;
        border-left-color: #f59e0b;
        color: #92400e;
    }

    .wpsg-result-error {
        background: #fef2f2;
        border-left-color: #ef4444;
        color: #991b1b;
    }

    .wpsg-result-info {
        background: #f0f9ff;
        border-left-color: #667eea;
        color: #1e40af;
    }

    .wpsg-test-button {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        border: none;
        padding: 12px 24px;
        border-radius: 8px;
        font-weight: 600;
        cursor: pointer;
        transition: all 0.3s ease;
        display: inline-flex;
        align-items: center;
        text-decoration: none;
    }

    .wpsg-test-button:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 15px -3px rgba(102, 126, 234, 0.4);
        color: white;
    }

    .wpsg-test-button:disabled {
        opacity: 0.7;
        cursor: not-allowed;
        transform: none;
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

    .wpsg-toast.error {
        background: #dc2626;
    }

    .wpsg-toast.warning {
        background: #d97706;
    }

    .wpsg-toast.info {
        background: #2563eb;
    }
</style>

<div class="wrap">
    <h1>🔍 Diagnostika & testování</h1>

    <div class="wpsg-settings-wrap">
        <div style="max-width: 1400px; margin: 0 auto; padding: 20px;">

            <!-- Header Section -->
            <div class="wpsg-gradient-header" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);padding: 32px;border-radius: 16px;margin-bottom: 32px;position: relative;overflow: hidden;color: #fff;">
                <div style="display: flex; align-items: flex-end; justify-content: space-between; flex-wrap: wrap; gap: 16px;">
                    <div style="display: flex;flex-direction: column;gap: 1rem;">
                        <h2 style="font-size: 24px; font-weight: 700;color:#fff;margin: 0; text-shadow: 0 2px 4px rgba(0,0,0,0.3);">Diagnostika & testování</h2>
                        <p style="font-size: 14px; opacity: 0.9; margin: 8px 0 0 0;">Spusťte komprehentivní testy a analyzujte stav zabezpečení vašeho webu</p>
                    </div>
                    <div style="text-align: right;">
                        <div style="font-size: 12px; opacity: 0.8;">Aktivní ochrana</div>
                        <div style="font-size: 14px; font-weight: 600;">🛡️ Zapnuto</div>
                    </div>
                </div>
            </div>

            <!-- Tab Navigation -->
            <nav class="nav-tab-wrapper" style="margin-bottom: 20px;">
                <a href="?page=wp-security-diagnostics&tab=status" class="nav-tab <?php echo $current_tab === 'status' ? 'nav-tab-active' : ''; ?>">
                    <?php _e('Stav zabezpečení', 'wp-security-guardian'); ?>
                </a>
                <a href="?page=wp-security-diagnostics&tab=testing" class="nav-tab <?php echo $current_tab === 'testing' ? 'nav-tab-active' : ''; ?>">
                    <?php _e('Pokročilé testování', 'wp-security-guardian'); ?>
                </a>
            </nav>

            <!-- Tab Content -->
            <?php if ($current_tab === 'status'): ?>
                <!-- Security Status Content -->
                <?php include __DIR__ . '/diagnostics-status.php'; ?>
            <?php else: ?>
                <!-- Security Testing Content -->
                <?php include __DIR__ . '/diagnostics-testing.php'; ?>
            <?php endif; ?>

        </div>
    </div>
</div>

<!-- Toast Notification -->
<div id="wpsg-toast" class="fixed top-4 right-4 bg-green-500 text-white px-6 py-4 rounded-lg shadow-lg transform translate-x-full transition-transform duration-300 z-50">
    <div class="flex items-center">
        <i class="fas fa-check-circle mr-2"></i>
        <span id="wpsg-toast-message">Test completed successfully!</span>
    </div>
</div>

<script>
    // Define ajaxurl for WordPress AJAX calls
    var ajaxurl = '<?php echo admin_url('admin-ajax.php'); ?>';

    // Toast notification function
    function showToast(message, type = 'success') {
        const toast = document.getElementById('wpsg-toast');
        const messageEl = document.getElementById('wpsg-toast-message');

        // Set color based on type
        const colors = {
            success: 'bg-green-500',
            warning: 'bg-yellow-500',
            error: 'bg-red-500',
            info: 'bg-blue-500'
        };

        toast.className = `fixed top-4 right-4 text-white px-6 py-4 rounded-lg shadow-lg transition-transform duration-300 z-50 ${colors[type]}`;
        messageEl.textContent = message;

        // Show toast
        toast.classList.remove('translate-x-full');

        // Hide after 4 seconds
        setTimeout(() => {
            toast.classList.add('translate-x-full');
        }, 4000);
    }

    // Global AJAX handler with enhanced error handling
    window.wpsgAjaxRequest = function(action, data = {}, onSuccess = null, onError = null) {
        console.log('🌐 AJAX Request:', action, 'Data:', data, 'URL:', ajaxurl);
        return jQuery.ajax({
            url: ajaxurl,
            type: 'POST',
            data: {
                action: action,
                nonce: '<?php echo wp_create_nonce('wpsg_security_test'); ?>',
                ...data
            },
            success: function(response) {
                if (response.success) {
                    if (onSuccess) onSuccess(response.data);
                } else {
                    if (onError) onError(response.data);
                    showToast('<?php _e('Chyba: ', 'wp-security-guardian'); ?>' + (response.data || 'Neznámá chyba'), 'error');
                }
            },
            error: function(xhr, status, error) {
                if (onError) onError(error);
                showToast('<?php _e('Síťová chyba: ', 'wp-security-guardian'); ?>' + error, 'error');
            }
        });
    };

    // Initialize tooltips and interactions
    jQuery(document).ready(function($) {
        // Add hover effects to cards
        $('.wpsg-test-card').hover(
            function() {
                $(this).find('.wpsg-button').addClass('transform scale-105');
            },
            function() {
                $(this).find('.wpsg-button').removeClass('transform scale-105');
            }
        );
    });
</script>