<?php
if (!defined('ABSPATH')) {
    exit;
}

// Fallback hodnoty pro template proměnné
$all_plugins = isset($all_plugins) ? $all_plugins : array();
$whitelist = isset($whitelist) ? $whitelist : array();  
$security_enabled = isset($security_enabled) ? $security_enabled : false;

// Template je připraven
?>

<script src="https://cdn.tailwindcss.com"></script>
<style>
    .wrap {
        margin: 0 !important;
        padding: 0 !important;
    }

    #wpcontent {
        padding-left: 0 !important;
    }

    .wpsg-gradient-header {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    }

    .wpsg-card {
        background: white;
        border-radius: 12px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
        transition: all 0.3s ease;
    }

    .wpsg-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
    }

    .wpsg-plugin-item {
        background: white;
        border: 1px solid #e5e7eb;
        border-radius: 8px;
        padding: 20px;
        margin-bottom: 12px;
        transition: all 0.2s ease;
    }

    .wpsg-plugin-item:hover {
        background: #f8fafc;
        border-color: #d1d5db;
        transform: translateX(4px);
    }

    .wpsg-status-active {
        background: linear-gradient(135deg, #10b981 0%, #059669 100%);
        color: white;
        padding: 4px 12px;
        border-radius: 20px;
        font-size: 11px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }

    .wpsg-status-inactive {
        background: linear-gradient(135deg, #6b7280 0%, #4b5563 100%);
        color: white;
        padding: 4px 12px;
        border-radius: 20px;
        font-size: 11px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }

    .wpsg-status-whitelisted {
        background: linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%);
        color: white;
        padding: 4px 12px;
        border-radius: 20px;
        font-size: 11px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }

    .wpsg-status-protected {
        background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
        color: white;
        padding: 4px 12px;
        border-radius: 20px;
        font-size: 11px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }

    .wpsg-checkbox {
        width: 20px;
        height: 20px;
        accent-color: #3b82f6;
        cursor: pointer;
        transform: scale(1.1);
    }

    .wpsg-button-primary {
        background: linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%);
        color: white;
        padding: 12px 24px;
        border: none;
        border-radius: 8px;
        font-weight: 600;
        cursor: pointer;
        transition: all 0.3s ease;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }

    .wpsg-button-primary:hover {
        transform: translateY(-2px);
        box-shadow: 0 10px 20px rgba(59, 130, 246, 0.4);
    }

    .wpsg-button-secondary {
        background: white;
        color: #374151;
        padding: 12px 20px;
        border: 2px solid #e5e7eb;
        border-radius: 8px;
        font-weight: 600;
        cursor: pointer;
        transition: all 0.3s ease;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }

    .wpsg-button-secondary:hover {
        background: #f3f4f6;
        border-color: #d1d5db;
        transform: translateY(-1px);
    }

    .wpsg-stats-card {
        background: linear-gradient(135deg, #8b5cf6 0%, #7c3aed 100%);
        color: white;
        padding: 24px;
        border-radius: 12px;
        margin-bottom: 20px;
    }

    .wpsg-help-card {
        background: linear-gradient(135deg, #06b6d4 0%, #0891b2 100%);
        color: white;
        padding: 24px;
        border-radius: 12px;
    }

    .wpsg-search-box {
        position: relative;
        margin-bottom: 20px;
    }

    .wpsg-search-box input {
        width: 100%;
        padding: 12px 16px 12px 48px;
        border: 2px solid #e5e7eb;
        border-radius: 10px;
        font-size: 16px;
        transition: all 0.3s ease;
    }

    .wpsg-search-box input:focus {
        border-color: #3b82f6;
        box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
        outline: none;
    }

    .wpsg-search-icon {
        position: absolute;
        top: 50%;
        left: 16px;
        transform: translateY(-50%);
        color: #9ca3af;
    }

    .wpsg-bulk-actions {
        display: flex;
        gap: 8px;
        flex-wrap: wrap;
        margin-bottom: 20px;
    }

    .wpsg-bulk-btn {
        padding: 8px 16px;
        border-radius: 6px;
        font-size: 14px;
        font-weight: 500;
        cursor: pointer;
        transition: all 0.2s ease;
    }

    .wpsg-bulk-btn:hover {
        transform: translateY(-1px);
    }

    @media (max-width: 768px) {
        .wpsg-grid {
            grid-template-columns: 1fr !important;
        }
    }
</style>

<div class="wrap" style="background: linear-gradient(135deg, #f3f4f6 0%, #e5e7eb 100%); min-height: 100vh; margin: 0 !important;">
    <div style="max-width: 1400px; margin: 0 auto; padding: 20px;">

        <!-- Úžasný Header -->
        <div class="wpsg-gradient-header" style="padding: 32px; border-radius: 16px; margin-bottom: 32px; position: relative; overflow: hidden;">
            <div style="position: absolute; top: 0; left: 0; right: 0; bottom: 0; background: rgba(255,255,255,0.05); opacity: 0.3;"></div>
            <div style="position: relative; z-index: 10;">
                <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 20px;">
                    <div style="display: flex; align-items: center;">
                        <div style="width: 64px; height: 64px; background: rgba(255,255,255,0.2); border-radius: 16px; display: flex; align-items: center; justify-content: center; margin-right: 20px;">
                            <svg style="width: 32px; height: 32px; color: white;" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path>
                            </svg>
                        </div>
                        <div>
                            <h1 style="font-size: 32px; font-weight: 800; color: white; margin: 0; text-shadow: 0 2px 4px rgba(0,0,0,0.1);">WP Security Guardian</h1>
                            <p style="font-size: 16px; color: rgba(255,255,255,0.9); margin: 4px 0 0 0;">Špičková ochrana vašeho WordPress webu</p>
                        </div>
                    </div>
                    <div style="display: flex; align-items: center; gap: 16px;">
                        <div style="background: rgba(255,255,255,0.2); padding: 12px 20px; border-radius: 50px; backdrop-filter: blur(10px);">
                            <span style="color: white; font-weight: 600; font-size: 14px;">
                                <?php echo $security_enabled ? '🛡️ AKTIVNÍ OCHRANA' : '⚠️ OCHRANA VYPNUTA'; ?>
                            </span>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <form method="post" action="">
            <?php wp_nonce_field('wpsg_admin_nonce', 'wpsg_admin_nonce'); ?>

            <div style="display: grid; grid-template-columns: 2fr 1fr; gap: 32px;" class="wpsg-grid">

                <!-- Hlavní panel -->
                <div>
                    <div class="wpsg-card">
                        <div style="padding: 32px 32px 24px 32px; border-bottom: 1px solid #f1f5f9;">
                            <h2 style="font-size: 24px; font-weight: 700; color: #1e293b; margin: 0 0 8px 0;">Správa Plugin Whitelistu</h2>
                            <p style="color: #64748b; font-size: 16px; margin: 0;">Vyberte pluginy, které mohou být bezpečně aktivovány na vašem webu</p>
                        </div>

                        <div style="padding: 32px;">

                            <!-- Search & Actions -->
                            <div class="wpsg-search-box">
                                <svg class="wpsg-search-icon" style="width: 20px; height: 20px;" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path>
                                </svg>
                                <input type="text" id="wpsg-search" placeholder="Hledat pluginy podle názvu, popisu nebo cesty...">
                            </div>

                            <div class="wpsg-bulk-actions">
                                <button type="button" id="wpsg-select-all" class="wpsg-bulk-btn" style="background: #f3f4f6; color: #374151; border: 1px solid #d1d5db;">Vybrat vše</button>
                                <button type="button" id="wpsg-bulk-enable" class="wpsg-bulk-btn" style="background: #10b981; color: white;">✓ Povolit vybrané</button>
                                <button type="button" id="wpsg-bulk-disable" class="wpsg-bulk-btn" style="background: #ef4444; color: white;">✗ Zakázat vybrané</button>
                                <button type="button" id="wpsg-export" class="wpsg-bulk-btn" style="background: #3b82f6; color: white;">📥 Export</button>
                                <label for="wpsg-import" class="wpsg-bulk-btn" style="background: #6b7280; color: white; cursor: pointer;">
                                    📤 Import
                                    <input type="file" id="wpsg-import" accept=".json" style="display: none;">
                                </label>
                            </div>

                            <!-- Plugin List -->
                            <div class="wpsg-plugin-list">
                                <?php foreach ($all_plugins as $plugin_path => $plugin_data): ?>
                                    <div class="wpsg-plugin-item">
                                        <div style="display: flex; align-items: flex-start; justify-content: space-between;">
                                            <label style="display: flex; align-items: flex-start; cursor: pointer; flex: 1;">
                                                <input
                                                    type="checkbox"
                                                    name="whitelist_plugins[]"
                                                    value="<?php echo esc_attr($plugin_path); ?>"
                                                    <?php checked(in_array($plugin_path, $whitelist)); ?>
                                                    <?php echo ($plugin_path === 'wp-security-guardian/wp-security-guardian.php') ? 'disabled checked' : ''; ?>
                                                    class="wpsg-checkbox"
                                                    style="margin-top: 4px;">
                                                <div style="margin-left: 16px; flex: 1;">
                                                    <div style="font-size: 18px; font-weight: 600; color: #1e293b; margin-bottom: 8px;" class="plugin-name">
                                                        <?php echo esc_html($plugin_data['Name']); ?>
                                                    </div>
                                                    <div style="font-size: 14px; color: #64748b; line-height: 1.5; margin-bottom: 8px;" class="plugin-description">
                                                        <?php echo esc_html($plugin_data['Description']); ?>
                                                    </div>
                                                    <div style="font-size: 12px; color: #94a3b8; font-family: 'Courier New', monospace; background: #f8fafc; padding: 4px 8px; border-radius: 4px; display: inline-block;" class="plugin-path">
                                                        <?php echo esc_html($plugin_path); ?>
                                                        <?php if (!empty($plugin_data['Version'])): ?>
                                                            <span style="margin-left: 12px; color: #3b82f6;">v<?php echo esc_html($plugin_data['Version']); ?></span>
                                                        <?php endif; ?>
                                                    </div>
                                                </div>
                                            </label>

                                            <div style="display: flex; flex-direction: column; gap: 8px; align-items: flex-end;">
                                                <?php if (is_plugin_active($plugin_path)): ?>
                                                    <span class="wpsg-status-active">Aktivní</span>
                                                <?php else: ?>
                                                    <span class="wpsg-status-inactive">Neaktivní</span>
                                                <?php endif; ?>

                                                <?php if (in_array($plugin_path, $whitelist)): ?>
                                                    <span class="wpsg-status-whitelisted">Povolený</span>
                                                <?php endif; ?>

                                                <?php if ($plugin_path === 'wp-security-guardian/wp-security-guardian.php'): ?>
                                                    <span class="wpsg-status-protected">Chráněný</span>
                                                <?php endif; ?>
                                            </div>
                                        </div>
                                    </div>
                                <?php endforeach; ?>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Postranní panel -->
                <div>

                    <!-- Rychlé akce -->
                    <div class="wpsg-card" style="margin-bottom: 24px;">
                        <div style="padding: 24px 24px 20px 24px; border-bottom: 1px solid #f1f5f9;">
                            <h3 style="font-size: 20px; font-weight: 700; color: #1e293b; margin: 0;">Rychlé nastavení</h3>
                        </div>
                        <div style="padding: 24px;">
                            <label style="display: flex; align-items: center; cursor: pointer;">
                                <input
                                    type="checkbox"
                                    name="security_enabled"
                                    value="1"
                                    <?php checked($security_enabled); ?>
                                    class="wpsg-checkbox">
                                <div style="margin-left: 16px;">
                                    <div style="font-weight: 600; color: #1e293b; font-size: 16px;">Aktivovat ochranu</div>
                                    <div style="font-size: 14px; color: #64748b; margin-top: 4px;">Blokuje aktivaci nepovolených pluginů</div>
                                </div>
                            </label>
                        </div>
                    </div>

                    <!-- Statistiky -->
                    <div class="wpsg-stats-card">
                        <h3 style="font-size: 20px; font-weight: 700; margin: 0 0 20px 0;">📊 Statistiky</h3>
                        <div style="display: grid; gap: 20px;">
                            <div>
                                <div style="font-size: 14px; font-weight: 500; opacity: 0.9; margin-bottom: 8px;">Celkem pluginů</div>
                                <div style="font-size: 36px; font-weight: 800;" id="wpsg-stat-total"><?php echo count($all_plugins); ?></div>
                            </div>
                            <div>
                                <div style="font-size: 14px; font-weight: 500; opacity: 0.9; margin-bottom: 8px;">Povolené pluginy</div>
                                <div style="font-size: 36px; font-weight: 800;" id="wpsg-stat-enabled"><?php echo count($whitelist); ?></div>
                            </div>
                            <div>
                                <div style="font-size: 14px; font-weight: 500; opacity: 0.9; margin-bottom: 8px;">Blokované pluginy</div>
                                <div style="font-size: 36px; font-weight: 800;" id="wpsg-stat-blocked"><?php echo count($all_plugins) - count($whitelist); ?></div>
                            </div>
                        </div>
                    </div>

                    <!-- Nápověda -->
                    <div class="wpsg-help-card">
                        <h3 style="font-size: 20px; font-weight: 700; margin: 0 0 16px 0;">💡 Jak to funguje</h3>
                        <div style="font-size: 14px; line-height: 1.6;">
                            <ul style="margin: 0; padding-left: 20px;">
                                <li style="margin-bottom: 8px;">Pouze zaškrtnuté pluginy mohou být aktivovány</li>
                                <li style="margin-bottom: 8px;">Security Guardian je vždy automaticky chráněný</li>
                                <li style="margin-bottom: 8px;">Blokuje všechny pokusy o aktivaci nepovolených pluginů</li>
                                <li>Chrání před malware pluginy nahranými přes FTP</li>
                            </ul>
                        </div>
                    </div>

                </div>
            </div>

            <!-- Spodní akční panel -->
            <div class="wpsg-card" style="margin-top: 32px; padding: 24px;">
                <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 16px;">
                    <div style="color: #64748b; font-size: 14px;">
                        <strong>Poslední změna:</strong> <?php echo date_i18n(get_option('date_format') . ' ' . get_option('time_format')); ?>
                    </div>
                    <div style="display: flex; gap: 16px;">
                        <button type="button" onclick="location.reload()" class="wpsg-button-secondary">🔄 Obnovit</button>
                        <button type="submit" name="submit" class="wpsg-button-primary">💾 Uložit změny</button>
                    </div>
                </div>
            </div>

        </form>
    </div>
</div>