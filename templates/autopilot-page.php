<?php
if (!defined('ABSPATH')) {
    exit;
}

// Fallback hodnoty pro template proměnné
if (!isset($autopilot_data) || !is_array($autopilot_data)) {
    $autopilot_data = array();
}

// Zajistit základní klíče s fallback hodnotami
$autopilot_data['status'] = isset($autopilot_data['status']) ? $autopilot_data['status'] : 'inactive';
$autopilot_data['settings'] = isset($autopilot_data['settings']) ? $autopilot_data['settings'] : array(
    'enabled' => false,
    'auto_block_ips' => false,
    'sensitivity_level' => 5
);

// Dočasně vypnout CSP pro tuto stránku kvůli ApexCharts
if (function_exists('header_remove')) {
    header_remove('Content-Security-Policy');
}
?>

<script src="https://cdn.tailwindcss.com"></script>
<script src="https://cdn.jsdelivr.net/npm/apexcharts"></script>

<style>
    .wrap {
        margin: 0 !important;
        padding: 0 !important;
    }

    #wpcontent {
        padding-left: 0 !important;
    }

    .wpsg-autopilot-wrap {
        background: linear-gradient(135deg, #f3f4f6 0%, #e5e7eb 100%);
        min-height: 100vh;
        margin: 0 !important;
    }

    .wpsg-autopilot-card {
        background: white;
        border-radius: 16px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
        transition: all 0.3s ease;
    }

    .wpsg-autopilot-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
    }

    .wpsg-gradient-header {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    }

    .wpsg-toggle-switch {
        position: relative;
        display: inline-block;
        width: 60px;
        height: 34px;
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
        background-color: #ccc;
        transition: .4s;
        border-radius: 34px;
    }

    .wpsg-toggle-slider:before {
        position: absolute;
        content: "";
        height: 26px;
        width: 26px;
        left: 4px;
        bottom: 4px;
        background-color: white;
        transition: .4s;
        border-radius: 50%;
    }

    input:checked+.wpsg-toggle-slider {
        background-color: #10b981;
    }

    input:checked+.wpsg-toggle-slider:before {
        transform: translateX(26px);
    }

    .wpsg-status-badge {
        padding: 6px 16px;
        border-radius: 20px;
        font-size: 12px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }

    .wpsg-status-active {
        background: linear-gradient(135deg, #10b981 0%, #059669 100%);
        color: white;
    }

    .wpsg-status-monitoring {
        background: linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%);
        color: white;
    }

    .wpsg-status-learning {
        background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
        color: white;
    }

    .wpsg-status-inactive {
        background: linear-gradient(135deg, #6b7280 0%, #4b5563 100%);
        color: white;
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

    .wpsg-button-danger {
        background: linear-gradient(135deg, #dc2626 0%, #b91c1c 100%);
        color: white;
        padding: 8px 16px;
        border: none;
        border-radius: 6px;
        font-weight: 500;
        cursor: pointer;
        transition: all 0.3s ease;
        font-size: 12px;
    }

    .wpsg-button-danger:hover {
        transform: translateY(-1px);
        box-shadow: 0 8px 16px rgba(220, 38, 38, 0.4);
    }

    .wpsg-action-item {
        padding: 16px;
        border-left: 4px solid;
        border-radius: 8px;
        margin-bottom: 12px;
        display: flex;
        align-items: center;
        justify-content: space-between;
    }

    .wpsg-action-blocked {
        background: #fee2e2;
        border-color: #dc2626;
    }

    .wpsg-action-updated {
        background: #f0fdf4;
        border-color: #16a34a;
    }

    .wpsg-action-monitored {
        background: #eff6ff;
        border-color: #3b82f6;
    }

    .wpsg-recommendation-item {
        background: #fffbeb;
        border-left: 4px solid #f59e0b;
        padding: 16px;
        border-radius: 8px;
        margin-bottom: 12px;
    }

    @media (max-width: 1200px) {
        .wpsg-autopilot-grid {
            grid-template-columns: 1fr !important;
        }
    }
</style>

<div class="wrap wpsg-autopilot-wrap">
    <div style="max-width: 1400px; margin: 0 auto; padding: 20px;">

        <!-- Header -->
        <div class="wpsg-gradient-header" style="padding: 32px; border-radius: 16px; margin-bottom: 32px; position: relative; overflow: hidden; color: white;">
            <div style="position: absolute; top: 0; left: 0; right: 0; bottom: 0; background: rgba(255,255,255,0.05); opacity: 0.3;"></div>
            <div style="position: relative; z-index: 10;">
                <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 20px;">
                    <div style="display: flex; align-items: center;">
                        <div style="width: 64px; height: 64px; background: rgba(255,255,255,0.2); border-radius: 16px; display: flex; align-items: center; justify-content: center; margin-right: 20px;">
                            <svg style="width: 32px; height: 32px; color: white;" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path>
                            </svg>
                        </div>
                        <div>
                            <h1 style="font-size: 32px; font-weight: 800; color: white; margin: 0; text-shadow: 0 2px 4px rgba(0,0,0,0.1);">Auto-Pilot Security</h1>
                            <p style="font-size: 16px; color: rgba(255,255,255,0.9); margin: 4px 0 0 0;">Automatická ochrana s AI asistencí</p>
                        </div>
                    </div>
                    <div style="display: flex; align-items: center; gap: 16px;">
                        <div style="background: rgba(255,255,255,0.2); padding: 12px 20px; border-radius: 50px; backdrop-filter: blur(10px);">
                            <span class="wpsg-status-badge <?php echo $autopilot_data['status'] == 'active' ? 'wpsg-status-active' : ($autopilot_data['status'] == 'learning' ? 'wpsg-status-learning' : 'wpsg-status-inactive'); ?>">
                                <?php
                                switch ($autopilot_data['status']) {
                                    case 'active':
                                        echo '🤖 AKTIVNÍ AUTO-PILOT';
                                        break;
                                    case 'learning':
                                        echo '🧠 UČÍCÍ SE REŽIM';
                                        break;
                                    case 'monitoring':
                                        echo '👁️ SLEDOVÁNÍ';
                                        break;
                                    default:
                                        echo '⚠️ NEAKTIVNÍ';
                                }
                                ?>
                            </span>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <form method="post" action="">
            <?php wp_nonce_field('wpsg_autopilot_nonce', 'wpsg_autopilot_nonce'); ?>

            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 24px; margin-bottom: 24px;" class="wpsg-autopilot-grid">

                <!-- Auto-Pilot Settings -->
                <div class="wpsg-autopilot-card">
                    <div style="padding: 24px; border-bottom: 1px solid #f1f5f9;">
                        <h3 style="font-size: 20px; font-weight: 700; color: #1e293b; margin: 0;">⚙️ Nastavení Auto-Pilot</h3>
                        <p style="color: #64748b; margin: 8px 0 0 0;">Konfigurace automatických bezpečnostních odpovědí</p>
                    </div>
                    <div style="padding: 24px;">

                        <!-- Master Switch -->
                        <div style="margin-bottom: 24px; padding: 20px; background: #f8fafc; border-radius: 12px;">
                            <div style="display: flex; align-items: center; justify-content: space-between;">
                                <div>
                                    <h4 style="margin: 0 0 8px 0; font-weight: 600; color: #1e293b;">Hlavní spínač Auto-Pilot</h4>
                                    <p style="margin: 0; color: #64748b; font-size: 14px;">Zapne/vypne všechny automatické funkce</p>
                                </div>
                                <label class="wpsg-toggle-switch">
                                    <input type="checkbox" name="autopilot_enabled" value="1" data-setting="wpsg_autopilot_enabled" class="wpsg-autopilot-toggle" <?php checked($autopilot_data['settings']['enabled'] ?? false); ?>>
                                    <span class="wpsg-toggle-slider"></span>
                                </label>
                            </div>
                        </div>

                        <!-- Individual Settings -->
                        <div style="display: grid; gap: 16px;">

                            <div style="display: flex; align-items: center; justify-content: space-between; padding: 16px; border: 1px solid #e5e7eb; border-radius: 8px;">
                                <div>
                                    <div style="font-weight: 600; color: #1e293b; margin-bottom: 4px;">Automatické blokování IP</div>
                                    <div style="font-size: 14px; color: #64748b;">Blokuje podezřelé IP adresy automaticky</div>
                                </div>
                                <label class="wpsg-toggle-switch">
                                    <input type="checkbox" name="auto_ip_blocking" value="1" data-setting="wpsg_autopilot_auto_block_ips" class="wpsg-autopilot-toggle" <?php checked($autopilot_data['settings']['auto_block_ips'] ?? false); ?>>
                                    <span class="wpsg-toggle-slider"></span>
                                </label>
                            </div>

                            <div style="display: flex; align-items: center; justify-content: space-between; padding: 16px; border: 1px solid #e5e7eb; border-radius: 8px;">
                                <div>
                                    <div style="font-weight: 600; color: #1e293b; margin-bottom: 4px;">Automatické aktualizace</div>
                                    <div style="font-size: 14px; color: #64748b;">Aktualizuje kritické security opravy</div>
                                </div>
                                <label class="wpsg-toggle-switch">
                                    <input type="checkbox" name="auto_updates" value="1" data-setting="wpsg_autopilot_auto_updates" class="wpsg-autopilot-toggle" <?php checked($autopilot_data['settings']['auto_updates'] ?? false); ?>>
                                    <span class="wpsg-toggle-slider"></span>
                                </label>
                            </div>

                            <div style="display: flex; align-items: center; justify-content: space-between; padding: 16px; border: 1px solid #e5e7eb; border-radius: 8px;">
                                <div>
                                    <div style="font-weight: 600; color: #1e293b; margin-bottom: 4px;">Nouzové uzamčení</div>
                                    <div style="font-size: 14px; color: #64748b;">Uzamkne web při detekci útoku</div>
                                </div>
                                <label class="wpsg-toggle-switch">
                                    <input type="checkbox" name="emergency_lockdown" value="1" data-setting="wpsg_autopilot_emergency_lockdown" class="wpsg-autopilot-toggle" <?php checked($autopilot_data['settings']['emergency_lockdown'] ?? false); ?>>
                                    <span class="wpsg-toggle-slider"></span>
                                </label>
                            </div>

                            <div style="display: flex; align-items: center; justify-content: space-between; padding: 16px; border: 1px solid #e5e7eb; border-radius: 8px;">
                                <div>
                                    <div style="font-weight: 600; color: #1e293b; margin-bottom: 4px;">Adaptivní učení</div>
                                    <div style="font-size: 14px; color: #64748b;">Učí se z chování návštěvníků</div>
                                </div>
                                <label class="wpsg-toggle-switch">
                                    <input type="checkbox" name="adaptive_learning" value="1" data-setting="wpsg_autopilot_adaptive_learning" class="wpsg-autopilot-toggle" <?php checked($autopilot_data['settings']['adaptive_learning'] ?? false); ?>>
                                    <span class="wpsg-toggle-slider"></span>
                                </label>
                            </div>

                        </div>

                        <!-- Sensitivity Settings -->
                        <div style="margin-top: 24px; padding: 20px; background: #f8fafc; border-radius: 12px;">
                            <h4 style="margin: 0 0 16px 0; font-weight: 600; color: #1e293b;">🎚️ Citlivost detekce</h4>

                            <div style="display: flex; align-items: center; gap: 16px;">
                                <label style="font-size: 14px; color: #64748b;">Nízká</label>
                                <input type="range" name="sensitivity_level" min="1" max="10" value="<?php echo $autopilot_data['settings']['sensitivity_level'] ?? 5; ?>" style="flex: 1; accent-color: #3b82f6;">
                                <label style="font-size: 14px; color: #64748b;">Vysoká</label>
                            </div>
                            <div style="text-align: center; margin-top: 8px; font-size: 14px; color: #64748b;">
                                Aktuální: <strong><?php echo $autopilot_data['settings']['sensitivity_level'] ?? 5; ?>/10</strong>
                            </div>
                        </div>

                    </div>
                </div>

                <!-- Statistics & Status -->
                <div class="wpsg-autopilot-card">
                    <div style="padding: 24px; border-bottom: 1px solid #f1f5f9;">
                        <h3 style="font-size: 20px; font-weight: 700; color: #1e293b; margin: 0;">📊 Statistiky & Status</h3>
                        <p style="color: #64748b; margin: 8px 0 0 0;">Přehled automatických akcí za posledních 24 hodin</p>
                    </div>
                    <div style="padding: 24px;">

                        <!-- Quick Stats -->
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 24px;">
                            <div style="background: linear-gradient(135deg, #dc2626 0%, #b91c1c 100%); color: white; padding: 20px; border-radius: 12px; text-align: center;">
                                <div style="font-size: 28px; font-weight: 800; margin-bottom: 6px;"><?php echo $autopilot_data['stats']['blocked_threats'] ?? 0; ?></div>
                                <div style="font-size: 14px; opacity: 0.9;">Zablokované hrozby</div>
                            </div>

                            <div style="background: linear-gradient(135deg, #10b981 0%, #059669 100%); color: white; padding: 20px; border-radius: 12px; text-align: center;">
                                <div style="font-size: 28px; font-weight: 800; margin-bottom: 6px;"><?php echo $autopilot_data['stats']['auto_actions'] ?? 0; ?></div>
                                <div style="font-size: 14px; opacity: 0.9;">Automatické akce</div>
                            </div>
                        </div>

                        <!-- AI Learning Status -->
                        <div style="margin-bottom: 24px; padding: 16px; background: #eff6ff; border-left: 4px solid #3b82f6; border-radius: 8px;">
                            <div style="display: flex; align-items: center; justify-content: space-between;">
                                <div>
                                    <h4 style="margin: 0 0 4px 0; color: #1e40af; font-weight: 600;">🧠 AI Učení</h4>
                                    <p style="margin: 0; color: #1e40af; font-size: 14px;">Model se učí z <?php echo $autopilot_data['stats']['learning_samples'] ?? 0; ?> vzorků chování</p>
                                </div>
                                <div style="background: #3b82f6; color: white; padding: 8px 16px; border-radius: 20px; font-size: 12px; font-weight: 600;">
                                    <?php echo $autopilot_data['stats']['learning_accuracy'] ?? 85; ?>% přesnost
                                </div>
                            </div>
                        </div>

                        <!-- Performance Chart -->
                        <div style="background: white; padding: 16px; border: 1px solid #e5e7eb; border-radius: 8px;">
                            <h4 style="margin: 0 0 16px 0; font-weight: 600; color: #1e293b;">📈 Výkonnost Auto-Pilot (7 dní)</h4>
                            <div id="autopilotPerformanceChart" style="height: 200px;"></div>
                        </div>

                    </div>
                </div>

            </div>

            <!-- Recent Actions -->
            <div class="wpsg-autopilot-card" style="margin-bottom: 24px;">
                <div style="padding: 24px; border-bottom: 1px solid #f1f5f9;">
                    <h3 style="font-size: 20px; font-weight: 700; color: #1e293b; margin: 0;">⚡ Nedávné automatické akce</h3>
                    <p style="color: #64748b; margin: 8px 0 0 0;">Přehled akcí provedených Auto-Pilot systémem</p>
                </div>
                <div style="padding: 24px;">

                    <?php if (!empty($autopilot_data['recent_actions'])): ?>
                        <div style="max-height: 400px; overflow-y: auto;">
                            <?php foreach ($autopilot_data['recent_actions'] as $action): ?>
                                <div class="wpsg-action-item wpsg-action-<?php echo esc_attr($action['type']); ?>">
                                    <div style="flex: 1;">
                                        <div style="font-weight: 600; color: #1e293b; margin-bottom: 4px;"><?php echo esc_html($action['title']); ?></div>
                                        <div style="font-size: 14px; color: #64748b; margin-bottom: 8px;"><?php echo esc_html($action['description']); ?></div>
                                        <div style="font-size: 12px; color: #94a3b8;">
                                            <?php echo date_i18n('d.m.Y H:i', strtotime($action['timestamp'])); ?>
                                            <?php if ($action['ip_address']): ?>
                                                • IP: <?php echo esc_html($action['ip_address']); ?>
                                            <?php endif; ?>
                                        </div>
                                    </div>
                                    <?php if ($action['type'] === 'blocked' && !isset($action['unblocked'])): ?>
                                        <button type="submit" name="unblock_ip" value="<?php echo esc_attr($action['ip_address']); ?>" class="wpsg-button-danger unblock-btn" data-ip="<?php echo esc_attr($action['ip_address']); ?>">
                                            Odblokovat
                                        </button>
                                        <span id="unblocked-status-<?php echo esc_attr(str_replace('.', '-', $action['ip_address'])); ?>" style="color: #10b981; font-size: 12px; font-weight: 600; display: none;">✓ ODBLOKOVÁNO</span>
                                    <?php elseif (isset($action['unblocked'])): ?>
                                        <span style="color: #10b981; font-size: 12px; font-weight: 600;">✓ ODBLOKOVÁNO</span>
                                    <?php endif; ?>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    <?php else: ?>
                        <div style="text-align: center; color: #64748b; padding: 60px 20px;">
                            <div style="font-size: 48px; margin-bottom: 16px;">🤖</div>
                            <div style="font-weight: 600; margin-bottom: 8px;">Žádné automatické akce</div>
                            <div style="font-size: 14px;">Auto-Pilot zatím neprovedl žádné akce</div>
                        </div>
                    <?php endif; ?>

                </div>
            </div>

            <!-- AI Recommendations -->
            <div class="wpsg-autopilot-card" style="margin-bottom: 24px;">
                <div style="padding: 24px; border-bottom: 1px solid #f1f5f9;">
                    <h3 style="font-size: 20px; font-weight: 700; color: #1e293b; margin: 0;">🎯 AI Doporučení</h3>
                    <p style="color: #64748b; margin: 8px 0 0 0;">Personalizovaná doporučení na základě analýzy vašeho webu</p>
                </div>
                <div style="padding: 24px;">

                    <?php if (!empty($autopilot_data['recommendations'])): ?>
                        <?php foreach ($autopilot_data['recommendations'] as $recommendation): ?>
                            <div class="wpsg-recommendation-item">
                                <div style="display: flex; align-items: flex-start; justify-content: space-between;">
                                    <div style="flex: 1;">
                                        <h4 style="margin: 0 0 8px 0; color: #d97706; font-weight: 600;"><?php echo esc_html($recommendation['title']); ?></h4>
                                        <p style="margin: 0 0 12px 0; color: #92400e; line-height: 1.5;"><?php echo esc_html($recommendation['description']); ?></p>
                                        <div style="font-size: 12px; color: #78350f;">
                                            Dopad: <?php echo esc_html($recommendation['impact']); ?> •
                                            Obtížnost: <?php echo esc_html($recommendation['difficulty']); ?>
                                        </div>
                                    </div>
                                    <?php if ($recommendation['auto_apply']): ?>
                                        <button type="button" class="wpsg-button-primary" style="margin-left: 16px;" onclick="applyRecommendation('<?php echo esc_attr($recommendation['id']); ?>')">
                                            Použít automaticky
                                        </button>
                                    <?php endif; ?>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <div style="text-align: center; color: #64748b; padding: 40px 20px;">
                            <div style="font-size: 48px; margin-bottom: 16px;">🎯</div>
                            <div style="font-weight: 600; margin-bottom: 8px;">Žádná doporučení</div>
                            <div style="font-size: 14px;">Váš web je dobře nakonfigurován!</div>
                        </div>
                    <?php endif; ?>

                </div>
            </div>

            <!-- Blocked IPs List -->
            <?php
            $blocked_ips = get_option('wpsg_blocked_ips', array());
            if (!empty($blocked_ips)):
            ?>
                <div class="wpsg-autopilot-card" style="margin-bottom: 24px;">
                    <div style="padding: 24px; border-bottom: 1px solid #f1f5f9;">
                        <h3 style="font-size: 20px; font-weight: 700; color: #1e293b; margin: 0;">🚫 Aktuálně blokované IP adresy</h3>
                        <p style="color: #64748b; margin: 8px 0 0 0;">Seznam všech IP adres blokovaných Auto-Pilot systémem</p>
                    </div>
                    <div style="padding: 24px;">
                        <?php
                        // Kontrola zda byla IP odblokována v autopilot akcích
                        $autopilot_actions = get_option('wpsg_autopilot_actions', array());
                        foreach ($blocked_ips as $ip => $info):
                            // Zkontrolovat zda není IP označena jako odblokována v autopilot akcích
                            $is_unblocked = false;
                            foreach ($autopilot_actions as $action) {
                                if ($action['ip_address'] === $ip && $action['type'] === 'blocked' && isset($action['unblocked']) && $action['unblocked']) {
                                    $is_unblocked = true;
                                    break;
                                }
                            }

                            // Debug: zobrazit stav pro testování
                            // error_log("WPSG Debug: IP $ip, is_unblocked: " . ($is_unblocked ? 'true' : 'false'));
                        ?>
                            <div style="display: flex; align-items: center; justify-content: space-between; padding: 12px; background: #fee2e2; border-radius: 8px; margin-bottom: 12px;">
                                <div>
                                    <div style="font-weight: 600; color: #dc2626; margin-bottom: 4px;">
                                        IP: <?php echo esc_html($ip); ?>
                                    </div>
                                    <div style="font-size: 14px; color: #64748b;">
                                        Blokováno: <?php echo esc_html($info['blocked_at']); ?> |
                                        Důvod: <?php echo esc_html($info['reason']); ?>
                                    </div>
                                </div>
                                <button type="submit" name="unblock_ip" value="<?php echo esc_attr($ip); ?>" class="wpsg-button-danger unblock-btn" data-ip="<?php echo esc_attr($ip); ?>">
                                    🔓 Odblokovat
                                </button>
                                <span id="unblocked-status-<?php echo esc_attr(str_replace('.', '-', $ip)); ?>" style="color: #10b981; font-size: 12px; font-weight: 600; display: none;">✓ ODBLOKOVÁNO</span>
                            </div>
                        <?php endforeach; ?>
                    </div>
                </div>
            <?php endif; ?>

            <!-- Action Buttons -->
            <div class="wpsg-autopilot-card" style="padding: 24px;">
                <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 16px;">
                    <div style="color: #64748b; font-size: 14px;">
                        <strong>Poslední aktualizace:</strong> <?php echo date_i18n('d.m.Y H:i'); ?>
                    </div>
                    <div style="display: flex; gap: 16px;">
                        <button type="button" onclick="location.reload()" style="background: white; color: #374151; padding: 12px 20px; border: 2px solid #e5e7eb; border-radius: 8px; font-weight: 600; cursor: pointer;">
                            🔄 Obnovit
                        </button>
                        <button type="submit" name="clear_actions" value="1" style="background: #dc2626; color: white; padding: 12px 20px; border: none; border-radius: 8px; font-weight: 600; cursor: pointer;" onclick="return confirm('Opravdu chcete vymazat všechny nedávné aktivity?')">
                            🗑️ Vymazat aktivity
                        </button>
                        <button type="submit" name="create_test_blocks" value="1" style="background: #f59e0b; color: white; padding: 12px 20px; border: none; border-radius: 8px; font-weight: 600; cursor: pointer;">
                            🧪 Vytvořit testovací bloky
                        </button>
                        <button type="submit" name="submit" class="wpsg-button-primary">
                            💾 Uložit nastavení
                        </button>
                    </div>
                </div>
            </div>

        </form>
    </div>
</div>

<script>
    document.addEventListener('DOMContentLoaded', function() {
        // Auto-Pilot Performance Chart
        const performanceData = <?php echo json_encode($autopilot_data['performance_data'] ?? []); ?>;

        // Prepare data for last 7 days
        const today = new Date();
        const chartData = [];

        for (let i = 6; i >= 0; i--) {
            const date = new Date(today);
            date.setDate(date.getDate() - i);
            const dateStr = date.toISOString().split('T')[0];

            const dayData = performanceData.find(d => d.date === dateStr) || {
                threats_blocked: 0,
                actions_taken: 0,
                accuracy: 85
            };

            chartData.push({
                date: dateStr,
                threats_blocked: dayData.threats_blocked,
                actions_taken: dayData.actions_taken,
                accuracy: dayData.accuracy
            });
        }

        const performanceOptions = {
            series: [{
                name: 'Zablokované hrozby',
                type: 'column',
                data: chartData.map(d => ({
                    x: d.date,
                    y: d.threats_blocked
                }))
            }, {
                name: 'Automatické akce',
                type: 'column',
                data: chartData.map(d => ({
                    x: d.date,
                    y: d.actions_taken
                }))
            }, {
                name: 'Přesnost AI (%)',
                type: 'line',
                data: chartData.map(d => ({
                    x: d.date,
                    y: d.accuracy
                }))
            }],
            chart: {
                height: 200,
                type: 'line',
                toolbar: {
                    show: false
                }
            },
            stroke: {
                width: [0, 0, 3],
                curve: 'smooth'
            },
            plotOptions: {
                bar: {
                    columnWidth: '50%'
                }
            },
            colors: ['#dc2626', '#10b981', '#3b82f6'],
            xaxis: {
                type: 'datetime',
                labels: {
                    format: 'dd.MM'
                }
            },
            yaxis: [{
                title: {
                    text: 'Počet',
                }
            }, {
                opposite: true,
                title: {
                    text: 'Přesnost (%)'
                }
            }],
            legend: {
                position: 'top',
                horizontalAlign: 'left'
            }
        };

        const performanceChart = new ApexCharts(document.querySelector("#autopilotPerformanceChart"), performanceOptions);
        performanceChart.render();

        // Range slider update
        const sensitivitySlider = document.querySelector('input[name="sensitivity_level"]');
        if (sensitivitySlider) {
            const valueDisplay = sensitivitySlider.parentNode.parentNode.querySelector('strong');
            sensitivitySlider.addEventListener('input', function() {
                valueDisplay.textContent = this.value + '/10';
            });
        }
    });

    // Unblock action function
    function unblockAction(actionId) {
        if (confirm('Opravdu chcete odblokovat tuto akci?')) {
            // AJAX call to unblock
            const formData = new FormData();
            formData.append('action', 'wpsg_unblock_action');
            formData.append('action_id', actionId);
            formData.append('nonce', '<?php echo wp_create_nonce('wpsg_unblock_action'); ?>');

            fetch('<?php echo admin_url('admin-ajax.php'); ?>', {
                    method: 'POST',
                    body: formData
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        location.reload();
                    } else {
                        alert('Chyba při odblokování: ' + data.message);
                    }
                });
        }
    }

    // Apply recommendation function
    function applyRecommendation(recommendationId) {
        if (confirm('Opravdu chcete použít toto doporučení?')) {
            // AJAX call to apply recommendation
            const formData = new FormData();
            formData.append('action', 'wpsg_apply_recommendation');
            formData.append('recommendation_id', recommendationId);
            formData.append('nonce', '<?php echo wp_create_nonce('wpsg_apply_recommendation'); ?>');

            fetch('<?php echo admin_url('admin-ajax.php'); ?>', {
                    method: 'POST',
                    body: formData
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        alert('Doporučení bylo úspěšně použito!');
                        location.reload();
                    } else {
                        alert('Chyba při aplikaci doporučení: ' + data.message);
                    }
                });
        }
    }

    // Izolovaný event listener pro unblock tlačítka
    try {
        document.addEventListener('click', function(e) {
            // Kontrola jestli je klik na unblock tlačítko
            let button = null;
            if (e.target && e.target.classList && e.target.classList.contains('unblock-btn')) {
                button = e.target;
            } else if (e.target && e.target.closest && e.target.closest('.unblock-btn')) {
                button = e.target.closest('.unblock-btn');
            }

            if (button) {
                const ip = button.getAttribute('data-ip');

                if (window.confirm('Opravdu chcete odblokovat IP ' + ip + '?')) {
                    // Okamžitě změní UI pro lepší user experience
                    const ipClass = ip.replace(/\./g, '-');
                    const status = document.getElementById('unblocked-status-' + ipClass);

                    if (status) {
                        button.style.display = 'none';
                        status.style.display = 'inline';
                    }

                    // Pokračuj s odesláním formuláře
                    return true;
                } else {
                    // Zablokuj odeslání formuláře
                    e.preventDefault();
                    e.stopPropagation();
                    return false;
                }
            }
        });
    } catch (error) {
        console.error('Chyba v unblock event listeneru:', error);
    }

    // Handle autopilot toggle changes with AJAX
    const autopilotToggles = document.querySelectorAll('.wpsg-autopilot-toggle');
    autopilotToggles.forEach(toggle => {
        toggle.addEventListener('change', function() {
            const settingKey = this.getAttribute('data-setting');
            const settingValue = this.checked;
            const originalValue = !settingValue;

            // Show loading state
            const toggleContainer = this.closest('.wpsg-toggle-switch');
            toggleContainer.style.opacity = '0.5';

            console.log('Autopilot setting change:', settingKey, settingValue);

            fetch(ajaxurl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: new URLSearchParams({
                    action: 'wpsg_toggle_setting',
                    setting_key: settingKey,
                    setting_value: settingValue ? '1' : '0',
                    nonce: '<?php echo wp_create_nonce('wpsg_settings_nonce'); ?>'
                })
            })
            .then(response => response.json())
            .then(data => {
                toggleContainer.style.opacity = '1';
                
                if (data.success) {
                    console.log('Autopilot setting saved:', data);
                    showAutopilotToast('Nastavení uloženo', 'success');
                    
                    // Special messages for autopilot features
                    if (settingKey === 'wpsg_autopilot_enabled' && settingValue) {
                        showAutopilotToast('Auto-Pilot aktivován - AI ochrana je nyní aktivní', 'info');
                        // Refresh page after 2 seconds to show updated status
                        setTimeout(() => location.reload(), 2000);
                    }
                    if (settingKey === 'wpsg_autopilot_auto_block_ips' && settingValue) {
                        showAutopilotToast('Automatické blokování IP zapnuto - podezřelé IP budou blokovány', 'info');
                    }
                    if (settingKey === 'wpsg_autopilot_emergency_lockdown' && settingValue) {
                        showAutopilotToast('Nouzové uzamčení aktivováno - při detekci útoku bude web uzamčen', 'warning');
                    }
                } else {
                    console.error('Autopilot AJAX error:', data.data);
                    showAutopilotToast('Chyba: ' + (data.data || 'Neznámá chyba'), 'error');
                    // Revert toggle state
                    this.checked = originalValue;
                }
            })
            .catch(error => {
                console.error('Autopilot network error:', error);
                toggleContainer.style.opacity = '1';
                showAutopilotToast('Chyba při ukládání: ' + error.message, 'error');
                // Revert toggle state
                this.checked = originalValue;
            });
        });
    });

    // Show toast notification for autopilot
    function showAutopilotToast(message, type = 'info') {
        // Remove existing toasts
        const existingToasts = document.querySelectorAll('.wpsg-autopilot-toast');
        existingToasts.forEach(toast => toast.remove());

        const toast = document.createElement('div');
        toast.className = 'wpsg-autopilot-toast';
        toast.style.cssText = `
            position: fixed;
            top: 32px;
            right: 32px;
            padding: 16px 24px;
            border-radius: 8px;
            color: white;
            font-weight: 600;
            z-index: 10000;
            max-width: 400px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.3);
            animation: slideIn 0.3s ease-out;
        `;

        // Set colors based on type
        switch(type) {
            case 'success':
                toast.style.background = 'linear-gradient(135deg, #10b981 0%, #059669 100%)';
                break;
            case 'error':
                toast.style.background = 'linear-gradient(135deg, #dc2626 0%, #b91c1c 100%)';
                break;
            case 'warning':
                toast.style.background = 'linear-gradient(135deg, #f59e0b 0%, #d97706 100%)';
                break;
            default:
                toast.style.background = 'linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%)';
        }

        toast.textContent = message;
        document.body.appendChild(toast);

        // Add slide-in animation
        const style = document.createElement('style');
        style.textContent = `
            @keyframes slideIn {
                from { transform: translateX(100%); opacity: 0; }
                to { transform: translateX(0); opacity: 1; }
            }
        `;
        document.head.appendChild(style);

        // Remove toast after 4 seconds
        setTimeout(() => {
            toast.style.animation = 'slideIn 0.3s ease-out reverse';
            setTimeout(() => toast.remove(), 300);
        }, 4000);
    }
</script>