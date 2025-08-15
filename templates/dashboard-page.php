<?php
if (!defined('ABSPATH')) {
    exit;
}

// Fallback hodnoty pro template proměnné
if (!isset($dashboard_data) || !is_array($dashboard_data)) {
    $dashboard_data = array();
}

// Zajistit základní klíče s fallback hodnotami
$dashboard_data['security_score'] = isset($dashboard_data['security_score']) ? $dashboard_data['security_score'] : 50;
$dashboard_data['security_enabled'] = isset($dashboard_data['security_enabled']) ? $dashboard_data['security_enabled'] : false;
$dashboard_data['threat_stats'] = isset($dashboard_data['threat_stats']) ? $dashboard_data['threat_stats'] : array(
    'total_threats' => 0,
    'blocked_ips' => 0, 
    'failed_logins' => 0
);
$dashboard_data['plugin_stats'] = isset($dashboard_data['plugin_stats']) ? $dashboard_data['plugin_stats'] : array(
    'total_plugins' => 0,
    'whitelisted_plugins' => 0
);
$dashboard_data['security_checklist'] = isset($dashboard_data['security_checklist']) ? $dashboard_data['security_checklist'] : array();
$dashboard_data['recommendations'] = isset($dashboard_data['recommendations']) ? $dashboard_data['recommendations'] : array();
?>

<script src="https://cdn.jsdelivr.net/npm/apexcharts"></script>
<script src="https://cdn.tailwindcss.com"></script>

<style>
    .wpsg-dashboard-wrap {
        margin: 20px 20px 0 2px;
        background: #f0f0f1;
        min-height: calc(100vh - 32px);
    }

    .wpsg-dashboard-card {
        background: white;
        border-radius: 16px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
        transition: all 0.3s ease;
    }

    .wpsg-dashboard-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
    }

    .wpsg-score-ring {
        position: relative;
        width: 200px;
        height: 200px;
        margin: 0 auto;
    }

    .wpsg-score-text {
        position: absolute;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        text-align: center;
    }

    .wpsg-metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 24px;
        border-radius: 12px;
        text-align: center;
    }

    .wpsg-chart-container {
        background: white;
        padding: 24px;
        border-radius: 12px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
    }

    .wpsg-recommendation {
        padding: 16px;
        border-left: 4px solid;
        border-radius: 8px;
        margin-bottom: 16px;
    }

    .wpsg-recommendation.critical {
        background: #fef2f2;
        border-color: #dc2626;
        color: #dc2626;
    }

    .wpsg-recommendation.warning {
        background: #fffbeb;
        border-color: #f59e0b;
        color: #f59e0b;
    }

    .wpsg-recommendation.info {
        background: #eff6ff;
        border-color: #3b82f6;
        color: #3b82f6;
    }

    .wpsg-recommendation.success {
        background: #f0fdf4;
        border-color: #16a34a;
        color: #16a34a;
    }

    .wpsg-event-item {
        padding: 12px 16px;
        border-bottom: 1px solid #f1f5f9;
        display: flex;
        align-items: center;
        justify-content: space-between;
    }

    .wpsg-event-item:last-child {
        border-bottom: none;
    }

    .wpsg-status-badge {
        padding: 4px 12px;
        border-radius: 20px;
        font-size: 12px;
        font-weight: 600;
        text-transform: uppercase;
    }

    .wpsg-status-excellent {
        background: #dcfce7;
        color: #16a34a;
    }

    .wpsg-status-good {
        background: #dbeafe;
        color: #3b82f6;
    }

    .wpsg-status-fair {
        background: #fef3c7;
        color: #f59e0b;
    }

    .wpsg-status-poor {
        background: #fee2e2;
        color: #dc2626;
    }

    @media (max-width: 1200px) {
        .wpsg-main-grid {
            grid-template-columns: 1fr !important;
        }

        .wpsg-charts-grid {
            grid-template-columns: 1fr !important;
        }

        .wpsg-bottom-grid {
            grid-template-columns: 1fr !important;
        }
    }

    @media (max-width: 768px) {
        .wpsg-metrics-grid {
            grid-template-columns: 1fr !important;
        }
    }
</style>

<div class="wrap">
    <h1>🛡️ Security Dashboard</h1>

    <div class="wpsg-dashboard-wrap">
        <div style="max-width: 1400px; margin: 0 auto; padding: 20px;">

            <!-- Status Overview -->
            <div class="wpsg-gradient-header" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);padding: 32px;border-radius: 16px;margin-bottom: 32px;position: relative;overflow: hidden;color: #fff;">
                <div style="display: flex; align-items: flex-end; justify-content: space-between; flex-wrap: wrap; gap: 16px;">
                    <div style="display: flex;flex-direction: column;gap: 1rem;">
                        <h2 style="font-size: 24px; font-weight: 700;color:#fff;margin: 0; text-shadow: 0 2px 4px rgba(0,0,0,0.3);">Kompletní přehled bezpečnosti</h2>
                        <p style="font-size: 14px; opacity: 0.9; margin: 8px 0 0 0;">Aktuální stav ochrany vašeho webu</p>
                    </div>
                    <div style="text-align: right;">
                        <div style="font-size: 12px; opacity: 0.8;">Poslední aktualizace</div>
                        <div style="font-size: 14px; font-weight: 600;"><?php echo date_i18n('d.m.Y H:i'); ?></div>
                    </div>
                </div>
            </div>

            <!-- Security Score & Quick Metrics -->
            <div style="display: grid; grid-template-columns: 1fr 2fr; gap: 24px; margin-bottom: 24px;" class="wpsg-main-grid">

                <!-- Security Score -->
                <div class="wpsg-dashboard-card" style="padding: 24px; text-align: center;">
                    <h3 style="font-size: 20px; font-weight: 700; color: #1e293b; margin: 0 0 20px 0;">Security Score</h3>

                    <div class="wpsg-score-ring">
                        <div id="securityScoreChart"></div>
                        <div class="wpsg-score-text">
                            <div style="font-size: 36px;padding-bottom: 1rem;font-weight: 800; color: <?php echo $dashboard_data['security_score'] >= 80 ? '#16a34a' : ($dashboard_data['security_score'] >= 60 ? '#f59e0b' : '#dc2626'); ?>;">
                                <?php echo $dashboard_data['security_score']; ?>
                            </div>
                            <div style="font-size: 16px; color: #64748b; font-weight: 600;">
                                <?php
                                $score = $dashboard_data['security_score'];
                                if ($score >= 90) echo 'VYNIKAJÍCÍ';
                                elseif ($score >= 80) echo 'VÝBORNÉ';
                                elseif ($score >= 70) echo 'DOBRÉ';
                                elseif ($score >= 50) echo 'STŘEDNÍ';
                                else echo 'SLABÉ';
                                ?>
                            </div>
                        </div>
                    </div>

                    <div style="margin-top: 24px;">
                        <span class="wpsg-status-badge <?php echo $dashboard_data['security_score'] >= 80 ? 'wpsg-status-excellent' : ($dashboard_data['security_score'] >= 60 ? 'wpsg-status-good' : 'wpsg-status-poor'); ?>">
                            <?php echo $dashboard_data['security_enabled'] ? 'AKTIVNÍ OCHRANA' : 'OCHRANA VYPNUTA'; ?>
                        </span>
                    </div>
                </div>

                <!-- Quick Metrics -->
                <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px;" class="wpsg-metrics-grid">
                    <div class="wpsg-metric-card">
                        <div style="font-size: 28px; font-weight: 800; margin-bottom: 6px;"><?php echo $dashboard_data['threat_stats']['total_threats']; ?></div>
                        <div style="font-size: 14px; opacity: 0.9;">Hrozby za 30 dní</div>
                    </div>

                    <div class="wpsg-metric-card" style="background: linear-gradient(135deg, #10b981 0%, #059669 100%);">
                        <div style="font-size: 28px; font-weight: 800; margin-bottom: 6px;"><?php echo $dashboard_data['threat_stats']['blocked_ips']; ?></div>
                        <div style="font-size: 14px; opacity: 0.9;">Blokované IP adresy</div>
                    </div>

                    <div class="wpsg-metric-card" style="background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);">
                        <div style="font-size: 28px; font-weight: 800; margin-bottom: 6px;"><?php echo $dashboard_data['plugin_stats']['whitelisted_plugins']; ?>/<?php echo $dashboard_data['plugin_stats']['total_plugins']; ?></div>
                        <div style="font-size: 14px; opacity: 0.9;">Povolené pluginy</div>
                    </div>

                    <div class="wpsg-metric-card" style="background: linear-gradient(135deg, #dc2626 0%, #b91c1c 100%);">
                        <div style="font-size: 28px; font-weight: 800; margin-bottom: 6px;"><?php echo $dashboard_data['threat_stats']['failed_logins']; ?></div>
                        <div style="font-size: 14px; opacity: 0.9;">Neúspěšná přihlášení</div>
                    </div>
                </div>
            </div>

            <!-- Charts Row -->
            <div style="display: grid; grid-template-columns: 2fr 1fr; gap: 24px; margin-bottom: 24px;" class="wpsg-charts-grid">

                <!-- Threat Timeline Chart -->
                <div class="wpsg-chart-container">
                    <h3 style="font-size: 18px; font-weight: 700; color: #1e293b; margin: 0 0 20px 0;">📊 Trend hrozeb (30 dní)</h3>
                    <div id="threatTimelineChart" style="height: 280px;"></div>
                </div>

                <!-- Plugin Protection Chart -->
                <div class="wpsg-chart-container">
                    <h3 style="font-size: 18px; font-weight: 700; color: #1e293b; margin: 0 0 20px 0;">🔌 Ochrana pluginů</h3>
                    <div id="pluginProtectionChart" style="height: 280px;"></div>
                </div>
            </div>

            <!-- Security Checklist -->
            <div class="wpsg-dashboard-card" style="margin-bottom: 24px;">
                <div style="padding: 24px; border-bottom: 1px solid #f1f5f9; display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <h3 style="font-size: 20px; font-weight: 700; color: #1e293b; margin: 0;">🔐 Detailní bezpečnostní audit</h3>
                        <p style="color: #64748b; margin: 8px 0 0 0;">Komplexní přehled všech bezpečnostních opatření (reaguje na aktuální nastavení)</p>
                    </div>
                    <button onclick="location.reload();" style="background: linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%); color: white; border: none; padding: 8px 16px; border-radius: 6px; font-weight: 600; cursor: pointer; font-size: 14px;">
                        🔄 Obnovit audit
                    </button>
                </div>
                <div style="padding: 24px;">
                    <?php foreach ($dashboard_data['security_checklist'] as $category_key => $category): ?>
                        <div style="margin-bottom: 32px;">
                            <h4 style="font-size: 16px; font-weight: 700; color: #1e293b; margin: 0 0 16px 0; padding: 8px 0; border-bottom: 2px solid #e2e8f0;">
                                <?php echo esc_html($category['title']); ?>
                            </h4>

                            <?php
                            $category_checks = count($category['checks']);
                            $category_passed = 0;
                            foreach ($category['checks'] as $check) {
                                if ($check['status']) $category_passed++;
                            }
                            $category_percentage = $category_checks > 0 ? round(($category_passed / $category_checks) * 100) : 0;
                            ?>

                            <div style="display: flex; align-items: center; margin-bottom: 16px;">
                                <div style="flex: 1; background: #f1f5f9; height: 8px; border-radius: 4px; overflow: hidden;">
                                    <div style="width: <?php echo $category_percentage; ?>%; height: 100%; background: <?php echo $category_percentage >= 80 ? '#10b981' : ($category_percentage >= 60 ? '#f59e0b' : '#dc2626'); ?>; transition: width 0.3s ease;"></div>
                                </div>
                                <span style="margin-left: 12px; font-weight: 600; color: #64748b; font-size: 14px;">
                                    <?php echo $category_passed; ?>/<?php echo $category_checks; ?> (<?php echo $category_percentage; ?>%)
                                </span>
                            </div>

                            <?php foreach ($category['checks'] as $check_key => $check): ?>
                                <div style="display: flex; align-items: flex-start; padding: 12px; background: <?php echo $check['status'] ? '#f0fdf4' : '#fef2f2'; ?>; border-radius: 8px; margin-bottom: 12px;">
                                    <div style="margin-right: 12px; margin-top: 2px;">
                                        <?php if ($check['status']): ?>
                                            <div style="width: 20px; height: 20px; background: #10b981; border-radius: 50%; display: flex; align-items: center; justify-content: center;">
                                                <svg style="width: 12px; height: 12px; color: white;" fill="currentColor" viewBox="0 0 20 20">
                                                    <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"></path>
                                                </svg>
                                            </div>
                                        <?php else: ?>
                                            <div style="width: 20px; height: 20px; background: #dc2626; border-radius: 50%; display: flex; align-items: center; justify-content: center;">
                                                <svg style="width: 12px; height: 12px; color: white;" fill="currentColor" viewBox="0 0 20 20">
                                                    <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"></path>
                                                </svg>
                                            </div>
                                        <?php endif; ?>
                                    </div>
                                    <div style="flex: 1;">
                                        <div style="font-weight: 600; color: <?php echo $check['status'] ? '#16a34a' : '#dc2626'; ?>; margin-bottom: 4px;">
                                            <?php echo esc_html($check['name']); ?>
                                        </div>
                                        <div style="font-size: 14px; color: #64748b; line-height: 1.4;">
                                            <?php echo esc_html($check['description']); ?>
                                        </div>
                                        <div style="font-size: 12px; color: #94a3b8; margin-top: 4px;">
                                            Váha: <?php echo $check['weight']; ?> bodů
                                        </div>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    <?php endforeach; ?>
                </div>
            </div>

            <!-- Recommendations & Recent Events -->
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 24px;" class="wpsg-bottom-grid">

                <!-- Security Recommendations -->
                <div class="wpsg-dashboard-card" style="padding: 24px;">
                    <h3 style="font-size: 18px; font-weight: 700; color: #1e293b; margin: 0 0 20px 0;">💡 Doporučení pro zlepšení</h3>

                    <?php foreach ($dashboard_data['recommendations'] as $recommendation): ?>
                        <div class="wpsg-recommendation <?php echo $recommendation['type']; ?>">
                            <div style="font-weight: 600; margin-bottom: 8px;"><?php echo esc_html($recommendation['title']); ?></div>
                            <div style="margin-bottom: 12px; opacity: 0.9;"><?php echo esc_html($recommendation['message']); ?></div>
                            <?php if ($recommendation['action']): ?>
                                <div>
                                    <button style="background: currentColor; color: white; padding: 6px 12px; border: none; border-radius: 6px; font-size: 12px; font-weight: 600; cursor: pointer;">
                                        <?php echo esc_html($recommendation['action']); ?>
                                    </button>
                                </div>
                            <?php endif; ?>
                        </div>
                    <?php endforeach; ?>
                </div>

                <!-- Recent Security Events -->
                <div class="wpsg-dashboard-card" style="padding: 24px;">
                    <h3 style="font-size: 18px; font-weight: 700; color: #1e293b; margin: 0 0 20px 0;">🕒 Nedávné události</h3>

                    <div style="max-height: 350px; overflow-y: auto;">
                        <?php if (empty($dashboard_data['recent_events'])): ?>
                            <div style="text-align: center; color: #64748b; padding: 40px 20px;">
                                <div style="font-size: 48px; margin-bottom: 16px;">🎉</div>
                                <div style="font-weight: 600;">Žádné události</div>
                                <div style="font-size: 14px; margin-top: 8px;">Váš web je v bezpečí!</div>
                            </div>
                        <?php else: ?>
                            <?php foreach ($dashboard_data['recent_events'] as $event): ?>
                                <div class="wpsg-event-item">
                                    <div>
                                        <div style="font-weight: 600; color: #1e293b;"><?php echo esc_html($event['message']); ?></div>
                                        <div style="font-size: 12px; color: #64748b; margin-top: 4px;">
                                            <?php echo date_i18n('d.m.Y H:i', strtotime($event['timestamp'])); ?>
                                            <?php if ($event['ip_address']): ?>
                                                • IP: <?php echo esc_html($event['ip_address']); ?>
                                            <?php endif; ?>
                                        </div>
                                    </div>
                                    <div>
                                        <span style="
                                        padding: 4px 8px; 
                                        border-radius: 12px; 
                                        font-size: 10px; 
                                        font-weight: 600; 
                                        text-transform: uppercase;
                                        background: <?php echo $event['event_type'] === 'IP_BLOCKED' ? '#fee2e2' : ($event['event_type'] === 'LOGIN_FAILED' ? '#fef3c7' : '#f3f4f6'); ?>;
                                        color: <?php echo $event['event_type'] === 'IP_BLOCKED' ? '#dc2626' : ($event['event_type'] === 'LOGIN_FAILED' ? '#f59e0b' : '#64748b'); ?>;
                                    ">
                                            <?php echo esc_html($event['event_type']); ?>
                                        </span>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </div>
                </div>
            </div>

        </div>
    </div>
</div>

<script>
    document.addEventListener('DOMContentLoaded', function() {
        // Připravit data pro grafy
        const threatStats = <?php echo json_encode($dashboard_data['threat_stats']); ?>;
        const pluginStats = <?php echo json_encode($dashboard_data['plugin_stats']); ?>;
        const securityScore = <?php echo $dashboard_data['security_score']; ?>;

        // Debug log
        console.log('Dashboard data:', {
            threatStats,
            pluginStats,
            securityScore
        });

        // Security Score Radial Chart
        const securityScoreOptions = {
            series: [securityScore],
            chart: {
                height: 200,
                type: 'radialBar',
                toolbar: {
                    show: false
                }
            },
            plotOptions: {
                radialBar: {
                    startAngle: -135,
                    endAngle: 135,
                    hollow: {
                        margin: 0,
                        size: '70%',
                        background: 'transparent',
                        position: 'front',
                    },
                    track: {
                        background: '#f1f5f9',
                        strokeWidth: '67%',
                        margin: 0,
                    },
                    dataLabels: {
                        show: false
                    }
                }
            },
            fill: {
                type: 'gradient',
                gradient: {
                    shade: 'dark',
                    shadeIntensity: 0.4,
                    inverseColors: false,
                    opacityFrom: 1,
                    opacityTo: 1,
                    stops: [0, 50, 53, 91],
                    colorStops: [{
                            offset: 0,
                            color: securityScore >= 80 ? '#10b981' : (securityScore >= 60 ? '#f59e0b' : '#dc2626'),
                            opacity: 1
                        },
                        {
                            offset: 100,
                            color: securityScore >= 80 ? '#059669' : (securityScore >= 60 ? '#d97706' : '#b91c1c'),
                            opacity: 1
                        }
                    ]
                }
            },
            stroke: {
                lineCap: 'round'
            }
        };

        // Render Security Score Chart
        const securityScoreElement = document.querySelector("#securityScoreChart");
        if (securityScoreElement && typeof ApexCharts !== 'undefined') {
            try {
                const securityScoreChart = new ApexCharts(securityScoreElement, securityScoreOptions);
                securityScoreChart.render();
            } catch (error) {
                console.error('Error rendering security score chart:', error);
                securityScoreElement.innerHTML = '<div style="color: #dc2626; text-align: center; padding: 40px;">Graf se nepodařilo načíst</div>';
            }
        } else if (securityScoreElement) {
            securityScoreElement.innerHTML = '<div style="color: #dc2626; text-align: center; padding: 40px;">ApexCharts se nepodařilo načíst</div>';
        }

        // Threat Timeline Chart
        let timelineData = [];
        if (threatStats.daily_stats && Object.keys(threatStats.daily_stats).length > 0) {
            timelineData = Object.keys(threatStats.daily_stats).map(date => ({
                x: date,
                threats: threatStats.daily_stats[date].threats || 0,
                blocked_ips: threatStats.daily_stats[date].blocked_ips || 0,
                failed_logins: threatStats.daily_stats[date].failed_logins || 0
            }));
        } else {
            // Generovat demo data pro poslední 30 dní
            for (let i = 29; i >= 0; i--) {
                const date = new Date();
                date.setDate(date.getDate() - i);
                timelineData.push({
                    x: date.toISOString().split('T')[0],
                    threats: 0,
                    blocked_ips: 0,
                    failed_logins: 0
                });
            }
        }

        const threatTimelineOptions = {
            series: [{
                    name: 'Celkové hrozby',
                    data: timelineData.map(d => ({
                        x: d.x,
                        y: d.threats
                    }))
                },
                {
                    name: 'Blokované IP',
                    data: timelineData.map(d => ({
                        x: d.x,
                        y: d.blocked_ips
                    }))
                },
                {
                    name: 'Neúspěšná přihlášení',
                    data: timelineData.map(d => ({
                        x: d.x,
                        y: d.failed_logins
                    }))
                }
            ],
            chart: {
                height: 280,
                type: 'area',
                stacked: false,
                toolbar: {
                    show: false
                },
                zoom: {
                    enabled: false
                }
            },
            dataLabels: {
                enabled: false
            },
            stroke: {
                curve: 'smooth',
                width: 2
            },
            fill: {
                type: 'gradient',
                gradient: {
                    opacityFrom: 0.6,
                    opacityTo: 0.8,
                }
            },
            legend: {
                position: 'top',
                horizontalAlign: 'left'
            },
            xaxis: {
                type: 'datetime',
                labels: {
                    format: 'dd.MM'
                }
            },
            colors: ['#dc2626', '#f59e0b', '#3b82f6']
        };

        // Render Threat Timeline Chart
        const threatTimelineElement = document.querySelector("#threatTimelineChart");
        if (threatTimelineElement && typeof ApexCharts !== 'undefined') {
            try {
                const threatTimelineChart = new ApexCharts(threatTimelineElement, threatTimelineOptions);
                threatTimelineChart.render();
            } catch (error) {
                console.error('Error rendering threat timeline chart:', error);
                threatTimelineElement.innerHTML = '<div style="color: #dc2626; text-align: center; padding: 40px;">Graf se nepodařilo načíst</div>';
            }
        } else if (threatTimelineElement) {
            threatTimelineElement.innerHTML = '<div style="color: #dc2626; text-align: center; padding: 40px;">ApexCharts se nepodařilo načíst</div>';
        }

        // Plugin Protection Donut Chart
        const pluginProtectionOptions = {
            series: [pluginStats.whitelisted_plugins || 0, pluginStats.blocked_plugins || 0],
            chart: {
                height: 280,
                type: 'donut',
            },
            labels: ['Povolené pluginy', 'Blokované pluginy'],
            colors: ['#10b981', '#dc2626'],
            plotOptions: {
                pie: {
                    donut: {
                        size: '70%',
                        labels: {
                            show: true,
                            total: {
                                show: true,
                                label: 'Celkem pluginů',
                                formatter: function() {
                                    return pluginStats.total_plugins || 0;
                                }
                            }
                        }
                    }
                }
            },
            legend: {
                position: 'bottom'
            },
            dataLabels: {
                formatter: function(val, opts) {
                    return opts.w.config.series[opts.seriesIndex];
                }
            }
        };

        // Render Plugin Protection Chart
        const pluginProtectionElement = document.querySelector("#pluginProtectionChart");
        if (pluginProtectionElement && typeof ApexCharts !== 'undefined') {
            try {
                const pluginProtectionChart = new ApexCharts(pluginProtectionElement, pluginProtectionOptions);
                pluginProtectionChart.render();
            } catch (error) {
                console.error('Error rendering plugin protection chart:', error);
                pluginProtectionElement.innerHTML = '<div style="color: #dc2626; text-align: center; padding: 40px;">Graf se nepodařilo načíst</div>';
            }
        } else if (pluginProtectionElement) {
            pluginProtectionElement.innerHTML = '<div style="color: #dc2626; text-align: center; padding: 40px;">ApexCharts se nepodařilo načíst</div>';
        }

        // Responzivní úpravy
        window.addEventListener('resize', function() {
            const mainGrid = document.querySelector('.wpsg-main-grid');
            const chartsGrid = document.querySelector('.wpsg-charts-grid');
            const bottomGrid = document.querySelector('.wpsg-bottom-grid');
            const metricsGrid = document.querySelector('.wpsg-metrics-grid');

            if (window.innerWidth < 1200) {
                if (mainGrid) mainGrid.style.gridTemplateColumns = '1fr';
                if (chartsGrid) chartsGrid.style.gridTemplateColumns = '1fr';
                if (bottomGrid) bottomGrid.style.gridTemplateColumns = '1fr';
            } else {
                if (mainGrid) mainGrid.style.gridTemplateColumns = '1fr 2fr';
                if (chartsGrid) chartsGrid.style.gridTemplateColumns = '2fr 1fr';
                if (bottomGrid) bottomGrid.style.gridTemplateColumns = '1fr 1fr';
            }

            if (window.innerWidth < 768) {
                if (metricsGrid) metricsGrid.style.gridTemplateColumns = '1fr';
            } else {
                if (metricsGrid) metricsGrid.style.gridTemplateColumns = 'repeat(2, 1fr)';
            }
        });
    });
</script>