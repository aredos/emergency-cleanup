<?php
/**
 * Plugin Name: Emergency Security Cleanup
 * Plugin URI: https://github.com/aredos/emergency-cleanup
 * Description: Plugin de emergencia para limpieza automática de malware después del compromiso del servidor. Incluye detección avanzada, backup automático y verificación de integridad.
 * Version: 1.3.0
 * Requires at least: 5.0
 * Tested up to: 6.7
 * Requires PHP: 7.4
 * Author: Aredos
 * Author URI: https://github.com/aredos
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: Emergency_Cleanup
 * Domain Path: /languages
 * Network: false
 * 
 * Emergency Security Cleanup is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * any later version.
 * 
 * Emergency Security Cleanup is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

// Prevenir acceso directo
if (!defined('ABSPATH')) {
    exit;
}

// Definir constantes del plugin
define('EMERGENCY_CLEANUP_VERSION', '1.3.0');
define('EMERGENCY_CLEANUP_PLUGIN_FILE', __FILE__);
define('EMERGENCY_CLEANUP_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('EMERGENCY_CLEANUP_PLUGIN_URL', plugin_dir_url(__FILE__));

// Hook de activación
register_activation_hook(__FILE__, 'emergency_cleanup_activate');
register_deactivation_hook(__FILE__, 'emergency_cleanup_deactivate');

/**
 * Función de activación del plugin
 */
function emergency_cleanup_activate() {
    // Verificar versión mínima de WordPress
    if (version_compare(get_bloginfo('version'), '5.0', '<')) {
        wp_die(
            esc_html__('Emergency Security Cleanup requiere WordPress 5.0 o superior.', 'Emergency_Cleanup'),
            esc_html__('Error de activación', 'Emergency_Cleanup'),
            array('back_link' => true)
        );
    }
    
    // Verificar versión mínima de PHP
    if (version_compare(PHP_VERSION, '7.4', '<')) {
        wp_die(
            esc_html__('Emergency Security Cleanup requiere PHP 7.4 o superior.', 'Emergency_Cleanup'),
            esc_html__('Error de activación', 'Emergency_Cleanup'),
            array('back_link' => true)
        );
    }
    
    // Crear opciones por defecto
    add_option('emergency_cleanup_version', EMERGENCY_CLEANUP_VERSION);
    add_option('emergency_cleanup_activated', current_time('mysql'));
}

/**
 * Función de desactivación del plugin
 */
function emergency_cleanup_deactivate() {
    // Limpiar opciones temporales si es necesario
    delete_option('emergency_cleanup_activated');
}

class EmergencySecurityCleanup {
    
    private $malicious_files = [];
    private $malicious_folders = [];
    private $malicious_plugins = [];
    private $log = [];
    private $backup_dir = '';
    private $malicious_patterns = [];
    private $scan_stats = [];
    
    public function __construct() {
        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_action('wp_ajax_emergency_cleanup', array($this, 'perform_cleanup'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_scripts'));
        add_action('init', array($this, 'load_textdomain'));
        
        // Crear directorio de backup
        $this->backup_dir = WP_CONTENT_DIR . '/emergency-backup-' . date('Y-m-d-H-i-s');
        
        // Definir archivos y carpetas maliciosos conocidos
        $this->define_malicious_items();
        $this->define_malicious_patterns();
    }
    
    /**
     * Cargar archivos de traducción
     */
    public function load_textdomain() {
        load_plugin_textdomain(
            'Emergency_Cleanup',
            false,
            dirname(plugin_basename(EMERGENCY_CLEANUP_PLUGIN_FILE)) . '/languages'
        );
    }
    
    private function define_malicious_items() {
        // Archivos maliciosos en raíz
        $this->malicious_files = [
            'index.html',
            'index.html_bak',
            'htaccess_bak',
            'public_html.rar',
            'wp-content.rar',
        ];
        
        // Carpetas maliciosas en raíz
        $this->malicious_folders = [
            '.usermin',
            'awstats-icon',
            'icon',
            'stats',
            'cgi-bin',
        ];
        
        // Plugins maliciosos conocidos
        $this->malicious_plugins = [
            'cardoza-3d-tag-cloud',
            'cphbgsu',
            'Fix',
            'Hellos',
            'wp-reforming-itself',
            'advanced-nocaptcha-recaptcha-old',
            're-add-text-justify-button',
            'slideshow-jquery-image-galleryNO',
        ];
    }
    
    private function define_malicious_patterns() {
        // Patrones de código malicioso común (refinados para evitar falsos positivos)
        $this->malicious_patterns = [
            // Backdoors comunes - eval con ofuscación
            '/eval\s*\(\s*base64_decode\s*\(/i',
            '/eval\s*\(\s*gzinflate\s*\(/i',
            '/eval\s*\(\s*gzuncompress\s*\(/i',
            '/eval\s*\(\s*str_rot13\s*\(/i',
            '/eval\s*\(\s*stripslashes\s*\(/i',
            '/assert\s*\(\s*base64_decode\s*\(/i',
            
            // Ejecución de comandos con variables (más sospechoso que strings literales)
            '/system\s*\(\s*\$[_a-zA-Z]/i',
            '/exec\s*\(\s*\$[_a-zA-Z]/i',
            '/shell_exec\s*\(\s*\$[_a-zA-Z]/i',
            '/passthru\s*\(\s*\$[_a-zA-Z]/i',
            '/proc_open\s*\(/i',
            '/popen\s*\(/i',
            
            // Variables superglobales sospechosas
            '/\$_(?:GET|POST|REQUEST|COOKIE)\s*\[\s*[\'"]\w+[\'"]\s*\]\s*\(\s*\$/i',
            '/create_function\s*\(\s*[\'"]\s*\$\w+\s*[\'"]/i',
            
            // Strings base64 muy largos (ofuscación)
            '/["\'][A-Za-z0-9+\/]{200,}={0,2}["\']/i',
            
            // Backdoors conocidos
            '/c99shell/i',
            '/r57shell/i',
            '/webshell/i',
            '/FilesMan/i',
            '/\$_\w+\s*=\s*\$\w+\s*\(\s*\$\w+\s*\)/i', // Variable functions comunes en backdoors
            
            // Código de minería de criptomonedas (más específico)
            '/coinhive\.min\.js/i',
            '/crypto-loot/i',
            '/cryptonight\s*\(/i',
            '/new\s+Miner\s*\(/i',
            
            // Inyección de base64 decode en variables
            '/base64_decode\s*\(\s*[\'"]\s*[A-Za-z0-9+\/]{50,}/i',
        ];
    }
    
    public function add_admin_menu() {
        add_options_page(
            'Emergency Cleanup',
            '🚨 Emergency Cleanup',
            'manage_options',
            'emergency-cleanup',
            array($this, 'admin_page')
        );
    }
    
    public function enqueue_scripts($hook) {
        if ($hook !== 'settings_page_emergency-cleanup') {
            return;
        }
        wp_enqueue_script('jquery');
    }
    
    public function admin_page() {
        ?>
        <div class="wrap">
            <h1>🚨 Emergency Security Cleanup</h1>
            
            <div class="notice notice-error">
                <p><strong><?php esc_html_e('ADVERTENCIA:', 'Emergency_Cleanup'); ?></strong> <?php esc_html_e('Este plugin eliminará archivos automáticamente. Asegúrate de tener backup antes de continuar.', 'Emergency_Cleanup'); ?></p>
            </div>
            
            <div class="card">
                <h2><?php esc_html_e('Verificación de Servidor', 'Emergency_Cleanup'); ?></h2>
                <p><strong><?php esc_html_e('Sitio:', 'Emergency_Cleanup'); ?></strong> <?php echo esc_url(get_site_url()); ?></p>
                <p><strong><?php esc_html_e('auto_prepend_file:', 'Emergency_Cleanup'); ?></strong> <?php echo esc_html(ini_get('auto_prepend_file') ?: __('No configurado', 'Emergency_Cleanup')); ?></p>
                <?php
                $malicious_server_file = '/usr/share/php/rate_from_php_set_envs.php';
                if (file_exists($malicious_server_file)) {
                    echo '<p style="color:orange;"><strong>⚠️ ' . esc_html__('Archivo de hosting detectado', 'Emergency_Cleanup') . '</strong></p>';
                    echo '<p>' . esc_html__('Confirmar con Hosting si es configuración estándar', 'Emergency_Cleanup') . '</p>';
                } else {
                    echo '<p style="color:green;">✅ ' . esc_html__('No se detecta archivo a nivel servidor', 'Emergency_Cleanup') . '</p>';
                }
                ?>
            </div>
            
            <div class="card">
                <h2><?php esc_html_e('Escaneo y Limpieza Automática', 'Emergency_Cleanup'); ?></h2>
                <div class="scan-options">
                    <label for="enable-backup">
                        <input type="checkbox" id="enable-backup" checked> 
                        💾 <?php esc_html_e('Crear backup antes de eliminar', 'Emergency_Cleanup'); ?>
                    </label><br>
                    <label for="scan-content">
                        <input type="checkbox" id="scan-content" checked> 
                        🔍 <?php esc_html_e('Escanear contenido de archivos', 'Emergency_Cleanup'); ?>
                    </label><br>
                    <label for="scan-database">
                        <input type="checkbox" id="scan-database" checked> 
                        🗄️ <?php esc_html_e('Verificar base de datos', 'Emergency_Cleanup'); ?>
                    </label><br>
                    <label for="verify-integrity">
                        <input type="checkbox" id="verify-integrity" checked> 
                        ✅ <?php esc_html_e('Verificar integridad WordPress', 'Emergency_Cleanup'); ?>
                    </label>
                </div>
                <br>
                <button type="button" class="button button-primary" id="start-scan" aria-describedby="scan-description">
                    🔍 <?php esc_html_e('Iniciar Escaneo Completo', 'Emergency_Cleanup'); ?>
                </button>
                <button type="button" class="button button-secondary" id="start-cleanup" style="display:none;" aria-describedby="cleanup-description">
                    🧹 <?php esc_html_e('Iniciar Limpieza', 'Emergency_Cleanup'); ?>
                </button>
                <button type="button" class="button" id="scan-all" aria-describedby="scan-only-description">
                    📊 <?php esc_html_e('Solo Escanear (Sin Limpiar)', 'Emergency_Cleanup'); ?>
                </button>
                
                <div id="scan-description" class="screen-reader-text">
                    <?php esc_html_e('Inicia un escaneo completo del sitio en busca de malware y permite la limpieza automática', 'Emergency_Cleanup'); ?>
                </div>
                <div id="cleanup-description" class="screen-reader-text">
                    <?php esc_html_e('Elimina automáticamente todos los archivos maliciosos detectados', 'Emergency_Cleanup'); ?>
                </div>
                <div id="scan-only-description" class="screen-reader-text">
                    <?php esc_html_e('Ejecuta solo el escaneo de diagnóstico sin eliminar archivos', 'Emergency_Cleanup'); ?>
                </div>
                
                <div id="progress-bar" style="margin-top: 20px; display:none;">
                    <div class="progress-container">
                        <div class="progress-bar" id="progress-fill"></div>
                        <span id="progress-text">0%</span>
                    </div>
                </div>
                
                <div id="scan-results" style="margin-top: 20px;"></div>
                <div id="cleanup-log" style="margin-top: 20px;"></div>
            </div>
            
            <div class="card">
                <h2>🔐 Generador de Contraseña Segura</h2>
                <button type="button" class="button" id="generate-password">Generar Nueva Contraseña</button>
                <div id="new-password" style="margin-top: 10px; font-family: monospace; font-size: 16px;"></div>
            </div>
            
            <div class="card">
                <h2>✅ Lista de Verificación Post-Limpieza</h2>
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
                    <div>
                        <h3>Acciones Críticas:</h3>
                        <ul style="list-style-type: disc; padding-left: 20px;">
                            <li>Cambiar contraseña WordPress admin</li>
                            <li>Cambiar contraseña base de datos</li>
                            <li>Cambiar credenciales FTP</li>
                            <li>Regenerar claves seguridad WordPress</li>
                            <li>Reconectar Jetpack (si aplica)</li>
                        </ul>
                    </div>
                    <div>
                        <h3>Seguridad Futura:</h3>
                        <ul style="list-style-type: disc; padding-left: 20px;">
                            <?php if (!$this->is_plugin_installed('wordfence/wordfence.php')): ?>
                            <li>Instalar Wordfence Security</li>
                            <?php else: ?>
                            <li style="list-style-type: none;">✅ Wordfence Security instalado</li>
                            <?php endif; ?>
                            
                            <?php if (!$this->is_plugin_installed('wp-security-audit-log/wp-security-audit-log.php')): ?>
                            <li>Instalar WP Activity Log</li>
                            <?php else: ?>
                            <li style="list-style-type: none;">✅ WP Activity Log instalado</li>
                            <?php endif; ?>
                            
                            <li>Configurar backups automáticos</li>
                            <li>Actualizar WordPress y plugins</li>
                            <li>Eliminar este plugin tras limpieza</li>
                        </ul>
                    </div>
                </div>
            </div>
            
            <div class="card">
                <h2>🔧 Enlaces Rápidos</h2>
                <p>
                    <a href="https://api.wordpress.org/secret-key/1.1/salt/" target="_blank" class="button">🔑 Generar Claves WordPress</a>
                    
                    <?php if (!$this->is_plugin_installed('wordfence/wordfence.php')): ?>
                    <a href="<?php echo esc_url(admin_url('plugin-install.php?s=wordfence&tab=search&type=term')); ?>" class="button">🛡️ Instalar Wordfence</a>
                    <?php else: ?>
                    <a href="<?php echo esc_url(admin_url('admin.php?page=Wordfence')); ?>" class="button">🛡️ Abrir Wordfence</a>
                    <?php endif; ?>
                    
                    <?php if (!$this->is_plugin_installed('wp-security-audit-log/wp-security-audit-log.php')): ?>
                    <a href="<?php echo esc_url(admin_url('plugin-install.php?s=wp-activity-log&tab=search&type=term')); ?>" class="button">📋 Instalar WP Activity Log</a>
                    <?php else: ?>
                    <a href="<?php echo esc_url(admin_url('admin.php?page=wsal-auditlog')); ?>" class="button">📋 Abrir Activity Log</a>
                    <?php endif; ?>
                </p>
            </div>
        </div>
        
        <script>
        jQuery(document).ready(function($) {
            
            // Escaneo completo
            $('#start-scan').click(function() {
                $('#scan-results').html('🔍 Escaneando sitio...');
                $('#progress-bar').show();
                performScan(true);
            });
            
            // Solo escaneo sin botón limpiar
            $('#scan-all').click(function() {
                $('#scan-results').html('📊 Escaneando (solo diagnóstico)...');
                $('#progress-bar').show();
                performScan(false);
            });
            
            function performScan(showCleanup) {
                var options = {
                    enable_backup: $('#enable-backup').is(':checked'),
                    scan_content: $('#scan-content').is(':checked'),
                    scan_database: $('#scan-database').is(':checked'),
                    verify_integrity: $('#verify-integrity').is(':checked')
                };
                
                $.post(ajaxurl, {
                    action: 'emergency_cleanup',
                    operation: 'scan',
                    options: options,
                    nonce: '<?php echo esc_attr(wp_create_nonce('emergency_cleanup')); ?>'
                }, function(response) {
                    $('#progress-bar').hide();
                    if (response.success) {
                        $('#scan-results').html(response.data.html);
                        if (response.data.found_malware && showCleanup) {
                            $('#start-cleanup').show();
                        }
                    } else {
                        $('#scan-results').html('❌ Error en el escaneo: ' + response.data);
                    }
                });
            }
            
            // Limpieza automática
            $('#start-cleanup').click(function() {
                if (!confirm('¿Estás seguro de que quieres eliminar todos los archivos maliciosos detectados?\n\nEsta acción no se puede deshacer.')) {
                    return;
                }
                
                $('#cleanup-log').html('🧹 Limpiando archivos maliciosos...');
                
                $.post(ajaxurl, {
                    action: 'emergency_cleanup',
                    operation: 'cleanup',
                    nonce: '<?php echo esc_attr(wp_create_nonce('emergency_cleanup')); ?>'
                }, function(response) {
                    if (response.success) {
                        $('#cleanup-log').html(response.data.html);
                        $('#start-cleanup').hide();
                        // Actualizar escaneo después de limpieza
                        setTimeout(function() {
                            performScan(false);
                        }, 2000);
                    } else {
                        $('#cleanup-log').html('❌ Error en la limpieza: ' + response.data);
                    }
                });
            });
            
            // Generador de contraseñas
            $('#generate-password').click(function() {
                var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
                var password = '';
                for (var i = 0; i < 24; i++) {
                    password += chars.charAt(Math.floor(Math.random() * chars.length));
                }
                $('#new-password').html('<strong>Nueva contraseña segura:</strong><br><div style="background: #f1f1f1; padding: 10px; border: 1px solid #ccc; margin: 5px 0;"><code>' + password + '</code></div><small>⚠️ Cópiala y guárdala en lugar seguro antes de cerrar</small>');
            });
            
        });
        </script>
        
        <style>
        .card {
            background: #fff;
            border: 1px solid #ccd0d4;
            box-shadow: 0 1px 1px rgba(0,0,0,.04);
            margin: 20px 0;
            padding: 20px;
            max-width: none;
        }
        #scan-results, #cleanup-log {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 4px;
            padding: 15px;
            font-family: monospace;
            white-space: pre-wrap;
        }
        .button {
            margin-right: 10px;
        }
        .scan-options {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 4px;
            padding: 15px;
            margin-bottom: 15px;
        }
        .scan-options label {
            display: block;
            margin-bottom: 8px;
            font-weight: 500;
        }
        .progress-container {
            background: #e9ecef;
            border-radius: 10px;
            overflow: hidden;
            position: relative;
            height: 25px;
            margin-bottom: 10px;
        }
        .progress-bar {
            background: linear-gradient(90deg, #28a745, #20c997);
            height: 100%;
            width: 0%;
            transition: width 0.3s ease;
            border-radius: 10px;
        }
        #progress-text {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            font-weight: bold;
            color: #333;
            font-size: 12px;
        }
        .screen-reader-text {
            border: 0;
            clip: rect(1px, 1px, 1px, 1px);
            clip-path: inset(50%);
            height: 1px;
            margin: -1px;
            overflow: hidden;
            padding: 0;
            position: absolute !important;
            width: 1px;
            word-wrap: normal !important;
        }
        </style>
        <?php
    }
    
    public function perform_cleanup() {
        // Verificar que sea una petición AJAX
        if (!wp_doing_ajax()) {
            wp_die(esc_html__('Acceso no autorizado', 'Emergency_Cleanup'));
        }
        
        // Verificar nonce de seguridad
        if (!isset($_POST['nonce']) || !wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['nonce'])), 'emergency_cleanup')) {
            wp_send_json_error(esc_html__('Verificación de seguridad fallida', 'Emergency_Cleanup'));
        }
        
        // Verificar permisos
        if (!current_user_can('manage_options')) {
            wp_send_json_error(esc_html__('Permisos insuficientes', 'Emergency_Cleanup'));
        }
        
        // Sanitizar y validar entrada
        $operation = isset($_POST['operation']) ? sanitize_text_field(wp_unslash($_POST['operation'])) : '';
        $options = isset($_POST['options']) ? $this->sanitize_options(wp_unslash($_POST['options'])) : array();
        
        // Validar operación
        if (!in_array($operation, array('scan', 'cleanup'), true)) {
            wp_send_json_error(esc_html__('Operación no válida', 'Emergency_Cleanup'));
        }
        
        // Ejecutar operación
        if ($operation === 'scan') {
            $this->scan_for_malware($options);
        } elseif ($operation === 'cleanup') {
            $this->perform_malware_cleanup($options);
        }
        
        wp_die();
    }
    
    /**
     * Sanitizar opciones de entrada
     */
    private function sanitize_options($options) {
        if (!is_array($options)) {
            return array();
        }
        
        $sanitized = array();
        $allowed_options = array('enable_backup', 'scan_content', 'scan_database', 'verify_integrity');
        
        foreach ($allowed_options as $option) {
            if (isset($options[$option])) {
                $sanitized[$option] = rest_sanitize_boolean($options[$option]);
            }
        }
        
        return $sanitized;
    }
    
    private function scan_for_malware($options = []) {
        $found_items = [];
        $found_malware = false;
        
        // Info del sitio
        $site_url = get_site_url();
        $scan_time = current_time('Y-m-d H:i:s');
        
        $found_items[] = "🌐 Sitio: {$site_url}";
        $found_items[] = "⏰ Escaneo: {$scan_time}";
        $found_items[] = "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━";
        
        // Escanear archivos maliciosos en raíz
        foreach ($this->malicious_files as $file) {
            if (file_exists(ABSPATH . $file)) {
                // Para index.html, verificar si es realmente malicioso
                if ($file === 'index.html') {
                    $content = @file_get_contents(ABSPATH . $file);
                    if ($content !== false) {
                        $content = trim($content);
                        // Si está vacío o es muy pequeño y no tiene redirecciones, probablemente no es malicioso
                        if (empty($content) || (strlen($content) < 100 && !preg_match('/(location\.href|window\.location|<meta[^>]*refresh)/i', $content))) {
                            continue; // No es malicioso, solo un placeholder
                        }
                    }
                }
                
                $found_items[] = "📄 ❌ Archivo malicioso: {$file}";
                $found_malware = true;
            }
        }
        
        // Escanear carpetas maliciosas en raíz
        foreach ($this->malicious_folders as $folder) {
            if (is_dir(ABSPATH . $folder)) {
                $found_items[] = "📁 ❌ Carpeta maliciosa: {$folder}/";
                $found_malware = true;
            }
        }
        
        // Escanear plugins maliciosos
        foreach ($this->malicious_plugins as $plugin) {
            $plugin_path = WP_CONTENT_DIR . '/plugins/' . $plugin;
            if (is_dir($plugin_path)) {
                $found_items[] = "🔌 ❌ Plugin malicioso: {$plugin}/";
                $found_malware = true;
            }
        }
        
        // Escanear carpetas de plugins NO registradas (backdoors ocultos)
        $found_items[] = "";
        $found_items[] = "🔍 Buscando carpetas de plugins NO registradas...";
        $unregistered_folders = $this->scan_unregistered_plugin_folders();
        if (!empty($unregistered_folders)) {
            $found_items[] = "⚠️ Encontradas " . count($unregistered_folders) . " carpetas NO registradas en plugins:";
            foreach ($unregistered_folders as $folder_info) {
                $icon = '🔸';
                if ($folder_info['severity'] === 'critical') {
                    $icon = '🚨';
                    $found_malware = true;
                } elseif ($folder_info['severity'] === 'high') {
                    $icon = '⚠️';
                    $found_malware = true;
                }
                $found_items[] = "   {$icon} {$folder_info['folder']} - {$folder_info['reason']}";
            }
        } else {
            $found_items[] = "✅ Todas las carpetas en plugins están registradas";
        }
        
        // Buscar archivos PHP en uploads
        $upload_dir = wp_upload_dir();
        $php_files = $this->find_php_files($upload_dir['basedir']);
        foreach ($php_files as $php_file) {
            $found_items[] = "⚠️ ❌ PHP en uploads: " . str_replace($upload_dir['basedir'], 'uploads', $php_file);
            $found_malware = true;
        }
        
        // Escanear contenido de archivos si está habilitado
        if (isset($options['scan_content']) && $options['scan_content']) {
            $found_items[] = "";
            $found_items[] = "🔍 Escaneando contenido de archivos...";
            $content_malware = $this->scan_file_content();
            
            // Mostrar estadísticas del escaneo
            if (!empty($this->scan_stats)) {
                $found_items[] = "📊 Archivos escaneados: {$this->scan_stats['total_files']}";
                if (!empty($this->scan_stats['file_counts'])) {
                    foreach ($this->scan_stats['file_counts'] as $dir => $count) {
                        $found_items[] = "   └─ {$dir}: {$count} archivos PHP";
                    }
                }
                
                // Análisis de anomalías basado en baseline esperado
                $found_items[] = "";
                $found_items[] = "📈 Análisis de anomalías (baseline esperado):";
                $anomaly_analysis = $this->analyze_file_count_anomalies();
                
                if (!empty($anomaly_analysis['stats'])) {
                    $stats = $anomaly_analysis['stats'];
                    $found_items[] = sprintf(
                        "   🔌 Plugins: %d instalados | Esperado: ~%d archivos | Real: %d archivos",
                        $stats['plugins_total'],
                        $stats['expected']['plugins'],
                        $stats['actual']['plugins']
                    );
                    $found_items[] = sprintf(
                        "   🎨 Themes: %d instalados | Esperado: ~%d archivos | Real: %d archivos",
                        $stats['themes_total'],
                        $stats['expected']['themes'],
                        $stats['actual']['themes']
                    );
                    $found_items[] = sprintf(
                        "   📁 Uploads: Esperado: ~%d archivos | Real: %d archivos",
                        $stats['expected']['uploads'],
                        $stats['actual']['uploads']
                    );
                }
                
                // Mostrar alertas de anomalías
                if (!empty($anomaly_analysis['anomalies'])) {
                    $found_items[] = "";
                    $found_items[] = "⚠️ ANOMALÍAS DETECTADAS:";
                    foreach ($anomaly_analysis['anomalies'] as $anomaly) {
                        $icon = '🔸';
                        if ($anomaly['severity'] === 'critical') {
                            $icon = '🚨';
                        } elseif ($anomaly['severity'] === 'high') {
                            $icon = '⚠️';
                        }
                        $found_items[] = "   {$icon} {$anomaly['message']}";
                        $found_malware = true;
                    }
                } else {
                    $found_items[] = "   ✅ No se detectaron anomalías en el conteo de archivos";
                }
            }
            
            if (!empty($content_malware)) {
                foreach ($content_malware as $malicious_file) {
                    $found_items[] = "📄 ❌ Contenido malicioso: {$malicious_file}";
                    $found_malware = true;
                }
            } else {
                $found_items[] = "✅ No se encontró código malicioso en archivos";
            }
            
            // Escanear archivos duplicados/backups sospechosos
            $found_items[] = "";
            $found_items[] = "🔎 Buscando duplicados y backups sospechosos...";
            $suspicious_duplicates = $this->scan_suspicious_duplicates();
            if (!empty($suspicious_duplicates)) {
                $found_items[] = "⚠️ Encontrados " . count($suspicious_duplicates) . " archivos sospechosos:";
                foreach ($suspicious_duplicates as $duplicate) {
                    $found_items[] = "   🔸 {$duplicate['file']} - {$duplicate['reason']}";
                    $found_malware = true;
                }
            } else {
                $found_items[] = "✅ No se encontraron duplicados sospechosos";
            }
        }
        
        // Verificar base de datos si está habilitado
        if (isset($options['scan_database']) && $options['scan_database']) {
            $found_items[] = "";
            $found_items[] = "🗄️ Verificando base de datos...";
            $db_issues = $this->scan_database();
            if (!empty($db_issues)) {
                foreach ($db_issues as $issue) {
                    $found_items[] = "🗄️ ❌ " . $issue;
                    $found_malware = true;
                }
            } else {
                $found_items[] = "✅ Base de datos limpia";
            }
        }
        
        // Verificar integridad de WordPress si está habilitado
        if (isset($options['verify_integrity']) && $options['verify_integrity']) {
            $found_items[] = "";
            $found_items[] = "✅ Verificando integridad de WordPress...";
            $integrity_issues = $this->verify_wordpress_integrity();
            if (!empty($integrity_issues)) {
                foreach ($integrity_issues as $issue) {
                    $found_items[] = "⚠️ " . $issue;
                }
            } else {
                $found_items[] = "✅ Archivos core de WordPress intactos";
            }
        }
        
        if (!$found_malware) {
            $found_items[] = "";
            $found_items[] = "✅ ¡SITIO LIMPIO!";
            $found_items[] = "🔍 No se detectaron archivos maliciosos conocidos";
            $found_items[] = "🛡️ El sitio aparenta estar seguro";
        } else {
            $found_items[] = "";
            $found_items[] = "🚨 ¡MALWARE DETECTADO!";
            $found_items[] = "⚠️ Se recomienda ejecutar limpieza automática";
        }
        
        wp_send_json_success([
            'html' => implode("\n", $found_items),
            'found_malware' => $found_malware
        ]);
    }
    
    private function perform_malware_cleanup($options = []) {
        $this->log = [];
        $deleted_count = 0;
        
        $site_url = get_site_url();
        $cleanup_time = current_time('Y-m-d H:i:s');
        
        $this->log[] = "🌐 Sitio: {$site_url}";
        $this->log[] = "🧹 Limpieza iniciada: {$cleanup_time}";
        $this->log[] = "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━";
        
        // Crear backup si está habilitado
        if (isset($options['enable_backup']) && $options['enable_backup']) {
            $this->log[] = "💾 Creando backup de seguridad...";
            if ($this->create_backup()) {
                $this->log[] = "✅ Backup creado en: {$this->backup_dir}";
            } else {
                $this->log[] = "⚠️ Error creando backup, continuando sin backup";
            }
        }
        
        // Eliminar archivos maliciosos
        foreach ($this->malicious_files as $file) {
            $file_path = ABSPATH . $file;
            if (file_exists($file_path)) {
                if (unlink($file_path)) {
                    $this->log[] = "✅ Eliminado archivo: {$file}";
                    $deleted_count++;
                } else {
                    $this->log[] = "❌ Error eliminando archivo: {$file}";
                }
            }
        }
        
        // Eliminar carpetas maliciosas
        foreach ($this->malicious_folders as $folder) {
            $folder_path = ABSPATH . $folder;
            if (is_dir($folder_path)) {
                if ($this->delete_directory($folder_path)) {
                    $this->log[] = "✅ Eliminada carpeta: {$folder}/";
                    $deleted_count++;
                } else {
                    $this->log[] = "❌ Error eliminando carpeta: {$folder}/";
                }
            }
        }
        
        // Eliminar plugins maliciosos
        foreach ($this->malicious_plugins as $plugin) {
            $plugin_path = WP_CONTENT_DIR . '/plugins/' . $plugin;
            if (is_dir($plugin_path)) {
                if ($this->delete_directory($plugin_path)) {
                    $this->log[] = "✅ Plugin eliminado: {$plugin}/";
                    $deleted_count++;
                } else {
                    $this->log[] = "❌ Error eliminando plugin: {$plugin}/";
                }
            }
        }
        
        // Eliminar carpetas de plugins NO registradas con severidad alta/crítica
        $unregistered_folders = $this->scan_unregistered_plugin_folders();
        foreach ($unregistered_folders as $folder_info) {
            // Solo eliminar automáticamente las de severidad alta o crítica
            if ($folder_info['severity'] === 'high' || $folder_info['severity'] === 'critical') {
                $folder_path = WP_CONTENT_DIR . '/plugins/' . basename($folder_info['folder']);
                if (is_dir($folder_path)) {
                    if ($this->delete_directory($folder_path)) {
                        $this->log[] = "✅ Carpeta NO registrada eliminada: {$folder_info['folder']}";
                        $deleted_count++;
                    } else {
                        $this->log[] = "❌ Error eliminando carpeta NO registrada: {$folder_info['folder']}";
                    }
                }
            }
        }
        
        // Eliminar archivos PHP de uploads
        $upload_dir = wp_upload_dir();
        $php_files = $this->find_php_files($upload_dir['basedir']);
        foreach ($php_files as $php_file) {
            if (unlink($php_file)) {
                $this->log[] = "✅ PHP eliminado de uploads: " . basename($php_file);
                $deleted_count++;
            } else {
                $this->log[] = "❌ Error eliminando PHP: " . basename($php_file);
            }
        }
        
        $this->log[] = "";
        $this->log[] = "🎉 LIMPIEZA COMPLETADA";
        $this->log[] = "📊 Total elementos eliminados: {$deleted_count}";
        
        if ($deleted_count > 0) {
            $this->log[] = "";
            $this->log[] = "⚠️ ACCIONES CRÍTICAS PENDIENTES:";
            
            $action_number = 1;
            $this->log[] = "{$action_number}. 🔐 Cambiar contraseña WordPress admin";
            $action_number++;
            $this->log[] = "{$action_number}. 🗄️ Cambiar contraseña base de datos";
            $action_number++;
            $this->log[] = "{$action_number}. 📁 Cambiar credenciales FTP";
            $action_number++;
            $this->log[] = "{$action_number}. 🔑 Regenerar claves de seguridad WordPress";
            $action_number++;
            
            // Verificar si Wordfence está instalado
            if (!$this->is_plugin_installed('wordfence/wordfence.php')) {
                $this->log[] = "{$action_number}. 🛡️ Instalar Wordfence Security";
                $action_number++;
            }
            
            // Verificar si WP Activity Log está instalado
            if (!$this->is_plugin_installed('wp-security-audit-log/wp-security-audit-log.php')) {
                $this->log[] = "{$action_number}. 📋 Instalar WP Activity Log";
                $action_number++;
            }
        } else {
            $this->log[] = "✅ No se encontraron elementos maliciosos para eliminar";
        }
        
        wp_send_json_success([
            'html' => implode("\n", $this->log)
        ]);
    }
    
    /**
     * Verifica si un plugin está instalado
     */
    private function is_plugin_installed($plugin_path) {
        if (!function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }
        $all_plugins = get_plugins();
        return isset($all_plugins[$plugin_path]);
    }
    
    /**
     * Verifica si un archivo index.php es realmente legítimo (archivo de protección)
     * o podría ser un backdoor disfrazado
     */
    private function is_legitimate_index_php($file_path) {
        // 1. Verificar que el archivo existe y es legible
        if (!file_exists($file_path) || !is_readable($file_path)) {
            return false;
        }
        
        // 2. Obtener información del archivo
        $file_size = filesize($file_path);
        $file_perms = fileperms($file_path);
        
        // 3. VERIFICACIÓN CRÍTICA: Si el archivo tiene permisos sospechosos (ejecutable por todos)
        // Permisos 0777, 0666, 0775 son sospechosos para archivos index.php
        $perms_octal = substr(sprintf('%o', $file_perms), -3);
        if (in_array($perms_octal, array('777', '666', '775', '776'))) {
            return false; // Permisos sospechosos
        }
        
        // 4. Si el archivo es completamente vacío (0 bytes), es legítimo
        if ($file_size === 0) {
            return true;
        }
        
        // 5. Leer el contenido completo en binario para detectar caracteres ocultos
        $content = file_get_contents($file_path);
        if ($content === false) {
            return false;
        }
        
        // 6. Verificar BOM (Byte Order Mark) y caracteres invisibles sospechosos
        $has_bom = (substr($content, 0, 3) === "\xEF\xBB\xBF");
        if ($has_bom) {
            $content = substr($content, 3); // Remover BOM para análisis
        }
        
        // 7. Detectar caracteres no-ASCII sospechosos (posible ofuscación)
        if (preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\xFF]/', $content)) {
            // Tiene caracteres binarios o Unicode sospechosos (excepto saltos de línea normales)
            return false;
        }
        
        // 8. Limpiar el contenido (trim) para verificar patrones conocidos
        $trimmed = trim($content);
        
        // 9. PATRONES SEGUROS CONOCIDOS (WordPress estándar)
        $safe_patterns = array(
            '',                                          // Completamente vacío
            '<?php',                                     // Solo apertura PHP
            "<?php\n// Silence is golden",              // WordPress estándar
            "<?php\n// Silence is golden.",             // WordPress estándar con punto
            '<?php // Silence is golden',               // Sin salto de línea
            '<?php // Silence is golden.',              // Sin salto de línea con punto
            "<?php\n/**\n * Empty index for security\n */", // Otro patrón común
        );
        
        foreach ($safe_patterns as $pattern) {
            if ($trimmed === $pattern) {
                return true; // Patrón conocido seguro
            }
        }
        
        // 10. Si tiene menos de 100 caracteres, verificar que NO contenga funciones peligrosas
        if (strlen($trimmed) < 100) {
            $dangerous_functions = array(
                'eval', 'base64_decode', 'gzinflate', 'gzuncompress', 'str_rot13',
                'system', 'exec', 'shell_exec', 'passthru', 'proc_open', 'popen',
                'curl_exec', 'curl_multi_exec', 'parse_ini_file', 'show_source',
                'file_get_contents', 'file_put_contents', 'fopen', 'readfile',
                'include', 'require', 'include_once', 'require_once',
                'assert', 'create_function', 'preg_replace', 'call_user_func'
            );
            
            foreach ($dangerous_functions as $func) {
                if (stripos($trimmed, $func) !== false) {
                    return false; // Contiene función peligrosa
                }
            }
            
            // 11. Verificar que solo contenga comentarios/espacios después de <?php
            if (preg_match('/^<\?php\s*(\/\/[^\n]*|\/\*.*?\*\/)?\s*$/', $trimmed)) {
                return true; // Solo comentarios
            }
        }
        
        // 12. Si llegamos aquí y el archivo es muy pequeño (< 50 bytes) sin funciones peligrosas
        // podría ser legítimo, pero por seguridad lo marcamos como sospechoso
        // MEJOR PREVENIR QUE LAMENTAR
        return false;
    }
    
    private function find_php_files($directory) {
        $php_files = [];
        
        if (!is_dir($directory)) {
            return $php_files;
        }
        
        // Directorios de backup legítimos a ignorar
        $legitimate_backup_dirs = [
            'backup',
            'backups',
            'updraft',
            'backwpup',
            'ai1wm-backups',
            'backup-guard',
        ];
        
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($directory, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );
        
        foreach ($iterator as $file) {
            if ($file->isFile() && $file->getExtension() === 'php') {
                $file_path = $file->getPathname();
                
                // Saltar directorios de backup legítimos
                $skip = false;
                foreach ($legitimate_backup_dirs as $backup_dir) {
                    if (strpos($file_path, DIRECTORY_SEPARATOR . $backup_dir . DIRECTORY_SEPARATOR) !== false) {
                        $skip = true;
                        break;
                    }
                }
                
                if ($skip) {
                    continue;
                }
                
                // Para index.php, verificar si es legítimo archivo de protección
                if (basename($file_path) === 'index.php') {
                    $is_legitimate = $this->is_legitimate_index_php($file_path);
                    if ($is_legitimate) {
                        continue;
                    }
                }
                
                $php_files[] = $file_path;
            }
        }
        
        return $php_files;
    }
    
    private function delete_directory($dir) {
        if (!is_dir($dir)) {
            return false;
        }
        
        $files = array_diff(scandir($dir), array('.', '..'));
        foreach ($files as $file) {
            $file_path = $dir . DIRECTORY_SEPARATOR . $file;
            if (is_dir($file_path)) {
                $this->delete_directory($file_path);
            } else {
                unlink($file_path);
            }
        }
        
        return rmdir($dir);
    }
    
    private function create_backup() {
        if (!wp_mkdir_p($this->backup_dir)) {
            return false;
        }
        
        $backup_log = [];
        $backup_log[] = "Backup creado: " . current_time('Y-m-d H:i:s');
        $backup_log[] = "Sitio: " . get_site_url();
        $backup_log[] = "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━";
        
        // Backup de archivos maliciosos encontrados
        foreach ($this->malicious_files as $file) {
            $file_path = ABSPATH . $file;
            if (file_exists($file_path)) {
                $backup_file = $this->backup_dir . '/' . $file;
                if (copy($file_path, $backup_file)) {
                    $backup_log[] = "Backup archivo: {$file}";
                }
            }
        }
        
        // Guardar log de backup
        file_put_contents($this->backup_dir . '/backup-log.txt', implode("\n", $backup_log));
        
        return true;
    }
    
    private function scan_file_content() {
        $malicious_files = [];
        $total_files_scanned = 0;
        $file_counts = [];
        
        // Solo escanear themes, plugins personalizados y uploads
        // NO escanear wp-admin ni wp-includes (son núcleo de WordPress)
        $scan_dirs = [
            WP_CONTENT_DIR . '/themes',
            WP_CONTENT_DIR . '/plugins',
            WP_CONTENT_DIR . '/uploads'
        ];
        
        // Directorios a ignorar (librerías legítimas conocidas)
        $ignore_dirs = [
            'node_modules',
            'vendor',
            'bower_components',
            '.git',
            '.svn',
        ];
        
        foreach ($scan_dirs as $dir) {
            if (!is_dir($dir)) {
                continue;
            }
            
            $dir_name = basename($dir);
            $file_counts[$dir_name] = 0;
            
            try {
                $iterator = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS),
                    RecursiveIteratorIterator::SELF_FIRST
                );
                
                foreach ($iterator as $file) {
                    // Saltar si no es archivo PHP
                    if (!$file->isFile() || $file->getExtension() !== 'php') {
                        continue;
                    }
                    
                    $file_path = $file->getPathname();
                    
                    // Saltar directorios ignorados
                    $skip = false;
                    foreach ($ignore_dirs as $ignore_dir) {
                        if (strpos($file_path, DIRECTORY_SEPARATOR . $ignore_dir . DIRECTORY_SEPARATOR) !== false) {
                            $skip = true;
                            break;
                        }
                    }
                    if ($skip) {
                        continue;
                    }
                    
                    // Saltar archivos muy grandes (más de 1MB) para evitar timeout
                    if ($file->getSize() > 1048576) {
                        continue;
                    }
                    
                    // Incrementar contadores
                    $total_files_scanned++;
                    $file_counts[$dir_name]++;
                    
                    // Leer y analizar contenido
                    $content = file_get_contents($file_path);
                    if ($content && $this->contains_malicious_code($content, $file_path)) {
                        $malicious_files[] = str_replace(ABSPATH, '', $file_path);
                    }
                }
            } catch (Exception $e) {
                // Continuar con el siguiente directorio si hay error
                continue;
            }
        }
        
        // Almacenar estadísticas para uso posterior
        $this->scan_stats = [
            'total_files' => $total_files_scanned,
            'file_counts' => $file_counts
        ];
        
        return $malicious_files;
    }
    
    /**
     * Calcula el baseline esperado de archivos y detecta anomalías
     */
    private function analyze_file_count_anomalies() {
        $anomalies = [];
        
        // 1. Obtener información de plugins y temas
        $all_plugins = get_plugins();
        $active_plugins = get_option('active_plugins', array());
        $all_themes = wp_get_themes();
        $active_theme = wp_get_theme();
        
        $total_plugins = count($all_plugins);
        $total_themes = count($all_themes);
        
        // 2. Calcular baseline esperado (promedios de la industria)
        $avg_files_per_plugin = 120;  // Plugin típico tiene ~120 archivos PHP
        $avg_files_per_theme = 60;     // Tema típico tiene ~60 archivos PHP
        $baseline_uploads = 5;         // Uploads debería tener casi 0 PHP (máx 5 para protección)
        
        $expected_plugin_files = $total_plugins * $avg_files_per_plugin;
        $expected_theme_files = $total_themes * $avg_files_per_theme;
        $expected_uploads_files = $baseline_uploads;
        
        // 3. Obtener conteos reales
        if (!empty($this->scan_stats['file_counts'])) {
            $actual_plugins = isset($this->scan_stats['file_counts']['plugins']) ? $this->scan_stats['file_counts']['plugins'] : 0;
            $actual_themes = isset($this->scan_stats['file_counts']['themes']) ? $this->scan_stats['file_counts']['themes'] : 0;
            $actual_uploads = isset($this->scan_stats['file_counts']['uploads']) ? $this->scan_stats['file_counts']['uploads'] : 0;
            
            // 4. Calcular desviaciones (tolerancia: ±50% para plugins/themes, 0% para uploads)
            $plugin_deviation = $expected_plugin_files > 0 ? (($actual_plugins - $expected_plugin_files) / $expected_plugin_files) * 100 : 0;
            $theme_deviation = $expected_theme_files > 0 ? (($actual_themes - $expected_theme_files) / $expected_theme_files) * 100 : 0;
            $uploads_deviation = $actual_uploads - $expected_uploads_files;
            
            // 5. Detectar anomalías
            
            // PLUGINS: Alerta si hay >50% más archivos de lo esperado
            if ($plugin_deviation > 50) {
                $anomalies[] = [
                    'type' => 'plugins_excess',
                    'severity' => 'high',
                    'message' => sprintf(
                        'Exceso de archivos en plugins: %d archivos (esperado: ~%d para %d plugins). Desviación: +%.1f%%',
                        $actual_plugins,
                        $expected_plugin_files,
                        $total_plugins,
                        $plugin_deviation
                    )
                ];
            }
            
            // PLUGINS: Alerta si hay muy pocos archivos (posible corrupción)
            if ($plugin_deviation < -50 && $total_plugins > 0) {
                $anomalies[] = [
                    'type' => 'plugins_missing',
                    'severity' => 'medium',
                    'message' => sprintf(
                        'Posibles archivos faltantes en plugins: %d archivos (esperado: ~%d). Desviación: %.1f%%',
                        $actual_plugins,
                        $expected_plugin_files,
                        $plugin_deviation
                    )
                ];
            }
            
            // THEMES: Alerta si hay >50% más archivos de lo esperado
            if ($theme_deviation > 50) {
                $anomalies[] = [
                    'type' => 'themes_excess',
                    'severity' => 'medium',
                    'message' => sprintf(
                        'Exceso de archivos en themes: %d archivos (esperado: ~%d para %d temas). Desviación: +%.1f%%',
                        $actual_themes,
                        $expected_theme_files,
                        $total_themes,
                        $theme_deviation
                    )
                ];
            }
            
            // UPLOADS: CRÍTICO - No debería haber casi ningún archivo PHP
            if ($actual_uploads > 10) {
                $severity = $actual_uploads > 50 ? 'critical' : 'high';
                $anomalies[] = [
                    'type' => 'uploads_excess',
                    'severity' => $severity,
                    'message' => sprintf(
                        '⚠️ CRÍTICO: %d archivos PHP en uploads (debería haber ~0). Posible inyección masiva de malware!',
                        $actual_uploads
                    )
                ];
            }
            
            // 6. Detectar "file spam" (muchos archivos en uploads)
            if ($actual_uploads > 100) {
                $anomalies[] = [
                    'type' => 'file_spam',
                    'severity' => 'critical',
                    'message' => sprintf(
                        '🚨 FILE SPAM DETECTADO: %d archivos PHP en uploads indica inyección masiva. Ataque en curso!',
                        $actual_uploads
                    )
                ];
            }
        }
        
        return [
            'anomalies' => $anomalies,
            'stats' => [
                'plugins_total' => $total_plugins,
                'themes_total' => $total_themes,
                'expected' => [
                    'plugins' => $expected_plugin_files,
                    'themes' => $expected_theme_files,
                    'uploads' => $expected_uploads_files,
                ],
                'actual' => [
                    'plugins' => isset($actual_plugins) ? $actual_plugins : 0,
                    'themes' => isset($actual_themes) ? $actual_themes : 0,
                    'uploads' => isset($actual_uploads) ? $actual_uploads : 0,
                ]
            ]
        ];
    }
    
    /**
     * Detecta carpetas de plugins NO registradas en WordPress (posibles backdoors)
     */
    private function scan_unregistered_plugin_folders() {
        $suspicious_folders = [];
        
        $plugins_dir = WP_CONTENT_DIR . '/plugins';
        
        if (!is_dir($plugins_dir)) {
            return $suspicious_folders;
        }
        
        // 1. Obtener todos los plugins registrados en WordPress
        if (!function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }
        $registered_plugins = get_plugins();
        
        // 2. Extraer solo los nombres de las carpetas de plugins registrados
        $registered_folders = [];
        foreach ($registered_plugins as $plugin_path => $plugin_data) {
            // El path es como: "akismet/akismet.php" o "hello.php"
            $parts = explode('/', $plugin_path);
            if (count($parts) > 1) {
                // Plugin con carpeta
                $registered_folders[] = $parts[0];
            } else {
                // Plugin de un solo archivo (hello.php) - raro pero posible
                $registered_folders[] = pathinfo($parts[0], PATHINFO_FILENAME);
            }
        }
        
        // Carpetas del sistema que son legítimas (no son plugins)
        $system_folders = [
            'index.php',  // Archivo de protección
            '.htaccess',  // Configuración
            '.', 
            '..',
        ];
        
        // Carpetas que pueden existir por residuos de desinstalación (ignorar si están vacías)
        $possible_residues = [];
        
        // 3. Listar todas las carpetas reales en /plugins/
        $actual_folders = [];
        $dir_iterator = new DirectoryIterator($plugins_dir);
        
        foreach ($dir_iterator as $item) {
            if ($item->isDot() || !$item->isDir()) {
                continue;
            }
            
            $folder_name = $item->getFilename();
            
            // Ignorar carpetas del sistema
            if (in_array($folder_name, $system_folders)) {
                continue;
            }
            
            $actual_folders[] = $folder_name;
        }
        
        // 4. Comparar: carpetas existentes vs registradas
        foreach ($actual_folders as $folder) {
            if (!in_array($folder, $registered_folders)) {
                $folder_path = $plugins_dir . '/' . $folder;
                
                // Verificar si tiene archivos PHP (posible backdoor)
                $has_php = false;
                $php_files = glob($folder_path . '/*.php');
                if ($php_files && count($php_files) > 0) {
                    $has_php = true;
                }
                
                // Verificar si tiene subcarpetas con PHP
                $has_deep_php = false;
                if (is_dir($folder_path)) {
                    $iterator = new RecursiveIteratorIterator(
                        new RecursiveDirectoryIterator($folder_path, RecursiveDirectoryIterator::SKIP_DOTS),
                        RecursiveIteratorIterator::SELF_FIRST
                    );
                    
                    foreach ($iterator as $file) {
                        if ($file->isFile() && $file->getExtension() === 'php') {
                            $has_deep_php = true;
                            break;
                        }
                    }
                }
                
                // Clasificar severidad
                $severity = 'low';
                $reason = 'Carpeta no registrada (posible residuo)';
                
                if ($has_php || $has_deep_php) {
                    $severity = 'high';
                    $reason = 'Carpeta NO registrada con archivos PHP (posible backdoor)';
                    
                    // Verificar si parece un backdoor conocido
                    $suspicious_names = ['shell', 'backdoor', 'hack', 'c99', 'r57', 'wso', 'adminer', 'bypass'];
                    foreach ($suspicious_names as $suspicious) {
                        if (stripos($folder, $suspicious) !== false) {
                            $severity = 'critical';
                            $reason = 'Carpeta NO registrada con nombre sospechoso y archivos PHP (BACKDOOR)';
                            break;
                        }
                    }
                }
                
                $suspicious_folders[] = [
                    'folder' => 'wp-content/plugins/' . $folder,
                    'reason' => $reason,
                    'severity' => $severity,
                    'has_php' => $has_php || $has_deep_php,
                ];
            }
        }
        
        return $suspicious_folders;
    }
    
    /**
     * Detecta archivos duplicados y backups sospechosos
     */
    private function scan_suspicious_duplicates() {
        $suspicious_files = [];
        
        // Patrones de nombres de archivo sospechosos
        $suspicious_patterns = [
            '.bak',
            '.backup',
            '.old',
            '.save',
            '.copy',
            '.orig',
            '.tmp',
            '_backup',
            '-backup',
            '-old',
            '-copy',
            '.suspected',
            '.infected',
            '.virus',
        ];
        
        // Archivos críticos que nunca deberían tener backups en producción
        $critical_files = [
            'wp-config.php',
            'wp-settings.php',
            'wp-load.php',
            '.htaccess',
        ];
        
        // Buscar en directorios críticos
        $scan_dirs = [
            ABSPATH,                    // Raíz de WordPress
            WP_CONTENT_DIR,            // wp-content
            WP_CONTENT_DIR . '/plugins',
            WP_CONTENT_DIR . '/themes',
            WP_CONTENT_DIR . '/uploads',
        ];
        
        foreach ($scan_dirs as $dir) {
            if (!is_dir($dir)) {
                continue;
            }
            
            try {
                // Para la raíz, solo buscar archivos directos (no recursivo)
                if ($dir === ABSPATH) {
                    $files = glob($dir . '*');
                    foreach ($files as $file_path) {
                        if (!is_file($file_path)) {
                            continue;
                        }
                        
                        $file_name = basename($file_path);
                        
                        // Verificar patrones sospechosos
                        foreach ($suspicious_patterns as $pattern) {
                            if (stripos($file_name, $pattern) !== false) {
                                $suspicious_files[] = [
                                    'file' => str_replace(ABSPATH, '', $file_path),
                                    'reason' => 'Archivo backup/duplicado en raíz'
                                ];
                                break;
                            }
                        }
                        
                        // Verificar backups de archivos críticos
                        foreach ($critical_files as $critical) {
                            if (strpos($file_name, str_replace('.', '', $critical)) !== false && $file_name !== $critical) {
                                $suspicious_files[] = [
                                    'file' => str_replace(ABSPATH, '', $file_path),
                                    'reason' => 'Posible backup de archivo crítico'
                                ];
                                break;
                            }
                        }
                    }
                } else {
                    // Para otros directorios, buscar recursivamente
                    $iterator = new RecursiveIteratorIterator(
                        new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS),
                        RecursiveIteratorIterator::SELF_FIRST
                    );
                    
                    $file_count = 0;
                    foreach ($iterator as $file) {
                        if (!$file->isFile()) {
                            continue;
                        }
                        
                        $file_path = $file->getPathname();
                        $file_name = basename($file_path);
                        
                        // Limitar escaneo para evitar timeout
                        $file_count++;
                        if ($file_count > 5000) {
                            break;
                        }
                        
                        // Verificar patrones sospechosos solo en archivos PHP
                        if ($file->getExtension() === 'php') {
                            foreach ($suspicious_patterns as $pattern) {
                                if (stripos($file_name, $pattern) !== false) {
                                    $suspicious_files[] = [
                                        'file' => str_replace(ABSPATH, '', $file_path),
                                        'reason' => 'Archivo PHP backup/duplicado'
                                    ];
                                    break;
                                }
                            }
                        }
                        
                        // Detectar archivos con nombres casi idénticos (typosquatting)
                        if ($file->getExtension() === 'php') {
                            if (preg_match('/(adrnin|adimin|admln|wp-lgin|wp-lgoin|wp-contig|cofig|confg)/i', $file_name)) {
                                $suspicious_files[] = [
                                    'file' => str_replace(ABSPATH, '', $file_path),
                                    'reason' => 'Nombre sospechoso (typosquatting)'
                                ];
                            }
                        }
                    }
                }
            } catch (Exception $e) {
                continue;
            }
        }
        
        return $suspicious_files;
    }
    
    private function contains_malicious_code($content, $file_path = '') {
        // Excluir el propio plugin de Emergency Cleanup
        if (strpos($file_path, 'Emergency_Cleanup') !== false || strpos($file_path, 'emergency-cleanup') !== false) {
            return false;
        }
        
        // Lista blanca de archivos conocidos que pueden tener código sospechoso pero legítimo
        $whitelist_files = [
            'PHPMailer',
            'class-phpmailer.php',
            'class-smtp.php',
            'wp-mail.php',
        ];
        
        // Lista blanca de plugins legítimos conocidos (plugins de seguridad especialmente)
        $whitelist_plugins = [
            'wordfence',           // Wordfence Security
            'ithemes-security',    // iThemes Security
            'sucuri-scanner',      // Sucuri Security
            'all-in-one-wp-security', // All In One WP Security
            'jetpack',             // Jetpack
            'akismet',             // Akismet
        ];
        
        // Verificar si el archivo pertenece a un plugin en lista blanca
        foreach ($whitelist_plugins as $plugin) {
            if (strpos($file_path, 'plugins' . DIRECTORY_SEPARATOR . $plugin) !== false) {
                return false;
            }
        }
        
        // Verificar si el archivo está en lista blanca
        foreach ($whitelist_files as $whitelist) {
            if (strpos($file_path, $whitelist) !== false) {
                return false;
            }
        }
        
        $matches_count = 0;
        $matched_patterns = [];
        
        foreach ($this->malicious_patterns as $pattern) {
            if (preg_match($pattern, $content)) {
                $matches_count++;
                $matched_patterns[] = $pattern;
                
                // Si coinciden 2 o más patrones peligrosos, es muy sospechoso
                if ($matches_count >= 2) {
                    return true;
                }
            }
        }
        
        // Un solo patrón puede ser falso positivo, pero algunos son críticos
        $critical_patterns = [
            '/eval\s*\(\s*base64_decode\s*\(/i',
            '/eval\s*\(\s*gzinflate\s*\(/i',
            '/c99shell/i',
            '/r57shell/i',
            '/webshell/i',
        ];
        
        foreach ($critical_patterns as $critical) {
            if (preg_match($critical, $content)) {
                return true;
            }
        }
        
        return false;
    }
    
    private function scan_database() {
        global $wpdb;
        $issues = [];
        
        // Verificar que tenemos acceso a la base de datos
        if (!$wpdb->db_connect()) {
            return array(esc_html__('No se pudo conectar a la base de datos', 'Emergency_Cleanup'));
        }
        
        // Verificar tablas sospechosas
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Necesario para escaneo de seguridad de todas las tablas de la base de datos.
        $tables = $wpdb->get_results("SHOW TABLES", ARRAY_N);
        if (is_wp_error($tables)) {
            return array(esc_html__('Error al obtener lista de tablas', 'Emergency_Cleanup'));
        }
        
        foreach ($tables as $table) {
            $table_name = sanitize_text_field($table[0]);
            
            // Buscar columnas sospechosas
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Necesario para escaneo de seguridad de estructura de tablas.
            $columns = $wpdb->get_results($wpdb->prepare("SHOW COLUMNS FROM `%s`", $table_name), ARRAY_A);
            if (!is_wp_error($columns)) {
                foreach ($columns as $column) {
                    $field_name = sanitize_text_field($column['Field']);
                    if (preg_match('/eval|base64|shell|exec|system/i', $field_name)) {
                        // translators: %1$s is the suspicious column name, %2$s is the table name
                        $issues[] = sprintf(
                            esc_html__('Columna sospechosa "%1$s" en tabla "%2$s"', 'Emergency_Cleanup'),
                            esc_html($field_name),
                            esc_html($table_name)
                        );
                    }
                }
            }
            
            // Buscar contenido malicioso en posts (patrones de código real, no solo menciones)
            if ($table_name === $wpdb->posts) {
                // Buscar PATRONES DE CÓDIGO EJECUTABLE, no solo palabras sueltas
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Escaneo de seguridad en tiempo real para detección de malware, no requiere caché.
                $malicious_posts = $wpdb->get_results($wpdb->prepare("
                    SELECT ID, post_title, post_content 
                    FROM {$wpdb->posts} 
                    WHERE (
                        post_content LIKE %s    -- eval(base64_decode(
                        OR post_content LIKE %s -- eval(gzinflate(
                        OR post_content LIKE %s -- eval($_
                        OR post_content LIKE %s -- <?php eval(
                        OR post_content LIKE %s -- base64_decode seguido de eval
                        OR post_content LIKE %s -- $_ con funciones peligrosas
                        OR post_content LIKE %s -- shell_exec con variables
                        OR post_content LIKE %s -- system con variables
                        OR post_content LIKE %s -- Strings base64 muy largos (>200 chars)
                    )
                    AND post_type IN ('post', 'page', 'revision')
                    LIMIT 20
                ", 
                    '%eval(base64_decode%',
                    '%eval(gzinflate%',
                    '%eval($_GET%',
                    '%<?php eval(%',
                    '%base64_decode%eval(%',
                    '%$_GET%system(%',
                    '%shell_exec($_%;',
                    '%system($_%;',
                    '%[A-Za-z0-9+/]{200,}%'
                ));
                
                if (!is_wp_error($malicious_posts) && !empty($malicious_posts)) {
                    foreach ($malicious_posts as $post) {
                        // Verificación adicional: analizar el contenido para confirmar
                        $is_malicious = $this->verify_malicious_post_content($post->post_content);
                        
                        if ($is_malicious) {
                            // translators: %1$d is the post ID, %2$s is the post title
                            $issues[] = sprintf(
                                esc_html__('Post sospechoso ID %1$d: %2$s', 'Emergency_Cleanup'),
                                intval($post->ID),
                                esc_html($post->post_title)
                            );
                        }
                    }
                }
            }
        }
        
        return $issues;
    }
    
    /**
     * Verifica si el contenido de un post contiene código malicioso REAL
     * y no solo menciones educativas o documentación
     */
    private function verify_malicious_post_content($content) {
        // 1. Decodificar HTML entities (el contenido podría estar escapado)
        $decoded = html_entity_decode($content, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        
        // 2. Si el contenido está dentro de bloques de código (pre, code, etc), probablemente es educativo
        // Remover bloques de código para análisis
        $without_code_blocks = preg_replace('/<(pre|code)[^>]*>.*?<\/\1>/is', '', $decoded);
        $without_code_blocks = preg_replace('/```.*?```/s', '', $without_code_blocks);
        $without_code_blocks = preg_replace('/`[^`]+`/s', '', $without_code_blocks);
        
        // 3. PATRONES CRÍTICOS que indican código ejecutable (no solo mención)
        $critical_patterns = array(
            // eval con ofuscación (MUY peligroso)
            '/eval\s*\(\s*base64_decode\s*\(/i',
            '/eval\s*\(\s*gzinflate\s*\(/i',
            '/eval\s*\(\s*gzuncompress\s*\(/i',
            '/eval\s*\(\s*str_rot13\s*\(/i',
            
            // eval con variables superglobales (backdoor común)
            '/eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[/i',
            
            // Funciones peligrosas con variables superglobales
            '/(?:system|exec|shell_exec|passthru)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[/i',
            
            // Tags PHP con eval
            '/<\?php\s+eval\s*\(/i',
            
            // assert con base64
            '/assert\s*\(\s*base64_decode\s*\(/i',
            
            // create_function malicioso
            '/create_function\s*\(\s*[\'"][^\'\"]*[\'"]\s*,\s*\$_(GET|POST|REQUEST)/i',
            
            // preg_replace con /e (ejecutable) - deprecado pero aún peligroso
            '/preg_replace\s*\(\s*[\'"].*\/.*e.*[\'"]/i',
            
            // Strings base64 muy largos (>200 chars) con eval/assert cerca
            '/(?:eval|assert|system|exec)\s*\([^)]*[A-Za-z0-9+\/]{200,}/i',
        );
        
        // 4. Verificar patrones críticos en el contenido SIN bloques de código
        foreach ($critical_patterns as $pattern) {
            if (preg_match($pattern, $without_code_blocks)) {
                return true; // Es MALICIOSO
            }
        }
        
        // 5. Verificar si hay tags PHP ejecutables (no en bloques de código)
        if (preg_match('/<\?php\s+(?:eval|system|exec|shell_exec|passthru|assert)/i', $without_code_blocks)) {
            return true; // Es MALICIOSO
        }
        
        // 6. Si no coincide con ningún patrón crítico, probablemente es educativo
        return false;
    }
    
    private function verify_wordpress_integrity() {
        $issues = [];
        $core_files = array(
            'wp-config.php',
            'wp-load.php',
            'wp-settings.php',
            'wp-includes/wp-db.php',
            'wp-includes/functions.php',
            'wp-admin/admin.php'
        );
        
        foreach ($core_files as $file) {
            $file_path = ABSPATH . $file;
            if (!file_exists($file_path)) {
                // translators: %s is the missing core file name
                $issues[] = sprintf(
                    esc_html__('Archivo core faltante: %s', 'Emergency_Cleanup'),
                    esc_html($file)
                );
            } elseif (filesize($file_path) < 100) {
                // translators: %s is the suspicious core file name
                $issues[] = sprintf(
                    esc_html__('Archivo core sospechoso (muy pequeño): %s', 'Emergency_Cleanup'),
                    esc_html($file)
                );
            }
        }
        
        // Verificar .htaccess
        $htaccess_path = ABSPATH . '.htaccess';
        if (file_exists($htaccess_path)) {
            $htaccess_content = file_get_contents($htaccess_path);
            if ($htaccess_content && preg_match('/eval|base64|shell_exec|system/i', $htaccess_content)) {
                $issues[] = esc_html__('Contenido sospechoso en .htaccess', 'Emergency_Cleanup');
            }
        }
        
        // Verificar permisos de archivos importantes
        $important_files = array(
            'wp-config.php' => 0600,
            '.htaccess' => 0644
        );
        
        foreach ($important_files as $file => $expected_perms) {
            $file_path = ABSPATH . $file;
            if (file_exists($file_path)) {
                $actual_perms = fileperms($file_path) & 0777;
                if ($actual_perms !== $expected_perms) {
                    // translators: %1$s is the file name, %2$o is the actual permissions, %3$o is the expected permissions
                    $issues[] = sprintf(
                        esc_html__('Permisos incorrectos en %1$s (actual: %2$o, esperado: %3$o)', 'Emergency_Cleanup'),
                        esc_html($file),
                        $actual_perms,
                        $expected_perms
                    );
                }
            }
        }
        
        return $issues;
    }
}

// Inicializar el plugin
new EmergencySecurityCleanup();
?>