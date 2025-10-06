<?php
/**
 * Uninstall file for Emergency Security Cleanup
 * 
 * This file is executed when the plugin is deleted through the WordPress admin.
 * It cleans up any data that the plugin has created.
 * 
 * @package Emergency_Security_Cleanup
 * @version 1.0.0
 */

// If uninstall not called from WordPress, then exit
if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

// Check if user has permission to uninstall plugins
if (!current_user_can('delete_plugins')) {
    exit;
}

// Clean up plugin options
delete_option('emergency_cleanup_version');
delete_option('emergency_cleanup_activated');

// Clean up any transients
delete_transient('emergency_cleanup_scan_results');
delete_transient('emergency_cleanup_cleanup_log');

// Remove backup directories (older than 30 days)
$upload_dir = wp_upload_dir();
$backup_pattern = $upload_dir['basedir'] . '/emergency-backup-*';

$backup_dirs = glob($backup_pattern, GLOB_ONLYDIR);
if ($backup_dirs) {
    foreach ($backup_dirs as $backup_dir) {
        // Check if backup is older than 30 days
        if (filemtime($backup_dir) < (time() - (30 * 24 * 60 * 60))) {
            // Remove directory and all contents
            if (is_dir($backup_dir)) {
                $files = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator($backup_dir, RecursiveDirectoryIterator::SKIP_DOTS),
                    RecursiveIteratorIterator::CHILD_FIRST
                );
                
                foreach ($files as $file) {
                    if ($file->isDir()) {
                        rmdir($file->getRealPath());
                    } else {
                        unlink($file->getRealPath());
                    }
                }
                rmdir($backup_dir);
            }
        }
    }
}

// Log the uninstall action
error_log('Emergency Security Cleanup plugin uninstalled on ' . current_time('mysql'));
