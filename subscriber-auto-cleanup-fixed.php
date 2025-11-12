<?php
/**
 * Plugin Name: Subscriber Auto Cleanup
 * Description: Automatically delete subscriber users with customizable intervals and manual testing
 * Version: 2.1
 * Author: MC Boshoff
 * Text Domain: subscriber-auto-cleanup
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Define plugin constants
define('SAC_PLUGIN_URL', plugin_dir_url(__FILE__));
define('SAC_PLUGIN_PATH', plugin_dir_path(__FILE__));

class SubscriberAutoCleanup {

    private $option_name = 'sac_settings';
    private $cron_hook = 'sac_cleanup_subscribers';
    private $batch_size = 100; // Process users in batches

    public function __construct() {
        // Activation/Deactivation hooks
        register_activation_hook(__FILE__, array($this, 'activate'));
        register_deactivation_hook(__FILE__, array($this, 'deactivate'));

        // Admin hooks
        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_action('admin_init', array($this, 'register_settings'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_scripts'));

        // Cron action
        add_action($this->cron_hook, array($this, 'cleanup_subscribers'));

        // AJAX handlers
        add_action('wp_ajax_sac_test_cleanup', array($this, 'ajax_test_cleanup'));
        add_action('wp_ajax_sac_get_stats', array($this, 'ajax_get_stats'));

        // Custom cron schedules
        add_filter('cron_schedules', array($this, 'add_custom_schedules'));

        // Clear user count cache when users are added/deleted
        add_action('deleted_user', array($this, 'clear_user_count_cache'));
        add_action('user_register', array($this, 'clear_user_count_cache'));
    }

    /**
     * Clear user count cache
     */
    public function clear_user_count_cache() {
        delete_transient('sac_user_count');
    }

    /**
     * Get cached user count
     */
    private function get_cached_user_count() {
        $user_count = get_transient('sac_user_count');
        if (false === $user_count) {
            $user_count = count_users();
            set_transient('sac_user_count', $user_count, 5 * MINUTE_IN_SECONDS);
        }
        return $user_count;
    }

    /**
     * Add custom cron schedules
     */
    public function add_custom_schedules($schedules) {
        $schedules['every_5_minutes'] = array(
            'interval' => 300,
            'display' => __('Every 5 Minutes', 'subscriber-auto-cleanup')
        );

        $schedules['every_15_minutes'] = array(
            'interval' => 900,
            'display' => __('Every 15 Minutes', 'subscriber-auto-cleanup')
        );

        $schedules['every_30_minutes'] = array(
            'interval' => 1800,
            'display' => __('Every 30 Minutes', 'subscriber-auto-cleanup')
        );

        $schedules['every_2_hours'] = array(
            'interval' => 7200,
            'display' => __('Every 2 Hours', 'subscriber-auto-cleanup')
        );

        $schedules['every_6_hours'] = array(
            'interval' => 21600,
            'display' => __('Every 6 Hours', 'subscriber-auto-cleanup')
        );

        $schedules['every_3_days'] = array(
            'interval' => 259200,
            'display' => __('Every 3 Days', 'subscriber-auto-cleanup')
        );

        return $schedules;
    }

    /**
     * Plugin activation
     */
    public function activate() {
        // Set default settings
        $defaults = array(
            'enabled' => true,
            'interval' => 'daily',
            'min_age_hours' => 24,
            'exclude_admin_email' => true,
            'exclude_emails' => '',
            'keep_content' => false,
            'log_deletions' => true,
            'email_notification' => false,
            'notification_email' => get_option('admin_email'),
            'max_deletions_per_run' => 50,
            'last_run' => null,
            'total_deleted' => 0
        );

        if (!get_option($this->option_name)) {
            update_option($this->option_name, $defaults);
        }

        // Schedule the cleanup
        $this->schedule_cleanup();
    }

    /**
     * Plugin deactivation
     */
    public function deactivate() {
        wp_clear_scheduled_hook($this->cron_hook);
        delete_transient('sac_user_count');
    }

    /**
     * Register settings for sanitization
     */
    public function register_settings() {
        register_setting(
            $this->option_name . '_group',
            $this->option_name,
            array(
                'sanitize_callback' => array($this, 'sanitize_settings')
            )
        );
    }

    /**
     * Sanitize settings before saving
     */
    public function sanitize_settings($input) {
        $sanitized = array();
        $current = get_option($this->option_name);

        // Boolean fields
        $sanitized['enabled'] = isset($input['enabled']) ? (bool)$input['enabled'] : false;
        $sanitized['exclude_admin_email'] = isset($input['exclude_admin_email']) ? (bool)$input['exclude_admin_email'] : false;
        $sanitized['keep_content'] = isset($input['keep_content']) ? (bool)$input['keep_content'] : false;
        $sanitized['log_deletions'] = isset($input['log_deletions']) ? (bool)$input['log_deletions'] : false;
        $sanitized['email_notification'] = isset($input['email_notification']) ? (bool)$input['email_notification'] : false;

        // String fields
        $sanitized['interval'] = isset($input['interval']) ? sanitize_text_field($input['interval']) : 'daily';

        // Validate interval
        $valid_intervals = array('every_5_minutes', 'every_15_minutes', 'every_30_minutes',
                                'hourly', 'every_2_hours', 'every_6_hours', 'twicedaily',
                                'daily', 'every_3_days', 'weekly');
        if (!in_array($sanitized['interval'], $valid_intervals)) {
            $sanitized['interval'] = 'daily';
        }

        // Integer fields
        $sanitized['min_age_hours'] = isset($input['min_age_hours']) ? absint($input['min_age_hours']) : 24;
        if ($sanitized['min_age_hours'] < 1) {
            $sanitized['min_age_hours'] = 1;
        }

        $sanitized['max_deletions_per_run'] = isset($input['max_deletions_per_run']) ? absint($input['max_deletions_per_run']) : 50;
        if ($sanitized['max_deletions_per_run'] < 1) {
            $sanitized['max_deletions_per_run'] = 1;
        }

        // Email fields with validation
        $notification_email = isset($input['notification_email']) ? sanitize_email($input['notification_email']) : '';
        if (is_email($notification_email)) {
            $sanitized['notification_email'] = $notification_email;
        } else {
            $sanitized['notification_email'] = get_option('admin_email');
            add_settings_error(
                'sac_messages',
                'sac_invalid_email',
                __('Invalid notification email address. Using admin email instead.', 'subscriber-auto-cleanup'),
                'warning'
            );
        }

        // Exclude emails - sanitize each email in the comma-separated list
        if (isset($input['exclude_emails'])) {
            $emails = explode(',', $input['exclude_emails']);
            $clean_emails = array();
            foreach ($emails as $email) {
                $clean_email = sanitize_email(trim($email));
                if (!empty($clean_email) && is_email($clean_email)) {
                    $clean_emails[] = $clean_email;
                }
            }
            $sanitized['exclude_emails'] = implode(',', $clean_emails);
        } else {
            $sanitized['exclude_emails'] = '';
        }

        // Preserve existing stats
        if (is_array($current)) {
            $sanitized['last_run'] = isset($current['last_run']) ? $current['last_run'] : null;
            $sanitized['total_deleted'] = isset($current['total_deleted']) ? $current['total_deleted'] : 0;
        } else {
            $sanitized['last_run'] = null;
            $sanitized['total_deleted'] = 0;
        }

        // Reschedule cron if needed
        if (is_array($current) && (
            $sanitized['enabled'] !== $current['enabled'] ||
            $sanitized['interval'] !== $current['interval'])) {
            $this->schedule_cleanup();
        }

        return $sanitized;
    }

    /**
     * Enqueue admin scripts and styles
     */
    public function enqueue_admin_scripts($hook) {
        // Only load on our plugin page
        if ($hook !== 'users_page_subscriber-cleanup') {
            return;
        }

        // Enqueue jQuery first
        wp_enqueue_script('jquery');

        // Create inline script with properly escaped data
        $ajax_data = array(
            'ajax_url' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('sac_ajax_nonce'),
            'i18n' => array(
                'testing' => __('Testing...', 'subscriber-auto-cleanup'),
                'found' => __('Found', 'subscriber-auto-cleanup'),
                'subscribers_eligible' => __('subscriber(s) eligible for deletion:', 'subscriber-auto-cleanup'),
                'registered' => __('Registered:', 'subscriber-auto-cleanup'),
                'hours_ago' => __('hours ago', 'subscriber-auto-cleanup'),
                'no_subscribers' => __('No subscribers meet the deletion criteria.', 'subscriber-auto-cleanup'),
                'test_cleanup' => __('Test Cleanup', 'subscriber-auto-cleanup')
            )
        );

        wp_add_inline_script('jquery', 'var sac_ajax = ' . wp_json_encode($ajax_data) . ';');
    }

    /**
     * Schedule the cleanup based on settings
     */
    private function schedule_cleanup() {
        $settings = get_option($this->option_name);

        // Clear existing schedule
        wp_clear_scheduled_hook($this->cron_hook);

        // Only schedule if enabled
        if ($settings && isset($settings['enabled']) && $settings['enabled']) {
            if (!wp_next_scheduled($this->cron_hook)) {
                wp_schedule_event(time(), $settings['interval'], $this->cron_hook);
            }
        }
    }

    /**
     * Check if user should be excluded from deletion
     */
    private function should_exclude_user($user, $settings) {
        // Always exclude users with admin capabilities
        if (user_can($user->ID, 'manage_options')) {
            return true;
        }

        // Check if user has administrator role
        if (in_array('administrator', (array) $user->roles)) {
            return true;
        }

        // Check if user email matches admin email
        $admin_email = get_option('admin_email');
        if (!empty($settings['exclude_admin_email']) && $user->user_email === $admin_email) {
            return true;
        }

        // Check if user email is in exclude list
        if (!empty($settings['exclude_emails'])) {
            $excluded_emails = array_map('trim', explode(',', $settings['exclude_emails']));
            if (in_array($user->user_email, $excluded_emails)) {
                return true;
            }
        }

        return false;
    }

    /**
     * The main cleanup function - simplified without broken batch processing
     */
    public function cleanup_subscribers($test_mode = false) {
        $settings = get_option($this->option_name);
        $deleted_users = array();
        $deleted_count = 0;

        // Get all subscribers - we process up to max_deletions_per_run
        $args = array(
            'role' => 'subscriber',
            'fields' => 'all',
            'orderby' => 'registered',
            'order' => 'ASC',
            'number' => $test_mode ? -1 : ($settings['max_deletions_per_run'] + 100) // Get extra to account for exclusions
        );

        $subscribers = get_users($args);

        foreach ($subscribers as $user) {
            // Skip if we've reached max deletions per run
            if (!$test_mode && $deleted_count >= $settings['max_deletions_per_run']) {
                break;
            }

            // Check exclusions
            if ($this->should_exclude_user($user, $settings)) {
                continue;
            }

            // Check account age
            $registered_timestamp = strtotime($user->user_registered);
            $account_age_hours = (current_time('timestamp') - $registered_timestamp) / 3600;

            if ($account_age_hours >= $settings['min_age_hours']) {
                // For test mode, just collect info without deleting
                if ($test_mode) {
                    $deleted_users[] = array(
                        'ID' => $user->ID,
                        'email' => $user->user_email,
                        'login' => $user->user_login,
                        'registered' => $user->user_registered,
                        'age_hours' => round($account_age_hours, 2)
                    );
                    $deleted_count++;
                } else {
                    // Actually delete the user
                    $reassign_id = $settings['keep_content'] ? 1 : null;
                    $result = wp_delete_user($user->ID, $reassign_id);

                    if ($result !== false) {
                        $deleted_users[] = $user->user_email;
                        $deleted_count++;

                        // Log individual deletion
                        if ($settings['log_deletions']) {
                            $this->log_deletion($user);
                        }
                    } else {
                        error_log('[Subscriber Cleanup] Failed to delete user ' . $user->ID . ' (' . $user->user_email . ')');
                    }
                }
            }
        }

        // Update stats (not in test mode)
        if (!$test_mode && $deleted_count > 0) {
            $settings['last_run'] = current_time('mysql');
            $settings['total_deleted'] += $deleted_count;
            update_option($this->option_name, $settings);

            // Clear user count cache
            $this->clear_user_count_cache();

            // Send notification email
            if ($settings['email_notification']) {
                $this->send_notification($deleted_count, $deleted_users);
            }
        }

        return array(
            'count' => $deleted_count,
            'users' => $deleted_users,
            'test_mode' => $test_mode
        );
    }

    /**
     * Log deletion to WordPress debug log
     */
    private function log_deletion($user) {
        if (defined('WP_DEBUG_LOG') && WP_DEBUG_LOG) {
            error_log(sprintf(
                '[Subscriber Cleanup] Deleted user: %s (ID: %d, Email: %s, Registered: %s)',
                $user->user_login,
                $user->ID,
                $user->user_email,
                $user->user_registered
            ));
        }
    }

    /**
     * Send notification email
     */
    private function send_notification($count, $users) {
        $settings = get_option($this->option_name);

        $to = $settings['notification_email'];
        $subject = sprintf('[%s] Subscriber Cleanup Report', get_bloginfo('name'));

        $message = "Automated Subscriber Cleanup Report\n";
        $message .= "=====================================\n\n";
        $message .= sprintf("Date: %s\n", current_time('mysql'));
        $message .= sprintf("Subscribers Deleted: %d\n\n", $count);

        if ($count <= 10 && !empty($users)) {
            $message .= "Deleted Users:\n";
            foreach ($users as $email) {
                $message .= "- " . $email . "\n";
            }
        }

        $message .= "\n---\n";
        $message .= "This is an automated message from the Subscriber Auto Cleanup plugin.\n";
        $message .= sprintf("Total deleted since activation: %d\n", $settings['total_deleted']);

        wp_mail($to, $subject, $message);
    }

    /**
     * Add admin menu
     */
    public function add_admin_menu() {
        add_submenu_page(
            'users.php',
            __('Subscriber Cleanup', 'subscriber-auto-cleanup'),
            __('Subscriber Cleanup', 'subscriber-auto-cleanup'),
            'manage_options',
            'subscriber-cleanup',
            array($this, 'admin_page')
        );
    }

    /**
     * AJAX handler for test cleanup with proper security
     */
    public function ajax_test_cleanup() {
        // Security checks with proper sanitization
        $nonce = isset($_POST['nonce']) ? sanitize_text_field(wp_unslash($_POST['nonce'])) : '';
        if (!wp_verify_nonce($nonce, 'sac_ajax_nonce')) {
            wp_send_json_error(array('message' => __('Security check failed', 'subscriber-auto-cleanup')), 403);
            return;
        }

        // Capability check
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => __('Unauthorized access', 'subscriber-auto-cleanup')), 403);
            return;
        }

        $result = $this->cleanup_subscribers(true);

        wp_send_json_success($result);
    }

    /**
     * AJAX handler for getting stats with proper security
     */
    public function ajax_get_stats() {
        // Security checks with proper sanitization
        $nonce = isset($_POST['nonce']) ? sanitize_text_field(wp_unslash($_POST['nonce'])) : '';
        if (!wp_verify_nonce($nonce, 'sac_ajax_nonce')) {
            wp_send_json_error(array('message' => __('Security check failed', 'subscriber-auto-cleanup')), 403);
            return;
        }

        // Capability check
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => __('Unauthorized access', 'subscriber-auto-cleanup')), 403);
            return;
        }

        $subscriber_count = $this->get_cached_user_count();
        $data = array(
            'subscriber_count' => isset($subscriber_count['avail_roles']['subscriber']) ?
                                 $subscriber_count['avail_roles']['subscriber'] : 0
        );

        wp_send_json_success($data);
    }

    /**
     * Handle manual cleanup
     */
    private function handle_manual_cleanup() {
        $nonce = isset($_POST['sac_manual_cleanup_nonce']) ? sanitize_text_field(wp_unslash($_POST['sac_manual_cleanup_nonce'])) : '';

        if (!wp_verify_nonce($nonce, 'sac_manual_cleanup')) {
            return;
        }

        if (!current_user_can('manage_options')) {
            return;
        }

        $result = $this->cleanup_subscribers(false);

        if ($result['count'] > 0) {
            add_settings_error(
                'sac_messages',
                'sac_message',
                sprintf(__('Successfully deleted %d subscriber(s)', 'subscriber-auto-cleanup'), $result['count']),
                'success'
            );
        } else {
            add_settings_error(
                'sac_messages',
                'sac_message',
                __('No subscribers met the deletion criteria', 'subscriber-auto-cleanup'),
                'info'
            );
        }
    }

    /**
     * Admin page
     */
    public function admin_page() {
        // Handle manual cleanup if requested
        if (isset($_POST['run_cleanup'])) {
            $this->handle_manual_cleanup();
        }

        // Get settings and stats
        $settings = get_option($this->option_name);
        $user_count = $this->get_cached_user_count();
        $subscriber_count = isset($user_count['avail_roles']['subscriber']) ?
                           $user_count['avail_roles']['subscriber'] : 0;

        // Calculate next run time
        $next_run = wp_next_scheduled($this->cron_hook);

        // Check for aggressive schedule warning
        $aggressive_schedules = array('every_5_minutes', 'every_15_minutes', 'every_30_minutes');
        $show_warning = in_array($settings['interval'], $aggressive_schedules);
        ?>
        <div class="wrap">
            <h1><?php echo esc_html__('Subscriber Auto Cleanup', 'subscriber-auto-cleanup'); ?></h1>

            <?php settings_errors('sac_messages'); ?>

            <?php if ($show_warning && $settings['enabled']): ?>
            <div class="notice notice-warning">
                <p><strong><?php esc_html_e('Warning:', 'subscriber-auto-cleanup'); ?></strong>
                <?php esc_html_e('You have selected a very frequent cleanup schedule. Please ensure this is intentional to avoid excessive server load.', 'subscriber-auto-cleanup'); ?></p>
            </div>
            <?php endif; ?>

            <!-- Dashboard -->
            <div class="sac-dashboard">
                <!-- Stats Cards -->
                <div class="sac-cards">
                    <div class="sac-card">
                        <h3><?php esc_html_e('Current Subscribers', 'subscriber-auto-cleanup'); ?></h3>
                        <div class="sac-number" id="current-subscribers"><?php echo absint($subscriber_count); ?></div>
                    </div>

                    <div class="sac-card">
                        <h3><?php esc_html_e('Total Deleted', 'subscriber-auto-cleanup'); ?></h3>
                        <div class="sac-number"><?php echo absint($settings['total_deleted']); ?></div>
                    </div>

                    <div class="sac-card">
                        <h3><?php esc_html_e('Status', 'subscriber-auto-cleanup'); ?></h3>
                        <div class="sac-status <?php echo $settings['enabled'] ? 'active' : 'inactive'; ?>">
                            <?php echo $settings['enabled'] ? esc_html__('Active', 'subscriber-auto-cleanup') : esc_html__('Inactive', 'subscriber-auto-cleanup'); ?>
                        </div>
                    </div>

                    <div class="sac-card">
                        <h3><?php esc_html_e('Next Cleanup', 'subscriber-auto-cleanup'); ?></h3>
                        <div class="sac-time">
                            <?php
                            if ($next_run && $settings['enabled']) {
                                echo esc_html(human_time_diff($next_run, current_time('timestamp')) . ' ' . __('from now', 'subscriber-auto-cleanup'));
                            } else {
                                echo esc_html__('Not scheduled', 'subscriber-auto-cleanup');
                            }
                            ?>
                        </div>
                    </div>
                </div>

                <!-- Settings Form -->
                <div class="sac-settings">
                    <h2><?php esc_html_e('Settings', 'subscriber-auto-cleanup'); ?></h2>

                    <form method="post" action="options.php">
                        <?php settings_fields($this->option_name . '_group'); ?>

                        <table class="form-table">
                            <tr>
                                <th scope="row"><?php esc_html_e('Enable Auto Cleanup', 'subscriber-auto-cleanup'); ?></th>
                                <td>
                                    <label>
                                        <input type="checkbox" name="<?php echo esc_attr($this->option_name); ?>[enabled]"
                                               value="1" <?php checked($settings['enabled'], true); ?>>
                                        <?php esc_html_e('Automatically delete subscribers based on schedule', 'subscriber-auto-cleanup'); ?>
                                    </label>
                                </td>
                            </tr>

                            <tr>
                                <th scope="row"><?php esc_html_e('Cleanup Schedule', 'subscriber-auto-cleanup'); ?></th>
                                <td>
                                    <select name="<?php echo esc_attr($this->option_name); ?>[interval]">
                                        <option value="every_5_minutes" <?php selected($settings['interval'], 'every_5_minutes'); ?>><?php esc_html_e('Every 5 Minutes ⚠️ Very Aggressive', 'subscriber-auto-cleanup'); ?></option>
                                        <option value="every_15_minutes" <?php selected($settings['interval'], 'every_15_minutes'); ?>><?php esc_html_e('Every 15 Minutes ⚠️ Aggressive', 'subscriber-auto-cleanup'); ?></option>
                                        <option value="every_30_minutes" <?php selected($settings['interval'], 'every_30_minutes'); ?>><?php esc_html_e('Every 30 Minutes ⚠️ Aggressive', 'subscriber-auto-cleanup'); ?></option>
                                        <option value="hourly" <?php selected($settings['interval'], 'hourly'); ?>><?php esc_html_e('Hourly', 'subscriber-auto-cleanup'); ?></option>
                                        <option value="every_2_hours" <?php selected($settings['interval'], 'every_2_hours'); ?>><?php esc_html_e('Every 2 Hours', 'subscriber-auto-cleanup'); ?></option>
                                        <option value="every_6_hours" <?php selected($settings['interval'], 'every_6_hours'); ?>><?php esc_html_e('Every 6 Hours', 'subscriber-auto-cleanup'); ?></option>
                                        <option value="twicedaily" <?php selected($settings['interval'], 'twicedaily'); ?>><?php esc_html_e('Twice Daily', 'subscriber-auto-cleanup'); ?></option>
                                        <option value="daily" <?php selected($settings['interval'], 'daily'); ?>><?php esc_html_e('Daily (Recommended)', 'subscriber-auto-cleanup'); ?></option>
                                        <option value="every_3_days" <?php selected($settings['interval'], 'every_3_days'); ?>><?php esc_html_e('Every 3 Days', 'subscriber-auto-cleanup'); ?></option>
                                        <option value="weekly" <?php selected($settings['interval'], 'weekly'); ?>><?php esc_html_e('Weekly', 'subscriber-auto-cleanup'); ?></option>
                                    </select>
                                </td>
                            </tr>

                            <tr>
                                <th scope="row"><?php esc_html_e('Minimum Account Age', 'subscriber-auto-cleanup'); ?></th>
                                <td>
                                    <input type="number" min="1" name="<?php echo esc_attr($this->option_name); ?>[min_age_hours]"
                                           value="<?php echo absint($settings['min_age_hours']); ?>">
                                    <span class="description"><?php esc_html_e('hours (only delete accounts older than this)', 'subscriber-auto-cleanup'); ?></span>
                                </td>
                            </tr>

                            <tr>
                                <th scope="row"><?php esc_html_e('Exclusions', 'subscriber-auto-cleanup'); ?></th>
                                <td>
                                    <label>
                                        <input type="checkbox" name="<?php echo esc_attr($this->option_name); ?>[exclude_admin_email]"
                                               value="1" <?php checked($settings['exclude_admin_email'], true); ?>>
                                        <?php esc_html_e('Exclude site admin email address', 'subscriber-auto-cleanup'); ?>
                                    </label>
                                    <br><br>
                                    <label><?php esc_html_e('Exclude specific emails:', 'subscriber-auto-cleanup'); ?><br>
                                        <textarea name="<?php echo esc_attr($this->option_name); ?>[exclude_emails]"
                                                  rows="3" cols="50"
                                                  placeholder="email1@example.com, email2@example.com"><?php echo esc_textarea($settings['exclude_emails']); ?></textarea>
                                    </label>
                                    <p class="description"><?php esc_html_e('Comma-separated list of email addresses to never delete', 'subscriber-auto-cleanup'); ?></p>
                                </td>
                            </tr>

                            <tr>
                                <th scope="row"><?php esc_html_e('Safety Settings', 'subscriber-auto-cleanup'); ?></th>
                                <td>
                                    <label>
                                        <?php esc_html_e('Maximum deletions per run:', 'subscriber-auto-cleanup'); ?>
                                        <input type="number" min="1" max="1000"
                                               name="<?php echo esc_attr($this->option_name); ?>[max_deletions_per_run]"
                                               value="<?php echo absint($settings['max_deletions_per_run']); ?>">
                                    </label>
                                    <p class="description"><?php esc_html_e('Safety limit to prevent accidental mass deletions', 'subscriber-auto-cleanup'); ?></p>
                                </td>
                            </tr>

                            <tr>
                                <th scope="row"><?php esc_html_e('Content Handling', 'subscriber-auto-cleanup'); ?></th>
                                <td>
                                    <label>
                                        <input type="checkbox" name="<?php echo esc_attr($this->option_name); ?>[keep_content]"
                                               value="1" <?php checked($settings['keep_content'], true); ?>>
                                        <?php esc_html_e('Reassign content to admin when deleting users', 'subscriber-auto-cleanup'); ?>
                                    </label>
                                </td>
                            </tr>

                            <tr>
                                <th scope="row"><?php esc_html_e('Logging', 'subscriber-auto-cleanup'); ?></th>
                                <td>
                                    <label>
                                        <input type="checkbox" name="<?php echo esc_attr($this->option_name); ?>[log_deletions]"
                                               value="1" <?php checked($settings['log_deletions'], true); ?>>
                                        <?php esc_html_e('Log deletions to debug.log (if WP_DEBUG_LOG is enabled)', 'subscriber-auto-cleanup'); ?>
                                    </label>
                                </td>
                            </tr>

                            <tr>
                                <th scope="row"><?php esc_html_e('Email Notifications', 'subscriber-auto-cleanup'); ?></th>
                                <td>
                                    <label>
                                        <input type="checkbox" id="email-notification"
                                               name="<?php echo esc_attr($this->option_name); ?>[email_notification]"
                                               value="1" <?php checked($settings['email_notification'], true); ?>>
                                        <?php esc_html_e('Send email report after cleanup', 'subscriber-auto-cleanup'); ?>
                                    </label>

                                    <div id="email-field" style="margin-top: 10px; <?php echo $settings['email_notification'] ? '' : 'display:none;'; ?>">
                                        <label>
                                            <?php esc_html_e('Notification Email:', 'subscriber-auto-cleanup'); ?>
                                            <input type="email" name="<?php echo esc_attr($this->option_name); ?>[notification_email]"
                                                   value="<?php echo esc_attr($settings['notification_email']); ?>"
                                                   class="regular-text">
                                        </label>
                                    </div>
                                </td>
                            </tr>
                        </table>

                        <?php submit_button(esc_html__('Save Settings', 'subscriber-auto-cleanup')); ?>
                    </form>
                </div>

                <!-- Actions Section -->
                <div class="sac-actions">
                    <h2><?php esc_html_e('Actions', 'subscriber-auto-cleanup'); ?></h2>

                    <div class="sac-action-buttons">
                        <!-- Test Cleanup -->
                        <div class="sac-action-item">
                            <h3><?php esc_html_e('Test Cleanup', 'subscriber-auto-cleanup'); ?></h3>
                            <p><?php esc_html_e('Preview which users would be deleted without actually deleting them.', 'subscriber-auto-cleanup'); ?></p>
                            <button id="test-cleanup" class="button">
                                <span class="dashicons dashicons-visibility"></span> <?php esc_html_e('Test Cleanup', 'subscriber-auto-cleanup'); ?>
                            </button>
                        </div>

                        <!-- Run Cleanup Now -->
                        <div class="sac-action-item">
                            <h3><?php esc_html_e('Manual Cleanup', 'subscriber-auto-cleanup'); ?></h3>
                            <p><?php esc_html_e('Immediately run the cleanup process.', 'subscriber-auto-cleanup'); ?></p>
                            <form method="post" style="display:inline;">
                                <?php wp_nonce_field('sac_manual_cleanup', 'sac_manual_cleanup_nonce'); ?>
                                <button type="submit" name="run_cleanup" class="button button-primary"
                                        onclick="return confirm('<?php echo esc_js(__('This will permanently delete eligible subscribers. Continue?', 'subscriber-auto-cleanup')); ?>');">
                                    <span class="dashicons dashicons-trash"></span> <?php esc_html_e('Run Cleanup Now', 'subscriber-auto-cleanup'); ?>
                                </button>
                            </form>
                        </div>

                        <!-- Refresh Stats -->
                        <div class="sac-action-item">
                            <h3><?php esc_html_e('Refresh Statistics', 'subscriber-auto-cleanup'); ?></h3>
                            <p><?php esc_html_e('Update the subscriber count and other statistics.', 'subscriber-auto-cleanup'); ?></p>
                            <button id="refresh-stats" class="button">
                                <span class="dashicons dashicons-update"></span> <?php esc_html_e('Refresh Stats', 'subscriber-auto-cleanup'); ?>
                            </button>
                        </div>
                    </div>

                    <!-- Test Results -->
                    <div id="test-results" style="display:none; margin-top: 20px;">
                        <h3><?php esc_html_e('Test Results', 'subscriber-auto-cleanup'); ?></h3>
                        <div id="test-output"></div>
                    </div>
                </div>

                <!-- Last Run Info -->
                <?php if (!empty($settings['last_run'])): ?>
                <div class="sac-info">
                    <p><strong><?php esc_html_e('Last cleanup run:', 'subscriber-auto-cleanup'); ?></strong> <?php echo esc_html($settings['last_run']); ?></p>
                </div>
                <?php endif; ?>
            </div>
        </div>

        <style>
        .sac-dashboard {
            max-width: 1200px;
            margin: 20px 0;
        }

        .sac-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .sac-card {
            background: #fff;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
        }

        .sac-card h3 {
            margin-top: 0;
            color: #555;
            font-size: 14px;
            font-weight: 600;
            text-transform: uppercase;
        }

        .sac-number {
            font-size: 32px;
            font-weight: bold;
            color: #2271b1;
        }

        .sac-status {
            font-size: 18px;
            font-weight: bold;
        }

        .sac-status.active {
            color: #46b450;
        }

        .sac-status.inactive {
            color: #dc3545;
        }

        .sac-time {
            font-size: 14px;
            color: #666;
        }

        .sac-settings, .sac-actions {
            background: #fff;
            padding: 25px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }

        .sac-settings h2, .sac-actions h2 {
            margin-top: 0;
            border-bottom: 2px solid #f0f0f1;
            padding-bottom: 10px;
        }

        .sac-action-buttons {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }

        .sac-action-item {
            padding: 15px;
            border: 1px solid #ddd;
            border-radius: 5px;
            background: #f9f9f9;
        }

        .sac-action-item h3 {
            margin-top: 0;
            margin-bottom: 10px;
        }

        .sac-action-item p {
            margin-bottom: 15px;
            color: #666;
            font-size: 13px;
        }

        .button .dashicons {
            vertical-align: middle;
            margin-right: 5px;
        }

        #test-results {
            background: #f0f0f1;
            padding: 20px;
            border-radius: 5px;
            border-left: 4px solid #2271b1;
        }

        .test-user-item {
            background: #fff;
            padding: 10px;
            margin-bottom: 10px;
            border-radius: 3px;
        }

        .sac-info {
            background: #f0f8ff;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid #2271b1;
        }
        </style>

        <script>
        jQuery(document).ready(function($) {
            // Show/hide email field
            $('#email-notification').change(function() {
                $('#email-field').toggle(this.checked);
            });

            // Test cleanup
            $('#test-cleanup').click(function() {
                var $button = $(this);
                $button.prop('disabled', true).text(sac_ajax.i18n.testing);

                $.ajax({
                    url: sac_ajax.ajax_url,
                    type: 'POST',
                    data: {
                        action: 'sac_test_cleanup',
                        nonce: sac_ajax.nonce
                    },
                    success: function(response) {
                        if (response.success) {
                            var result = response.data;
                            var html = '<p><strong>' + sac_ajax.i18n.found + ' ' + result.count + ' ' + sac_ajax.i18n.subscribers_eligible + '</strong></p>';

                            if (result.count > 0) {
                                html += '<div style="max-height: 300px; overflow-y: auto;">';
                                result.users.forEach(function(user) {
                                    html += '<div class="test-user-item">';
                                    html += '<strong>' + $('<div>').text(user.login).html() + '</strong> (' + $('<div>').text(user.email).html() + ')<br>';
                                    html += sac_ajax.i18n.registered + ' ' + $('<div>').text(user.registered).html() + ' (' + user.age_hours + ' ' + sac_ajax.i18n.hours_ago + ')';
                                    html += '</div>';
                                });
                                html += '</div>';
                            } else {
                                html += '<p>' + sac_ajax.i18n.no_subscribers + '</p>';
                            }

                            $('#test-output').html(html);
                            $('#test-results').slideDown();
                        }
                    },
                    error: function() {
                        alert('An error occurred. Please try again.');
                    },
                    complete: function() {
                        $button.prop('disabled', false).html('<span class="dashicons dashicons-visibility"></span> ' + sac_ajax.i18n.test_cleanup);
                    }
                });
            });

            // Refresh stats
            $('#refresh-stats').click(function() {
                var $button = $(this);
                $button.prop('disabled', true);

                $.ajax({
                    url: sac_ajax.ajax_url,
                    type: 'POST',
                    data: {
                        action: 'sac_get_stats',
                        nonce: sac_ajax.nonce
                    },
                    success: function(response) {
                        if (response.success) {
                            $('#current-subscribers').text(response.data.subscriber_count);

                            // Add animation effect
                            $('#current-subscribers').css('color', '#46b450').animate({
                                fontSize: '36px'
                            }, 200).animate({
                                fontSize: '32px'
                            }, 200, function() {
                                $(this).css('color', '#2271b1');
                            });
                        }
                    },
                    error: function() {
                        alert('An error occurred. Please try again.');
                    },
                    complete: function() {
                        $button.prop('disabled', false);
                    }
                });
            });
        });
        </script>
        <?php
    }
}

// Initialize the plugin
new SubscriberAutoCleanup();
