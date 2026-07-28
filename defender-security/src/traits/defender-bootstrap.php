<?php
/**
 * Handle common bootstrap functionalities.
 *
 * @package WP_Defender\Traits
 */

namespace WP_Defender\Traits;

use WP_CLI;
use Calotes\DB\Mapper;
use WP_Defender\Admin;
use WP_Defender\Component\Cli;
use Calotes\Helper\Array_Cache;
use WP_Defender\Controller\HUB;
use WP_Defender\Controller\WAF;
use WP_Defender\Controller\Scan;
use WP_Defender\Component\Crypt;
use WP_Defender\Behavior\WPMUDEV;
use WP_Defender\Controller\Webauthn;
use WP_Defender\Controller\Dashboard;
use WP_Defender\Controller\Captcha;
use WP_Defender\Controller\Recipients;
use WP_Defender\Controller\Quarantine;
use WP_Defender\Controller\Mask_Login;
use WP_Defender\Controller\Two_Factor;
use WP_Defender\Component\Hub_Connector;
use WP_Defender\Controller\Main_Setting;
use WP_Defender\Controller\Notification;
use WP_Defender\Controller\Audit_Logging;
use WP_Defender\Controller\Data_Tracking;
use WP_Defender\Controller\Login_Access;
use WP_Defender\Controller\Password_Reset;
use WP_Defender\Controller\Setup_Wizard;
use WP_Defender\Controller\Strong_Password;
use WP_Defender\Controller\Security_Tweaks;
use WP_Defender\Controller\Blocklist_Monitor;
use WP_Defender\Controller\Session_Protection;
use WP_Defender\Controller\Password_Protection;
use WP_Defender\Component\Network_Cron_Manager;
use WP_Defender\Component\Logger\Rotation_Logger;
use WP_Defender\Component\Firewall as Firewall_Component;
use WP_Defender\Controller\Firewall as Firewall_Controller;
use WP_Defender\Controller\Hub_Connector as Hub_Connector_Controller;
use WP_Defender\Model\Onboard as Onboard_Model;
use WP_Defender\Controller\Rate as Rate_Controller;
use WP_Defender\Component\Rate as Rate_Component;
use WP_Defender\Upgrader;

trait Defender_Bootstrap {

	/**
	 * Table name for quarantine.
	 *
	 * @var string
	 */
	private $quarantine_table = 'defender_quarantine';

	/**
	 * Table name for scan item.
	 *
	 * @var string
	 */
	private $scan_item_table = 'defender_scan_item';

	/**
	 * Activation.
	 */
	private function activation_hook_common(): void {
		Upgrader::date_activated();
		$this->create_database_tables_common();
		$this->on_activation();
		$this->set_activation_redirect_flag();
		// Create a file with a random key if it doesn't exist.
		( new Crypt() )->create_key_file();
		// If this is a plugin reactivating, then track it. No need the check by 'wd_nofresh_install' key because the option is disabled by default.
		$settings = wd_di()->get( Main_Setting::class );
		$settings->set_intention( 'Reactivation' );
		$settings->track_opt( true );

		$service = wd_di()->get( Firewall_Component::class );
		$service->auto_switch_ip_detection_option();
		$service->maybe_show_misconfigured_ip_detection_option_notice();
		$service->maybe_dismiss_cf_notice();
		wp_schedule_single_event( time() + 5, 'wpdef_smart_ip_detection_ping' );
	}

	/**
	 * Deactivation - clears shared cron hooks present in both free and pro versions.
	 */
	protected function deactivation_hook_common(): void {
		wp_clear_scheduled_hook( 'firewall_clean_up_logs' );
		wp_clear_scheduled_hook( 'wdf_maybe_send_report' );
		wp_clear_scheduled_hook( 'wp_defender_clear_logs' );
		wp_clear_scheduled_hook( 'wpdef_sec_key_gen' );
		wp_clear_scheduled_hook( 'wpdef_clear_scan_logs' );
		wp_clear_scheduled_hook( 'wpdef_log_rotational_delete' );
		wp_clear_scheduled_hook( 'wpdef_update_geoip' );
		wp_clear_scheduled_hook( 'wpdef_fetch_global_ip_list' );
		wp_clear_scheduled_hook( 'wpdef_firewall_clean_up_lockout' );
		wp_clear_scheduled_hook( 'wpdef_firewall_send_compact_logs_to_api' );
		wp_clear_scheduled_hook( 'wpdef_firewall_fetch_trusted_proxy_preset_ips' );
		wp_clear_scheduled_hook( 'wpdef_firewall_clean_up_unlockout' );
		wp_clear_scheduled_hook( 'wpdef_antibot_global_firewall_fetch_blocklist' );
		wp_clear_scheduled_hook( 'wpdef_smart_ip_detection_ping' );
		wp_clear_scheduled_hook( 'wpdef_confirm_antibot_toggle_on_hosting' );
		wp_clear_scheduled_hook( 'wpdef_firewall_whitelist_server_public_ip' );
		wp_clear_scheduled_hook( 'wpdef_rotate_malicious_bot_secret_hash' );

		// Remove old legacy cron jobs if they exist.
		wp_clear_scheduled_hook( 'lockoutReportCron' );
		wp_clear_scheduled_hook( 'cleanUpOldLog' );
		wp_clear_scheduled_hook( 'scanReportCron' );
		wp_clear_scheduled_hook( 'tweaksSendNotification' );
	}

	/**
	 * Creates the 'defender_unlockout' table if it doesn't exist in the database.
	 *
	 * @return void
	 */
	public function create_table_unlockout() {
		global $wpdb;

		$charset_collate = $wpdb->get_charset_collate();

		$sql = <<<SQL
		CREATE TABLE IF NOT EXISTS {$wpdb->base_prefix}defender_unlockout (
			`id` int(11) unsigned NOT NULL AUTO_INCREMENT,
			`ip` varchar(45) DEFAULT NULL,
			`type` varchar(16) NOT NULL,
			`email` varchar(255) NOT NULL,
			`status` varchar(16) NOT NULL,
			`timestamp` int(11) NOT NULL,
			PRIMARY KEY  (`id`),
			KEY `ip` (`ip`),
			KEY `type` (`type`),
			KEY `email` (`email`),
			KEY `status` (`status`)
		   ) {$charset_collate};
SQL;
		$wpdb->query( $sql ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
	}

	/**
	 * Create blocklist table.
	 *
	 * @since 2.8.0
	 * @return void
	 */
	public function create_table_blocklist(): void {
		global $wpdb;

		$charset_collate = $wpdb->get_charset_collate();

		$sql = <<<SQL
		CREATE TABLE IF NOT EXISTS {$wpdb->base_prefix}defender_antibot (
			`id` int(11) unsigned NOT NULL AUTO_INCREMENT,
			`ip` varchar(45) NOT NULL,
			`unlocked` tinyint(1) DEFAULT NULL,
			`unlocked_at` int(11) DEFAULT NULL,
			PRIMARY KEY  (`id`),
			UNIQUE KEY ip (ip)
		   ) {$charset_collate};
SQL;
		$wpdb->query( $sql ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared
	}

	/**
	 * Creates Defender's tables.
	 *
	 * @since 2.7.1 No use dbDelta because PHP v8.1 triggers an error when calling query "DESCRIBE {$table};" if the
	 *     table doesn't exist.
	 */
	protected function create_database_tables_common(): void {
		global $wpdb;

		$charset_collate = $wpdb->get_charset_collate();
		// Hide errors.
		$wpdb->hide_errors();
		// Email log table.
		$sql = "CREATE TABLE IF NOT EXISTS {$wpdb->base_prefix}defender_email_log (
 `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
 `timestamp` int NOT NULL,
 `source` varchar(255) NOT NULL,
 `to` varchar(255) NOT NULL,
 PRIMARY KEY  (`id`),
 KEY `source` (`source`)
) $charset_collate;";
		$wpdb->query( $sql ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

		// Scan item table.
		$sql = "CREATE TABLE IF NOT EXISTS {$wpdb->base_prefix}defender_scan_item (
 `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
 `parent_id` int NOT NULL,
 `type` varchar(255) NOT NULL,
 `status` varchar(255) NOT NULL,
 `raw_data` text NOT NULL,
 PRIMARY KEY  (`id`),
 KEY `type` (`type`),
 KEY `status` (`status`)
) $charset_collate;";
		$wpdb->query( $sql ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

		// Scan table.
		$sql = "CREATE TABLE IF NOT EXISTS {$wpdb->base_prefix}defender_scan (
 `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
 `percent` float NOT NULL,
 `total_tasks` tinyint(4) NOT NULL,
 `task_checkpoint` varchar(255) NOT NULL,
 `status` varchar(255) NOT NULL,
 `date_start` datetime NOT NULL,
 `date_end` datetime NOT NULL,
 `is_automation` bool NOT NULL,
 PRIMARY KEY  (`id`)
) $charset_collate;";
		$wpdb->query( $sql ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

		// Lockout log table.
		$sql = "CREATE TABLE IF NOT EXISTS {$wpdb->base_prefix}defender_lockout_log (
 `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
 `log` text,
 `ip` varchar(45) DEFAULT NULL,
 `date` int(11) DEFAULT NULL,
 `type` varchar(16) DEFAULT NULL,
 `user_agent` varchar(255) DEFAULT NULL,
 `blog_id` int(11) DEFAULT NULL,
 `tried` varchar(255),
 `country_iso_code` char(2) DEFAULT NULL,
 PRIMARY KEY  (`id`),
 KEY `ip` (`ip`),
 KEY `type` (`type`),
 KEY `tried` (`tried`),
 KEY `country_iso_code` (`country_iso_code`)
) $charset_collate;";
		$wpdb->query( $sql ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

		// Lockout table.
		$sql = "CREATE TABLE IF NOT EXISTS {$wpdb->base_prefix}defender_lockout (
 `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
 `ip` varchar(45) DEFAULT NULL,
 `status` varchar(16) DEFAULT NULL,
 `lockout_message` text,
 `release_time` int(11) DEFAULT NULL,
 `lock_time` int(11) DEFAULT NULL,
 `lock_time_404` int(11) DEFAULT NULL,
 `attempt` int(11) DEFAULT NULL,
 `attempt_404` int(11) DEFAULT NULL,
 `meta` text,
 PRIMARY KEY  (`id`),
 KEY `ip` (`ip`),
 KEY `status` (`status`),
 KEY `attempt` (`attempt`),
 KEY `attempt_404` (`attempt_404`)
) $charset_collate;";
		$wpdb->query( $sql ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

		// Create unlockout table.
		$this->create_table_unlockout();
		// Create Blocklist table.
		$this->create_table_blocklist();
		// Create Quarantine table.
		$this->create_table_quarantine();
	}

	/**
	 * Check if all quarantine-dependent tables use the InnoDB storage engine.
	 *
	 * @return bool True if all dependent tables are InnoDB, false otherwise.
	 */
	private function is_quarantine_dependent_tables_innodb(): bool {
		global $wpdb;

		$tables      = array( $wpdb->users, $wpdb->base_prefix . $this->scan_item_table );
		$total_table = count( $tables );

		return $wpdb->get_var( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$wpdb->prepare(
				"SELECT COUNT(`ENGINE`) = %d FROM information_schema.TABLES WHERE TABLE_SCHEMA = %s AND `ENGINE` = %s AND TABLE_NAME IN ( '{$wpdb->users}', '{$wpdb->base_prefix}defender_scan_item' );",
				$total_table,
				$wpdb->dbname,
				'innodb',
			)
		) === '1';
	}

	/**
	 * Creates the quarantine table if it doesn't exist.
	 * Uses InnoDB foreign key constraints when the dependent tables support it,
	 * otherwise falls back to plain KEY indexes.
	 *
	 * @return void
	 */
	public function create_table_quarantine(): void {
		global $wpdb;

		$quarantine_table = $wpdb->base_prefix . $this->quarantine_table;
		$scan_item_table  = $wpdb->base_prefix . $this->scan_item_table;
		$charset_collate  = $wpdb->get_charset_collate();
		$unique_id        = uniqid( $wpdb->prefix );

		$common_columns = <<<'SQL'
		`id` bigint UNSIGNED NOT NULL AUTO_INCREMENT,
		`defender_scan_item_id` int UNSIGNED DEFAULT NULL,
		`file_hash` char(53) NOT NULL,
		`file_full_path` text NOT NULL,
		`file_original_name` tinytext NOT NULL,
		`file_extension` varchar(16) DEFAULT NULL,
		`file_mime_type` varchar(64) DEFAULT NULL,
		`file_rw_permission` smallint UNSIGNED DEFAULT NULL,
		`file_owner` varchar(255) DEFAULT NULL,
		`file_group` varchar(255) DEFAULT NULL,
		`file_version` varchar(32) DEFAULT NULL,
		`file_category` tinyint UNSIGNED DEFAULT 0,
		`file_modified_time` datetime NOT NULL,
		`source_slug` varchar(255) NOT NULL,
		`created_time` datetime NOT NULL,
		`created_by` bigint UNSIGNED DEFAULT NULL,
		PRIMARY KEY (`id`)
		SQL;

		// Define key names.
		$scan_item_key  = "{$unique_id}_defender_scan_item_id";
		$created_by_key = "{$unique_id}_created_by";

		// Build the SQL statement based on the storage engine.
		if ( $this->is_quarantine_dependent_tables_innodb() ) {
			$sql = <<<SQL
			CREATE TABLE IF NOT EXISTS `{$quarantine_table}` (
				$common_columns,
				CONSTRAINT `{$scan_item_key}`
				FOREIGN KEY (`defender_scan_item_id`) REFERENCES {$scan_item_table}(`id`)
				ON UPDATE CASCADE ON DELETE SET NULL,
				CONSTRAINT `{$created_by_key}`
				FOREIGN KEY (`created_by`) REFERENCES {$wpdb->users}(`ID`)
				ON UPDATE CASCADE ON DELETE SET NULL
			) {$charset_collate};
			SQL;
		} else {
			$sql = <<<SQL
			CREATE TABLE IF NOT EXISTS `{$quarantine_table}` (
				$common_columns,
				KEY `{$scan_item_key}` (`defender_scan_item_id`),
				KEY `{$created_by_key}` (`created_by`)
			) {$charset_collate};
			SQL;
		}

		// Execute the SQL query.
		$wpdb->query( $sql ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
	}

	/**
	 * Check if this is onboarding.
	 *
	 * @return bool
	 */
	private function is_onboarding(): bool {
		// Temporary switch for setup-wizard showcase phase:
		// keep legacy onboarding disabled until new flow integration.
		$enable_legacy_onboarding = (bool) apply_filters( 'wpdef_enable_legacy_onboarding', false );
		if ( ! $enable_legacy_onboarding ) {
			return false;
		}

		/**
		 * Display Onboarding if:
		 * it's a fresh install and there were no requests from the Hub before,
		 * after Reset Settings.
		 *
		 * @var HUB
		 */
		$hub_class = wd_di()->get( HUB::class );
		$hub_class->set_onboarding_status( Onboard_Model::maybe_show_onboarding() );

		return $hub_class->get_onboarding_status() && ! defender_is_wp_cli();
	}

	/**
	 * Initialize the common modules of the application.
	 *
	 * @return void
	 */
	private function init_modules_common(): void {
		// Init main ORM.
		Array_Cache::set( 'orm', new Mapper() );

		// New setup wizard is rendered directly inside Dashboard React UI.
		wd_di()->get( Setup_Wizard::class );
		wd_di()->get( \WP_Defender\Controller\Activity_Log::class );
		wd_di()->get( Dashboard::class );
		wd_di()->get( Scan::class );
		wd_di()->get( Security_Tweaks::class );
		wd_di()->get( Audit_Logging::class );
		wd_di()->get( Firewall_Controller::class );
		wd_di()->get( Login_Access::class );
		// Initialize Mask Login globally so runtime protections hook into wp-login/wp-admin requests.
		wd_di()->get( Mask_Login::class );
		wd_di()->get( WAF::class );
		wd_di()->get( Two_Factor::class );
		wd_di()->get( Mask_Login::class );
		wd_di()->get( Captcha::class );
		wd_di()->get( Notification::class );
		wd_di()->get( Recipients::class );
		wd_di()->get( Main_Setting::class );
		wd_di()->get( Blocklist_Monitor::class );
		wd_di()->get( Password_Protection::class );
		wd_di()->get( Password_Reset::class );
		wd_di()->get( Webauthn::class );
		wd_di()->get( Hub_Connector_Controller::class );
		wd_di()->get( Strong_Password::class );
		wd_di()->get( Session_Protection::class );
		wd_di()->get( Quarantine::class );
		wd_di()->get( Data_Tracking::class );
		if ( defender_is_wp_org_version() ) {
			wd_di()->get( Rate_Controller::class );
		}

		if ( is_multisite() ) {
			wd_di()->get( Network_Cron_Manager::class );
		}
	}

	/**
	 * Adds a specific class to the body tag if the current page is a Defender page.
	 *
	 * @param  string $classes  The existing body classes.
	 *
	 * @return string The modified body classes.
	 */
	public function add_sui_to_body( $classes ) {
		if ( ! is_defender_page() ) {
			return $classes;
		}
		$classes .= sprintf( ' sui-%s ', DEFENDER_SUI );

		return $classes;
	}

	/**
	 * Registers the necessary styles for the plugin.
	 *
	 * @return void
	 */
	private function register_styles(): void {
		wp_enqueue_style( 'defender-menu', WP_DEFENDER_BASE_URL . 'assets/css/defender-icon.css', array(), DEFENDER_VERSION );
		wp_add_inline_style(
			'defender-menu',
			'#toplevel_page_wp-defender .wd-issue-indicator-sidebar {
				position: relative;
				background-color: transparent !important;
				width: 8px;
				min-width: unset;
				padding: 0;
				margin-left: 4px;
			}
			#toplevel_page_wp-defender .wd-issue-indicator-sidebar::after {
				content: "";
				position: absolute;
				width: 8px;
				height: 8px;
				top: 50%;
				left: 50%;
				transform: translate(-50%, -50%);
				border-radius: 50%;
				background: #d63638;
			}'
		);

		$css_files = array(
			'defender'     => WP_DEFENDER_BASE_URL . 'assets/css/styles.css',
			'def-sui'      => WP_DEFENDER_BASE_URL . 'assets/css/shared-ui.css',
			'def-admin'    => WP_DEFENDER_BASE_URL . 'assets/css/admin.css',
			'def-showcase' => WP_DEFENDER_BASE_URL . 'assets/css/showcase.css',
		);

		foreach ( $css_files as $slug => $file ) {
			wp_register_style( $slug, $file, array(), DEFENDER_VERSION );
		}
	}

	/**
	 * Registers the necessary scripts for the plugin.
	 *
	 * @return void
	 */
	private function register_scripts(): void {
		$base_url     = WP_DEFENDER_BASE_URL;
		$dependencies = array( 'def-vue', 'def-manifest', 'def-core-ui', 'defender', 'wp-i18n' );
		$js_files     = array(
			'wpmudev-sui'             => array(
				$base_url . 'assets/js/shared-ui.js',
			),
			'defender'                => array(
				$base_url . 'assets/js/scripts.js',
			),
			'def-deactivation-survey' => array(
				$base_url . 'assets/js/deactivation-survey.js',
				array( 'clipboard', 'wpmudev-sui' ),
			),
			'def-admin'               => array(
				$base_url . 'assets/js/admin.js',
				array( 'def-deactivation-survey' ),
			),
			'def-vue'                 => array(
				$base_url . 'assets/js/vendor.js',
			),
			'def-manifest'            => array(
				$base_url . 'assets/js/manifest.js',
			),
			'def-core-ui'             => array(
				$base_url . 'assets/js/core-ui.js',
				array( 'def-vue', 'def-manifest' ),
			),
			// React files.
			'def-showcase'            => array(
				$base_url . 'assets/js/showcase.js',
				$dependencies,
			),
			'def-setup-wizard'        => array(
				$base_url . 'assets/js/setup-wizard.js',
				$dependencies,
			),
		);

		foreach ( $js_files as $slug => $file ) {
			if ( isset( $file[1] ) ) {
				// This ensures that when JavaScript file changes,
				// browsers will load the new version instead of
				// serving a cached old version.
				$file_path    = str_replace( $base_url, WP_DEFENDER_DIR, $file[0] );
				$file_version = file_exists( $file_path ) ? filemtime( $file_path ) : DEFENDER_VERSION;
				wp_register_script( $slug, $file[0], $file[1], $file_version, true );
				wp_set_script_translations( $slug, 'defender-security' );
			} else {
				wp_register_script( $slug, $file[0], array( 'jquery' ), DEFENDER_VERSION, true );
			}
		}
	}

	/**
	 * Localizes the script by adding necessary data to the 'defender' object.
	 *
	 * @return void
	 */
	private function localize_script(): void {
		$wpmu_dev = new WPMUDEV();
		global $wp_defender_central;

		$misc          = array();
		$data_tracking = wd_di()->get( Data_Tracking::class );
		$is_tracking   = $data_tracking->show_tracking_modal();
		if ( $is_tracking ) {
			$misc = $data_tracking->get_tracking_modal();
		}
		$misc['high_contrast'] = defender_high_contrast();
		$is_wp_org             = defender_is_wp_org_version();
		if ( $is_wp_org ) {
			$misc['rating'] = array();
			$rate_service   = Rate_Component::is_achievement_displayed();
			if ( $rate_service['is_displayed'] ) {
				$misc['rating']         = wd_di()->get( Rate_Controller::class )->data_frontend();
				$misc['rating']['text'] = Rate_Component::get_notice_by_slug( $rate_service['slug'] );
			}

			$misc['rating']['is_displayed'] = $rate_service['is_displayed'];
			$misc['rating']['type']         = $rate_service['slug'];
		} else {
			$misc['rating']['is_displayed'] = false;
		}

		wp_localize_script(
			'def-vue',
			'defender',
			array(
				'whitelabel'                  => defender_white_label_status(),
				'misc'                        => $misc,
				'home_url'                    => network_home_url(),
				'site_url'                    => network_site_url(),
				'admin_url'                   => network_admin_url(),
				'defender_url'                => WP_DEFENDER_BASE_URL,
				// There might be Pro version but without pro features, for example when the membership expires.
				'is_free'                     => $wpmu_dev->is_pro() ? 0 : 1,
				// Strictly Free version.
				'is_wp_org'                   => $is_wp_org ? 1 : 0,
				'is_membership'               => true,
				'is_whitelabel'               => $wpmu_dev->is_whitelabel_enabled() ? 'enabled' : 'disabled',
				'wpmu_dev_url_action'         => $wpmu_dev->hide_wpmu_dev_urls() ? 'hide' : 'show',
				'opcache_save_comments'       => $wp_defender_central->is_opcache_save_comments_disabled() ? 'disabled' : 'enabled',
				'opcache_message'             => $wp_defender_central->display_opcache_message(),
				'wpmudev_url'                 => WP_DEFENDER_DOCS_LINK,
				'wpmudev_support_ticket_text' => defender_support_ticket_text(),
				'wpmudev_api_base_url'        => $wpmu_dev->get_api_base_url(),
				'upgrade_title'               => esc_html__( 'UPGRADE TO PRO', 'defender-security' ),
				'tracking_modal'              => $is_tracking ? 'show' : 'hide',
				'hosted'                      => $wpmu_dev->is_wpmu_hosting(),
				'file_upload_nonce'           => wp_create_nonce( 'defender_file_upload' ),
				'wpmudev_hub_link'            => 'https://wpmudev.com/hub2/',
			)
		);

		wp_localize_script( 'defender', 'defenderGetText', defender_gettext_translations() );

		wp_localize_script(
			'def-deactivation-survey',
			'defender',
			array(
				'usage_tracking' => wd_di()->get( \WP_Defender\Model\Setting\Main_Setting::class )->usage_tracking,
				'admin_url'      => admin_url( 'admin-ajax.php' ),
				'nonce'          => wp_create_nonce( 'defender_deactivation_survey_modal' ),
			)
		);
	}

	/**
	 * Register all core assets.
	 */
	public function register_assets(): void {
		$this->register_styles();
		$this->register_scripts();
		$this->localize_script();

		do_action( 'defender_enqueue_assets' );
	}

	/**
	 * Trigger mandatory actions on activation.
	 */
	private function on_activation(): void {
		update_site_option( Data_Tracking::TRACKING_SLUG, true );

		add_action(
			'admin_init',
			function () {
				$security_tweaks = wd_di()->get( Security_Tweaks::class );
				$security_tweaks->get_security_key()->cron_schedule();
			}
		);
	}

	/**
	 * Returns the cron schedules.
	 *
	 * @param  array $schedules  The existing cron schedules.
	 *
	 * @return array The updated cron schedules.
	 */
	public function cron_schedules( array $schedules ) {
		return defender_cron_schedules( $schedules );
	}

	/**
	 * Serves script translations from the single MO file our in-site translation
	 * tools (e.g. WPMU DEV Hub's translation editor) produce, since those only
	 * generate one MO/PO file per plugin rather than the per-script JSON files
	 * `wp_set_script_translations()` normally expects.
	 *
	 * @param string|false $translations Translations as JSON, false if there are none.
	 * @param string|false $file         Path to the translation file to load, false if there isn't one.
	 * @param string       $handle       Name of the script to register a translation domain to.
	 * @param string       $domain       The text domain.
	 *
	 * @return string|false
	 */
	public function provide_script_translations( $translations, $file, $handle, $domain ) {
		if ( 'defender-security' !== $domain ) {
			return $translations;
		}

		static $served      = false;
		static $cached_json = null;

		if ( $served ) {
			return wp_json_encode(
				array(
					'locale_data' => array(
						'defender-security' => array(
							'' => array(
								'domain' => 'defender-security',
							),
						),
					),
				)
			);
		}

		if ( null !== $cached_json ) {
			return $cached_json;
		}

		$locale  = is_admin() ? get_user_locale() : get_locale();
		$mo_file = WP_LANG_DIR . "/plugins/{$domain}-{$locale}.mo";

		if ( ! file_exists( $mo_file ) ) {
			return $translations;
		}

		$mo = new \MO();
		if ( ! $mo->import_from_file( $mo_file ) ) {
			return $translations;
		}

		$locale_data = array(
			'' => array(
				'domain' => $domain,
				'lang'   => $locale,
			),
		);

		if ( ! empty( $mo->headers['Plural-Forms'] ) ) {
			$locale_data['']['plural-forms'] = $mo->headers['Plural-Forms'];
		}

		foreach ( $mo->entries as $msgid => $entry ) {
			$locale_data[ $msgid ] = $entry->translations;
		}

		$cached_json = wp_json_encode(
			array(
				'locale_data' => array(
					$domain => $locale_data,
				),
			)
		);

		$served = true;

		return $cached_json;
	}

	/**
	 * Initialize the modules and register the plugin routes. Also include the admin class, adds WP-CLI commands.
	 *
	 * @return void
	 */
	public function includes(): void {
		// Initialize modules.
		add_action(
			'after_setup_theme',
			function () {
				add_filter( 'cron_schedules', array( $this, 'cron_schedules' ) );
				if ( method_exists( $this, 'init_modules' ) ) {
					$this->init_modules();
				}
			}
		);
		// Register routes.
		add_action(
			'init',
			function () {
				require_once WP_DEFENDER_DIR . 'src/routes.php';
			},
			9
		);
		// Serve script translations from the single MO file our in-site translation tools produce.
		add_filter( 'pre_load_script_translations', array( $this, 'provide_script_translations' ), 10, 4 );
		// Register the Hub Connector early to handle the auth callback during the admin init hook.
		add_action( 'plugins_loaded', array( wd_di()->get( Hub_Connector::class ), 'init' ) );
		// Register the Cross-Sell module.
		// add_action( 'init', array( wd_di()->get( \WP_Defender\Component\Cross_Sell::class ), 'init' ), 9 );
		// Include admin class. Don't use is_admin().
		add_action( 'admin_init', array( ( new Admin() ), 'init' ) );
		// Initialize deactivation survey.
		add_action( 'admin_enqueue_scripts', array( ( new Admin() ), 'init_deactivation_survey' ) );
		// Add WP-CLI commands.
		if ( defender_is_wp_cli() ) {
			WP_CLI::add_command( 'defender', Cli::class );
		}
		// Rotational logger initialization.
		add_action( 'init', array( ( new Rotation_Logger() ), 'init' ), 99 );
		// Handle plugin deactivation.
		add_action( 'deactivated_plugin', array( ( new HUB() ), 'intercept_deactivate' ) );
	}

	/**
	 * Sets a one-time redirect flag after plugin activation.
	 *
	 * The actual redirect is executed later during `admin_init` to avoid exiting activation flow prematurely.
	 *
	 * @return void
	 */
	public function set_activation_redirect_flag(): void {
		if ( defender_is_wp_cli() ) {
			return;
		}

		update_site_option( 'wp_defender_activation_redirect', 1 );
	}

	/**
	 * Redirects once to the Defender dashboard after activation.
	 *
	 * Safety checks:
	 * - Redirect only when the activation flag exists.
	 * - Skip AJAX, cron and WP-CLI contexts.
	 * - Redirect only for users with proper admin capability.
	 *
	 * @return void
	 */
	public function maybe_redirect_after_activation(): void {
		if ( ! (bool) get_site_option( 'wp_defender_activation_redirect' ) ) {
			return;
		}

		delete_site_option( 'wp_defender_activation_redirect' );

		if ( wp_doing_ajax() || wp_doing_cron() || defender_is_wp_cli() ) {
			return;
		}

		$cap = is_multisite() ? 'manage_network_options' : 'manage_options';
		if ( ! current_user_can( $cap ) ) {
			return;
		}

		$url = add_query_arg(
			array(
				'page' => 'wp-defender',
			),
			is_multisite() ? network_admin_url( 'admin.php' ) : admin_url( 'admin.php' )
		);

		wp_safe_redirect( $url );
		exit;
	}
}
