<?php
/**
 * Handles the main settings.
 *
 * @package WP_Defender\Controller
 */

namespace WP_Defender\Controller;

use Countable;
use WP_Defender\Event;
use Calotes\Component\Request;
use Calotes\Component\Response;
use WP_Defender\Behavior\WPMUDEV;
use WP_Defender\Controller\Notification;
use WP_Defender\Component\Backup_Settings;
use WP_Defender\Component\Config\Config_Adapter;
use WP_Defender\Component\Config\Local_Config_Store;
use WP_Defender\Component\Network_Cron_Manager;
use WP_Defender\Traits\Defender_Dashboard_Client;
use WP_Defender\Component\Config\Config_Hub_Helper;
use WP_Defender\Model\Setting\Main_Setting as Model_Main_Setting;
use WP_Filesystem_Base;
use WP_Defender\Controller\Security_Headers;
use WP_Defender\Controller\Firewall;

/**
 * Methods for handling main settings.
 */
class Main_Setting extends Event {
	use Defender_Dashboard_Client;

	/**
	 * The slug identifier for this controller.
	 *
	 * @var string
	 */
	public $slug = 'wdf-setting';

	/**
	 * The model for handling the data.
	 *
	 * @var Model_Main_Setting
	 */
	public $model;

	/**
	 * Service for handling logic.
	 *
	 * @var Backup_Settings
	 */
	protected $service;

	/**
	 * Service for handling WPMUDEV.
	 *
	 * @var WPMUDEV
	 */
	protected $wpmudev;

	/**
	 * Local configs store.
	 *
	 * @var Local_Config_Store
	 */
	protected $local_store;

	/**
	 * The intention/nonce action of the current request.
	 *
	 * @since 4.0.0
	 * @var string
	 */
	protected $intention = '';

	/**
	 * Initializes the model and service, registers routes, and sets up scheduled events if the model is active.
	 */
	public function __construct() {
		$this->register_page(
			esc_html__( 'Settings', 'defender-security' ),
			$this->slug,
			array( $this, 'main_view' ),
			$this->parent_slug
		);

		// Internal cache.
		$this->model       = new Model_Main_Setting();
		$this->service     = wd_di()->get( Backup_Settings::class );
		$this->wpmudev     = wd_di()->get( WPMUDEV::class );
		$this->local_store = new Local_Config_Store( $this->service );
		add_action( 'defender_enqueue_assets', array( $this, 'enqueue_assets' ) );
		$this->register_routes();

		/**
		 * Add cron schedule to clean out outdated logs.
		 *
		 * @var Network_Cron_Manager $network_cron_manager
		 */
		$network_cron_manager = wd_di()->get( Network_Cron_Manager::class );
		$network_cron_manager->register_callback(
			'wp_defender_clear_logs',
			array( $this, 'clear_logs' ),
			DAY_IN_SECONDS,
			time() + HOUR_IN_SECONDS
		);
		add_action( 'wd_settings_update', array( $this, 'intercept_settings_update' ), 10, 2 );
		// Initialize Security Headers so its routes are registered on every request,
		// including AJAX calls from the Security Policies tab.
		wd_di()->get( Security_Headers::class );
		// Initialize Firewall so its routes (sync_ip_header, save_settings, empty_logs, etc.)
		// are registered on AJAX requests originating from the Tools tab.
		// Guarded to AJAX only to prevent a duplicate admin menu entry on normal page loads.
		if ( wp_doing_ajax() ) {
			wd_di()->get( Firewall::class );
		}
	}

	/**
	 * Check actual config data.
	 *
	 * @return Response
	 * @defender_route
	 */
	public function check_configs(): Response {
		Config_Hub_Helper::clear_config_transient();

		return new Response( true, array() );
	}

	/**
	 * Safe way to get cached model.
	 *
	 * @return Model_Main_Setting
	 */
	private function get_model() {
		if ( is_object( $this->model ) ) {
			return $this->model;
		}

		return wd_di()->get( Model_Main_Setting::class );
	}

	/**
	 * Enqueues scripts and styles for this page.
	 * Only enqueues assets if the page is active.
	 */
	public function enqueue_assets() {
		if ( ! $this->is_page_active() ) {
			return;
		}

		$handle = 'defender-ui-settings';
		wp_enqueue_script(
			$handle,
			WP_DEFENDER_BASE_URL . 'assets/js/settings-ui.js',
			array( 'def-vue', 'def-manifest', 'def-core-ui', 'defender', 'wp-i18n' ),
			DEFENDER_VERSION,
			true
		);
		wp_set_script_translations( $handle, 'wpdef' );

		$data   = $this->data_frontend();
		$routes = $data['routes'] ?? array();
		$nonces = $data['nonces'] ?? array();
		unset( $data['routes'], $data['nonces'] );

		// Include Security Headers data for the Security Policies tab.
		$sh_controller = wd_di()->get( Security_Headers::class );
		$sh_data       = $sh_controller->data_frontend();
		$sh_routes     = $sh_data['routes'] ?? array();
		$sh_nonces     = $sh_data['nonces'] ?? array();
		unset( $sh_data['routes'], $sh_data['nonces'] );

		// Namespace security headers routes/nonces to avoid key collisions.
		foreach ( $sh_routes as $key => $route ) {
			$routes[ 'security_headers_' . $key ] = $route;
		}
		foreach ( $sh_nonces as $key => $nonce ) {
			$nonces[ 'security_headers_' . $key ] = $nonce;
		}

		// Include Module data for the Tools tab.
		$scan_controller              = wd_di()->get( Scan::class );
		$firewall_controller          = wd_di()->get( Firewall::class );
		$blocklist_monitor_controller = wd_di()->get( Blocklist_Monitor::class );
		$notification_controller      = wd_di()->get( Notification::class );
		$recipients_controller        = wd_di()->get( Recipients::class );
		wp_localize_script(
			$handle,
			'defenderUIData',
			array_merge(
				$this->get_shared_data(),
				// Specific data.
				array(
					'settings'          => array_merge( $data, array( 'security_headers' => $sh_data ) ),
					'scan'              => $scan_controller->data_frontend(),
					'firewall'          => $firewall_controller->data_frontend(),
					'blocklist_monitor' => $blocklist_monitor_controller->data_frontend(),
					'notification'      => $notification_controller->data_frontend(),
					'recipients'        => $recipients_controller->data_frontend(),
					'routes'            => $routes,
					'nonces'            => $nonces,
				)
			)
		);

		wp_enqueue_style(
			$handle,
			WP_DEFENDER_BASE_URL . 'assets/css/showcase.css',
			array(),
			DEFENDER_VERSION
		);

		$this->enqueue_main_assets();
	}

	/**
	 * Render the root element for frontend.
	 *
	 * @return void
	 */
	public function main_view(): void {
		$this->render( 'main' );
	}

	/**
	 * Save settings.
	 *
	 * @param  Request $request  The request object containing new settings data.
	 *
	 * @return Response
	 * @defender_route
	 */
	public function save_settings( Request $request ) {
		$model = $this->get_model();
		$data  = $request->get_data();

		$model->import( $data );
		if ( $model->validate() ) {
			$this->set_intention( 'Settings' );
			$model->save();
			Config_Hub_Helper::set_clear_active_flag();

			return new Response(
				true,
				array(
					'message'    => esc_html__( 'Your settings have been updated.', 'defender-security' ),
					'auto_close' => true,
				)
			);
		}

		return new Response(
			false,
			array(
				'message' => $model->get_formatted_errors(),
			)
		);
	}

	/**
	 * Reset settings.
	 *
	 * @return Response
	 * @defender_route
	 */
	public function reset_settings(): Response {
		$preserve_settings = 'preserve' === $this->get_model()->uninstall_settings;

		wd_di()->get( Login_Access::class )->remove_settings();
		wd_di()->get( Blocklist_Monitor::class )->remove_settings();
		wd_di()->get( Dashboard::class )->remove_settings();
		wd_di()->get( Security_Tweaks::class )->remove_settings();
		wd_di()->get( Scan::class )->remove_settings();
		// Parent and submodules.
		wd_di()->get( Firewall::class )->remove_settings();

		wd_di()->get( Mask_Login::class )->remove_settings();
		wd_di()->get( Notification::class )->remove_settings();
		wd_di()->get( Two_Factor::class )->remove_settings();
		wd_di()->get( Blocklist_Monitor::class )->remove_settings();
		wd_di()->get( Data_Tracking::class )->remove_settings();
		wd_di()->get( \WP_Defender\Controller\Setup_Wizard::class )->remove_settings();
		wd_di()->get( \WP_Defender\Controller\Activity_Log::class )->remove_settings();

		$this->set_intention( 'Data Reset' );
		// Track first until settings are removed.
		$this->track_opt( false );
		$this->remove_settings();
		if ( ! $preserve_settings ) {
			update_site_option( Scan::FIRST_SCAN_STARTED, '0' );
		}
		// Indicate that it is not a new installation.
		defender_no_fresh_install();

		return new Response(
			true,
			array(
				'message'  => esc_html__( 'Your settings have been reset.', 'defender-security' ),
				'redirect' => network_admin_url( 'admin.php?page=wp-defender' ),
				'interval' => 1,
			)
		);
	}

	/**
	 * Tracks the settings toggle.
	 *
	 * @param  bool $active  The status of the toggle.
	 *
	 * @return void
	 */
	public function track_opt( $active ) {
		$model = $this->get_model();
		// Track only if the Data tracking option was enabled before changes.
		if ( $model->usage_tracking ) {
			$from = $this->get_triggered_location();
			$this->track_opt_toggle( $active, $from );
		}
	}

	/**
	 * Removes settings for all submodules.
	 */
	public function remove_settings(): void {
		wd_di()->get( Model_Main_Setting::class )->delete();
	}

	/**
	 * Delete all the data & the cache.
	 */
	public function remove_data() {
	}

	/**
	 * Provides data for the frontend.
	 *
	 * @return array An array of data for the frontend.
	 */
	public function data_frontend(): array {
		$model = $this->get_model();

		$this->service->maybe_create_default_config();
		$configs = $this->local_store->get_frontend_configs();

		$link           = $this->wpmudev->is_member()
			? 'https://wpmudev.com/translate/projects/wpdef/'
			: 'https://translate.wordpress.org/projects/wp-plugins/defender-security/';
		$can_whitelabel = wd_di()->get( \WP_Defender\Integrations\Dashboard_Whitelabel::class )->can_whitelabel();

		return array_merge(
			array(
				'general'       => array(
					'translate'           => $model->translate,
					'show_usage_tracking' => $this->wpmudev->is_wpmu_dev_admin() || ! $can_whitelabel,
					'usage_tracking'      => $model->usage_tracking,
					'translation_link'    => $link,
				),
				'data_settings' => array(
					'uninstall_settings'   => $model->uninstall_settings,
					'uninstall_data'       => $model->uninstall_data,
					'uninstall_quarantine' => $model->uninstall_quarantine,
				),
				'accessibility' => array(
					'high_contrast_mode' => $model->high_contrast_mode,
				),
				'misc'          => array(
					'setting_url'  => network_admin_url( is_multisite() ? 'settings.php' : 'options-general.php' ),
					'privacy_link' => Model_Main_Setting::PRIVACY_LINK,
				),
				'configs'       => $configs,
				'hub_connector' => wd_di()->get( Hub_Connector::class )->data_frontend(),
				'antibot'       => wd_di()->get( Antibot_Global_Firewall::class )->data_frontend(),
			),
			$this->dump_routes_and_nonces()
		);
	}

	/**
	 * Converts the current object state to an array.
	 *
	 * @return array The array representation of the object.
	 */
	public function to_array(): array {
		return array();
	}

	/**
	 * Imports data into the model.
	 *
	 * @param  array $data  Data to be imported into the model.
	 */
	public function import_data( array $data ) {
		$model = $this->get_model();

		$model->import( $data );
		if ( $model->validate() ) {
			$model->save();
		}
	}

	/**
	 * Validates the importer data.
	 * This function checks if the importer data is valid by verifying its configuration data and comparing it with the
	 * sample data.
	 *
	 * @param  array $importer  The importer data to be validated.
	 *
	 * @return bool Returns true if the importer data is valid, false otherwise.
	 */
	private function validate_importer( $importer ): bool {
		return $this->service->verify_config_data( $importer );
	}

	/**
	 * Import config.
	 *
	 * @return Response
	 * @defender_route
	 */
	public function import_config(): Response {
		global $wp_filesystem;
		// Initialize the WP filesystem, no more using 'file-put-contents' function.
		if ( ! $wp_filesystem instanceof WP_Filesystem_Base ) {
			require_once ABSPATH . '/wp-admin/includes/file.php';
			WP_Filesystem();
		}
		$file     = defender_get_data_from_request( 'file', 'f' );
		$tmp      = $file['tmp_name'];
		$content  = $wp_filesystem->get_contents( $tmp );
		$importer = json_decode( $content, true );
		if ( ! is_array( $importer ) ) {
			return new Response(
				false,
				array(
					'message' => esc_html__( 'The file is corrupted.', 'defender-security' ),
				)
			);
		}


		if ( ! $this->validate_importer( $importer ) ) {
			return new Response(
				false,
				array(
					'message' => esc_html__(
						'An error occurred while importing the file. Please check your file or upload another file.',
						'defender-security'
					),
				)
			);
		}

		// Do not use wp_strip_all_tags() to prevent XSS attack.
		$name = sanitize_text_field( $importer['name'] );
		$this->local_store->add_imported( $importer );

		// Detect Pro-only modules that were skipped during validation
		// to inform Free users that some settings were not imported.
		$response_data = array(
			'message' => sprintf(
				/* translators: %s: Config name. */
				esc_html__(
					'%s config has been uploaded successfully – you can now apply it to this site.',
					'defender-security'
				),
				'<strong>' . $name . '</strong>'
			),
			'configs' => $this->local_store->get_frontend_configs(),
		);

		if ( ! $this->wpmudev->is_pro() ) {
			$sample = $this->service->gather_data();
			$pro_modules = array();

			foreach ( $importer['configs'] as $slug => $module ) {
				// Modules present in the imported config but NOT in Free's sample data are Pro-only.
				if ( ! isset( $sample[ $slug ] ) ) {
					$pro_modules[] = $slug;
				}
			}

			if ( ! empty( $pro_modules ) ) {
				$module_names = array_map(
					function ( $slug ) {
						$names = array(
							'audit'             => esc_html__( 'Audit Logs', 'defender-security' ),
							'waf'               => esc_html__( 'Web Application Firewall (WAF)', 'defender-security' ),
							'blocklist_monitor' => esc_html__( 'Blocklist Monitor', 'defender-security' ),
							'pwned_passwords'   => esc_html__( 'Pwned Passwords', 'defender-security' ),
							'force_strong_password' => esc_html__( 'Strong Passwords', 'defender-security' ),
							'session_protection' => esc_html__( 'Session Protection', 'defender-security' ),
							'two_factor'        => esc_html__( 'Two-Factor Authentication', 'defender-security' ),
							'mask_login'        => esc_html__( 'Hide Login URL', 'defender-security' ),
							'security_headers'  => esc_html__( 'Security Policies', 'defender-security' ),
						);

						return $names[ $slug ] ?? $slug;
					},
					$pro_modules
				);

				$response_data['message'] .= ' ' . sprintf(
					/* translators: %s: Comma-separated list of Pro-only feature names. */
					esc_html__(
						'This config included features not available in the Free version: %s. Only the available settings were imported.',
						'defender-security'
					),
					implode( ', ', $module_names )
				);
			}
		}

		return new Response(
			true,
			$response_data
		);
	}

	/**
	 * Create config.
	 *
	 * @param  Request $request  The request object containing new config data.
	 *
	 * @return Response
	 * @defender_route
	 */
	public function new_config( Request $request ): Response {
		$data = $request->get_data();
		$name = trim( $data['name'] );
		if ( '' === $name ) {
			return new Response(
				false,
				array(
					'message' => esc_html__( 'Invalid config name', 'defender-security' ),
				)
			);
		}
		$name = sanitize_text_field( $name );
		$desc = '';
		if ( isset( $data['desc'] ) && is_string( $data['desc'] ) && '' !== trim( $data['desc'] ) ) {
			$desc = wp_kses_post( $data['desc'] );
		} elseif ( isset( $data['description'] ) && is_string( $data['description'] ) && '' !== trim( $data['description'] ) ) {
			$desc = wp_kses_post( $data['description'] );
		}
		$note_added_time = isset( $data['note_added_time'] ) && is_scalar( $data['note_added_time'] )
			? sanitize_text_field( (string) $data['note_added_time'] )
			: '';
		$this->local_store->create_from_current( $name, $desc, $note_added_time );

		return new Response(
			true,
			array(
				'message' => sprintf(
					/* translators: %s: Config name. */
					esc_html__( '%s config saved successfully.', 'defender-security' ),
					'<strong>' . $name . '</strong>'
				),
				'configs' => $this->local_store->get_frontend_configs(),
			)
		);
	}

	/**
	 * Download config
	 *
	 * @return Response|void
	 * @defender_route
	 */
	public function download_config() {
		$key = defender_get_data_from_request( 'key', 'g' );
		if ( ! is_string( $key ) || '' === trim( $key ) ) {
			return new Response(
				false,
				array(
					'message' => esc_html__( 'Invalid config', 'defender-security' ),
				)
			);
		}

		$config = $this->local_store->get_full_for_key( $key );
		if ( null === $config ) {
			$config = $this->prepare_config_for_download( $key );
		}
		if ( null === $config ) {
			return new Response(
				false,
				array(
					'message' => esc_html__( 'Invalid config', 'defender-security' ),
				)
			);
		}

		$filename = 'wp-defender-config-' . sanitize_file_name( $config['name'] ) . '.json';
		header( 'Content-Disposition: attachment; filename="' . $filename . '"' );
		echo wp_json_encode( $config, JSON_PRETTY_PRINT );
		exit();
	}

	/**
	 * Download multiple configs as a zip file.
	 *
	 * @return Response|void
	 * @defender_route
	 */
	public function download_configs_zip() {
		$keys_raw = defender_get_data_from_request( 'keys', 'g' );
		if ( ! is_string( $keys_raw ) || '' === trim( $keys_raw ) ) {
			return new Response(
				false,
				array(
					'message' => esc_html__( 'Invalid config list', 'defender-security' ),
				)
			);
		}

		$decoded = json_decode( wp_unslash( $keys_raw ), true );
		$keys    = is_array( $decoded ) ? $decoded : explode( ',', $keys_raw );
		$keys    = array_values(
			array_filter(
				array_map(
					static function ( $key ) {
						return is_string( $key ) ? trim( $key ) : '';
					},
					$keys
				),
				'boolval'
			)
		);

		if ( array() === $keys ) {
			return new Response(
				false,
				array(
					'message' => esc_html__( 'Invalid config list', 'defender-security' ),
				)
			);
		}

		if ( ! class_exists( 'ZipArchive' ) ) {
			return new Response(
				false,
				array(
					'message' => esc_html__( 'Zip archive is not supported on this server.', 'defender-security' ),
				)
			);
		}

		$tmp_zip_path = wp_tempnam( 'wp-defender-configs-' . time() . '.zip' );
		if ( false === $tmp_zip_path ) {
			return new Response(
				false,
				array(
					'message' => esc_html__( 'Could not prepare zip file.', 'defender-security' ),
				)
			);
		}

		$cleanup_tmp_zip = static function () use ( $tmp_zip_path ) {
			if ( file_exists( $tmp_zip_path ) ) {
				wp_delete_file( $tmp_zip_path );
			}
		};

		$zip = new \ZipArchive();
		if ( true !== $zip->open( $tmp_zip_path, \ZipArchive::OVERWRITE ) ) {
			$cleanup_tmp_zip();

			return new Response(
				false,
				array(
					'message' => esc_html__( 'Could not create zip file.', 'defender-security' ),
				)
			);
		}

		$has_entries = false;

		foreach ( $keys as $key ) {
			$config = $this->local_store->get_full_for_key( $key );
			if ( null === $config ) {
				$config = $this->prepare_config_for_download( $key );
			}
			if ( null === $config ) {
				continue;
			}

			$file_name = $this->make_unique_zip_entry_name(
				'wp-defender-config-' . sanitize_file_name( $config['name'] ),
				$key,
				$zip
			);
			if ( false === $zip->addFromString( $file_name, wp_json_encode( $config, JSON_PRETTY_PRINT ) ) ) {
				$zip->close();
				$cleanup_tmp_zip();

				return new Response(
					false,
					array(
						'message' => esc_html__( 'Could not prepare zip file.', 'defender-security' ),
					)
				);
			}

			$has_entries = true;
		}

		$zip->close();

		if ( ! $has_entries ) {
			$cleanup_tmp_zip();

			return new Response(
				false,
				array(
					'message' => esc_html__( 'No valid configs found to export.', 'defender-security' ),
				)
			);
		}

		$download_name = 'wp-defender-configs-' . gmdate( 'Ymd-His' ) . '.zip';
		header( 'Content-Type: application/zip' );
		header( 'Content-Disposition: attachment; filename="' . $download_name . '"' );
		header( 'Content-Length: ' . filesize( $tmp_zip_path ) );
		readfile( $tmp_zip_path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_readfile
		$cleanup_tmp_zip();
		exit();
	}

	/**
	 * Apply config.
	 *
	 * @param  Request $request  The request object containing new config data.
	 *
	 * @return Response
	 * @defender_route
	 */
	public function apply_config( Request $request ) {
		$data = $request->get_data();
		$key  = trim( $data['key'] );
		if ( '' === $key ) {
			return new Response(
				false,
				array(
					'message' => esc_html__( 'Invalid config', 'defender-security' ),
				)
			);
		}

		$config = $this->local_store->get_full_for_key( $key );
		if ( null === $config ) {
			$config = get_site_option( $key );
		}
		if ( false === $config || null === $config ) {
			return new Response(
				false,
				array(
					'message' => esc_html__( 'Invalid config', 'defender-security' ),
				)
			);
		}
		// Return error message or bool value for auth action.
		$restore_result = $this->service->restore_data( $config['configs'], 'plugin' );
		if ( is_string( $restore_result ) ) {
			return $this->apply_config_recommendations_error_message();
		}

		$this->local_store->apply( $key );
		$this->service->make_config_active( $key );
		// Track.
		$this->track_feature(
			'def_config_applied',
			array(
				// The check is based on the fact that the Default config cannot be deleted.
				'Config Type' => isset( $config['is_removable'] ) && false === $config['is_removable'] ? 'Default' : 'Custom',
			)
		);

		$message = sprintf(
			/* translators: %s: Config name. */
			esc_html__(
				'%s config has been applied successfully.',
				'defender-security'
			),
			'<strong>' . $config['name'] . '</strong>'
		);
		$return = array();
		if ( $restore_result ) {
			$login_url           = wp_login_url();
			$settings_mask_login = new \WP_Defender\Model\Setting\Mask_Login();
			if ( $settings_mask_login->is_active() ) {
				$login_url = $settings_mask_login->get_new_login_url();
			}
			$message .= '<br/>' . sprintf(
				/* translators: %s: Login link. */
				esc_html__(
					'Due to currently applied security recommendations, you will now need to %s.',
					'defender-security'
				),
				'<a href="' . $login_url . '"><strong>' . esc_html__( 're-login', 'defender-security' ) . '</strong></a>'
			);
			$message .= '<br/>';
			$message .= esc_html__( 'This will auto reload now.', 'defender-security' );

			$return['reload'] = 3;
			$redirect         = rawurlencode( network_admin_url( 'admin.php?page=wdf-setting&view=configs' ) );
			if ( isset( $data['screen'] ) && 'dashboard' === $data['screen'] ) {
				$redirect = rawurlencode( network_admin_url( 'admin.php?page=wp-defender' ) );
			}
			$return['redirect'] = add_query_arg(
				'redirect_to',
				$redirect,
				$login_url
			);
			$return['interval'] = 2;
		}

		$return['message']    = $message;
		$return['auto_close'] = true;
		$return['configs']    = $this->local_store->get_frontend_configs();

		return new Response( true, $return );
	}

	/**
	 * Update config.
	 *
	 * @param  Request $request  The request object containing new config data.
	 *
	 * @return Response
	 * @defender_route
	 */
	public function update_config( Request $request ) {
		$data        = $request->get_data();
		$key         = trim( $data['key'] );
		$key         = $this->resolve_config_key( $key );
		$name        = trim( $data['name'] );
		$description = isset( $data['desc'] ) ? trim( (string) $data['desc'] ) : '';
		if ( '' === $description && isset( $data['description'] ) ) {
			$description = trim( (string) $data['description'] );
		}
		$note_added_time = isset( $data['note_added_time'] ) && is_scalar( $data['note_added_time'] )
			? sanitize_text_field( (string) $data['note_added_time'] )
			: null;
		if ( '' === $name || '' === $key ) {
			return new Response(
				false,
				array(
					'message' => esc_html__( 'Invalid config', 'defender-security' ),
				)
			);
		}

		$config = $this->local_store->get_one( $key );
		if ( null === $config ) {
			$config = get_site_option( $key );
		}
		if ( false === $config || null === $config ) {
			return new Response(
				false,
				array(
					'message' => esc_html__( 'Invalid config', 'defender-security' ),
				)
			);
		}

		$option_updated = $this->local_store->update_metadata( $key, $name, $description, $note_added_time );
		if ( ! $option_updated ) {
			$old_config            = $config;
			$config['name']        = sanitize_text_field( $name );
			$config['description'] = sanitize_textarea_field( $description );
			if ( null !== $note_added_time ) {
				$config['note_added_time'] = $note_added_time;
			}
			$option_updated = update_site_option( $key, $config );
		}

		if ( $option_updated ) {
			return new Response(
				true,
				array(
					'message'    => sprintf(
						/* translators: %s: Config name. */
						esc_html__( '%s config saved successfully.', 'defender-security' ),
						'<strong>' . $name . '</strong>'
					),
					'auto_close' => true,
					'configs'    => $this->local_store->get_frontend_configs(),
				)
			);
		} else {
			return new Response(
				false,
				array(
					'message' => esc_html__(
						'An error occurred while saving your config. Please try it again.',
						'defender-security'
					),
				)
			);
		}
	}

	/**
	 * Sync config metadata list.
	 *
	 * This method updates name/description/note timestamp for provided configs
	 * without changing config payload values.
	 *
	 * @param  Request $request  The request object containing configs metadata list.
	 *
	 * @return Response
	 * @defender_route
	 */
	public function sync_configs_metadata( Request $request ): Response {
		// Defense in depth: central routing already validates nonce and access.
		if ( ! $this->check_permission() ) {
			return new Response(
				false,
				array(
					'message' => esc_html__( 'You shall not pass.', 'defender-security' ),
				)
			);
		}

		$data = $request->get_data();
		if ( ! isset( $data['configs'] ) || ! is_array( $data['configs'] ) ) {
			return new Response(
				false,
				array(
					'message' => esc_html__( 'Invalid config list', 'defender-security' ),
				)
			);
		}

		$stored_configs = $this->local_store->get_all();
		foreach ( $data['configs'] as $item ) {
			if ( ! is_array( $item ) ) {
				return new Response(
					false,
					array(
						'message' => esc_html__( 'Invalid config list', 'defender-security' ),
					)
				);
			}

			$key = '';
			if ( isset( $item['key'] ) && is_string( $item['key'] ) ) {
				$key = trim( $item['key'] );
			} elseif ( isset( $item['id'] ) && is_string( $item['id'] ) ) {
				$key = trim( $item['id'] );
			}
			$key = $this->resolve_config_key( $key, $stored_configs );

			if (
				'' === $key ||
				0 !== strpos( $key, 'wp_defender_config' ) ||
				! isset( $stored_configs[ $key ] )
			) {
				return new Response(
					false,
					array(
						'message' => esc_html__( 'Invalid config list', 'defender-security' ),
					)
				);
			}

			$config = $this->local_store->get_one( $key );
			if ( null === $config ) {
				continue;
			}

			$name            = isset( $item['name'] ) ? (string) $item['name'] : null;
			$description     = null;
			$note_added_time = null;
			if ( isset( $item['description'] ) && is_string( $item['description'] ) ) {
				$description = $item['description'];
			} elseif ( isset( $item['desc'] ) && is_string( $item['desc'] ) ) {
				$description = $item['desc'];
			}
			if ( isset( $item['note_added_time'] ) && is_scalar( $item['note_added_time'] ) ) {
				$note_added_time = (string) $item['note_added_time'];
			}
			$this->local_store->update_metadata( $key, $name, $description, $note_added_time );
		}

		return new Response(
			true,
			array(
				'message' => esc_html__( 'Configs synced successfully.', 'defender-security' ),
				'configs' => $this->local_store->get_frontend_configs(),
			)
		);
	}

	/**
	 * Delete config.
	 *
	 * @param  Request $request  The request object containing config key.
	 *
	 * @return Response
	 * @defender_route
	 */
	public function delete_config( Request $request ) {
		$data = $request->get_data();
		$key  = trim( $data['key'] );
		$key  = $this->resolve_config_key( $key, $this->local_store->get_all() );
		if ( '' === $key ) {
			return new Response(
				false,
				array(
					'message' => esc_html__( 'Invalid config', 'defender-security' ),
				)
			);
		}

		$config = $this->local_store->get_one( $key );
		if ( null === $config ) {
			$config = get_site_option( $key );
		}
		if ( isset( $config['is_removable'] ) && false === (bool) $config['is_removable'] ) {
			return new Response(
				false,
				array(
					'message' => esc_html__( 'Config can\'t be removed', 'defender-security' ),
				)
			);
		}

		if ( $this->local_store->delete_one( $key ) ) {
			return new Response(
				true,
				array(
					'message'    => esc_html__( 'Config removed successfully.', 'defender-security' ),
					'auto_close' => true,
					'configs'    => $this->local_store->get_frontend_configs(),
				)
			);
		}

		if ( 0 === strpos( $key, 'wp_defender_config' ) ) {
			delete_site_option( $key );
			$this->service->remove_index( $key );
			$this->service->clear_keys();
			delete_site_transient( Config_Hub_Helper::CONFIGS_TRANSIENT_KEY );

			return new Response(
				true,
				array(
					'message'    => esc_html__( 'Config removed successfully.', 'defender-security' ),
					'auto_close' => true,
					'configs'    => $this->local_store->get_frontend_configs(),
				)
			);
		}

		return new Response(
			false,
			array(
				'message' => esc_html__( 'Invalid config', 'defender-security' ),
			)
		);
	}

	/**
	 * Syncs configs list by keeping only the provided config keys.
	 *
	 * This method is intentionally separate from `delete_config` for backward compatibility.
	 *
	 * @param  Request $request  The request object containing the list of configs to keep.
	 *
	 * @return Response
	 * @defender_route
	 */
	public function sync_configs_list( Request $request ): Response {
		// Defense in depth: central routing already enforces nonce and private access checks.
		if ( ! $this->check_permission() ) {
			return new Response(
				false,
				array(
					'message' => esc_html__( 'You shall not pass.', 'defender-security' ),
				)
			);
		}

		$data = $request->get_data();
		if ( ! isset( $data['configs'] ) || ! is_array( $data['configs'] ) ) {
			return new Response(
				false,
				array(
					'message' => esc_html__( 'Invalid config list', 'defender-security' ),
				)
			);
		}

		$stored_configs = $this->local_store->get_all();
		$keep_keys      = array();
		foreach ( $data['configs'] as $item ) {
			if ( ! is_array( $item ) ) {
				return new Response(
					false,
					array(
						'message' => esc_html__( 'Invalid config list', 'defender-security' ),
					)
				);
			}
			$key = '';
			if ( isset( $item['key'] ) && is_string( $item['key'] ) ) {
				$key = trim( $item['key'] );
			} elseif ( isset( $item['id'] ) && is_string( $item['id'] ) ) {
				$key = trim( $item['id'] );
			}

			if (
				'' === $key ||
				0 !== strpos( $key, 'wp_defender_config' ) ||
				! isset( $stored_configs[ $key ] )
			) {
				return new Response(
					false,
					array(
						'message' => esc_html__( 'Invalid config list', 'defender-security' ),
					)
				);
			}

			$keep_keys[ $key ] = true;
		}

		$this->local_store->sync_keep_list( array_keys( $keep_keys ) );

		return new Response(
			true,
			array(
				'message'    => esc_html__( 'Config list synced successfully.', 'defender-security' ),
				'auto_close' => true,
				'configs'    => $this->local_store->get_frontend_configs(),
			)
		);
	}

	/**
	 * Exports strings.
	 *
	 * @return array An array of strings.
	 */
	public function export_strings(): array {
		return array();
	}

	/**
	 * Resolves a config key from an incoming identifier.
	 *
	 * Supports direct option keys and numeric Hub IDs.
	 *
	 * @param  string     $incoming_key    Incoming key/id.
	 * @param  array|null $stored_configs  Optional preloaded configs map.
	 *
	 * @return string
	 */
	private function resolve_config_key( string $incoming_key, ?array $stored_configs = null ): string {
		$key = trim( $incoming_key );
		if ( '' === $key ) {
			return '';
		}

		if ( 0 === strpos( $key, 'wp_defender_config' ) ) {
			return $key;
		}

		$configs = is_array( $stored_configs ) ? $stored_configs : $this->local_store->get_all();
		foreach ( $configs as $config_key => $config ) {
			if ( ! is_array( $config ) || ! isset( $config['hub_id'] ) ) {
				continue;
			}
			if ( (string) $config['hub_id'] === $key ) {
				return (string) $config_key;
			}
		}

		return $key;
	}

	/**
	 * Generates an error message for when there is an issue applying some tweaks from the Recommendations tab.
	 *
	 * @return Response The response object containing the error message and fresh frontend configurations.
	 */
	private function apply_config_recommendations_error_message(): Response {
		$message = sprintf(
			/* translators: 1: Recommendations tab, 2: wp-config.php file, 3: Documentation. */
			esc_html__(
				'There was an issue with applying some of the tweaks from the %1$s tab because we cannot make changes to your %2$s file. Please see our %3$s to apply the changes manually.',
				'defender-security'
			),
			'<strong>' . esc_html__( 'Recommendations', 'defender-security' ) . '</strong>',
			'<strong>' . esc_html__( 'wp-config.php', 'defender-security' ) . '</strong>',
			'<a href="' . WP_DEFENDER_DOCS_LINK . '#manually-applying-recommendations" target="_blank">' . esc_html__( 'documentation', 'defender-security' ) . '</a>'
		);

		return new Response(
			false,
			array(
				'message' => $message,
				'configs' => $this->local_store->get_frontend_configs(),
			)
		);
	}

	/**
	 * Prepares a config payload for download.
	 *
	 * @param  string $key  Config option key.
	 *
	 * @return array|null
	 */
	private function prepare_config_for_download( string $key ): ?array {
		$config = get_site_option( $key );
		if ( false === $config || ! is_array( $config ) ) {
			return null;
		}

		$sample = $this->service->gather_data();
		foreach ( $sample as $slug => $data ) {
			foreach ( $data as $k => $val ) {
				if ( ! isset( $config['configs'][ $slug ][ $k ] ) ) {
					$config['configs'][ $slug ][ $k ] = null;
				}
			}
		}

		return $config;
	}

	/**
	 * Creates a unique JSON filename for a zip entry.
	 *
	 * @param  string      $base_name  Base file name without extension.
	 * @param  string      $key  Config option key.
	 * @param  \ZipArchive $zip  Active zip archive.
	 *
	 * @return string
	 */
	private function make_unique_zip_entry_name( string $base_name, string $key, \ZipArchive $zip ): string {
		$base_name = trim( $base_name );
		if ( '' === $base_name ) {
			$base_name = 'wp-defender-config';
		}

		$try_name = $base_name . '.json';
		if ( false === $zip->locateName( $try_name ) ) {
			return $try_name;
		}

		$key_suffix = sanitize_file_name( str_replace( 'wp_defender_config_', '', $key ) );
		if ( '' !== $key_suffix ) {
			$try_name = $base_name . '-' . $key_suffix . '.json';
			if ( false === $zip->locateName( $try_name ) ) {
				return $try_name;
			}
		}

		$index = 2;
		while ( true ) {
			$try_name = $base_name . '-' . $index . '.json';
			if ( false === $zip->locateName( $try_name ) ) {
				return $try_name;
			}
			++$index;
		}
	}

	/**
	 * Clear out lines that are older than 30 days.
	 *
	 * @return void
	 */
	public function clear_logs(): void {
		// since 2.7.0.
		$time_limit = apply_filters( 'wpdef_clear_logs_time_limit', MONTH_IN_SECONDS );

		if ( is_multisite() ) {
			global $wpdb;
			$offset = 0;
			$limit  = 100;
			$blogs  = $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
				$wpdb->prepare( "SELECT blog_id FROM {$wpdb->blogs} LIMIT %d, %d", $offset, $limit ),
				ARRAY_A
			);
			while ( is_array( $blogs ) && array() !== $blogs ) {
				foreach ( $blogs as $blog ) {
					switch_to_blog( $blog['blog_id'] );

					$this->clear_logs_from_files( $time_limit );

					restore_current_blog();
				}
				$offset += $limit;
				$blogs   = $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
					$wpdb->prepare( "SELECT blog_id FROM {$wpdb->blogs} LIMIT %d, %d", $offset, $limit ),
					ARRAY_A
				);
			}
		} else {
			$this->clear_logs_from_files( $time_limit );
		}
	}

	/**
	 * Clear log files older than the specified time.
	 *
	 * @param  int $time_limit  The time limit in seconds.
	 *
	 * @return void
	 * @since 2.7.0
	 */
	public function clear_logs_from_files( int $time_limit = MONTH_IN_SECONDS ) {
		global $wp_filesystem;
		// Initialize the WP filesystem, no more using 'file-put-contents' function.
		if ( ! $wp_filesystem instanceof WP_Filesystem_Base ) {
			require_once ABSPATH . '/wp-admin/includes/file.php';
			WP_Filesystem();
		}
		$now   = wp_date( 'c' );
		$files = array( wd_internal_log() );

		foreach ( $files as $file_name ) {
			$file_path = $this->get_log_path( $file_name );

			if ( ! file_exists( $file_path ) ) {
				return;
			}

			$content         = file( $file_path );
			$size_of_content = is_array( $content ) || $content instanceof Countable ? count( $content ) : 0;

			foreach ( $content as $index => $line ) {
				// If the line does not start with '[' (it's probably not a new entry).
				$first_char = substr( $line, 0, 1 );

				if ( '[' !== $first_char ) {
					// Delete.
					unset( $content[ $index ] );
				}

				/**
				 * Get the date from entry. Items can be an array it two cases - if there's a valid date, or if the line
				 * contained something like [header] in the start. Cannot make assumptions just on the fact it's an array.
				 */
				preg_match( '/\[(.*)\]/', $line, $items );

				// If, for some reason, can't get the date, or it's not the size of an ISO 8601 date.
				if ( ! isset( $items[1] ) || 25 !== strlen( $items[1] ) ) {
					// Delete.
					unset( $content[ $index ] );
				} else {
					// It looks like it's a valid date string, compare with today.
					$time_diff = strtotime( $now ) - strtotime( $items[1] );

					// We don't need to continue on, because if this entry is not older than specific time, the next one will not be as well.
					if ( $time_diff < $time_limit ) {
						break;
					}

					unset( $content[ $index ] );
				}
			}

			// Nothing changed - do nothing.
			if ( ( is_array( $content ) || $content instanceof Countable ? count( $content ) : 0 ) === $size_of_content ) {
				return;
			}

			// Glue back together and write back to file.
			$content = implode( '', $content );

			$wp_filesystem->put_contents( $file_path, $content );
		}
	}

	/**
	 * Track the data if there are settings changes.
	 *
	 * @param  array $old_settings  Old settings.
	 * @param  array $new_settings  New settings.
	 *
	 * @return void
	 * @since 4.2.0
	 */
	public function intercept_settings_update( $old_settings, $new_settings ) {
		$from = $this->get_triggered_location();
		if (
			'' !== $from
			&& isset( $new_settings['usage_tracking'], $old_settings['usage_tracking'] )
			&& $new_settings['usage_tracking'] !== $old_settings['usage_tracking']
		) {
			$this->track_opt_toggle( (bool) $new_settings['usage_tracking'], $from );
		}
	}
}
