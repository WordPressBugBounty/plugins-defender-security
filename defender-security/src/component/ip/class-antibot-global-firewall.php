<?php
/**
 * Responsible for handling AntiBot Global Firewall.
 *
 * @package WP_Defender\Component\IP
 */

namespace WP_Defender\Component\IP;

use Exception;
use Generator;
use WP_Defender\Behavior\WPMUDEV;
use WP_Defender\Component;
use WP_Defender\Controller\Firewall;
use WP_Defender\Integrations\Antibot_Global_Firewall_Client;
use WP_Defender\Model\Antibot_Global_Firewall as Antibot_Global_Firewall_Model;
use WP_Defender\Model\Setting\Antibot_Global_Firewall_Setting;
use WP_Defender\Traits\Defender_Dashboard_Client;
use WP_Error;

/**
 * Provides methods for downloading IPs from AntiBot Global Firewall, storing, deleting and checking IPs in DB table.
 */
class Antibot_Global_Firewall extends Component {
	use Defender_Dashboard_Client;

	public const REASON_SLUG = 'antibot_global_firewall';

	public const LOG_FILE_NAME = 'antibot-global-firewall.log';

	public const DOWNLOAD_SYNC_SCHEDULE = 'twicedaily';

	public const DOWNLOAD_SYNC_NEXT_RUN_OPTION = 'wpdef_antibot_global_firewall_download_sync_next_run';

	public const LAST_SYNC_OPTION = 'wpdef_antibot_global_firewall_last_sync';

	public const NOTICE_SLUG = 'wpdef_show_antibot_global_firewall_notice';

	public const BLOCKLIST_STATS_KEY = 'wpdef_antibot_global_firewall_stats';

	public const BLOCKLIST_STATS_FULL_KEY = 'wpdef_antibot_global_firewall_stats_full';

	public const BLOCKLIST_STATS_FAILURE_KEY = 'wpdef_antibot_global_firewall_stats_failure';

	public const FAILURE_CACHE_TTL = HOUR_IN_SECONDS;

	public const MAX_BACKOFF_TIME = HOUR_IN_SECONDS;

	public const IS_SWITCHING_TO_PLUGIN_IN_PROGRESS = 'wpdef_antibot_global_firewall_switching_to_plugin_in_progress';

	public const GLOBAL_NOTICE_TIME_OPTION = 'wpdef_antibot_global_firewall_global_notice_time';

	public const GLOBAL_NOTICE_DELAY_DAYS_OPTION = 60;

	/**
	 * The AntiBot Global Firewall model for storing IPs.
	 *
	 * @var Antibot_Global_Firewall_Model
	 */
	private $model;

	/**
	 * The AntiBot Global Firewall setting model.
	 *
	 * @var Antibot_Global_Firewall_Setting
	 */
	private $model_setting;

	/**
	 * The WPMUDEV object.
	 *
	 * @var WPMUDEV
	 */
	private $wpmudev;

	/**
	 * The client object for AntiBot Global Firewall.
	 *
	 * @var Antibot_Global_Firewall_Client
	 */
	private $antibot_client;

	/**
	 * Lock file name for firewall updates.
	 *
	 * @var string
	 */
	protected string $lock_filename = 'antibot_global_firewall.lock';

	/**
	 * Initializes the class with the Antibot_Global_Firewall_Model, Antibot_Global_Firewall_Setting, WPMUDEV and Antibot_Global_Firewall_Client instances.
	 *
	 * @param Antibot_Global_Firewall_Model   $model          The AntiBot Global Firewall model.
	 * @param Antibot_Global_Firewall_Setting $model_setting  The AntiBot Global FIrewall setting model.
	 * @param WPMUDEV                         $wpmudev        The WPMUDEV object.
	 * @param Antibot_Global_Firewall_Client  $antibot_client The client object for AntiBot Global Firewall API.
	 */
	public function __construct( Antibot_Global_Firewall_Model $model, Antibot_Global_Firewall_Setting $model_setting, WPMUDEV $wpmudev, Antibot_Global_Firewall_Client $antibot_client ) {
		$this->model          = $model;
		$this->model_setting  = $model_setting;
		$this->wpmudev        = $wpmudev;
		$this->antibot_client = $antibot_client;

		add_action( 'wpdef_confirm_antibot_toggle_on_hosting', array( $this, 'confirm_toggle_on_hosting' ) );
		add_action( 'wp_loaded', array( $this, 'clear_antibot_on_disconnection' ) );
	}

	/**
	 * Check if AntiBot Global Firewall feature is enabled.
	 *
	 * @return bool True for enabled or false for disabled.
	 */
	public function is_enabled(): bool {
		/**
		 * Filter to enable or disable the AntiBot Global Firewall.
		 *
		 * @param bool $is_enabled True for enabled or false for disabled.
		 */
		$is_enabled = apply_filters( 'wpdef_antibot_enabled', $this->model_setting->enabled );

		return is_bool( $is_enabled ) ? $is_enabled : (bool) $is_enabled;
	}

	/**
	 * Check if the AntiBot Global Firewall is enabled on WPMU DEV.
	 *
	 * @return bool True if the AntiBot Global Firewall is enabled, false otherwise.
	 */
	public function hosting_is_enabled(): bool {
		return true === defender_get_hosting_feature_state( 'antibot' );
	}

	/**
	 * Is managed by Plugin side?
	 *
	 * @return bool
	 */
	protected function is_managed_by_plugin(): bool {
		return 'plugin' === $this->get_managed_by();
	}

	/**
	 * Check if the AntiBot Global Firewall is enabled based on managed by.
	 *
	 * @return bool True if the AntiBot Global Firewall is enabled, false otherwise.
	 */
	public function frontend_is_enabled(): bool {
		return $this->is_managed_by_plugin()
			? ! $this->is_expired_membership_type() && $this->is_enabled()
			: $this->hosting_is_enabled();
	}

	/**
	 * Check if the AntiBot Global Firewall is enabled and the site is connected to the HUB.
	 *
	 * @return bool True if the AntiBot Global Firewall is active, false otherwise.
	 */
	public function is_active(): bool {
		return $this->frontend_is_enabled() && $this->is_site_connected_to_hub_via_hcm_or_dash();
	}

	/**
	 * Check if the AntiBot Global Firewall is active via plugin.
	 *
	 * @since 5.1.1
	 * @return bool True if the AntiBot Global Firewall is active via plugin, false otherwise.
	 */
	public function is_active_via_plugin(): bool {
		return $this->is_managed_by_plugin() && $this->is_enabled() && $this->is_site_connected_to_hub_via_hcm_or_dash();
	}

	/**
	 * Check if the AntiBot Global Firewall is active via hosting.
	 *
	 * @since 5.6.0
	 * @return bool True if the AntiBot Global Firewall is active via hosting, false otherwise.
	 */
	public function is_active_via_hosting(): bool {
		return 'hosting' === $this->get_managed_by() && $this->hosting_is_enabled();
	}

	/**
	 * Check if the IP is blocked.
	 *
	 * @param string $ip The IP address.
	 *
	 * @return bool True if the IP is blocked, false otherwise.
	 */
	public function is_ip_blocked( string $ip ): bool {
		$result = $this->model->get_by_ip( $ip );

		return isset( $result->unlocked ) && 1 !== $result->unlocked;
	}

	/**
	 * Delete complete blocklist.
	 */
	public function delete_blocklist() {
		$this->model->truncate();

		delete_site_option( self::LAST_SYNC_OPTION );
	}

	/**
	 * Check if the Unlock Me Captcha should be displayed.
	 *
	 * @param array $ips The IP addresses.
	 *
	 * @return bool True if the IP is blocked by AntiBot Global Firewall, false otherwise.
	 */
	public function is_displayed( array $ips ): bool {
		if ( ! $this->is_enabled() ) {
			return false;
		}

		foreach ( $ips as $ip ) {
			if ( $this->is_ip_blocked( $ip ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Get the Unlock Me Captcha button text.
	 *
	 * @return string The button text.
	 */
	public static function get_button_text(): string {
		return esc_html__( 'AntiBot Unlock Me', 'defender-security' );
	}

	/**
	 * Handle the download and store blocklist.
	 *
	 * @since 4.8.0
	 * @return void
	 */
	public function download_and_store_blocklist(): void {
		if ( ! $this->is_site_connected_to_hub_via_hcm_or_dash() ) {
			return;
		}

		if ( $this->has_lock( $this->lock_filename ) ) {
			$this->log( 'Fallback as already a process is running', Firewall::FIREWALL_LOG );
			return;
		}

		$this->create_lock( $this->lock_filename );
		$file_path = $this->download_blocklist();

		if ( is_string( $file_path ) && '' !== $file_path ) {
			$this->store_blocklist( $file_path );
		}
		$this->remove_lock( $this->lock_filename );
	}

	/**
	 * Download blocklist.
	 *
	 * @since 4.8.0
	 * @return string|void
	 */
	private function download_blocklist() {
		$response = $this->antibot_client->get_blocklist_download( $this->model_setting->mode );

		if ( is_wp_error( $response ) ) {
			$this->log( sprintf( 'AntiBot Global Firewall Error: %s', $response->get_error_message() ), Firewall::FIREWALL_LOG );
			return;
		} elseif ( isset( $response['status'] ) && 'error' === $response['status'] ) {
			$this->log( sprintf( 'AntiBot Global Firewall Error: %s', $response['message'] ), Firewall::FIREWALL_LOG );
			return;
		} elseif (
			! isset( $response['data']['download_url'] )
			|| ! is_string( $response['data']['download_url'] )
			|| '' === $response['data']['download_url']
			|| ! isset( $response['data']['hashes']['sha256'] )
			|| ! is_string( $response['data']['hashes']['sha256'] )
			|| '' === $response['data']['hashes']['sha256']
		) {
			$this->log( 'AntiBot Global Firewall Error: Download link not found in the response.', Firewall::FIREWALL_LOG );
			return;
		}

		$file_url = $response['data']['download_url'];

		if ( ! function_exists( 'download_url' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}

		$tmp_file = download_url( $file_url );

		if ( is_wp_error( $tmp_file ) ) {
			$this->log( 'AntiBot Global Firewall Error: Unable to download file', Firewall::FIREWALL_LOG );
			return;
		}

		$expected_file_hash = '';
		$response           = wp_remote_get( $response['data']['hashes']['sha256'] );
		if ( wp_remote_retrieve_response_code( $response ) === 200 ) {
			$expected_file_hash = trim( wp_remote_retrieve_body( $response ) );
		}

		$file_hash = hash_file( 'sha256', $tmp_file );
		if ( $file_hash !== $expected_file_hash ) {
			$this->log( 'AntiBot Global Firewall Error: File is not legit. Hash does not match.', Firewall::FIREWALL_LOG );
			return;
		}

		$this->log( 'AntiBot Global Firewall: Downloaded ' . $this->model_setting->get_mode_label() . ' blocklist successfully.', Firewall::FIREWALL_LOG );

		return $tmp_file;
	}

	/**
	 * Store blocklist.
	 *
	 * @param string $file_path File path.
	 *
	 * @since 4.8.0
	 * @return void
	 */
	private function store_blocklist( string $file_path ): void {
		try {
			$generator = $this->read_file_generator( $file_path );

			$this->delete_blocklist();
			$this->model->bulk_insert( $generator );

			self::set_last_sync();

			$this->log( 'AntiBot Global Firewall: IPs stored in the DB table.', Firewall::FIREWALL_LOG );
		} catch ( Exception $e ) {
			$this->log( 'AntiBot Global Firewall Error: ' . $e->getMessage(), Firewall::FIREWALL_LOG );
		}

		// Remove temporary file.
		wp_delete_file( $file_path );
	}

	/**
	 * Read file generator.
	 *
	 * @param string $file_path File path.
	 *
	 * @return Generator
	 * @throws Exception If file not found or could not open the file.
	 */
	private function read_file_generator( $file_path ) {
		if ( ! file_exists( $file_path ) ) {
			throw new Exception( 'File not found.' );
		}

		global $wp_filesystem;
		$lines = $wp_filesystem->get_contents_array( $file_path );

		if ( ! is_array( $lines ) || array() === $lines ) {
			throw new Exception( 'Could not retrieve the file contents!' );
		}

		try {
			foreach ( $lines as $line ) {
				yield trim( $line );
			}
		} catch ( Exception $exception ) {
			throw $exception;
		}
	}

	/**
	 * Get the blocklisted IP count.
	 *
	 * @return string The blocklisted IP count.
	 */
	public function get_blocklisted_ip_count(): string {
		static $count = null;

		if ( null !== $count ) {
			return $count;
		}

		// Check if the feature is enabled.
		if ( ! $this->frontend_is_enabled() ) {
			$count = '0';
		} else {
			// Since from v5.0.2 one method is used for counting.
			$count = number_format( $this->get_cached_blocklisted_ips() );
		}

		return $count;
	}

	/**
	 * Get the last sync timestamp.
	 *
	 * @return false|int The last sync timestamp.
	 */
	public static function get_last_sync() {
		return get_site_option( self::LAST_SYNC_OPTION, false );
	}

	/**
	 * Set the last sync timestamp.
	 */
	public static function set_last_sync(): void {
		update_site_option( self::LAST_SYNC_OPTION, time() );
	}

	/**
	 * Check if the IPs should be downloaded from Antibot service.
	 *
	 * @return bool True if the IPs should be downloaded, false otherwise.
	 */
	public function maybe_download(): bool {
		if ( $this->wpmudev->is_wpmu_hosting() && 'plugin' !== $this->get_managed_by() ) {
			return false;
		}

		$last_sync = self::get_last_sync();

		if ( false === $last_sync ) {
			return true;
		}

		return time() - $last_sync >= 12 * HOUR_IN_SECONDS;
	}

	/**
	 * Get the default managed by.
	 *
	 * @return string The default managed by.
	 */
	public function get_default_managed_by(): string {
		return $this->wpmudev->is_wpmu_hosting() ? 'hosting' : 'plugin';
	}

	/**
	 * Get the AntiBot managed by.
	 *
	 * @return string The AntiBot managed by.
	 */
	public function get_managed_by(): string {
		$managed_by = $this->model_setting->managed_by;

		return '' !== $managed_by ? $managed_by : $this->get_default_managed_by();
	}

	/**
	 * Get the AntiBot managed by label.
	 *
	 * @return string The AntiBot managed by label.
	 */
	public function get_managed_by_label(): string {
		return $this->is_managed_by_plugin() ?
			esc_html__( 'Defender Plugin', 'defender-security' ) :
			esc_html__( 'WPMU DEV Hosting', 'defender-security' );
	}

	/**
	 * Set the AntiBot managed by.
	 *
	 * @param string $managed_by The managed by value.
	 *
	 * @return bool True if the managed by is set, false otherwise.
	 */
	public function set_managed_by( string $managed_by ): bool {
		if ( in_array( $managed_by, Antibot_Global_Firewall_Setting::MANAGED_BY_ALLOWED, true ) ) {
			$this->model_setting->managed_by = $managed_by;
			$this->model_setting->save();

			return true;
		}

		return false;
	}

	/**
	 * Switch the AntiBot managed by.
	 *
	 * @return string|false The managed by value if it's switched, false otherwise.
	 */
	public function switch_managed_by() {
		$managed_by = $this->is_managed_by_plugin() ? 'hosting' : 'plugin';

		if ( $this->set_managed_by( $managed_by ) ) {
			if ( 'plugin' === $managed_by ) {
				return false === $this->managed_by_plugin_action() ? false : $managed_by;
			} else {
				return false === $this->managed_by_hosting_action() ? false : $managed_by;
			}
		}

		return false;
	}

	/**
	 * Action when the AntiBot Global Firewall is enabled/disabled by plugin.
	 *
	 * @param bool $enabled True to enable, false to disable.
	 *
	 * @return bool True if the enabled/disabled action is successful, false otherwise.
	 */
	public function managed_by_plugin_action( bool $enabled = true ): bool {
		if ( $enabled ) {
			set_site_transient( self::IS_SWITCHING_TO_PLUGIN_IN_PROGRESS, true, 30 );

			// Disable AntiBot on hosting if it's currently enabled.
			$this->toggle_on_hosting( false, 0.1 );

			// Schedule a single event to confirm AntiBot is disabled on hosting after 15 seconds.
			if ( ! wp_next_scheduled( 'wpdef_confirm_antibot_toggle_on_hosting' ) ) {
				wp_schedule_single_event( time() + 15, 'wpdef_confirm_antibot_toggle_on_hosting', array( false ) );
			}

			// Enable AntiBot on plugin side.
			$this->model_setting->enabled = true;
			$this->model_setting->save();

			// Download IPs.
			$this->download_and_store_blocklist();
		} else {
			// Disable AntiBot on plugin side.
			$this->model_setting->enabled = false;
			$this->model_setting->save();

			// Remove IPs.
			$this->delete_blocklist();
		}

		return true;
	}

	/**
	 * Action when the AntiBot Global Firewall is enabled/disabled by hosting.
	 *
	 * @param bool $enabled True to enable, false to disable.
	 * @return bool True if the enabled/disabled action is successful, false otherwise.
	 */
	public function managed_by_hosting_action( bool $enabled = true ): bool {
		if ( $enabled ) {
			wp_clear_scheduled_hook( 'wpdef_confirm_antibot_toggle_on_hosting' );
			delete_site_transient( self::IS_SWITCHING_TO_PLUGIN_IN_PROGRESS );

			// Disable AntiBot on plugin side.
			$this->model_setting->enabled = false;
			$this->model_setting->save();

			// Remove IPs from DB table.
			$this->delete_blocklist();

			// Enable AntiBot on hosting if it's currently disabled.
			$result = $this->toggle_on_hosting( true );
			if ( is_wp_error( $result ) ) {
				return false;
			}
		} else {
			$result = $this->toggle_on_hosting( false );
			if ( is_wp_error( $result ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Toggle the AntiBot Global Firewall on hosting.
	 *
	 * @param bool  $enable True to enable, false to disable.
	 * @param float $timeout The timeout for the request.
	 *
	 * @return bool|WP_Error True if the AntiBot Global Firewall is toggled, false if not, WP_Error otherwise.
	 */
	public function toggle_on_hosting( bool $enable, float $timeout = 30 ) {
		if ( ! $this->wpmudev->is_wpmu_hosting() ) {
			return false;
		}

		$hosting_enable = defender_get_hosting_feature_state( 'antibot' );

		if (
			( $enable && ! $hosting_enable ) ||
			( ! $enable && $hosting_enable )
		) {
			$this->attach_behavior( WPMUDEV::class, WPMUDEV::class );

			$body = array( 'is_active' => $enable );
			if ( $enable ) {
				$body['mode'] = $this->get_hosting_mode();
			}

			$data = $this->make_wpmu_request(
				WPMUDEV::API_ANTIBOT_GLOBAL_FIREWALL,
				$body,
				array(
					'method'  => 'PUT',
					'timeout' => $timeout,
				)
			);

			if ( $timeout > 1 && is_wp_error( $data ) ) {
				$this->log( 'AntiBot Global Firewall Error: ' . $data->get_error_message(), Firewall::FIREWALL_LOG );
				return $data;
			}
		}

		return true;
	}

	/**
	 * Fetches the number of blocklisted IPs from cache or from the Blocklist API.
	 *
	 * If the value is not cached, it will fetch the number of blocklisted IPs from the Blocklist API and cache it.
	 * Implements failure caching and exponential backoff to prevent API hammering on errors.
	 *
	 * @return int The number of blocklisted IPs.
	 */
	public function get_cached_blocklisted_ips(): int {
		// If not connected skip the remote call entirely and return zero.
		if ( ! $this->is_site_connected_to_hub_via_hcm_or_dash() ) {
			return 0;
		}

		$mode        = $this->frontend_mode();
		$stats_key   = self::BLOCKLIST_STATS_KEY . '_' . $mode;
		$cached_data = get_site_transient( $stats_key );
		$cached_full = get_site_transient( self::BLOCKLIST_STATS_FULL_KEY );
		if ( false !== $cached_data && is_array( $cached_full ) ) {
			return (int) $cached_data;
		}
		$cached_count = false !== $cached_data ? (int) $cached_data : 0;

		// Check if we're in a backoff period due to previous failures.
		$failure_key  = self::BLOCKLIST_STATS_FAILURE_KEY;
		$failure_data = get_site_transient( $failure_key );
		if ( is_array( $failure_data ) && array() !== $failure_data ) {
			$fail_count = isset( $failure_data['count'] ) ? (int) $failure_data['count'] : 0;
			$fail_time  = isset( $failure_data['time'] ) ? (int) $failure_data['time'] : 0;

			if ( $fail_count > 0 && $fail_time > 0 ) {
				// Exponential backoff: 5, 25, 125, 625, 3125, max 1 hour.
				$backoff = min( pow( 5, $fail_count ), self::MAX_BACKOFF_TIME );
				if ( $fail_time > ( defender_get_current_time() - $backoff ) ) {
					$this->log( 'AntiBot Global Firewall: Skipping API call due to backoff (failures: ' . $fail_count . ')', Firewall::FIREWALL_LOG );
					return $cached_count;
				}
			}
		}

		$blocklist_stats = $this->antibot_client->get_blocklist_stats();

		if ( is_wp_error( $blocklist_stats ) ) {
			$this->log( 'AntiBot Global Firewall Error: ' . $blocklist_stats->get_error_message(), Firewall::FIREWALL_LOG );
			$this->record_stats_failure( $failure_key, $failure_data );
			return $cached_count;
		}

		$blocklisted_ips_key = Antibot_Global_Firewall_Setting::MODE_BASIC === $mode ? 'blocked_ips' : 'strict_blocked_ips';
		if ( ! isset( $blocklist_stats[ $blocklisted_ips_key ] ) || ! is_int( $blocklist_stats[ $blocklisted_ips_key ] ) || 0 >= $blocklist_stats[ $blocklisted_ips_key ] ) {
			$this->log( 'AntiBot Global Firewall Error: Stats missing for mode: ' . $mode, Firewall::FIREWALL_LOG );
			$this->record_stats_failure( $failure_key, $failure_data );
			return $cached_count;
		}

		// Success - clear any failure tracking.
		delete_site_transient( $failure_key );

		set_site_transient( self::BLOCKLIST_STATS_FULL_KEY, $blocklist_stats, 12 * HOUR_IN_SECONDS );

		$blocklisted_ips = $blocklist_stats[ $blocklisted_ips_key ];
		set_site_transient( $stats_key, $blocklisted_ips, 12 * HOUR_IN_SECONDS );

		return $blocklisted_ips;
	}

	/**
	 * Cached full GET /stats `data` (BLOCKLIST_STATS_FULL_KEY).
	 *
	 * @return array<string, mixed>
	 */
	public function get_cached_blocklist_stats_data(): array {
		if ( ! $this->is_site_connected_to_hub_via_hcm_or_dash() ) {
			return array();
		}
		$full = get_site_transient( self::BLOCKLIST_STATS_FULL_KEY );

		return is_array( $full ) ? $full : array();
	}

	/**
	 * Records a stats API failure for backoff tracking.
	 *
	 * @param string      $failure_key  The transient key for failure tracking.
	 * @param array|false $failure_data Existing failure data or false.
	 */
	private function record_stats_failure( string $failure_key, $failure_data ): void {
		$fail_count = 0;
		if ( false !== $failure_data && is_array( $failure_data ) && isset( $failure_data['count'] ) ) {
			$fail_count = (int) $failure_data['count'];
		}

		set_site_transient(
			$failure_key,
			array(
				'count' => $fail_count + 1,
				'time'  => defender_get_current_time(),
			),
			self::FAILURE_CACHE_TTL
		);
	}

	/**
	 * Confirm the toggle on hosting.
	 *
	 * @param bool $enable True to enable, false to disable.
	 *
	 * @return void
	 */
	public function confirm_toggle_on_hosting( bool $enable ): void {
		$this->toggle_on_hosting( $enable );
		delete_site_transient( self::IS_SWITCHING_TO_PLUGIN_IN_PROGRESS );
	}

	/**
	 * Logs IP-related messages if logging is enabled via filter.
	 *
	 * @param string $message The message to be logged.
	 */
	public function log_ip_message( string $message ): void {
		/**
		 * Filters whether IP logging is enabled.
		 *
		 * This filter allows developers to enable or disable IP logging globally.
		 * Returning false will prevent the log message from being written.
		 *
		 * @param bool $is_enabled Whether IP logging is enabled. Default true.
		 * @since 5.1.0
		 */
		$is_logging_enabled = apply_filters( 'wpdef_antibot_global_firewall_ip_log', true );
		$is_logging_enabled = is_bool( $is_logging_enabled ) ? $is_logging_enabled : (bool) $is_logging_enabled;
		if ( ! $is_logging_enabled ) {
			return;
		}

		$this->log( $message, self::LOG_FILE_NAME );
	}

	/**
	 * Get the AntiBot mode status in DB.
	 *
	 * @return string The AntiBot mode.
	 */
	public function get_mode(): string {
		return $this->model_setting->mode;
	}

	/**
	 * Get the AntiBot mode on WPMU DEV.
	 *
	 * @return string The AntiBot mode label.
	 */
	public function get_hosting_mode(): string {
		$mode = defender_get_hosting_feature_state( 'antibot_mode' );

		return '' !== $mode ? $mode : Antibot_Global_Firewall_Setting::MODE_BASIC;
	}

	/**
	 * Get AntiBot mode based on managed by.
	 *
	 * @return string The AntiBot mode.
	 */
	public function frontend_mode(): string {
		return $this->is_managed_by_plugin() ? $this->get_mode() : $this->get_hosting_mode();
	}

	/**
	 * Switch the AntiBot mode.
	 *
	 * @return string|false|WP_Error The AntiBot mode value if it's switched, false otherwise.
	 */
	public function switch_mode() {
		if ( $this->is_managed_by_plugin() ) {
			$mode = $this->get_mode();

			$this->model_setting->mode = Antibot_Global_Firewall_Setting::MODE_STRICT === $mode
				? Antibot_Global_Firewall_Setting::MODE_BASIC
				: Antibot_Global_Firewall_Setting::MODE_STRICT;
			$this->model_setting->save();

			$this->download_and_store_blocklist();

			delete_site_transient( self::BLOCKLIST_STATS_KEY . '_' . $mode );
			delete_site_transient( self::BLOCKLIST_STATS_FULL_KEY );
		} else {
			if ( ! $this->wpmudev->is_wpmu_hosting() ) {
				return false;
			}

			$mode = $this->get_hosting_mode();

			$this->attach_behavior( WPMUDEV::class, WPMUDEV::class );
			$data = $this->make_wpmu_request(
				WPMUDEV::API_ANTIBOT_GLOBAL_FIREWALL,
				array(
					'is_active' => $this->hosting_is_enabled(),
					'mode'      => Antibot_Global_Firewall_Setting::MODE_STRICT === $mode
						? Antibot_Global_Firewall_Setting::MODE_BASIC
						: Antibot_Global_Firewall_Setting::MODE_STRICT,
				),
				array( 'method' => 'PUT' )
			);

			if ( is_wp_error( $data ) ) {
				$this->log( 'AntiBot Global Firewall Error: ' . $data->get_error_message(), Firewall::FIREWALL_LOG );
				return $data;
			}

			delete_site_transient( self::BLOCKLIST_STATS_KEY . '_' . $mode );
			delete_site_transient( self::BLOCKLIST_STATS_FULL_KEY );
		}

		return $this->frontend_mode();
	}

	/**
	 * Clear antibot table when site is disconnected from HUB.
	 *
	 * @return void
	 */
	public function clear_antibot_on_disconnection(): void {
		if ( $this->is_site_connected_to_hub_via_hcm_or_dash() ) {
			return;
		}
		// Skip if there is nothing to clean up. No local DB records and no cached stats transients.
		$has_db_records   = $this->model->has_records();
		$has_stats_cached = false !== get_site_transient( self::BLOCKLIST_STATS_KEY . '_' . $this->get_mode() )
			|| false !== get_site_transient( self::BLOCKLIST_STATS_KEY . '_' . $this->get_hosting_mode() )
			|| false !== get_site_transient( self::BLOCKLIST_STATS_FULL_KEY );
		if ( ! $has_db_records && ! $has_stats_cached ) {
			return;
		}

		$this->delete_blocklist();
		delete_site_transient( self::BLOCKLIST_STATS_KEY . '_' . $this->get_mode() );
		delete_site_transient( self::BLOCKLIST_STATS_KEY . '_' . $this->get_hosting_mode() );
		delete_site_transient( self::BLOCKLIST_STATS_FULL_KEY );
		$this->log( 'Antibot table cleared due to site disconnection.', self::LOG_FILE_NAME );
	}

	/**
	 * Get the timestamp for when the notice should start showing.
	 *
	 * @return false|int The timestamp or false if not set.
	 */
	public function get_global_notice_time() {
		return (int) get_site_option( self::GLOBAL_NOTICE_TIME_OPTION, 0 );
	}

	/**
	 * Set a timestamp for when the notice should start showing.
	 *
	 * @return void
	 */
	public function maybe_set_notice_time(): void {
		if ( 0 === $this->get_global_notice_time() ) {
			$future = time() + ( DAY_IN_SECONDS * self::GLOBAL_NOTICE_DELAY_DAYS_OPTION );
			update_site_option( self::GLOBAL_NOTICE_TIME_OPTION, $future );
		}
	}

	/**
	 * Disable the global notice.
	 *
	 * @return void
	 */
	public function dismiss_global_notice(): void {
		update_site_option( self::GLOBAL_NOTICE_TIME_OPTION, -1 );
	}

	/**
	 * Determine if the global notice should be shown.
	 *
	 * @return bool True if the notice should be shown, false otherwise.
	 */
	public function should_show_global_notice(): bool {
		// Is this from Unlimited hosting?
		if ( defender_is_unlimited_hosting() ) {
			return false;
		}
		// Is FREE or PRO plugin?
		if ( $this->wpmudev->is_pro() ) {
			return false;
		}

		// Is AntiBot enabled?
		if ( $this->frontend_is_enabled() ) {
			return false;
		}

		// Has 60 days passed since installation?
		$notice_time = $this->get_global_notice_time();

		// No notice time or marked as dismissed (-1) or not yet reached the time.
		if ( false === $notice_time || -1 === $notice_time || time() < $notice_time ) {
			return false;
		}

		return true;
	}

	/**
	 * Get the Unlimited Hosting site ID.
	 *
	 * @return string|bool
	 */
	private function get_uh_site_id() {
		return defined( 'WPMUDEV_HOSTING_SITE_ID' ) ? WPMUDEV_HOSTING_SITE_ID : gethostname();
	}

	/**
	 * Get the link to the site tools page on the Unlimited Hosting dashboard.
	 *
	 * @return string|bool
	 */
	public function get_uh_site_tools_link() {
		if ( $this->get_uh_site_id() ) {
			return 'https://wpmudev.com/hub2/unlimited-hosting/' . $this->get_uh_site_id() . '/tools';
		}

		return false;
	}

	/**
	 * Show some Antibot parts depending on Antibot settings on Unlimited hosting (UH) server:
	 * 1) when Antibot is enabled on UH, on the plugin side we need to:
	 * -remove the Switch & Deactivate buttons,
	 * -only show the Active Mode & hide the other mode.
	 * 2) when Antibot is disabled on UH, on the plugin side we need to:
	 * -remove only the Switch button.
	 * 2.1) if Whitelabel is enabled, the activation button is disabled.
	 * 2.2) if Whitelabel is disabled, the activation button is redirected to the Hub.
	 *
	 * If the Antibot is managed by Dedicated DEV hosting, we can show the Switch button.
	 *
	 * Without changes for other hostings.
	 */
	public function get_states_of_antibot_options_for_different_hosting_types(): array {
		$show_antibot_options = array(
			'is_unlimited_hosting' => false,
			'switch_button'        => true,
			'deactivate_button'    => true,
			'available_modes'      => Antibot_Global_Firewall_Setting::get_valid_modes(),
			'uh_activate_btn_text' => __( 'Activate', 'defender-security' ),
			'uh_activate_btn_link' => '',
		);

		if ( defender_is_unlimited_hosting() ) {
			$show_antibot_options['switch_button'] = false;
			if ( $this->is_active_via_hosting() ) {
				$show_antibot_options['deactivate_button'] = false;
				// Rewrite the array().
				$show_antibot_options['available_modes'] = array( $this->frontend_mode() );
			}
			// Get activation button text if the Antibot is disabled.
			if ( ! $this->frontend_is_enabled() ) {
				$show_antibot_options['is_unlimited_hosting'] = true;
				if ( $this->wpmudev->is_whitelabel_enabled() ) {
					$show_antibot_options['uh_activate_btn_text'] = __( 'DISABLED', 'defender-security' );
				} else {
					$uh_site_tools_link = $this->get_uh_site_tools_link();
					if ( $uh_site_tools_link ) {
						$show_antibot_options['uh_activate_btn_link'] = $uh_site_tools_link;
						$show_antibot_options['uh_activate_btn_text'] = __( 'MANAGE', 'defender-security' );

					}
				}
			}
		} else {
			$show_antibot_options['switch_button'] = $this->wpmudev->is_wpmu_hosting();
		}

		return $show_antibot_options;
	}
}
