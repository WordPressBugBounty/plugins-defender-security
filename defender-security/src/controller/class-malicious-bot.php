<?php
/**
 * Handles malicious bot functionality.
 *
 * @package WP_Defender\Controller
 */

namespace WP_Defender\Controller;

use WP_Defender\Controller;
use WP_Defender\Component\Blacklist_Lockout;
use WP_Defender\Component\Network_Cron_Manager;
use WP_Defender\Component\Malicious_Bot as Malicious_Bot_Component;
use WP_Defender\Component\Known_Bots\Known_Bots_Factory;
use WP_Defender\Model\Lockout_Ip;
use WP_Defender\Traits\IP;

/**
 * Handles operations to insert a weekly rotating hash URL into the footer,
 * and blocking IP addresses that access this URL.
 */
class Malicious_Bot extends Controller {
	use IP;

	/**
	 * Service for handling logic.
	 *
	 * @var Malicious_Bot_Component
	 */
	public $service;

	/**
	 * Constructor for the Malicious_Bot class.
	 * Initializes the service and sets up necessary hooks.
	 *
	 * @param Malicious_Bot_Component $service The service instance for malicious bot functionality.
	 */
	public function __construct( Malicious_Bot_Component $service ) {
		$this->service = $service;

		if ( $this->service->is_enabled() ) {
			add_action( 'init', array( $this, 'init' ) );
			add_action( 'wpdef_rotate_malicious_bot_secret_hash', array( $this->service, 'rotate_hash' ) );
			add_filter( 'query_vars', array( $this, 'add_query_var' ) );

			$service = wd_di()->get( Blacklist_Lockout::class );
			$ip      = $this->get_user_ip();
			if ( ! $service->are_ips_whitelisted( $ip ) ) {
				add_action( 'wp_footer', array( $this, 'inject_footer' ) );
				add_action( 'login_footer', array( $this, 'inject_footer' ) );
				add_action( 'template_redirect', array( $this, 'handle_hash_url' ) );
			}
		}
	}

	/**
	 * Initializes the malicious bot functionality.
	 * Schedules a weekly cron job to rotate the hash and registers a rewrite rule.
	 */
	public function init() {
		$this->schedule_cron();

		if ( ! $this->service->get_hash() ) {
			$this->service->rotate_hash();
		} else {
			$this->service->register_rewrite_rule();
		}

		$this->service->handle_robots_txt();
	}

	/**
	 * Schedules a weekly cron job to rotate the malicious bot hash.
	 * This ensures that the malicious bot URL changes weekly.
	 */
	public function schedule_cron() {
		/**
		 * Network Cron Manager
		 *
		 * @var Network_Cron_Manager $network_cron_manager
		 */
		$network_cron_manager = wd_di()->get( Network_Cron_Manager::class );
		$network_cron_manager->register_callback(
			'wpdef_rotate_malicious_bot_secret_hash',
			array( $this->service, 'rotate_hash' ),
			WEEK_IN_SECONDS
		);
	}

	/**
	 * Adds a query variable for the malicious bot URL.
	 * This allows us to capture the hash from the URL.
	 *
	 * @param array $vars Existing query variables.
	 * @return array Modified query variables.
	 */
	public function add_query_var( $vars ) {
		$vars[] = Malicious_Bot_Component::URL_QUERY;
		return $vars;
	}

	/**
	 * Handles the malicious bot URL when accessed.
	 * If the hash in the URL matches the stored hash, block the IP.
	 * Otherwise, it will do nothing.
	 */
	public function handle_hash_url() {
		$used_hash  = get_query_var( Malicious_Bot_Component::URL_QUERY );
		$valid_hash = $this->service->get_hash();

		if ( $used_hash === $valid_hash ) {
			if ( $this->is_cross_site_request() ) {
				return;
			}

			$known_bots = Known_Bots_Factory::create();
			$bot_ips    = $known_bots->get_all_bot_ips();

			// Flatten 2D array into a single array.
			$flattened_bot_ips = array();
			foreach ( $bot_ips as $ips ) {
				foreach ( $ips as $ip ) {
					$flattened_bot_ips[] = $ip;
				}
			}

			$model = $this->service->model;
			$ips   = $this->service->get_user_ip();

			foreach ( $ips as $ip ) {
				// Skip if the IP is a known bot IP.
				if ( $this->is_ip_in_format( $ip, $flattened_bot_ips ) ) {
					continue;
				}

				$lockout_model  = Lockout_Ip::get( $ip );
				$remaining_time = 0;
				if ( 'permanent' === $model->malicious_bot_lockout_type ) {
					$lockout_model->attempt       = 0;
					$lockout_model->meta['login'] = array();
					$lockout_model->meta['nf']    = array();
					$lockout_model->save();
					// We block IP here unlike other UA lockout cases.
					do_action( 'wd_blacklist_this_ip', $ip );
				} else {
					$lockout_model->status    = Lockout_Ip::STATUS_BLOCKED;
					$lockout_model->lock_time = time();

					$this->service->create_blocked_lockout(
						$lockout_model,
						$model->malicious_bot_message,
						strtotime( '+' . $model->malicious_bot_lockout_duration . ' ' . $model->malicious_bot_lockout_duration_unit )
					);

					$remaining_time = $lockout_model->remaining_release_time();
				}

				// Need to create a log.
				$this->service->log_event( $ip, $used_hash, Malicious_Bot_Component::SCENARIO_MALICIOUS_BOT );

				wd_di()->get( Firewall::class )->actions_for_blocked(
					$model->malicious_bot_message,
					$remaining_time,
					Malicious_Bot_Component::SCENARIO_MALICIOUS_BOT,
					$ips,
					true
				);
			}
		}
	}

	/**
	 * Checks if the current request is a cross-site or embedded request.
	 *
	 * @return bool True if cross-site or embedded, false otherwise.
	 */
	public function is_cross_site_request(): bool {
		$sec_fetch_site = defender_get_data_from_request( 'HTTP_SEC_FETCH_SITE', 's' );
		if ( is_string( $sec_fetch_site ) && 'cross-site' === strtolower( $sec_fetch_site ) ) {
			return true;
		}

		$sec_fetch_dest = defender_get_data_from_request( 'HTTP_SEC_FETCH_DEST', 's' );
		if ( is_string( $sec_fetch_dest ) && in_array( strtolower( $sec_fetch_dest ), array( 'image', 'iframe', 'frame', 'embed', 'object', 'audio', 'video', 'track', 'style', 'script', 'font' ), true ) ) {
			return true;
		}

		$sec_fetch_mode = defender_get_data_from_request( 'HTTP_SEC_FETCH_MODE', 's' );
		if ( is_string( $sec_fetch_mode ) && 'no-cors' === strtolower( $sec_fetch_mode ) ) {
			return true;
		}

		$site_host = wp_parse_url( home_url(), PHP_URL_HOST );
		$site_host = is_string( $site_host ) ? strtolower( $site_host ) : '';

		$http_host = defender_get_data_from_request( 'HTTP_HOST', 's' );
		if ( is_string( $http_host ) && '' !== $http_host ) {
			$http_host = strtolower( explode( ':', $http_host )[0] );
		} else {
			$http_host = '';
		}

		foreach ( array( 'HTTP_REFERER', 'HTTP_ORIGIN' ) as $header ) {
			$header_val = defender_get_data_from_request( $header, 's' );
			if ( is_string( $header_val ) && '' !== $header_val ) {
				$header_host = wp_parse_url( $header_val, PHP_URL_HOST );
				if ( is_string( $header_host ) && '' !== $header_host ) {
					$header_host_lower = strtolower( $header_host );
					if ( $header_host_lower !== $site_host && ( '' === $http_host || $header_host_lower !== $http_host ) ) {
						return true;
					}
				}
			}
		}

		return false;
	}

	/**
	 * Injects the malicious bot URL into the footer of frontend pages.
	 * This URL is hidden.
	 */
	public function inject_footer() {
		if ( is_admin() ) {
			return;
		}

		$hash = $this->service->get_hash();
		echo '<div style="display:none;"><a href="' . esc_url( home_url( "/{$hash}" ) ) . '" rel="nofollow">Secret Link</a></div>';
	}

	/**
	 * Checks if the current request is for the malicious bot hash URL.
	 *
	 * @return bool True if the request is for the hash URL, false otherwise.
	 */
	public function is_hash_request(): bool {
		$hash = $this->service->get_hash();
		if ( ! is_string( $hash ) || '' === trim( $hash ) ) {
			return false;
		}

		$uri  = defender_get_data_from_request( 'REQUEST_URI', 's' );
		$path = is_string( $uri ) ? wp_parse_url( $uri, PHP_URL_PATH ) : null;
		if ( ! is_string( $path ) || '' === $path ) {
			return false;
		}

		$path = trim( $path, '/' );

		// Always check last segment only.
		$segments = explode( '/', $path );
		$last     = end( $segments );

		return $last === $hash;
	}

	/**
	 * Rotate the malicious bot hash and refresh the related rules.
	 */
	public function rotate_hash() {
		$this->service->rotate_hash();
	}

	/**
	 * Delete all the data & the cache.
	 */
	public function remove_data() {
		// Remove the malicious bot hash from options.
		delete_site_option( Malicious_Bot_Component::URL_HASH_KEY );

		$this->service->remove_rule();

		// Flush rewrite rules to remove the malicious bot URL.
		flush_rewrite_rules();
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
	 * Converts the object data to an array.
	 *
	 * @return array An array representation of the object.
	 */
	public function to_array(): array {
		return array();
	}

	/**
	 * Imports data into the model.
	 *
	 * @param  array $data  Data to be imported into the model.
	 *
	 * @throws Exception If table is not defined.
	 */
	public function import_data( array $data ) {
	}

	/**
	 * Removes settings for all submodules.
	 */
	public function remove_settings(): void {
	}

	/**
	 * Provides data for the frontend.
	 *
	 * @return array An array of data for the frontend.
	 */
	public function data_frontend(): array {
		return array();
	}
}
