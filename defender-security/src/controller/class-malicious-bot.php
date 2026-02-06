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

	const URL_QUERY = 'wpdef-malicious-bot-url';

	/**
	 * Service for handling logic.
	 *
	 * @var Malicious_Bot_Component
	 */
	protected $service;

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
			add_action( 'wpdef_rotate_malicious_bot_secret_hash', array( $this, 'rotate_hash' ) );
			add_filter( 'query_vars', array( $this, 'add_query_var' ) );
			add_action( 'after_switch_theme', array( $this, 'flush_rewrite' ) );

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
		}

		$this->flush_rewrite();
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
	 * Registers a rewrite rule for the malicious bot URL.
	 * The URL will be in the format: /{hash}/
	 * where {hash} is a 16-character hexadecimal string.
	 */
	public function register_rewrite_rule() {
		$hash = $this->service->get_hash();
		add_rewrite_rule( "^{$hash}/?$", 'index.php?' . self::URL_QUERY . '=' . $hash, 'top' );
	}

	/**
	 * Rotates the malicious bot hash and flushes rewrite rules.
	 */
	public function rotate_hash() {
		$this->service->rotate_hash();
	}

	/**
	 * Adds a query variable for the malicious bot URL.
	 * This allows us to capture the hash from the URL.
	 *
	 * @param array $vars Existing query variables.
	 * @return array Modified query variables.
	 */
	public function add_query_var( $vars ) {
		$vars[] = self::URL_QUERY;
		return $vars;
	}

	/**
	 * Handles the malicious bot URL when accessed.
	 * If the hash in the URL matches the stored hash, block the IP.
	 * Otherwise, it will do nothing.
	 */
	public function handle_hash_url() {
		$used_hash  = get_query_var( self::URL_QUERY );
		$valid_hash = $this->service->get_hash();

		if ( $used_hash === $valid_hash ) {
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
	 * Flushes the rewrite rules to ensure the new malicious bot URL is recognized.
	 */
	public function flush_rewrite() {
		$this->register_rewrite_rule();
		flush_rewrite_rules();
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

		$uri = defender_get_data_from_request( 'REQUEST_URI', 's' );
		if ( ! is_string( $uri ) || '' === $uri ) {
			return false;
		}

		// Get request path.
		$uri = wp_parse_url( $uri, PHP_URL_PATH );
		$uri = trim( $uri, '/' );

		// Always check last segment only.
		$segments = explode( '/', $uri );
		$last     = end( $segments );

		return $last === $hash;
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
