<?php
/**
 * Handles bot trap functionality.
 *
 * @package WP_Defender\Controller
 */

namespace WP_Defender\Controller;

use WP_Defender\Controller;
use WP_Defender\Component\Bot_Trap as Bot_Trap_Component;
use WP_Defender\Component\Known_Bots\Known_Bots_Factory;
use WP_Defender\Model\Lockout_Ip;
use WP_Defender\Traits\IP;

/**
 * Handles operations to insert a weekly rotating hash URL into the footer,
 * and blocking IP addresses that access this URL.
 */
class Bot_Trap extends Controller {
	use IP;

	const URL_QUERY = 'wpdef-bot-trap-url';

	/**
	 * Service for handling logic.
	 *
	 * @var Bot_Trap_Component
	 */
	protected $service;

	/**
	 * Constructor for the Bot_Trap class.
	 * Initializes the service and sets up necessary hooks.
	 *
	 * @param Bot_Trap_Component $service The service instance for bot trap functionality.
	 */
	public function __construct( Bot_Trap_Component $service ) {
		$this->service = $service;

		if ( $this->service->is_enabled() ) {
			add_action( 'init', array( $this, 'init' ) );
			add_action( 'wp_footer', array( $this, 'inject_footer' ) );
			add_action( 'wpdef_rotate_bot_trap_secret_hash', array( $this, 'rotate_hash' ) );
			add_action( 'template_redirect', array( $this, 'handle_hash_url' ) );
			add_filter( 'query_vars', array( $this, 'add_query_var' ) );
			add_action( 'after_switch_theme', array( $this, 'flush_rewrite' ) );
		}
	}

	/**
	 * Initializes the bot trap functionality.
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
	 * Schedules a weekly cron job to rotate the bot trap hash.
	 * This ensures that the bot trap URL changes weekly.
	 */
	public function schedule_cron() {
		if ( ! wp_next_scheduled( 'wpdef_rotate_bot_trap_secret_hash' ) ) {
			wp_schedule_event( time(), 'weekly', 'wpdef_rotate_bot_trap_secret_hash' );
		}
	}

	/**
	 * Registers a rewrite rule for the bot trap URL.
	 * The URL will be in the format: /{hash}/
	 * where {hash} is a 16-character hexadecimal string.
	 */
	public function register_rewrite_rule() {
		$hash = $this->service->get_hash();
		add_rewrite_rule( "^{$hash}/?$", 'index.php?' . self::URL_QUERY . '=' . $hash, 'top' );
	}

	/**
	 * Rotates the bot trap hash and flushes rewrite rules.
	 */
	public function rotate_hash() {
		$this->service->rotate_hash();
	}

	/**
	 * Adds a query variable for the bot trap URL.
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
	 * Handles the bot trap URL when accessed.
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
				if ( 'permanent' === $model->bot_trap_lockout_type ) {
					$lockout_model->attempt       = 0;
					$lockout_model->meta['login'] = array();
					$lockout_model->meta['nf']    = array();
					$lockout_model->save();

					do_action( 'wd_blacklist_this_ip', $ip );
				} else {
					$lockout_model->status    = Lockout_Ip::STATUS_BLOCKED;
					$lockout_model->lock_time = time();

					$this->service->create_blocked_lockout(
						$lockout_model,
						$model->bot_trap_message,
						strtotime( '+' . $model->bot_trap_lockout_duration . ' ' . $model->bot_trap_lockout_duration_unit )
					);

					$remaining_time = $lockout_model->remaining_release_time();
				}

				// Need to create a log.
				$this->service->log_event( $ip, $used_hash, Bot_Trap_Component::SCENARIO_BOT_TRAP );

				wd_di()->get( Firewall::class )->actions_for_blocked(
					$model->bot_trap_message,
					$remaining_time,
					Bot_Trap_Component::SCENARIO_BOT_TRAP,
					$ips
				);
			}
		}
	}

	/**
	 * Injects the bot trap URL into the footer of frontend pages.
	 * This URL is hidden.
	 */
	public function inject_footer() {
		if ( is_admin() ) {
			return;
		}

		$hash = $this->service->get_hash();
		echo '<div style="display:none;"><a href="' . esc_url( home_url( "/{$hash}" ) ) . '">Secret Link</a></div>';
	}

	/**
	 * Flushes the rewrite rules to ensure the new bot trap URL is recognized.
	 */
	public function flush_rewrite() {
		$this->register_rewrite_rule();
		flush_rewrite_rules();
	}

	/**
	 * Delete all the data & the cache.
	 */
	public function remove_data() {
		// Remove the bot trap hash from options.
		delete_site_option( Bot_Trap_Component::URL_HASH_KEY );

		$this->service->remove_rule();

		// Flush rewrite rules to remove the bot trap URL.
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
