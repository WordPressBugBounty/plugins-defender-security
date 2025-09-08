<?php
/**
 * Network Cron Manager for WP Defender.
 *
 * This file contains the Network_Cron_Manager class which manages
 * centralized cron jobs across a multisite network with locking.
 *
 * @package WP_Defender\Component
 */

namespace WP_Defender\Component;

use WP_Defender\Component;

/**
 * Network Cron Manager class.
 *
 * Provides centralized cron management with locking and multisite execution control.
 */
class Network_Cron_Manager extends Component {
	/**
	 * Array of registered callbacks.
	 *
	 * @var array
	 */
	private $callbacks = array();

	/**
	 * Prefix for lock keys.
	 *
	 * @var string
	 */
	private $lock_prefix = 'wpdef_cron_manager_lock_';

	/**
	 * Prefix for last run timestamp keys.
	 *
	 * @var string
	 */
	private $lastrun_prefix = 'wpdef_cron_manager_lastrun_';

	/**
	 * Option name for storing callbacks.
	 *
	 * @var string
	 */
	private $callbacks_option = 'wpdef_cron_manager_callbacks';

	/**
	 * Constructor.
	 *
	 * Initializes the cron manager and hooks into WordPress.
	 */
	public function __construct() {
		add_action( 'init', array( $this, 'check_and_execute_callbacks' ), 20 );
	}

	/**
	 * Load callbacks from network options.
	 */
	private function load_callbacks() {
		$this->callbacks = get_network_option( get_main_network_id(), $this->callbacks_option, array() );
	}

	/**
	 * Save callbacks to network options.
	 */
	private function save_callbacks() {
		update_network_option( get_main_network_id(), $this->callbacks_option, $this->callbacks );
	}

	/**
	 * Register a callback for cron execution.
	 *
	 * @param string   $hook_name        The hook name.
	 * @param callable $callback         The callback function.
	 * @param int      $interval_seconds The interval in seconds.
	 * @param array    $args             Arguments for the callback.
	 * @return bool|void False on validation failure, void on success.
	 */
	public function register_callback( $hook_name, $callback, $interval_seconds, $args = array() ) {
		$hook_name = sanitize_key( $hook_name );
		if ( empty( $hook_name ) || ! is_string( $hook_name ) ) {
			return false;
		}
		if ( ! is_callable( $callback ) ) {
			return false;
		}
		if ( ! is_numeric( $interval_seconds ) || $interval_seconds < 1 ) {
			return false;
		}
		$this->callbacks[ $hook_name ] = array(
			'callback' => $callback,
			'interval' => $interval_seconds,
			'args'     => $args,
		);
		$this->save_callbacks();
	}

	/**
	 * Check and execute registered callbacks.
	 */
	public function check_and_execute_callbacks() {
		$this->load_callbacks();
		if ( empty( $this->callbacks ) ) {
			return;
		}
		foreach ( $this->callbacks as $hook_name => $config ) {
			$this->execute_callback( $hook_name, $config );
		}
	}

	/**
	 * Execute a specific callback.
	 *
	 * @param string $hook_name The hook name.
	 * @param array  $config    The callback configuration.
	 */
	private function execute_callback( $hook_name, $config ) {
		if ( ! $this->should_execute( $hook_name, $config['interval'] ) ) {
			return;
		}
		if ( ! $this->acquire_lock( $hook_name ) ) {
			$this->log( "Failed to acquire lock for {$hook_name}", 'cron-manager' );
			return;
		}
		try {
			if ( is_callable( $config['callback'] ) ) {
				call_user_func_array( $config['callback'], $config['args'] );
				$this->update_last_run( $hook_name );
			}
		} catch ( \Exception $exception ) {
			$this->log( "Exception in {$hook_name}: " . $exception->getMessage(), 'cron-manager' );
		} finally {
			$this->release_lock( $hook_name );
		}
	}

	/**
	 * Check if a callback should be executed based on interval.
	 *
	 * @param string $hook_name The hook name.
	 * @param int    $interval  The interval in seconds.
	 * @return bool Whether the callback should execute.
	 */
	private function should_execute( $hook_name, $interval ) {
		/**
		 * Filter to modify execution intervals for network cron jobs.
		 *
		 * @param int    $interval  The interval in seconds.
		 * @param string $hook_name The hook name being executed.
		 */
		$interval     = apply_filters( 'wpdef_network_cron_interval', $interval, $hook_name );
		$last_run     = $this->get_last_run( $hook_name );
		$current_time = time();
		$time_diff    = $current_time - $last_run;
		if ( $last_run && $time_diff < $interval ) {
			$this->log( "Skipping {$hook_name}: not enough time elapsed ({$time_diff} < {$interval})", 'cron-manager' );
			return false;
		}
		return true;
	}

	/**
	 * Acquire a lock for a specific hook.
	 *
	 * @param string $hook_name The hook name.
	 * @return bool Whether the lock was acquired.
	 */
	private function acquire_lock( $hook_name ) {
		/**
		 * Filter to modify lock timeout for network cron jobs.
		 *
		 * @param int    $timeout   The timeout in seconds.
		 * @param string $hook_name The hook name being locked.
		 */
		$lock_timeout  = apply_filters( 'wpdef_network_cron_lock_timeout', 300, $hook_name );
		$lock_key      = $this->lock_prefix . $hook_name;
		$existing_lock = get_network_option( get_main_network_id(), $lock_key );
		if ( $existing_lock && ( time() - $existing_lock ) < $lock_timeout ) {
			return false;
		}
		$lock_value = time();
		return update_network_option( get_main_network_id(), $lock_key, $lock_value );
	}

	/**
	 * Release a lock for a specific hook.
	 *
	 * @param string $hook_name The hook name.
	 */
	private function release_lock( $hook_name ) {
		$lock_key = $this->lock_prefix . $hook_name;
		delete_network_option( get_main_network_id(), $lock_key );
	}

	/**
	 * Get the last run timestamp for a hook.
	 *
	 * @param string $hook_name The hook name.
	 * @return int The last run timestamp.
	 */
	private function get_last_run( $hook_name ) {
		$lastrun_key = $this->lastrun_prefix . $hook_name;
		return get_network_option( get_main_network_id(), $lastrun_key, 0 );
	}

	/**
	 * Update the last run timestamp for a hook.
	 *
	 * @param string $hook_name The hook name.
	 */
	private function update_last_run( $hook_name ) {
		$lastrun_key = $this->lastrun_prefix . $hook_name;
		$timestamp   = time();
		update_network_option( get_main_network_id(), $lastrun_key, $timestamp );
	}

	/**
	 * Get all registered callbacks.
	 *
	 * @return array The registered callbacks.
	 */
	public function get_callbacks() {
		return $this->callbacks;
	}

	/**
	 * Remove all Network Cron Manager data during uninstallation.
	 */
	public function remove_data() {
		if ( ! is_multisite() ) {
			return;
		}

		$network_id = get_main_network_id();

		delete_network_option( $network_id, $this->callbacks_option );

		global $wpdb;
		$wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$wpdb->prepare(
				"DELETE FROM {$wpdb->sitemeta} WHERE meta_key LIKE %s OR meta_key LIKE %s",
				$this->lock_prefix . '%',
				$this->lastrun_prefix . '%'
			)
		);
	}
}
