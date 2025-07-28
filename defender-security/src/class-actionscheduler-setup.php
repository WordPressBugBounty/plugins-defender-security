<?php
/**
 * Action Scheduler Setup
 *
 * Ensures required Action Scheduler database tables exist for each site.
 * Supports single-site and multisite setups.
 *
 * @package WP_Defender
 */

namespace WP_Defender;

use ActionScheduler_HybridStore;
use ActionScheduler_LoggerSchema;
use ActionScheduler_StoreSchema;
use WP_Site;

/**
 * Class ActionScheduler_Setup
 *
 * Ensures Action Scheduler database tables are created for each site in a multisite network,
 * as well as for single-site setups. Handles scenarios such as
 * admin fallback checks, new subsite creation.
 */
class ActionScheduler_Setup {

	/**
	 * Initialize hooks for setting up Action Scheduler tables.
	 */
	public static function init(): void {
		add_action( 'plugins_loaded', array( __CLASS__, 'maybe_create_tables' ) );
		add_action( 'wp_initialize_site', array( __CLASS__, 'create_tables_for_new_site' ) );
	}

	/**
	 * Ensure tables exist on the current site.
	 * Runs as a fallback during plugin load.
	 */
	public static function maybe_create_tables(): void {
		if ( ! self::tables_exist() ) {
			self::register_tables();
		}
	}

	/**
	 * Set up Action Scheduler tables for a new site in a multisite network.
	 *
	 * @param WP_Site $site The new site object.
	 */
	public static function create_tables_for_new_site( WP_Site $site ): void {
		switch_to_blog( $site->blog_id );
		self::register_tables();
		restore_current_blog();
	}

	/**
	 * Register Action Scheduler tables on the current site.
	 */
	private static function register_tables(): void {
		self::load_dependencies();

		$store = new ActionScheduler_HybridStore();
		add_action( 'action_scheduler/created_table', array( $store, 'set_autoincrement' ), 10, 2 );

		$store_schema  = new ActionScheduler_StoreSchema();
		$logger_schema = new ActionScheduler_LoggerSchema();

		$store_schema->register_tables( true );
		$logger_schema->register_tables( true );

		remove_action( 'action_scheduler/created_table', array( $store, 'set_autoincrement' ), 10 );
	}

	/**
	 * Check if Action Scheduler tables exist.
	 *
	 * @return bool
	 */
	private static function tables_exist(): bool {
		self::load_dependencies();

		$store_schema = new ActionScheduler_StoreSchema();
		return $store_schema->tables_exist();
	}

	/**
	 * Load required Action Scheduler classes if not already loaded.
	 */
	private static function load_dependencies(): void {
		if ( ! class_exists( 'ActionScheduler_HybridStore' ) ) {
			require_once WP_DEFENDER_DIR . 'vendor/woocommerce/action-scheduler/classes/data-stores/ActionScheduler_HybridStore.php';
		}
		if ( ! class_exists( 'ActionScheduler_StoreSchema' ) ) {
			require_once WP_DEFENDER_DIR . 'vendor/woocommerce/action-scheduler/classes/schema/ActionScheduler_StoreSchema.php';
		}
		if ( ! class_exists( 'ActionScheduler_LoggerSchema' ) ) {
			require_once WP_DEFENDER_DIR . 'vendor/woocommerce/action-scheduler/classes/schema/ActionScheduler_LoggerSchema.php';
		}
	}
}
