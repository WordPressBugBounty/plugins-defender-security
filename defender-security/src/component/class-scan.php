<?php
/**
 * Handling the scanning process.
 *
 * @package WP_Defender\Component
 */

namespace WP_Defender\Component;

use Countable;
use ArrayIterator;
use WP_Defender\Component;
use WP_Plugins_List_Table;
use WP_Defender\Model\Scan_Item;
use WP_Defender\Behavior\WPMUDEV;
use WP_Defender\Model\Scan as Scan_Model;
use WP_Defender\Behavior\Scan\Gather_Fact;
use WP_Defender\Behavior\Scan\Malware_Scan;
use WP_Defender\Behavior\Scan\Core_Integrity;
use WP_Defender\Behavior\Scan\Plugin_Integrity;
use WP_Defender\Behavior\Scan\Known_Vulnerability;
use WP_Defender\Behavior\Scan\Abandoned_Plugin;
use WP_Defender\Model\Setting\Scan as Scan_Settings;
use WP_Defender\Helper\Analytics\Scan as Scan_Analytics;
use WP_Defender\Controller\Scan as Scan_Controller;

/**
 * The Scan class handles the scanning process, managing tasks, and coordinating different types of scans.
 */
class Scan extends Component {
	use \WP_Defender\Traits\Plugin;

	// For all Scan types where plugins are used.
	public const PLUGINS_ACTIONED = 'wp-defender-actioned-plugins';

	/**
	 * The current scan model.
	 *
	 * @var Scan_Model
	 */
	public $scan;

	/**
	 * Scan settings model.
	 *
	 * @var Scan_Settings
	 */
	public $settings;
	/**
	 * Instance of Gather_Fact to gather necessary information before scanning.
	 *
	 * @var Gather_Fact|null
	 */
	private ?Gather_Fact $gather_fact = null;

	/**
	 * Instance of Abandoned_Plugin to handle abandoned plugin checks.
	 *
	 * @var Abandoned_Plugin
	 */
	private $abandoned_plugin;

	/**
	 * Lock file name for scanning.
	 *
	 * @var string
	 */
	protected string $lock_filename = 'scan.lock';


	/**
	 * Constructs the Scan object and initializes behaviors.
	 */
	public function __construct() {
		$this->attach_behavior( WPMUDEV::class, WPMUDEV::class );
		$this->attach_behavior( Core_Integrity::class, Core_Integrity::class );
		$this->attach_behavior( Plugin_Integrity::class, Plugin_Integrity::class );
		$this->settings = wd_di()->get( Scan_Settings::class );
	}

	/**
	 * Performs additional actions after an advanced scan.
	 *
	 * @param Scan_Model $model  The scan model.
	 */
	public function advanced_scan_actions( $model ) {
		$this->reindex_ignored_issues( $model );
		$this->clean_up();

		if ( defender_is_wp_org_version() ) {
			Rate::run_counter_of_completed_scans();
		}
	}

	/**
	 * Process current scan.
	 *
	 * @return bool|int
	 */
	public function process() {
		$scan = Scan_Model::get_active();
		if ( ! is_object( $scan ) ) {
			// This case can be a scan get cancel.
			return - 1;
		}
		$this->scan = $scan;
		$tasks      = $this->get_tasks();
		$runner     = new ArrayIterator( $tasks );
		$task       = $this->scan->status;
		if ( Scan_Model::STATUS_INIT === $scan->status ) {
			// Get the first.
			$this->log( 'Prepare facts for a scan', Scan_Controller::SCAN_LOG );
			$task                    = Scan_Model::STEP_GATHER_INFO;
			$this->scan->percent     = 0;
			$this->scan->total_tasks = $runner->count();
			$this->scan->save();
		}
		if (
			in_array(
				$this->scan->status,
				array(
					Scan_Model::STATUS_ERROR,
					Scan_Model::STATUS_IDLE,
				),
				true
			)
		) {
			// Stop and return true to abort the process.
			return true;
		}
		// Find the current task.
		$offset = array_search( $task, array_values( $tasks ), true );
		if ( false === $offset ) {
			$this->log( sprintf( 'offset is not found, search %s', $task ), Scan_Controller::SCAN_LOG );

			return false;
		}
		// Reset the tasks to current.
		$runner->seek( $offset );
		$this->log( sprintf( 'Current task %s', $runner->current() ), Scan_Controller::SCAN_LOG );
		if ( $this->has_method( $task ) ) {
			$this->log( sprintf( 'processing %s', $runner->key() ), Scan_Controller::SCAN_LOG );
			$result = $this->task_handler( $task );
			if ( true === $result ) {
				$this->log( sprintf( 'task %s processed', $runner->key() ), Scan_Controller::SCAN_LOG );
				// Task is done, move to next.
				$runner->next();
				if ( $runner->valid() ) {
					$this->log( sprintf( 'queue %s for next', $runner->key() ), Scan_Controller::SCAN_LOG );
					$this->scan->status          = $runner->key();
					$this->scan->task_checkpoint = '';
					$this->scan->date_end        = gmdate( 'Y-m-d H:i:s' );
					$this->scan->save();
					// Queue for next run.
					return false;
				}
				$this->log( 'All done!', Scan_Controller::SCAN_LOG );
				// No more task in the queue, we are done.
				$this->scan->status = Scan_Model::STATUS_FINISH;
				$this->scan->save();
				$this->advanced_scan_actions( $this->scan );
				do_action( 'defender_notify', 'malware-notification', $this->scan );

				return true;
			}
			$this->scan->status = $task;
			$this->scan->save();
		}

		return false;
	}

	/**
	 * Reindex ignored issues to update their status in the scan model.
	 *
	 * @param  Scan_Model $model  The scan model.
	 */
	private function reindex_ignored_issues( $model ) {
		$issues       = $model->get_issues( null, Scan_Item::STATUS_IGNORE );
		$ignore_lists = array();
		foreach ( $issues as $issue ) {
			$data = $issue->raw_data;
			if ( isset( $data['file'] ) ) {
				$ignore_lists[] = $data['file'];
			} elseif ( isset( $data['slug'] ) ) {
				$ignore_lists[] = $data['slug'];
			}
		}
		$model->update_ignore_list( $ignore_lists );
	}

	/**
	 * Get a list of tasks will run in a scan.
	 *
	 * @return array
	 */
	public function get_tasks(): array {
		$tasks = array( Scan_Model::STEP_GATHER_INFO => 'gather_info' );
		if ( $this->settings->integrity_check ) {
			// Nested options.
			if ( $this->settings->check_core ) {
				$tasks[ Scan_Model::STEP_CHECK_CORE ] = 'core_integrity_check';
			}
			if ( $this->settings->check_plugins ) {
				$tasks[ Scan_Model::STEP_CHECK_PLUGIN ] = 'plugin_integrity_check';
			}
		}

		if ( $this->settings->check_abandoned_plugin ) {
			$tasks[ Scan_Model::STEP_ABANDONED_PLUGIN_CHECK ] = 'abandoned_plugin_check';
		}

		return $tasks;
	}

	/**
	 * Handles individual scan tasks based on the task identifier.
	 *
	 * @param  string $task  The task identifier.
	 *
	 * @return bool Returns true if the task was handled successfully.
	 */
	private function task_handler( $task ) {
		switch ( $task ) {
			case 'gather_info':
				if ( ! ( $this->gather_fact instanceof Gather_Fact ) && class_exists( Gather_Fact::class ) ) {
					$this->set_gather_fact(
						wd_di()->make( Gather_Fact::class, array( 'scan' => $this->scan ) )
					);
				}

				return $this->gather_info( $this->gather_fact );
			case 'abandoned_plugin_check':
				if ( ! ( $this->abandoned_plugin instanceof Abandoned_Plugin ) && class_exists( Abandoned_Plugin::class ) ) {
					$this->set_abandoned_plugin(
						wd_di()->make( Abandoned_Plugin::class, array( 'scan' => $this->scan ) )
					);
				}

				return $this->abandoned_plugin_check( $this->abandoned_plugin );
			default:
				return is_callable( array( $this, $task ) ) ? $this->$task() : false;
		}
	}
	/**
	 * Set the Abandoned_Plugin object.
	 *
	 * @param  Abandoned_Plugin $abandoned_plugin  The Abandoned_Plugin object to set.
	 */
	public function set_abandoned_plugin( Abandoned_Plugin $abandoned_plugin ) {
		if ( class_exists( Abandoned_Plugin::class ) ) {
			$this->abandoned_plugin = $abandoned_plugin;
		}
	}

	/**
	 * A wrapper method for Abandoned_Plugin class method abandoned_plugin_check.
	 *
	 * @param  Abandoned_Plugin $abandoned_plugin  An instance of Abandoned_Plugin.
	 *
	 * @return bool
	 */
	private function abandoned_plugin_check( Abandoned_Plugin $abandoned_plugin ): bool {
		if ( method_exists( $abandoned_plugin, 'abandoned_plugin_check' ) ) {
			return $abandoned_plugin->abandoned_plugin_check();
		}

		return true;
	}

	/**
	 * Cancels an active scan and cleans up related data.
	 */
	public function cancel_a_scan() {
		$scan = Scan_Model::get_active();
		if ( is_object( $scan ) ) {
			$scan->delete();
		}
		$this->clean_up();
		$this->remove_lock( $this->lock_filename );

		$scan_analytics = wd_di()->get( Scan_Analytics::class );

		$scan_analytics->track_feature(
			$scan_analytics::EVENT_SCAN_FAILED,
			array(
				$scan_analytics::EVENT_SCAN_FAILED_PROP => $scan_analytics::EVENT_SCAN_FAILED_CANCEL,
			)
		);
	}

	/**
	 * Track the event if we have a failed checksum.
	 */
	public function maybe_track_failed_checksum() {
		// If there is a Checksum issue, then check DB's value from time().
		$checksum_issue = (int) get_site_option( Core_Integrity::ISSUE_CHECKSUMS, 0 );
		if ( $checksum_issue > 0 ) {
			$scan_analytics = wd_di()->get( Scan_Analytics::class );
			$reason         = 'Failed to fetch checksums from wp.org';

			$scan_analytics->track_feature(
				$scan_analytics::EVENT_SCAN_FAILED,
				array(
					$scan_analytics::EVENT_SCAN_FAILED_PROP => $scan_analytics::EVENT_SCAN_FAILED_ERROR,
					'Error_Reason' => $reason,
				)
			);

			$this->log( $reason, Scan_Controller::SCAN_LOG );
		}
	}

	/**
	 * Clean up data generate by current scan.
	 */
	public function clean_up() {
		$this->delete_interim_data();

		$models = Scan_Model::get_last_all();
		if ( is_array( $models ) && array() !== $models ) {
			// Remove the latest. Don't remove code to find the first value.
			$current = array_shift( $models );
			foreach ( $models as $model ) {
				$model->delete();
			}
		}
	}

	/**
	 * Get the total scanning active issues.
	 *
	 * @return int $count
	 */
	public function indicator_issue_count(): int {
		$count = 0;
		$scan  = Scan_Model::get_last();
		if ( is_object( $scan ) && ! is_wp_error( $scan ) ) {
			// Only Scan issues.
			$count = (int) $scan->count( null, Scan_Item::STATUS_ACTIVE );
		}

		return $count;
	}

	/**
	 * Checks if any scan type is active based on the scan settings and the user's membership status.
	 *
	 * @param  array $scan_settings  The scan settings.
	 *
	 * @return bool Returns true if any scan type is active, false otherwise.
	 */
	public function is_any_scan_active( $scan_settings ): bool {
		if ( ! isset( $scan_settings['integrity_check'] ) || ! $scan_settings['integrity_check'] ) {
			// Check the parent type.
			$file_change_check = false;
		} elseif (
			$scan_settings['integrity_check']
			&& ( ! isset( $scan_settings['check_core'] ) || ! $scan_settings['check_core'] )
			&& ( ! isset( $scan_settings['check_plugins'] ) || ! $scan_settings['check_plugins'] )
		) {
			// Check the parent and child types.
			$file_change_check = false;
		} else {
			$file_change_check = true;
		}
		return $file_change_check || ( isset( $scan_settings['check_abandoned_plugin'] ) && $scan_settings['check_abandoned_plugin'] );
	}

	/**
	 * Update the idle scan status due the time limit.
	 *
	 * @since 2.6.1
	 */
	public function update_idle_scan_status() {
		$idle_scan = wd_di()->get( Scan_Model::class )->get_idle();

		if ( is_object( $idle_scan ) ) {
			$ready_to_send = false;
			if ( Scan_Model::STATUS_IDLE === $idle_scan->status ) {
				$ready_to_send = true;
			}
			$this->delete_interim_data();

			if ( function_exists( 'as_unschedule_all_actions' ) ) {
				as_unschedule_all_actions( 'defender/async_scan' );
			}

			$idle_scan->status          = Scan_Model::STATUS_IDLE;
			$idle_scan->task_checkpoint = 'time_limit';
			$idle_scan->save();

			$this->remove_lock( $this->lock_filename );
			if ( $ready_to_send ) {
				do_action( 'defender_notify', 'malware-notification', $idle_scan );
			}
		}
	}

	/**
	 * Update the idle scan status due the checksum issue.
	 *
	 * @param object $scan The current scan.
	 *
	 * @since 4.9.0
	 */
	public function update_idle_scan_status_by_checksum_issue( $scan ) {
		$ready_to_send = false;
		if ( Scan_Model::STATUS_IDLE === $scan->status ) {
			$ready_to_send = true;
		}
		$this->delete_interim_data();

		if ( function_exists( 'as_unschedule_all_actions' ) ) {
			as_unschedule_all_actions( 'defender/async_scan' );
		}

		$scan->status          = Scan_Model::STATUS_IDLE;
		$scan->task_checkpoint = 'checksum_issue';
		$scan->save();

		$this->remove_lock( $this->lock_filename );
		if ( $ready_to_send ) {
			do_action( 'defender_notify', 'malware-notification', $scan );
		}
	}

	/**
	 * Clear all temporary scan data.
	 *
	 * @since 2.6.1
	 */
	private function delete_interim_data() {
		delete_site_option( Gather_Fact::CACHE_CORE );
		delete_site_option( Gather_Fact::CACHE_CONTENT );
		delete_site_option( Core_Integrity::CACHE_CHECKSUMS );
		delete_site_option( Plugin_Integrity::PLUGIN_SLUGS );
		delete_site_option( Plugin_Integrity::PLUGIN_PREMIUM_SLUGS );
		delete_site_option( self::PLUGINS_ACTIONED );
		$this->maybe_track_failed_checksum();
	}
	/**
	 * Clear completed action scheduler logs.
	 *
	 * @since 2.6.5
	 */
	public static function clear_logs() {
		global $wpdb;

		$table_actions = isset( $wpdb->actionscheduler_actions ) && '' !== $wpdb->actionscheduler_actions ?
			$wpdb->actionscheduler_actions :
			$wpdb->prefix . 'actionscheduler_actions';
		$table_logs    = isset( $wpdb->actionscheduler_logs ) && '' !== $wpdb->actionscheduler_logs ?
			$wpdb->actionscheduler_logs :
			$wpdb->prefix . 'actionscheduler_logs';

		$table_count = (int) $wpdb->get_var( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			$wpdb->prepare(
				'SELECT count(*)
				 FROM information_schema.tables
				 WHERE table_schema = %s AND table_name IN (%s, %s);',
				$wpdb->dbname,
				$table_actions,
				$table_logs
			)
		);

		if ( 2 !== $table_count ) {
			return array( 'error' => esc_html__( 'Action scheduler is not setup', 'defender-security' ) );
		}

		$hook       = 'defender/async_scan';
		$status     = 'complete';
		$limit      = 100;
		$action_ids = $wpdb->get_col( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			$wpdb->prepare(
				"SELECT action_id FROM {$table_actions} as_actions WHERE as_actions.hook = %s AND as_actions.status = %s LIMIT %d", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$hook,
				$status,
				$limit
			)
		);
		while ( $action_ids ) {
			if ( ! is_array( $action_ids ) || array() === $action_ids ) {
				break;
			}

			$query = "DELETE as_actions, as_logs FROM {$table_actions} as_actions LEFT JOIN {$table_logs} as_logs ON as_actions.action_id = as_logs.action_id WHERE as_actions.action_id IN ( " . implode(
				', ',
				array_fill(
					0,
					is_array( $action_ids ) || $action_ids instanceof Countable ? count( $action_ids ) : 0,
					'%s'
				)
			) . ' )';
			$query = call_user_func_array(
				array( $wpdb, 'prepare' ),
				array_merge(
					array( $query ),
					$action_ids
				)
			);
			// SQL is prepared here, so we will ignore WordPress.DB.PreparedSQL.NotPrepared.
			$wpdb->query( $query ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery

			$action_ids = $wpdb->get_col( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
				$wpdb->prepare(
					"SELECT action_id FROM {$table_actions} as_actions WHERE as_actions.hook = %s AND as_actions.status = %s LIMIT %d", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
					$hook,
					$status,
					$limit
				)
			);
		}

		return array( 'success' => esc_html__( 'Malware scan logs are cleared', 'defender-security' ) );
	}

	/**
	 * Set the Gather_Fact object.
	 *
	 * @param  Gather_Fact $gather_fact  The Gather_Fact object to set.
	 */
	public function set_gather_fact( Gather_Fact $gather_fact ) {
		if ( class_exists( Gather_Fact::class ) ) {
			$this->gather_fact = $gather_fact;
		}
	}

	/**
	 * Gathers information using the Gather_Fact class.
	 *
	 * @param  Gather_Fact $gather_fact  The Gather_Fact instance.
	 *
	 * @return bool Returns true if information gathering is successful.
	 */
	public function gather_info( Gather_Fact $gather_fact ): bool {
		if ( method_exists( $gather_fact, 'gather_info' ) ) {
			return $gather_fact->gather_info();
		}

		return true;
	}

	/**
	 * Get intentions.
	 *
	 * @since 4.11.0
	 * @return array
	 */
	public static function get_intentions(): array {
		return array(
			'resolve',
			'ignore',
			'delete',
			'unignore',
		);
	}

	/**
	 * Get the list of actioned plugins taking into account the Ignored and Excluded.
	 *
	 * @return array
	 */
	public function gather_actioned_plugin_details(): array {
		$cache = get_site_option( self::PLUGINS_ACTIONED );
		if ( self::are_actioned_plugins( $cache ) ) {
			return $cache;
		}

		$items          = array();
		$is_plugin_used = false;
		if ( $this->settings->integrity_check && $this->settings->check_plugins ) {
			$is_plugin_used = true;
		} elseif ( $this->settings->check_abandoned_plugin ) {
			$is_plugin_used = true;
		}

		if ( $is_plugin_used ) {
			$model = Scan_Model::get_last();
			/**
			 * Exclude plugin slugs.
			 *
			 * @param  array  $slugs  Slugs of excluded plugins.
			 *
			 * @since 3.1.0
			 */
			$excluded_slugs = apply_filters( 'wd_scan_excluded_plugin_slugs', array() );
			$excluded_slugs = ! is_array( $excluded_slugs ) ? (array) $excluded_slugs : $excluded_slugs;

			foreach ( $this->get_plugins() as $slug => $item ) {
				if ( is_object( $model ) && $model->is_issue_ignored( $slug ) ) {
					continue;
				}
				$base_slug = $this->get_plugin_slug_by( $slug );
				if ( in_array( $base_slug, $excluded_slugs, true ) ) {
					continue;
				}
				// Use keys with the first capital letter to match default plugin header keys.
				$items[ $base_slug ] = array(
					'Name'    => $item['Name'],
					'Version' => $item['Version'],
					'Slug'    => $slug,
				);
			}

			update_site_option( self::PLUGINS_ACTIONED, $items );
		}

		return $items;
	}

	/**
	 * Does the list of actioned plugins exist and no empty?
	 *
	 * @param array|false $actioned_plugins The actioned plugins.
	 *
	 * @return bool
	 */
	public static function are_actioned_plugins( $actioned_plugins ): bool {
		return is_array( $actioned_plugins ) && array() !== $actioned_plugins;
	}

	/**
	 * Get the lock filename.
	 *
	 * @return string
	 */
	public function get_lock_filename(): string {
		return $this->lock_filename;
	}
}
