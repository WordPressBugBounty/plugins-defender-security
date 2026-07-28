<?php
/**
 * Handles interaction with the database for scans.
 *
 * @package WP_Defender\Model
 */

namespace WP_Defender\Model;

use WP_Error;
use DateTime;
use Countable;
use DateTimeZone;
use WP_Defender\DB;
use WP_Defender\Traits\IO;
use WP_Defender\Traits\Formats;
use WP_Defender\Component\Error_Code;
use WP_Defender\Behavior\Scan_Item\Core_Integrity;
use WP_Defender\Behavior\Scan_Item\Plugin_Integrity;
use WP_Defender\Behavior\Scan_Item\Abandoned_Result;

/**
 * Model for scan table.
 */
class Scan extends DB {

	use IO;
	use Formats;

	public const STATUS_INIT = 'init', STATUS_ERROR = 'error', STATUS_FINISH = 'finish';
	// Default state.
	public const STEP_GATHER_INFO = 'gather_info', STEP_ABANDONED_PLUGIN_CHECK = 'abandoned_plugin_check';
	public const STEP_CHECK_CORE  = 'core_integrity_check', STEP_CHECK_PLUGIN = 'plugin_integrity_check';
	public const STEP_VULN_CHECK  = 'vuln_check', STEP_SUSPICIOUS_CHECK = 'suspicious_check';
	public const IGNORE_INDEXER   = 'defender_scan_ignore_index';

	/**
	 * Table name.
	 *
	 * @var string
	 */
	protected $table = 'defender_scan';

	/**
	 * Active scan type across page loads.
	 */
	public const OPTION_SCAN_TYPE = 'wpdef_active_scan_type';

	/**
	 * Any valid relative Date and Time formats.
	 *
	 * @link  https://www.php.net/manual/en/datetime.formats.relative.php
	 * @since 2.6.1
	 * @var string
	 */
	public const THRESHOLD_PERIOD = '3 hours ago';

	/**
	 * Constant to notate the scan is idle or crossed the threshold limit.
	 *
	 * @since 2.6.1
	 * @var string
	 */
	public const STATUS_IDLE = 'idle';

	/**
	 * Primary key column.
	 *
	 * @var int
	 * @defender_property
	 */
	public $id;
	/**
	 * Table column for the status.
	 * Possible values are,
	 *  - init
	 *  - error
	 *  - finish
	 *  - gather_fact
	 *  - core_integrity_check
	 *  - plugin_integrity_check
	 *  - vuln_check
	 *  - suspicious_check
	 *  - idle
	 *  - abandoned_plugin_check
	 *
	 * @var string
	 * @defender_property
	 */
	public $status;
	/**
	 * Table column for the start time.
	 *
	 * @var string
	 * @defender_property
	 */
	public $date_start;

	/**
	 * Table column for the current percentage.
	 *
	 * @var int
	 * @defender_property
	 */
	public $percent = 0;

	/**
	 * Table column for the total tasks.
	 * Store how many tasks we process.
	 *
	 * @var int
	 * @defender_property
	 */
	public $total_tasks = 0;

	/**
	 * Table column for the current task checkpoint.
	 *
	 * @var string
	 * @defender_property
	 */
	public $task_checkpoint = '';

	/**
	 * Table column for the end time.
	 *
	 * @var string
	 * @defender_property
	 */
	public $date_end;

	/**
	 * Table column for the scan trigger by report schedule.
	 *
	 * @var bool
	 * @defender_property
	 */
	public $is_automation = false;

	/**
	 * Prepare and fetch issues with various counts.
	 * This method retrieves active and ignored issues based on the specified type, page, and items per page.
	 * It prepares a detailed summary including total counts and filtered counts by type.
	 *
	 * @param  int|null    $per_page  Number of items per page. Default null.
	 * @param  int|null    $paged  Current page number. Default null.
	 * @param  string|null $type  Type of issues to filter. Default null.
	 *
	 * @return array An array containing the list of issues, ignored issues, and various count statistics.
	 *     - 'ignored' (array): List of ignored issues.
	 *     - 'issues' (array): List of active issues.
	 *     - 'count_total' (int): Total number of active issues.
	 *     - 'count_issues' (int): Total number of issues of all types.
	 *     - 'count_issues_filtered' (int): Number of issues filtered by type.
	 *     - 'count_ignored' (int): Total number of ignored issues.
	 *     - 'count_core' (int): Number of core integrity issues.
	 *     - 'count_plugin' (int): Number of plugin check issues.
	 *     - 'count_malware' (int): Number of suspicious/malware issues.
	 *     - 'count_vuln' (int): Number of vulnerability issues.
	 *     - 'count_outdated_plugin' (int): Number of outdated plugin issues.
	 *     - 'count_closed_plugin' (int): Number of closed plugin issues.
	 * @param  string|null $scenario  Pagination scenario: 'issue', 'ignored', or null (paginate both).
	 */
	public function prepare_issues( $per_page = null, $paged = null, $type = null, $scenario = null ): array {
		if ( 'issue' === $scenario ) {
			// Paginate active issues only; ignored items are not needed for this tab.
			$ignored_models = array();
			$active_models  = $this->get_issues( $type, Scan_Item::STATUS_ACTIVE, $per_page, $paged );
		} elseif ( 'ignored' === $scenario ) {
			// Paginate ignored items only; active issues are not needed for this tab.
			$ignored_models = $this->get_issues( $type, Scan_Item::STATUS_IGNORE, $per_page, $paged );
			$active_models  = array();
		} else {
			// Default (initial load): paginate both statuses with the same page.
			$ignored_models = $this->get_issues( $type, Scan_Item::STATUS_IGNORE, $per_page, $paged );
			$active_models  = $this->get_issues( $type, Scan_Item::STATUS_ACTIVE, $per_page, $paged );
		}

		$issues                = array();
		$ignored               = array();
		$count_total           = count( $active_models );
		$count_issues_filtered = 0;

		$scan_item_group_total = wd_di()->get( Scan_Item::class )->get_types_total( $this->id, Scan_Item::STATUS_ACTIVE );

		$count_issues  = isset( $scan_item_group_total['all'] ) ?
			$scan_item_group_total['all'] : 0;
		$count_core    = isset( $scan_item_group_total[ Scan_Item::TYPE_INTEGRITY ] ) ?
			$scan_item_group_total[ Scan_Item::TYPE_INTEGRITY ] : 0;
		$count_plugin  = isset( $scan_item_group_total[ Scan_Item::TYPE_PLUGIN_CHECK ] ) ?
			$scan_item_group_total[ Scan_Item::TYPE_PLUGIN_CHECK ] : 0;
		$count_malware = isset( $scan_item_group_total[ Scan_Item::TYPE_SUSPICIOUS ] ) ?
			$scan_item_group_total[ Scan_Item::TYPE_SUSPICIOUS ] : 0;
		$count_vuln    = isset( $scan_item_group_total[ Scan_Item::TYPE_VULNERABILITY ] ) ?
			$scan_item_group_total[ Scan_Item::TYPE_VULNERABILITY ] : 0;
		// New counts since v5.5.0.
		$count_outdated_plugin = isset( $scan_item_group_total[ Scan_Item::TYPE_PLUGIN_OUTDATED ] ) ?
			$scan_item_group_total[ Scan_Item::TYPE_PLUGIN_OUTDATED ] : 0;
		$count_closed_plugin   = isset( $scan_item_group_total[ Scan_Item::TYPE_PLUGIN_CLOSED ] ) ?
			$scan_item_group_total[ Scan_Item::TYPE_PLUGIN_CLOSED ] : 0;

		$scan_item_ignore_total = wd_di()->get( Scan_Item::class )->get_types_total( $this->id, Scan_Item::STATUS_IGNORE );

		$count_ignored = isset( $scan_item_ignore_total['all'] ) ?
			$scan_item_ignore_total['all'] : 0;

		foreach ( $ignored_models as $model ) {
			$ignored[] = $model->to_array();
		}
		foreach ( $active_models as $active_model ) {
			$issues[] = $active_model->to_array();

			// We will now count all issues again by type filter for pagination usage.
			if ( null !== $type && 'all' !== $type ) {
				if ( is_array( $type ) && in_array( $active_model->type, $type, true ) ) {
					++$count_issues_filtered;
				} elseif ( $type === $active_model->type ) {
					++$count_issues_filtered;
				}
			} else {
				++$count_issues_filtered;
			}
		}

		return array(
			'ignored'               => $ignored,
			'issues'                => $issues,
			'count_total'           => $count_total,
			'count_issues'          => $count_issues,
			'count_issues_filtered' => $count_issues_filtered,
			'count_ignored'         => $count_ignored,
			'count_core'            => $count_core,
			'count_plugin'          => $count_plugin,
			'count_malware'         => $count_malware,
			'count_vuln'            => $count_vuln,
			'count_outdated_plugin' => $count_outdated_plugin,
			'count_closed_plugin'   => $count_closed_plugin,
		);
	}

	/**
	 * Get abandoned plugin types.
	 *
	 * @return array
	 */
	public static function get_abandoned_types(): array {
		return array(
			Scan_Item::TYPE_PLUGIN_CLOSED,
			Scan_Item::TYPE_PLUGIN_OUTDATED,
		);
	}

	/**
	 * Retrieves scan issues based on provided filters.
	 * This method fetches scan items related to the current object's ID,
	 * filtered by type, status, and pagination parameters.
	 * The retrieved items are then attached with relevant behaviors based on their type.
	 *
	 * @param  string|array|null $type  Optional. The type of scan issue to filter by.
	 *                                  Accepts 'vulnerability', 'integrity', 'plugin_check', or 'suspicious'. Default null.
	 * @param  string|null       $status  Optional. The status of the scan issue to filter by.
	 *                                    Accepts 'ignore' or 'active'. Default null.
	 * @param  int|null          $per_page  Optional. The number of items to retrieve per page. Default null.
	 * @param  int|null          $paged  Optional. The page number of items to retrieve. Default null.
	 *
	 * @return array An array of scan issue models with attached behaviors.
	 */
	public function get_issues( $type = null, $status = null, $per_page = null, $paged = null ) {
		$orm     = self::get_orm();
		$builder = $orm->get_repository( Scan_Item::class )
						->where( 'parent_id', $this->id );

		$valid_types = Scan_Item::get_all_scan_types();
		if ( null !== $type ) {
			if ( is_array( $type ) ) {
				$filtered_types = array_intersect( $type, $valid_types );
				if ( array() !== $filtered_types ) {
					$builder->where( 'type', 'IN', $filtered_types );
				}
			} elseif ( in_array( $type, $valid_types, true ) ) {
				$builder->where( 'type', $type );
			} elseif ( 'all' === $type ) {
				$builder->where( 'type', 'IN', $valid_types );
			}
		} else {
			// Include all possible types.
			$builder->where( 'type', 'IN', $valid_types );
		}

		if ( null !== $status ) {
			if ( in_array( $status, Scan_Item::get_all_scan_statuses(), true ) ) {
				$builder->where( 'status', $status );
			}
		}

		if ( is_int( $per_page ) && is_int( $paged ) && $per_page > 0 && $paged > 0 ) {
			$offset = ( $paged - 1 ) * $per_page;
			$builder->limit( $per_page, $offset );
		}

		$models = $builder->get();

		static $behavior_map = array(
			Scan_Item::TYPE_INTEGRITY       => Core_Integrity::class,
			Scan_Item::TYPE_PLUGIN_CHECK    => Plugin_Integrity::class,
			Scan_Item::TYPE_PLUGIN_CLOSED   => Abandoned_Result::class,
			Scan_Item::TYPE_PLUGIN_OUTDATED => Abandoned_Result::class,
		);

		foreach ( $models as $model ) {
			if ( isset( $behavior_map[ $model->type ] ) ) {
				$behavior_class = $behavior_map[ $model->type ];
				$model->attach_behavior( $behavior_class, $behavior_class );
			}
		}

		return $models;
	}

	/**
	 * Counts the number of Scan_Item models that match the given type and status.
	 *
	 * @param  string|array|null $type  The type(s) of Scan_Item to count.
	 * @param  string|null       $status  The status of the Scan_Item to count. Must be one of the following:
	 *                                    Scan_Item::STATUS_IGNORE, Scan_Item::STATUS_ACTIVE.
	 *
	 * @return mixed The number of matching Scan_Item models.
	 */
	public function count( $type = null, $status = null ) {
		$orm     = self::get_orm();
		$builder = $orm->get_repository( Scan_Item::class )->where( 'parent_id', $this->id );

		$valid_types = Scan_Item::get_all_scan_types();

		if ( is_array( $type ) ) {
			$filtered_types = array_intersect( $type, $valid_types );
			if ( array() !== $filtered_types ) {
				$builder->where( 'type', 'IN', $filtered_types );
			}
		} elseif (
			! is_null( $type )
			&& in_array( $type, $valid_types, true )
		) {
			$builder->where( 'type', $type );
		} elseif ( is_null( $type ) || 'all' === $type ) {
			$builder->where( 'type', 'IN', $valid_types );
		}

		if (
			! is_null( $status )
			&& in_array( $status, Scan_Item::get_all_scan_statuses(), true )
		) {
			$builder->where( 'status', $status );
		}

		return $builder->count();
	}

	/**
	 * Allow a specific issue by updating its status and removing it from the global ignore indexer.
	 *
	 * @param int $id The ID of the issue to Allow.
	 *
	 * @return bool
	 */
	public function unignore_issue( $id ): bool {
		$issue = $this->get_issue( $id );
		if ( ! is_object( $issue ) ) {
			return false;
		}
		// Check if the current issue already exists in the Issues list, there is no need to add a duplicate.
		$current_issue_arr = $issue->to_array();
		foreach ( $this->get_issues( null, Scan_Item::STATUS_ACTIVE ) as $active_issue ) {
			$active_issue_arr = $active_issue->to_array();
			if ( $issue->type === $active_issue_arr['type'] && $current_issue_arr['file_name'] === $active_issue_arr['file_name'] ) {
				return false;
			}
		}

		$issue->status = Scan_Item::STATUS_ACTIVE;
		$issue->save();

		$ignore_lists = get_site_option( self::IGNORE_INDEXER, array() );
		$data         = $issue->raw_data;
		if ( isset( $data['file'] ) ) {
			unset( $ignore_lists[ array_search( $data['file'], $ignore_lists, true ) ] );
		} elseif ( isset( $data['slug'] ) ) {
			unset( $ignore_lists[ array_search( $data['slug'], $ignore_lists, true ) ] );
		}
		$this->update_ignore_list( $ignore_lists );

		return true;
	}

	/**
	 * Check if a slug is ignored, we use a global indexer, so we can check while
	 * the active scan is running.
	 *
	 * @param  string $slug The path to file.
	 *
	 * @return bool
	 */
	public function is_issue_ignored( $slug ) {
		$ignore_lists = get_site_option( self::IGNORE_INDEXER, array() );

		return in_array( $slug, $ignore_lists, true );
	}

	/**
	 * Ignore a specific issue by updating its status and adding it to the global ignored indexer.
	 *
	 * @param int $id The ID of the issue to ignore.
	 *
	 * @return bool
	 */
	public function ignore_issue( $id ): bool {
		$issue = $this->get_issue( $id );
		if ( ! is_object( $issue ) ) {
			return false;
		}
		// Check if the current issue already exists in the Ignored list, there is no need to add a duplicate.
		$current_issue_arr = $issue->to_array();
		foreach ( $this->get_issues( null, Scan_Item::STATUS_IGNORE ) as $ignore_issue ) {
			$ignore_issue_arr = $ignore_issue->to_array();
			if ( $current_issue_arr['type'] === $ignore_issue_arr['type'] &&
				$current_issue_arr['full_path'] === $ignore_issue_arr['full_path']
			) {
				return false;
			}
		}

		$issue->status = Scan_Item::STATUS_IGNORE;
		$issue->save();

		// Add this into a global ignored index and update the ignored list.
		$ignore_lists   = get_site_option( self::IGNORE_INDEXER, array() );
		$ignore_lists[] = $current_issue_arr['full_path'];
		$this->update_ignore_list( $ignore_lists );

		return true;
	}

	/**
	 * Retrieves a Scan_Item object based on the given ID.
	 *
	 * @param  int $id  The ID of the Scan_Item.
	 *
	 * @return Scan_Item|null The Scan_Item object if found, null otherwise.
	 */
	public function get_issue( $id ) {
		$orm   = self::get_orm();
		$model = $orm->get_repository( Scan_Item::class )
			->where( 'id', $id )
			->first();

		if ( is_object( $model ) ) {
			static $behavior_map = array(
				Scan_Item::TYPE_INTEGRITY       => Core_Integrity::class,
				Scan_Item::TYPE_PLUGIN_CHECK    => Plugin_Integrity::class,
				Scan_Item::TYPE_PLUGIN_CLOSED   => Abandoned_Result::class,
				Scan_Item::TYPE_PLUGIN_OUTDATED => Abandoned_Result::class,
			);

			if ( isset( $behavior_map[ $model->type ] ) ) {
				$behavior_class = $behavior_map[ $model->type ];
				$model->attach_behavior( $behavior_class, $behavior_class );
			}
		}

		return $model;
	}

	/**
	 * Remove an issue, this will happen when that issue is resolve, or the file link to this issue get deleted.
	 *
	 * @param  int $id  The ID of the issue to remove.
	 */
	public function remove_issue( $id ) {
		$orm = self::get_orm();
		$orm->get_repository( Scan_Item::class )->delete( array( 'id' => $id ) );
	}

	/**
	 * Get all scan types where the target entity is the whole folder.
	 *
	 * @return array
	 */
	private function get_scan_types_for_whole_folder(): array {
		return array(
			Scan_Item::TYPE_VULNERABILITY,
			Scan_Item::TYPE_PLUGIN_CLOSED,
			Scan_Item::TYPE_PLUGIN_OUTDATED,
		);
	}

	/**
	 * Remove other Scan issue(-s) for the same file.
	 *
	 * @param string $path The path to file.
	 * @param string $type The type of scan issue.
	 *
	 * @return void
	 */
	public function remove_related_issue_by( string $path, string $type ) {
		$orm     = self::get_orm();
		$builder = $orm->get_repository( Scan_Item::class )
			->where( 'parent_id', $this->id );
		// No needs to separate check VULNERABILITY, PLUGIN_CLOSED and PLUGIN_OUTDATED because we do not delete per file for such types.
		$arr_excluded_types = $this->get_scan_types_for_whole_folder();
		if ( '' !== $path ) {
			$arr_excluded_types[] = $type;
		}
		$builder->where( 'type', 'NOT IN', $arr_excluded_types );
		$models = $builder->get();

		if ( is_array( $models ) && array() !== $models ) {
			foreach ( $models as $model ) {
				if ( isset( $model->raw_data['file'] ) && $model->raw_data['file'] === $path ) {
					$this->remove_issue( $model->id );
				}
			}
		}
	}

	/**
	 * Converts the object to an array representation.
	 *
	 * @param  int|null    $per_page  The number of items to retrieve per page. Default null.
	 * @param  int|null    $paged     The page number of items to retrieve. Default null.
	 * @param  string|null $type      The type of scan issue to filter by. Default null.
	 * @param  string|null $scenario  Pagination scenario ('issue', 'ignored', or null). Default null.
	 *
	 * @return array The array representation of the object.
	 */
	public function to_array( $per_page = null, $paged = null, $type = null, $scenario = null ) {
		if ( ! in_array( $this->status, self::get_inactive_statuses(), true ) ) {

			return array(
				'status'          => $this->status,
				'status_text'     => $this->get_status_text(),
				'percent'         => $this->percent,
				'task_checkpoint' => $this->task_checkpoint,
				// This only for hub, when a scan running.
				'count'           => array( 'total' => 0 ),
			);
		} elseif ( in_array( $this->status, array( self::STATUS_FINISH, self::STATUS_IDLE ), true ) ) {
			$total_filtered        = (int) $this->count( $type );
			$count_issues_filtered = (int) $this->count( $type, Scan_Item::STATUS_ACTIVE );
			$total_count           = (int) $this->count( null, Scan_Item::STATUS_ACTIVE );

			$scan_item_ignore_total = wd_di()->get( Scan_Item::class )
				->get_types_total( $this->id, Scan_Item::STATUS_IGNORE );

			$count_ignored          = isset( $scan_item_ignore_total['all'] ) ?
				$scan_item_ignore_total['all'] : 0;
			$count_ignored_filtered = (int) $this->count( $type, Scan_Item::STATUS_IGNORE );

			$total_issue_pages   = 1;
			$total_ignored_pages = 1;
			if ( is_int( $per_page ) && $per_page > 0 ) {
				$total_issue_pages   = max( 1, (int) ceil( $count_issues_filtered / $per_page ) );
				$total_ignored_pages = max( 1, (int) ceil( $count_ignored_filtered / $per_page ) );
			}

			// On the initial load both tabs are fetched, so either tab can require pagination.
			if ( 'ignored' === $scenario ) {
				$relevant_count = $count_ignored_filtered;
			} elseif ( 'issue' === $scenario ) {
				$relevant_count = $count_issues_filtered;
			} else {
				$relevant_count = max( $count_issues_filtered, $count_ignored_filtered );
			}

			if ( is_int( $per_page ) && $per_page > 0 && $relevant_count > $per_page ) {
				$data = $this->prepare_issues( $per_page, $paged, $type, $scenario );
			} else {
				$data = $this->prepare_issues( null, null, $type, $scenario );
			}

			$scan_item_group_total = wd_di()->get( Scan_Item::class )
				->get_types_total( $this->id, Scan_Item::STATUS_ACTIVE );

			$count_issues  = isset( $scan_item_group_total['all'] ) ?
				$scan_item_group_total['all'] : 0;
			$count_core    = isset( $scan_item_group_total[ Scan_Item::TYPE_INTEGRITY ] ) ?
				$scan_item_group_total[ Scan_Item::TYPE_INTEGRITY ] : 0;
			$count_plugin  = isset( $scan_item_group_total[ Scan_Item::TYPE_PLUGIN_CHECK ] ) ?
				$scan_item_group_total[ Scan_Item::TYPE_PLUGIN_CHECK ] : 0;
			$count_malware = isset( $scan_item_group_total[ Scan_Item::TYPE_SUSPICIOUS ] ) ?
				$scan_item_group_total[ Scan_Item::TYPE_SUSPICIOUS ] : 0;
			$count_vuln    = isset( $scan_item_group_total[ Scan_Item::TYPE_VULNERABILITY ] ) ?
				$scan_item_group_total[ Scan_Item::TYPE_VULNERABILITY ] : 0;
			// New counts since v5.5.0.
			$count_outdated_plugin = isset( $scan_item_group_total[ Scan_Item::TYPE_PLUGIN_OUTDATED ] ) ?
				$scan_item_group_total[ Scan_Item::TYPE_PLUGIN_OUTDATED ] : 0;
			$count_closed_plugin   = isset( $scan_item_group_total[ Scan_Item::TYPE_PLUGIN_CLOSED ] ) ?
				$scan_item_group_total[ Scan_Item::TYPE_PLUGIN_CLOSED ] : 0;

			return array(
				'status'          => $this->status,
				'issues_items'    => $data['issues'],
				'ignored_items'   => $data['ignored'],
				'last_scan'       => $this->date_start
					? sprintf(
						/* translators: %s: human-readable time difference, e.g. "5 minutes" */
						__( '%s ago', 'defender-security' ),
						human_time_diff( strtotime( $this->date_start ) )
					)
					: '',
				'count'           => array(
					'total'                  => is_array( $data['issues'] ) || $data['issues'] instanceof Countable ? count( $data['issues'] ) : 0,
					'total_filtered'         => $total_filtered,
					'issues_total'           => $count_issues,
					'issues_total_filtered'  => $count_issues_filtered,
					'ignored_total'          => $count_ignored,
					'ignored_total_filtered' => $count_ignored_filtered,
					'core'                   => $count_core + $count_plugin,
					'content'                => $count_malware,
					'vuln'                   => $count_vuln,
					'outdated_plugin'        => $count_outdated_plugin,
					'closed_plugin'          => $count_closed_plugin,
				),
				'paging'          => array(
					'issue'    => array(
						'paged'       => $paged,
						'total_pages' => $total_issue_pages,
					),
					'ignored'  => array(
						'paged'       => $paged,
						'total_pages' => $total_ignored_pages,
					),
					'per_page' => $per_page,
				),
				'task_checkpoint' => $this->task_checkpoint,
			);
		} else {
			return array();
		}
	}

	/**
	 * Creates a new record in the database.
	 *
	 * @param  bool $from_report  Is this a scan from report.
	 *
	 * @return bool|WP_Error|Scan
	 */
	public static function create( $from_report = false ) {
		$orm    = self::get_orm();
		$active = self::get_active();
		if ( is_object( $active ) ) {
			return new WP_Error( Error_Code::INVALID, esc_html__( 'A scan is already in progress.', 'defender-security' ) );
		}
		$model                = new Scan();
		$model->status        = self::STATUS_INIT;
		$model->date_start    = gmdate( 'Y-m-d H:i:s' );
		$model->date_end      = gmdate( 'Y-m-d H:i:s' );
		$model->is_automation = $from_report;

		$orm->save( $model );

		return $model;
	}

	/**
	 * Delete current scan.
	 *
	 * @param  int|null $id  Table primary key id.
	 */
	public function delete( $id = null ) {
		if ( ! $this->is_positive_int( $id ) ) {
			$id = $this->id;
		}

		// Delete all the related result items.
		$orm = self::get_orm();

		$orm->get_repository( Scan_Item::class )->delete(
			array( 'parent_id' => $id )
		);

		$orm->get_repository( self::class )->delete(
			array( 'id' => $id )
		);
	}

	/**
	 * Get the inactive scan statuses.
	 *
	 * @return array
	 */
	public static function get_inactive_statuses(): array {
		return array(
			self::STATUS_FINISH,
			self::STATUS_ERROR,
			self::STATUS_IDLE,
		);
	}

	/**
	 * Get the current active scan if any.
	 *
	 * @return self|null
	 */
	public static function get_active() {
		$orm = self::get_orm();

		return $orm->get_repository( self::class )
			->where( 'status', 'NOT IN', self::get_inactive_statuses() )
			->first();
	}

	/**
	 * Check if the current state is Core integrity.
	 *
	 * @return self|null
	 */
	public static function get_core_check() {
		$orm = self::get_orm();

		return $orm->get_repository( self::class )
			->where( 'status', self::STEP_CHECK_CORE )
			->first();
	}

	/**
	 * Get last result.
	 *
	 * @return self|null
	 */
	public static function get_last() {
		$orm = self::get_orm();

		return $orm->get_repository( self::class )
			->where( 'status', 'IN', array( self::STATUS_FINISH, self::STATUS_IDLE ) )
			->order_by( 'id', 'desc' )
			->first();
	}

	/**
	 * Get last results.
	 *
	 * @return array
	 */
	public static function get_last_all() {
		$orm = self::get_orm();

		return $orm->get_repository( self::class )
			->where( 'status', 'IN', array( self::STATUS_FINISH, self::STATUS_IDLE ) )
			->order_by( 'id', 'desc' )
			->get();
	}

	/**
	 * Adds an item to the scan.
	 *
	 * @param  mixed  $type  The type of the item.
	 * @param  mixed  $data  The data of the item.
	 * @param  string $status  The status of the item. Default is Scan_Item::STATUS_ACTIVE.
	 *
	 * @return bool Returns true if the item is successfully added, false otherwise.
	 */
	public function add_item( $type, $data, $status = Scan_Item::STATUS_ACTIVE ) {
		$model            = new Scan_Item();
		$model->type      = $type;
		$model->parent_id = $this->id;
		$model->raw_data  = $data;
		$model->status    = $status;
		$ret              = $model->save();

		return $ret;
	}

	/**
	 * Carry previously-ignored issues forward into this scan, without duplicating
	 * any that were already re-detected as active in the current pass.
	 *
	 * @param  array|string $type       Scan item type(s) the issues belong to.
	 * @param  array        $issues     Scan_Item objects (status ignore) to carry forward.
	 * @param  string       $key_field  Field inside raw_data used to match issues, e.g. 'file' or 'slug'.
	 */
	public function carry_forward_ignored_issues( $type, array $issues, string $key_field ) {
		if ( array() === $issues ) {
			return;
		}

		$active_by_key = array();
		foreach ( $this->get_issues( $type, Scan_Item::STATUS_ACTIVE ) as $active_item ) {
			$key = $active_item->raw_data[ $key_field ] ?? null;
			if ( null !== $key ) {
				$active_by_key[ $key ] = $active_item;
			}
		}

		foreach ( $issues as $issue ) {
			$key = $issue->raw_data[ $key_field ] ?? null;
			if ( null !== $key && isset( $active_by_key[ $key ] ) ) {
				// Already re-detected as active in this scan; keep it ignored, don't duplicate.
				$active_by_key[ $key ]->status = Scan_Item::STATUS_IGNORE;
				$active_by_key[ $key ]->save();
				continue;
			}
			$this->add_item( $issue->type, $issue->raw_data, Scan_Item::STATUS_IGNORE );
		}
	}

	/**
	 * Persist the current scan type ('deep' or 'malware') in a site option.
	 *
	 * @param  string $type  Scan type identifier. Accepts 'deep' or 'malware'.
	 * @return void
	 */
	public static function set_scan_type( string $type ): void {
		update_site_option( self::OPTION_SCAN_TYPE, $type );
	}

	/**
	 * Retrieve the persisted scan type. Returns 'malware' when nothing is stored.
	 *
	 * @return string
	 */
	public static function get_scan_type(): string {
		return (string) get_site_option( self::OPTION_SCAN_TYPE, 'malware' );
	}

	/**
	 * Delete the persisted scan type (called on scan cancel or after returning
	 * the finished-scan response so the option does not linger).
	 *
	 * @return void
	 */
	public static function clear_scan_type(): void {
		delete_site_option( self::OPTION_SCAN_TYPE );
	}

	/**
	 * Return current status as readable string.
	 *
	 * @return string
	 */
	public function get_status_text() {
		switch ( $this->status ) {
			case self::STATUS_INIT:
				return 'deep' === self::get_scan_type() ? wp_strip_all_tags( __( 'Gathering information...', 'defender-security' ) ) : wp_strip_all_tags( __( 'Initializing...', 'defender-security' ) );
			case self::STEP_GATHER_INFO:
				return wp_strip_all_tags( __( 'Gathering information...', 'defender-security' ) );
			case self::STEP_CHECK_CORE:
				return wp_strip_all_tags( __( 'Analyzing WordPress Core...', 'defender-security' ) );
			case self::STEP_CHECK_PLUGIN:
				return wp_strip_all_tags( __( 'Analyzing WordPress Plugins...', 'defender-security' ) );
			case self::STEP_VULN_CHECK:
				return wp_strip_all_tags( __( 'Checking for vulnerabilities in plugins and themes...', 'defender-security' ) );
			case self::STEP_SUSPICIOUS_CHECK:
				return wp_strip_all_tags( __( 'Analyzing WordPress Content...', 'defender-security' ) );
			case self::STEP_ABANDONED_PLUGIN_CHECK:
				return wp_strip_all_tags( __( 'Checking for outdated & removed plugins...', 'defender-security' ) );
			default:
				return wp_strip_all_tags( __( 'Scanning...', 'defender-security' ) );
		}
	}

	/**
	 * Calculates the percentage of a task based on its progress and position.
	 *
	 * @param  int $task_percent  The percentage of the task completed.
	 * @param  int $pos  The position of the task in the list of tasks. Default is 1.
	 *
	 * @return float The calculated percentage.
	 */
	public function calculate_percent( $task_percent, $pos = 1 ) {
		$task_max      = ( 0 !== $this->total_tasks ) ? ( 100 / $this->total_tasks ) : 0;
		$task_base     = $task_max * ( $pos - 1 );
		$micro         = $task_percent * $task_max / 100;
		$this->percent = (int) round( $task_base + $micro, 2 );
		if ( $this->percent > 100 ) {
			$this->percent = 100;
		}

		return $this->percent;
	}

	/**
	 * Get list of whitelisted files.
	 *
	 * @return array
	 */
	private function whitelisted_files() {
		return array(
			// Configuration files.
			'user.ini',
			'php.ini',
			'robots.txt',
			'.htaccess',
			'nginx.conf',
			// Hidden system files and directories.
			'.well-known',
			'.idea',
			'.DS_Store',
			'.svn',
			'.git',
			'.quarantine',
			'.tmb',
			'.vscode',
		);
	}

	/**
	 * Check if a slug is whitelisted.
	 *
	 * @param  string $slug The path to file.
	 *
	 * @return bool
	 */
	public function is_issue_whitelisted( string $slug ): bool {
		$whitelisted_files = $this->whitelisted_files();
		foreach ( $whitelisted_files as $file ) {
			if ( false !== stristr( $slug, $file ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Update ignore list.
	 *
	 * @param  array $ignore_lists  Items to be added to the ignore list.
	 */
	public function update_ignore_list( $ignore_lists ) {
		$ignore_lists = array_unique( $ignore_lists );
		$ignore_lists = array_filter( $ignore_lists, 'strlen' );
		update_site_option( self::IGNORE_INDEXER, $ignore_lists );
	}

	/**
	 * Get the threshold time limit as DateTime object.
	 *
	 * @return DateTime Threshold time limit as DateTime object.
	 */
	public function threshold_date_time_object() {
		$timezone = new DateTimeZone( 'UTC' );

		/**
		 * Filter to override scan threshold period.
		 *
		 * @param  string  $threshold  Any valid relative Date and Time formats.
		 *
		 * @link  https://www.php.net/manual/en/datetime.formats.relative.php
		 * @since 2.6.1
		 */
		$threshold = apply_filters( 'wd_scan_threshold', self::THRESHOLD_PERIOD );

		return new DateTime( $threshold, $timezone );
	}

	/**
	 * Threshold time limit in mysql string format.
	 *
	 * @return string Threshold time limit as mysql string format.
	 */
	public function threshold_date_time_mysql() {
		$type                       = 'Y-m-d H:i:s';
		$threshold_date_time_object = $this->threshold_date_time_object();
		$mysql_format               = $threshold_date_time_object->format( $type );

		return $mysql_format;
	}

	/**
	 * Get the idle scan if any.
	 *
	 * @return self|null
	 */
	public function get_idle() {
		$orm = self::get_orm();

		$mysql_date = $this->threshold_date_time_mysql();

		return $orm->get_repository( self::class )
			->where( 'status', 'NOT IN', array( self::STATUS_FINISH, self::STATUS_ERROR ) )
			->where( 'date_start', '<', $mysql_date )
			->first();
	}

	/**
	 * Delete all idle scan and scan items
	 *
	 * @since 2.6.1
	 */
	public function delete_idle() {
		$idle_scans = self::get_orm()
			->get_repository( self::class )
			->where( 'status', self::STATUS_IDLE )
			->get();

		foreach ( $idle_scans as $idle_scan ) {
			$this->delete( $idle_scan->id );
		}
	}

	/**
	 * Verify positive integer or not.
	 *
	 * @param  mixed $id  Argument to check for a positive number.
	 *
	 * @return bool Return true on positive integer else false.
	 * @since 2.6.1
	 */
	private function is_positive_int( $id ): bool {
		return is_int( $id ) && $id > 0;
	}
}
