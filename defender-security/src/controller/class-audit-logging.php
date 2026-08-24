<?php
/**
 * Handle Audit Logging module.
 *
 * @package WP_Defender\Controller
 */

namespace WP_Defender\Controller;

use DateTime;
use Exception;
use DateInterval;
use WP_Defender\Event;
use Calotes\Helper\HTTP;
use WP_Defender\Traits\User;
use Calotes\Component\Request;
use Calotes\Component\Response;
use Calotes\Helper\Array_Cache;
use WP_Defender\Traits\Formats;
use WP_Defender\Component\Audit;
use WP_Defender\Model\Audit_Log;
use WP_Defender\Behavior\WPMUDEV;
use WP_Defender\Component\Network_Cron_Manager;
use WP_Defender\Model\Notification\Audit_Report;
use WP_Defender\Component\Config\Config_Hub_Helper;
use WP_Defender\Model\Setting\Audit_Logging as Model_Audit_Logging;

/**
 * Handle Audit Logging module.
 */
class Audit_Logging extends Event {

	public const DEFAULT_PER_PAGE = 10;

	use User;
	use Formats;

	/**
	 * The slug identifier for this controller.
	 *
	 * @var string
	 */
	public $slug = 'wdf-logging';

	/**
	 * The model for handling the data.
	 *
	 * @var Model_Audit_Logging
	 */
	public $model;

	/**
	 * Service for handling logic.
	 *
	 * @var Audit|null
	 */
	public ?Audit $service;

	/**
	 * Indicates whether the current installation is a pro version.
	 *
	 * @var bool
	 */
	private $is_pro;

	/**
	 * Initializes the model and service, registers routes, and sets up scheduled events if the model is active.
	 */
	public function __construct() {
		$this->register_page(
			esc_html__( 'Audit Log', 'defender-security' ),
			$this->slug,
			array( $this, 'main_view' ),
			$this->parent_slug
		);
		add_action( 'defender_enqueue_assets', array( $this, 'enqueue_assets' ) );
		$this->model   = wd_di()->get( Model_Audit_Logging::class );
		$this->service = new Audit();
		$this->register_routes();
		$this->is_pro = wd_di()->get( WPMUDEV::class )->is_pro();
		if ( $this->is_active() ) {
			$this->service->enqueue_event_listener();
			add_action( 'shutdown', array( $this, 'cache_audit_logs' ) );

			/**
			 * Network Cron Manager
			 *
			 * @var Network_Cron_Manager $network_cron_manager
			 */
			$network_cron_manager = wd_di()->get( Network_Cron_Manager::class );
			$network_cron_manager->register_callback(
				'audit_clean_up_logs',
				array( $this->service, 'audit_clean_up_logs' ),
				HOUR_IN_SECONDS
			);
		}
	}

	/**
	 * Is there permission to Pro feature?
	 *
	 * @return bool
	 */
	private function is_active(): bool {
		return $this->model->is_active();
	}

	/**
	 * Parses a raw request params array, resolves filters, and fetches audit logs.
	 *
	 * Accepted keys (all optional except date range):
	 *   date_from   — date string or empty (defaults to -7 days midnight).
	 *   date_to     — date string or empty (defaults to today 23:59:59).
	 *   events      — array of event type strings (also accepts key 'event_type' for CSV route).
	 *   username    — login name (also accepts key 'term' for CSV route).
	 *   ip_address  — IP filter string.
	 *   paged       — page number; pass false for unbounded export.
	 *
	 * Returns the resolved user_id via the $user_id out-param so callers can use it for COUNT queries.
	 *
	 * @param  array      $params   Raw request data.
	 * @param  mixed      $paged    Page number or false for all results.
	 * @param  int|string $user_id  Populated with the resolved user ID (out-param).
	 * @param  int        $per_page  Number of logs per page.
	 *
	 * @return array|\WP_Error
	 */
	private function fetch_logs( array $params, $paged, &$user_id = '', $per_page = self::DEFAULT_PER_PAGE ) {
		$date_from_str = $params['date_from'] ?? '';
		$date_to_str   = $params['date_to'] ?? '';
		$date_from     = $date_from_str ? $this->date_string_to_timestamp( $date_from_str ) : strtotime( '-7 days midnight' );
		$date_to       = $date_to_str ? $this->date_string_to_timestamp( $date_to_str, true ) : strtotime( 'today 23:59:59' );
		$events        = $params['events'] ?? ( isset( $params['event_type'] ) && is_array( $params['event_type'] ) ? $params['event_type'] : array() );
		$username      = $params['username'] ?? ( $params['term'] ?? '' );
		$ip_address    = $params['ip_address'] ?? '';
		$user_id       = '';

		if ( '' !== $username ) {
			$user = get_user_by( 'login', $username );
			if ( ! is_object( $user ) ) {
				// Try matching by display_name or email before giving up.
				$users = get_users(
					array(
						'search'         => '*' . $username . '*',
						'search_columns' => array( 'display_name' ),
						'number'         => 1,
					)
				);
				if ( array() === $users ) {
					return array();
				}
				$user_id = $users[0]->ID;
			} else {
				$user_id = $user->ID;
			}
		}

		return $this->service->fetch( $date_from, $date_to, $events, $user_id, $ip_address, $paged, $per_page );
	}

	/**
	 * Prefetches users from a result set then formats each log into an array.
	 *
	 * @param  array $result  Array of Audit_Log objects.
	 *
	 * @return array
	 */
	private function format_log_rows( array $result ): array {
		$user_ids = array_filter(
			array_unique( array_column( $result, 'user_id' ) ),
			static fn ( $user_id ): bool => (int) $user_id > 0
		);
		if ( array() !== $user_ids ) {
			get_users( array( 'include' => $user_ids ) );
		}

		$logs = array();
		foreach ( $result as $item ) {
			$item_user_id = isset( $item->user_id ) ? $item->user_id : 0;
			$item_user_id = ! is_int( $item_user_id ) ? (int) $item_user_id : $item_user_id;
			$logs[]       = array_merge(
				$item->export(),
				array(
					'user'        => $this->get_user_display( $item->user_id ),
					'user_url'    => $item_user_id > 0 ? get_edit_user_link( $item_user_id ) : '',
					'log_date'    => $this->get_date( $item->timestamp ),
					'format_date' => $this->format_date_time( $item->timestamp ),
				)
			);
		}

		return $logs;
	}

	/**
	 * Exports audit logs as a CSV file.
	 *
	 * @return void
	 * @throws Exception If there is an error during export.
	 * @defender_route
	 */
	public function export_as_csv(): void {
		$result = $this->fetch_logs( defender_get_data_from_request( null, 'g' ), false );

		if ( is_wp_error( $result ) ) {
			wp_send_json_error(
				array(
					'message' => $result->get_error_message(),
				)
			);
		}

		// WP_Filesystem class doesn't directly provide a function for opening a stream to php://memory with the 'w' mode.
		$fp      = fopen( 'php://memory', 'w' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen
		$headers = array(
			esc_html__( 'Summary', 'defender-security' ),
			esc_html__( 'Date / Time', 'defender-security' ),
			esc_html__( 'Context', 'defender-security' ),
			esc_html__( 'Type', 'defender-security' ),
			esc_html__( 'IP address', 'defender-security' ),
			esc_html__( 'User', 'defender-security' ),
		);
		fputcsv( $fp, $headers, ',', '"', '\\' );
		foreach ( $this->format_log_rows( $result ) as $row ) {
			$vars = array(
				$row['msg'],
				is_array( $row['timestamp'] )
					? $this->format_date_time( $row['timestamp'][0] )
					: $this->format_date_time( $row['timestamp'] ),
				$row['context'],
				$row['action_type'],
				$row['ip'],
				$row['user'],
			);
			fputcsv( $fp, $vars, ',', '"', '\\' );
		}
		$filename = 'wdf-audit-logs-export-' . wp_date( 'ymdHis' ) . '.csv';
		fseek( $fp, 0 );
		header( 'Content-Type: text/csv' );
		header( 'Content-Disposition: attachment; filename="' . $filename . '";' );
		// Make php send the generated csv lines to the browser.
		fpassthru( $fp );
		exit();
	}

	/**
	 * We'll pass all the event logs into the db handler, so it writes down to db.
	 * Do it in shutdown runtime, so no delay time.
	 *
	 * @return void
	 */
	public function cache_audit_logs(): void {
		$audit = new Audit();
		$audit->log_audit_events();
	}

	/**
	 * Pull the logs from db cached:
	 * - date_from: the start of the date we will run the query, as mysql time format,
	 * - date_to: similar to the above,
	 * others will refer to Audit.
	 *
	 * @param  Request $request  The request object containing filter parameters.
	 *
	 * @return Response
	 * @throws Exception If there is an error during log retrieval.
	 * @defender_route
	 */
	public function pull_logs( Request $request ): Response {
		$data = $request->get_data(
			array(
				'date_from'  => array(
					'type'     => 'string',
					'sanitize' => 'sanitize_text_field',
				),
				'date_to'    => array(
					'type'     => 'string',
					'sanitize' => 'sanitize_text_field',
				),
				'username'   => array(
					'type'     => 'string',
					'sanitize' => 'sanitize_text_field',
				),
				'events'     => array(
					'type'     => 'array',
					'sanitize' => 'sanitize_text_field',
				),
				'ip_address' => array(
					'type'     => 'string',
					'sanitize' => 'sanitize_text_field',
				),
				'paged'      => array(
					'type'     => 'int',
					'sanitize' => 'sanitize_text_field',
				),
				'per_page'   => array(
					'type'     => 'int',
					'sanitize' => 'sanitize_text_field',
				),
			)
		);
		if ( ! isset( $data['date_from'] ) || ! isset( $data['date_to'] ) ) {
			return new Response( false, array( 'message' => esc_html__( 'Invalid data.', 'defender-security' ) ) );
		}
		// Validate date strings before passing to fetch_logs.
		$date_from_check = $this->date_string_to_timestamp( $data['date_from'] );
		$date_to_check   = $this->date_string_to_timestamp( $data['date_to'], true );
		if ( $date_from_check <= 0 || $date_to_check <= 0 ) {
			return new Response( false, array( 'message' => esc_html__( 'Invalid data.', 'defender-security' ) ) );
		}

		$paged    = $data['paged'] ?? 1;
		$per_page = min( 100, max( 1, (int) ( $data['per_page'] ?? self::DEFAULT_PER_PAGE ) ) );
		$result   = $this->fetch_logs( $data, $paged, $user_id, $per_page );

		if ( is_wp_error( $result ) ) {
			return new Response( false, array( 'message' => $result->get_error_message() ) );
		}
		$logs = is_array( $result ) && array() !== $result ? $this->format_log_rows( $result ) : array();

		// @since 3.0.0 If no logs then $count = 0.
		// Skip the COUNT query when the result is a partial page — the fetch already told us the total is count($logs).
		$events     = $data['events'] ?? array();
		$ip_address = $data['ip_address'] ?? '';
		if ( array() === $logs ) {
			$count = 0;
		} elseif ( count( $logs ) < $per_page ) {
			$count = ( $paged - 1 ) * $per_page + count( $logs );
		} else {
			$count = Audit_Log::count( $date_from_check, $date_to_check, $events, $user_id, $ip_address );
		}

		// Get the count for the submitted data.
		return new Response(
			true,
			array(
				'logs'        => $logs,
				'total_items' => $count,
				'total_pages' => ceil( $count / $per_page ),
				'per_page'    => $per_page,
			)
		);
	}

	/**
	 * Generates a human-readable frequency text for audit reports.
	 *
	 * @param  Audit_Report $audit_report  The audit report object.
	 *
	 * @return string Returns the formatted frequency description.
	 */
	public function get_frequency_text( Audit_Report $audit_report ): string {
		$text = '';
		switch ( $audit_report->frequency ) {
			case 'daily':
				$text = ucfirst( $audit_report->day ) . 's at ' . $audit_report->time;
				break;
			case 'weekly':
			case 'monthly':
				$text = ucfirst( $audit_report->frequency ) . ' on ' . ucfirst( $audit_report->day ) . 's at ' . $audit_report->time;
				break;
			default:
				break;
		}

		return $text;
	}

	/**
	 * Enqueues scripts and styles for this page.
	 */
	public function enqueue_assets(): void {
		if ( ! $this->is_page_active() ) {
			return;
		}

		$handle = 'defender-ui-audit-logging';
		wp_enqueue_script(
			$handle,
			WP_DEFENDER_BASE_URL . 'assets/js/audit-logging-ui.js',
			array( 'def-vue', 'def-manifest', 'def-core-ui', 'defender', 'wp-i18n' ),
			DEFENDER_VERSION,
			true
		);
		wp_set_script_translations( $handle, 'wpdef' );

		wp_localize_script(
			$handle,
			'defenderUIData',
			array_merge(
				$this->get_shared_data(),
				$this->data_frontend()
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
	 * Provides a summary of audit logs.
	 *
	 * @return void
	 * @throws Exception If there is an error during summary generation.
	 * @defender_route
	 */
	public function summary(): void {
		$response = $this->is_active() ? $this->summary_data() : array();
		wp_send_json_success( $response );
	}

	/**
	 * Returns an array with summary data for audit logging.
	 *
	 * @param  bool $for_hub  Default 'false' because it's displayed on site summary sections.
	 *
	 * @return array
	 * @throws Exception Emits Exception in case of an error.
	 */
	public function summary_data( bool $for_hub = false ): array {
		$timezone = wp_timezone();

		// Monthly count.
		$date_from   = ( new DateTime( '-30 days', $timezone ) )
			->setTime( 0, 0, 0 )
			->getTimestamp();
		$date_to     = ( new DateTime( 'now', $timezone ) )
			->setTime( 23, 59, 59 )
			->getTimestamp();
		$month_count = Audit_Log::count( $date_from, $date_to );

		// Weekly count.
		$date_from  = ( new DateTime( '-7 days', $timezone ) )
			->setTime( 0, 0, 0 )
			->getTimestamp();
		$week_count = Audit_Log::count( $date_from, $date_to );

		// Daily count. Sync data to the Hub without timezone.
		$date_from = $for_hub ? new DateTime( 'now' ) : new DateTime( 'now', wp_timezone() );
		$date_from = $date_from->modify( '-24 hours' )->setTime( 0, 0, 0 )->getTimestamp();
		$day_count = Audit_Log::count( $date_from, $date_to );

		// Get the last item.
		$last = Audit_Log::get_last();
		if ( is_object( $last ) ) {
			$last = $for_hub
				? $this->persistent_hub_datetime_format( $last->timestamp )
				: $this->format_date_time( $last->timestamp );
		} else {
			$last = 'n/a';
		}

		return array(
			'monthCount' => $month_count,
			'weekCount'  => $week_count,
			'dayCount'   => $day_count,
			'lastEvent'  => $last,
			'report'     => wd_di()->get( Audit_Report::class )->to_string(),
		);
	}

	/**
	 * Save settings.
	 *
	 * @param  Request $request  The request object containing new settings data.
	 *
	 * @return Response
	 * @defender_route
	 */
	public function save_settings( Request $request ): Response {
		$data = $request->get_data_by_model( $this->model );

		$this->model->import( $data );
		if ( $this->model->validate() ) {
			$this->model->save();
		}

		Config_Hub_Helper::set_clear_active_flag();

		return new Response(
			true,
			array_merge(
				$this->data_frontend(),
				array(
					'message'    => esc_html__( 'Your settings have been updated.', 'defender-security' ),
					'auto_close' => true,
					'model'      => $this->model->export(),
				)
			)
		);
	}

	/**
	 * Provides the audit settings data used outside the Audit Logging page.
	 *
	 * @return array
	 */
	public function settings_data_frontend(): array {
		return array_merge(
			array(
				'model' => $this->model->export(),
			),
			$this->dump_routes_and_nonces()
		);
	}

	/**
	 * Converts the current state of the object to an array.
	 *
	 * @return array Returns an associative array of object properties.
	 */
	public function to_array(): array {
		return array_merge(
			array(
				'enabled' => $this->is_active(),
				'report'  => true,
			),
			$this->dump_routes_and_nonces()
		);
	}

	/**
	 * Removes settings for all submodules.
	 */
	public function remove_settings(): void {
		( new Model_Audit_Logging() )->delete();
	}

	/**
	 * Delete all the data & the cache.
	 */
	public function remove_data(): void {
		Audit_Log::truncate();
		// Remove cached data.
		Array_Cache::remove( 'sockets', 'audit' );
		Array_Cache::remove( 'logs', 'audit' );
		Array_Cache::remove( 'menu_updated', 'audit' );
		Array_Cache::remove( 'post_updated', 'audit' );
		delete_site_option( 'wd_audit_fetch_checkpoint' );
	}

	/**
	 * Provides data for the frontend.
	 *
	 * @return array An array of data for the frontend.
	 * @throws Exception If there is an error.
	 */
	public function data_frontend(): array {
		$logs       = array();
		$count      = 0;
		$per_page   = self::DEFAULT_PER_PAGE;
		$total_page = 1;
		if ( $this->is_active() ) {
			$timezone   = wp_timezone();
			$date_from  = ( new DateTime( '-7 days', $timezone ) )->setTime( 0, 0, 0 );
			$date_to    = ( new DateTime( 'now', $timezone ) )->setTime( 23, 59, 59 );
			$ip_address = sanitize_text_field( defender_get_data_from_request( 'ip', 'g' ) );
			$result     = $this->service->fetch(
				$date_from->getTimestamp(),
				$date_to->getTimestamp(),
				array(),
				'',
				$ip_address,
				1,
				$per_page
			);
			if ( ! is_wp_error( $result ) ) {
				$logs = $this->format_log_rows( $result );
				// Skip COUNT query when the first page is a partial result — it's cheaper than a second DB round-trip.
				if ( count( $logs ) < $per_page ) {
					$count = count( $logs );
				} else {
					$count = Audit_Log::count( $date_from->getTimestamp(), $date_to->getTimestamp(), array(), '', $ip_address );
				}
				$total_page = ceil( $count / $per_page );
			}
		}

		return array(
			'auditLogging' => array_merge(
				array(
					'model'       => $this->model->export(),
					'logs'        => $logs,
					'events_type' => Audit_Log::allowed_events(),
					'summary'     => array(
						'count_7_days' => $count,
						'report'       => wd_di()->get( Audit_Report::class )->to_string(),
					),
					'paging'      => array(
						'paged'       => 1,
						'total_pages' => $total_page,
						'count'       => $count,
					),
				),
				$this->dump_routes_and_nonces()
			),
			'antibot'      => wd_di()->get( Antibot_Global_Firewall::class )->data_frontend(),
		);
	}

	/**
	 * Imports data into the model.
	 *
	 * @param  array $data  Data to be imported into the model.
	 *
	 * @throws Exception If table is not defined.
	 */
	public function import_data( array $data ) {
		$model = $this->model;
		if ( array() === $data ) {
			$model->enabled      = false;
			$model->storage_days = '6 months';
			$model->save();
		} else {
			$model->import( $data );
			if ( $model->validate() ) {
				$model->save();
			}
		}
	}

	/**
	 * Exports strings.
	 *
	 * @return array An array of strings.
	 */
	public function export_strings(): array {
		$strings = $this->is_active()
			? array( esc_html__( 'Active', 'defender-security' ) )
			: array( esc_html__( 'Inactive', 'defender-security' ) );

			$strings[] = sprintf(
				/* translators: %s: Html for Pro-tag. */
				esc_html__( 'Email report inactive %s', 'defender-security' ),
				'<span class="sui-tag sui-tag-pro">Pro</span>'
			);

		return $strings;
	}

	/**
	 * Generates configuration strings based on the provided configuration.
	 *
	 * @param  array $config  Configuration data.
	 *
	 * @return array Returns an array of configuration strings.
	 */
	public function config_strings( array $config ): array {
		$strings = $config['enabled']
			? array( esc_html__( 'Active', 'defender-security' ) )
			: array( esc_html__( 'Inactive', 'defender-security' ) );

			$strings[] = sprintf(
				/* translators: %s: Html for Pro-tag. */
				esc_html__( 'Email report inactive %s', 'defender-security' ),
				'<span class="sui-tag sui-tag-pro">Pro</span>'
			);

		return $strings;
	}
}
