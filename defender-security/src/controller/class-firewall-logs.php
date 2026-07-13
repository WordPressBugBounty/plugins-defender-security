<?php
/**
 * Handles firewall logs and interactions with Block list API service.
 *
 * @package WP_Defender\Controller
 */

namespace WP_Defender\Controller;

use DateTime;
use Exception;
use Valitron\Validator;
use Calotes\Helper\HTTP;
use WP_Defender\Controller;
use Calotes\Component\Request;
use Calotes\Component\Response;
use WP_Defender\Traits\Formats;
use WP_Defender\Behavior\WPMUDEV;
use WP_Defender\Model\Lockout_Log;
use WP_Defender\Component\User_Agent;
use WP_Defender\Component\IP\Global_IP;
use WP_Defender\Component\Table_Lockout;
use WP_Defender\Component\Network_Cron_Manager;
use WP_Defender\Integrations\Antibot_Global_Firewall_Client;
use WP_Defender\Model\Setting\Blacklist_Lockout;
use WP_Defender\Model\Setting\User_Agent_Lockout;
use WP_Defender\Component\Firewall_Logs as Firewall_Logs_Component;

/**
 * Responsible for managing firewall logs, including bulk actions, exporting logs to CSV,
 *  toggling IP addresses and user agents, querying logs, and sending logs to the Block list API.
 */
class Firewall_Logs extends Controller {

	use Formats;

	/**
	 * The slug identifier for this controller.
	 *
	 * @var string
	 */
	protected $slug = 'wdf-ip-lockout';

	/**
	 * The WPMUDEV instance used for interacting with WPMUDEV services.
	 *
	 * @var WPMUDEV
	 */
	private $wpmudev;

	/**
	 * The client for interacting with the AntiBot Global Firewall API.
	 *
	 * @var Antibot_Global_Firewall_Client
	 */
	private $antibot_client;

	/**
	 * The transient key used to store the list of IP addresses from the
	 * Akismet service that are blocked in the firewall.
	 *
	 * @var string
	 */
	const AKISMET_BLOCKED_IPS = 'defender_akismet_blocked_ips';

	/**
	 * Default number of items per page.
	 */
	public const DEFAULT_PER_PAGE = 10;

	/**
	 * Constructor for the class.
	 *
	 * @param  Antibot_Global_Firewall_Client $antibot_client  The client for interacting with the Block list API service.
	 */
	public function __construct( Antibot_Global_Firewall_Client $antibot_client ) {
		$this->register_routes();
		add_action( 'defender_enqueue_assets', array( $this, 'enqueue_assets' ) );

		$this->wpmudev = wd_di()->get( WPMUDEV::class );

		$this->antibot_client = $antibot_client;

		/**
		 * Send Firewall logs to AntiBot Global Firewall API.
		 *
		 * @var Network_Cron_Manager $network_cron_manager
		 */
		$network_cron_manager = wd_di()->get( Network_Cron_Manager::class );
		$network_cron_manager->register_callback(
			'wpdef_firewall_send_compact_logs_to_api',
			array( $this, 'send_compact_logs_to_api' ),
			12 * HOUR_IN_SECONDS,
			time() + 15
		);
		if ( class_exists( 'Akismet' ) ) {
			add_filter( 'http_response', array( $this, 'akismet_http_response' ), 10, 3 );
		}
	}

	/**
	 * Bulk action handler for lockout logs.
	 *
	 * @param  Request $request  The request object containing the data.
	 *
	 * @return Response The response object with the result of the bulk action.
	 * @defender_route
	 */
	public function bulk( Request $request ): Response {
		$data = $request->get_data(
			array(
				'action' => array(
					'type'     => 'string',
					'sanitize' => 'sanitize_text_field',
				),
				'ips'    => array(
					'type' => 'array',
				),
			)
		);

		$ips = implode( PHP_EOL, array_filter( array_map( 'sanitize_text_field', (array) $data['ips'] ), 'boolval' ) );
		$bl  = wd_di()->get( Blacklist_Lockout::class );

		switch ( $data['action'] ) {
			case 'ban':
				$bl->ip_blacklist = $ips;
				break;
			case 'allowlist':
				$bl->ip_whitelist = $ips;
				break;
			default:
				break;
		}

		$bl->save();

		return new Response(
			true,
			array(
				'banning' => $bl->export(),
			)
		);
	}

	/**
	 * Export all logs matching the current filter to CSV.
	 *
	 * @return void
	 * @defender_route
	 */
	public function export_as_csv(): void {
		$date_from   = (int) HTTP::get( 'date_from', strtotime( '-7 days midnight' ) );
		$date_to     = (int) HTTP::get( 'date_to', strtotime( 'tomorrow' ) );
		$ip          = sanitize_text_field( (string) HTTP::get( 'ip', '' ) );
		$user_agent  = sanitize_text_field( (string) HTTP::get( 'user_agent', '' ) );
		$type        = sanitize_text_field( (string) HTTP::get( 'type', '' ) );
		$ban_status  = sanitize_text_field( (string) HTTP::get( 'ban_status', '' ) );
		$sort        = sanitize_text_field( (string) HTTP::get( 'sort', Table_Lockout::SORT_DESC ) );
		$sort_params = wd_di()->get( Table_Lockout::class )->resolve_sort( $sort );

		$filters = array(
			'from'       => $date_from,
			'to'         => $date_to,
			'ip'         => $ip,
			'user_agent' => $user_agent,
			'type'       => 'all' === $type ? '' : $type,
			'ban_status' => 'all' === $ban_status ? '' : $ban_status,
		);

		$logs = Lockout_Log::query_logs( $filters, 1, $sort_params['order_by'], $sort_params['order'], -1 );

		$tl_component = new Table_Lockout();

		$ua_component = wd_di()->get( User_Agent::class );

		$filename = 'wdf-lockout-logs-export-' . wp_date( 'ymdHis' ) . '.csv';

		header( 'Expires: 0' );
		header( 'Cache-Control: must-revalidate, post-check=0, pre-check=0' );
		header( 'Cache-Control: private', false );
		header( 'Content-Type: application/octet-stream' );
		header( 'Content-Disposition: attachment; filename="' . $filename . '";' );
		header( 'Content-Transfer-Encoding: binary' );

		extension_loaded( 'zlib' ) ? ob_start( 'ob_gzhandler' ) : ob_start();

		$fp      = fopen( 'php://output', 'w' );
		$headers = array(
			esc_html__( 'Log', 'defender-security' ),
			esc_html__( 'Date / Time', 'defender-security' ),
			esc_html__( 'Type', 'defender-security' ),
			esc_html__( 'IP address', 'defender-security' ),
			esc_html__( 'IP Status', 'defender-security' ),
			esc_html__( 'User Agent Name', 'defender-security' ),
			esc_html__( 'User Agent Status', 'defender-security' ),
		);
		fputcsv( $fp, $headers, ',', '"', '\\' );

		$flush_limit = Lockout_Log::INFINITE_SCROLL_SIZE;
		foreach ( $logs as $key => $log ) {
			$item = array(
				$log->log,
				$this->format_date_time( $log->date ),
				$tl_component->get_type( $log->type ),
				$log->ip,
				$tl_component->get_ip_status_text( $log->ip ),
				$log->user_agent,
				$ua_component->get_status_text( $log->type, $log->tried ),
			);
			fputcsv( $fp, $item, ',', '"', '\\' );

			if ( 0 === $key % $flush_limit ) {
				ob_flush();
				flush();
			}
		}
		// WP_Filesystem is not suitable here because it abstracts to reading/writing files on disk, not to output streams.
		fclose( $fp ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
		exit();
	}

	/**
	 * Toggles an IP address to or from a specified list.
	 *
	 * @param  Request $request  The HTTP request object.
	 *
	 * @return Response The HTTP response object.
	 * @defender_route
	 */
	public function toggle_ip_to_list( Request $request ): Response {
		$data = $request->get_data(
			array(
				'list' => array(
					'type'     => 'string',
					'sanitize' => 'sanitize_textarea_field',
				),
				'type' => array(
					'type'     => 'string',
					'sanitize' => 'sanitize_text_field',
				),
			)
		);

		$collection = $data['list'];
		$list_type  = $data['type'];

		$model = wd_di()->get( Blacklist_Lockout::class );
		if ( 'blacklist' === $list_type ) {
			$model->ip_blacklist = $collection;
		} elseif ( 'whitelist' === $list_type ) {
			$model->ip_whitelist = $collection;
		}
		$model->save();

		return new Response(
			true,
			array(
				'banning' => $model->export(),
			)
		);
	}

	/**
	 * Toggles a user agent to/from a specified list based on the given request data.
	 *
	 * @param Request $request  The request object containing the data for toggling the user agent.
	 *
	 * @return Response The response object indicating the success or failure of the toggle operation.
	 * @defender_route
	 */
	public function toggle_ua_to_list( Request $request ): Response {
		$data = $request->get_data(
			array(
				'list' => array(
					'type'     => 'string',
					'sanitize' => 'sanitize_textarea_field',
				),
				'type' => array(
					'type'     => 'string',
					'sanitize' => 'sanitize_text_field',
				),
			)
		);

		$collection = $data['list'];
		$list_type  = $data['type'];

		$model = wd_di()->get( User_Agent_Lockout::class );
		if ( 'blacklist' === $list_type ) {
			$model->blacklist = $collection;
		} elseif ( 'whitelist' === $list_type ) {
			$model->whitelist = $collection;
		}
		$model->save();

		return new Response(
			true,
			array(
				'uaLockout' => $model->export(),
			)
		);
	}

	/**
	 * Query the logs and display on frontend.
	 *
	 * @param Request $request  The request object containing filter parameters.
	 *
	 * @return Response
	 * @defender_route
	 * @throws Exception If an argument is not of the expected type.
	 */
	public function query_logs( Request $request ): Response {
		$data = $request->get_data(
			array(
				'date_from'  => array(
					'type'     => 'int',
					'sanitize' => 'sanitize_text_field',
				),
				'date_to'    => array(
					'type'     => 'int',
					'sanitize' => 'sanitize_text_field',
				),
				'ip'         => array(
					'type'     => 'string',
					'sanitize' => 'sanitize_text_field',
				),
				'user_agent' => array(
					'type'     => 'string',
					'sanitize' => 'sanitize_text_field',
				),
				'type'       => array(
					'type'     => 'string',
					'sanitize' => 'sanitize_text_field',
				),
				'paged'      => array(
					'type'     => 'int',
					'sanitize' => 'sanitize_text_field',
				),
				'sort'       => array(
					'type'     => 'string',
					'sanitize' => 'sanitize_text_field',
				),
				'ban_status' => array(
					'type'     => 'string',
					'sanitize' => 'sanitize_text_field',
				),
				'per_page'   => array(
					'type'     => 'int',
					'sanitize' => 'sanitize_text_field',
				),
			)
		);
		// Validate.
		$v = new Validator( $data, array() );
		$v->rule( 'required', array( 'date_from', 'date_to' ) );
		$v->rule( 'integer', array( 'date_from', 'date_to' ) );
		$v->rule( 'min', array( 'date_from', 'date_to' ), 0 );
		if ( ! $v->validate() ) {
			return new Response( false, array( 'message' => esc_html__( 'Wrong start and end date.', 'defender-security' ) ) );
		}

		$sort        = $data['sort'] ?? Table_Lockout::SORT_DESC;
		$sort_params = wd_di()->get( Table_Lockout::class )->resolve_sort( $sort );

		$result = $this->retrieve_logs(
			array(
				'from'       => $data['date_from'],
				'to'         => $data['date_to'],
				'ip'         => $data['ip'],
				'user_agent' => $data['user_agent'] ?? '',
				// If this is all, then we set to null to exclude it from the filter.
				'type'       => 'all' === $data['type'] ? '' : $data['type'],
				'ban_status' => 'all' === $data['ban_status'] ? '' : $data['ban_status'],
			),
			$data['paged'],
			$sort_params['order'],
			$sort_params['order_by'],
			$data['per_page'] ?? 0
		);

		return new Response( true, $result );
	}

	/**
	 * Enqueues scripts and styles for this page.
	 * Only enqueues assets if the page is active.
	 */
	public function enqueue_assets() {
		if ( ! $this->is_page_active() ) {
			return;
		}
	}

	/**
	 * Provides data for the frontend.
	 *
	 * @return array An array of data for the frontend.
	 */
	public function data_frontend(): array {
		$type       = defender_get_data_from_request( 'type', 'g' );
		$ip         = defender_get_data_from_request( 'ip', 'g' );
		$user_agent = defender_get_data_from_request( 'user_agent', 'g' );

		$init_filters = array(
			'from'       => strtotime( '-30 days' ),
			'to'         => time(),
			'type'       => $type,
			'ip'         => $ip,
			'user_agent' => $user_agent,
			'ban_status' => '',
		);
		$def_filters  = array(
			'misc'           => wd_di()->get( Table_Lockout::class )->get_filters(),
			'default_filter' => $init_filters,
			'per_page'       => self::DEFAULT_PER_PAGE,
		);

		return array_merge(
			$this->retrieve_logs( $init_filters ),
			$def_filters,
			$this->dump_routes_and_nonces()
		);
	}

	/**
	 * Retrieves logs based on the given filters, paging, order, and order by.
	 *
	 * @param  array  $filters  An array containing the following keys:
	 *                               - 'from': The start date of the logs.
	 *                               - 'to': The end date of the logs.
	 *                               - 'type': The type of logs.
	 *                               - 'ip': The IP address of the logs.
	 *                               - 'ban_status': The ban status of the logs.
	 * @param  int    $paged  The page number of the logs to retrieve. Default is 1.
	 * @param  string $order  The order of the logs. Default is 'desc'.
	 * @param  string $order_by  The field to order the logs by. Default is 'id'.
	 * @param  int    $per_page  Number of logs per page. 0 falls back to the default of 10.
	 *
	 * @return array An array containing the following keys:
	 *               - 'count': The total count of logs.
	 *               - 'logs': The retrieved logs.
	 *               - 'per_page': The number of logs per page.
	 *               - 'total_pages': The total number of pages.
	 */
	private function retrieve_logs( $filters, $paged = 1, $order = 'desc', $order_by = 'id', $per_page = 0 ): array {
		$per_page = (int) $per_page;
		if ( 0 === $per_page ) {
			$per_page = self::DEFAULT_PER_PAGE;
		}
		$conditions = array( 'ban_status' => $filters['ban_status'] );

		$count = Lockout_Log::count( $filters['from'], $filters['to'], $filters['type'], $filters['ip'], $conditions );
		$logs  = Lockout_Log::get_logs_and_format( $filters, $paged, $order_by, $order, $per_page );
		return array(
			'logs'        => $logs,
			'per_page'    => $per_page,
			'total_pages' => ceil( $count / $per_page ),
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
	}

	/**
	 * Removes settings for all submodules.
	 */
	public function remove_settings() {
	}

	/**
	 * Delete all the data & the cache.
	 */
	public function remove_data() {
		delete_site_transient( self::AKISMET_BLOCKED_IPS );
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
	 * Exports strings.
	 *
	 * @param array $logs Prepared logs.
	 * @param bool  $is_staging  Send logs to staging.
	 */
	private function maybe_send_reports( array $logs, bool $is_staging = false ): void {
		$offset     = 0;
		$length     = 1000;
		$logs_chunk = array_slice( $logs, $offset, $length );
		while ( array() !== $logs_chunk ) {
			$data = array(
				'logs' => $logs_chunk,
			);

			$antibot_client = $this->antibot_client;
			if ( $is_staging ) {
				$antibot_client = new Antibot_Global_Firewall_Client( 'https://staging-api.blocklist-service.com' );
			}
			$response = $antibot_client->send_reports( $data );

			if ( is_wp_error( $response ) ) {
				$this->log(
					sprintf( 'AntiBot Global Firewall Error: %s', $response->get_error_message() ),
					Firewall::FIREWALL_LOG
				);
			} elseif ( isset( $response['status'] ) && 'error' === $response['status'] ) {
				$this->log(
					sprintf( 'AntiBot Global Firewall Error: %s', $response['message'] ),
					Firewall::FIREWALL_LOG
				);
			}

			$offset    += $length;
			$logs_chunk = array_slice( $logs, $offset, $length );
		}

		$this->log( 'AntiBot Global Firewall: Process for sending logs completed.', Firewall::FIREWALL_LOG );
	}

	/**
	 * Send last 12 hours logs to AntiBot Global Firewall API.
	 * If running for first time then grab 7 days of logs.
	 * If last run difference is greater than 12 hours then grab 12+ hours of log but at most grab 7 days of logs.
	 *
	 * @return void
	 */
	public function send_compact_logs_to_api(): void {
		$site_id    = get_current_blog_id();
		$event_name = 'wpdef_firewall_send_compact_logs_to_api';
		$this->log( "Cron job {$event_name} triggered at site {$site_id}", Firewall::FIREWALL_LOG );

		/**
		 * Enable/disable sending Firewall logs to API.
		 *
		 * @param bool  $status  Status for sending logs. Send logs to API if true.
		 *
		 * @since 4.5.0
		 */
		$send_logs = apply_filters( 'wpdef_firewall_send_logs_to_api', true );
		$send_logs = is_bool( $send_logs ) ? $send_logs : (bool) $send_logs;

		if (
			! $send_logs ||
			! $this->wpmudev->is_dash_activated() ||
			! $this->wpmudev->is_site_connected_to_hub()
		) {
			return;
		}

		// Acquire lock before executing.
		if ( ! $this->acquire_cron_lock( $event_name, 'twicedaily' ) ) {
			$this->log( "{$event_name} is skipped running from site {$site_id}", Firewall::FIREWALL_LOG );
			return;
		}
		// Log the site ID where the event is triggered.
		$this->log( "{$event_name} is processing from site {$site_id}", Firewall::FIREWALL_LOG );
		$from = time() - ( 7 * DAY_IN_SECONDS );

		$last_run_time = get_site_option( 'wpdef_ip_blocklist_sync_last_run_time', 0 );
		if ( 0 < $last_run_time ) {
			$time_difference = time() - $last_run_time;

			if ( $time_difference < 7 * DAY_IN_SECONDS ) { // 7 days in seconds
				$from = $last_run_time;
			}
		}
		update_site_option( 'wpdef_ip_blocklist_sync_last_run_time', time() );

		$service = wd_di()->get( Firewall_Logs_Component::class );

		$logs = $service->get_compact_logs( $from );
		if ( array() !== $logs ) {
			$this->maybe_send_reports( $logs );
		}

		$logs = $service->get_akismet_auto_spam_comment_logs();
		if ( array() !== $logs ) {
			$this->maybe_send_reports( $logs );
		}

		$logs = $service->get_404_intelligence_logs( $from );
		if ( array() !== $logs ) {
			$this->maybe_send_reports( $logs, true );
		}

		// Release lock after execution.
		$this->release_cron_lock( $event_name );
	}

	/**
	 * Filters a successful HTTP API response before returning it.
	 *
	 * @param array  $response    HTTP response.
	 * @param array  $parsed_args HTTP request arguments.
	 * @param string $url         The request URL.
	 *
	 * @return array HTTP response.
	 */
	public function akismet_http_response( $response, $parsed_args, $url ) {
		// If the URL is not the Akismet comment-check endpoint, return the response as is.
		if ( 'https://rest.akismet.com/1.1/comment-check' !== $url ) {
			return $response;
		}

		// Retrieve response body safely.
		$body = wp_remote_retrieve_body( $response );
		// If the body is empty or does not equal 'true' (indicating spam), return the response as is.
		if ( ! is_string( $body ) || in_array( trim( $body ), array( '', 'true' ), true ) ) {
			return $response;
		}

		// Ensure the request body contains data; otherwise, return the response.
		$body_arg = $parsed_args['body'] ?? '';
		if (
			( is_string( $body_arg ) && '' === trim( $body_arg ) )
			|| ( is_array( $body_arg ) && array() === $body_arg )
			|| ( is_object( $body_arg ) && 0 === count( get_object_vars( $body_arg ) ) )
		) {
			return $response;
		}

		$request_data = wp_parse_args( $body_arg );
		// If the comment author's IP is not present in the request data, return the response.
		$author_ip = $request_data['comment_author_IP'] ?? '';
		if ( '' === $author_ip ) {
			return $response;
		}

		// Validate the user IP address from the request data.
		$user_ip = filter_var( $author_ip, FILTER_VALIDATE_IP );
		if ( false === $user_ip ) {
			return $response;
		}

		// Retrieve the current list of blocked IPs from the site transient.
		$option = get_site_transient( self::AKISMET_BLOCKED_IPS );
		// Ensure the retrieved data is an array; if not, initialize it as an empty array.
		if ( ! is_array( $option ) ) {
			$option = array();
		}

		// Increment the count of how many times this IP has been associated with spam.
		$option[ $user_ip ] = isset( $option[ $user_ip ] ) ? (int) $option[ $user_ip ] + 1 : 1;
		// Update the site transient with the new list of blocked IPs.
		set_site_transient( self::AKISMET_BLOCKED_IPS, $option );

		// Return the original HTTP response.
		return $response;
	}
}
