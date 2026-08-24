<?php
/**
 * Responsible for handling audit logs.
 *
 * @package WP_Defender\Component
 */

namespace WP_Defender\Component;

use WP_Error;
use DateTime;
use Exception;
use Countable;
use DateInterval;
use WP_Defender\Traits\IO;
use WP_Defender\Component;
use WP_Defender\Traits\Formats;
use Calotes\Helper\Array_Cache;
use WP_Defender\Model\Audit_Log;
use WP_Defender\Behavior\WPMUDEV;
use WP_Defender\Model\Setting\Audit_Logging;

/**
 * Provides methods for fetching, querying, and managing audit logs.
 */
class Audit extends Component {

	use IO;
	use Formats;

	public const AUDIT_LOG             = 'audit.log';
	public const CACHE_LAST_CHECKPOINT = 'wd_audit_fetch_checkpoint';

	/**
	 * Fetches audit logs, either from local storage or via API if not available locally.
	 *
	 * @param  int    $date_from  Start date for fetching logs.
	 * @param  int    $date_to  End date for fetching logs.
	 * @param  array  $events  Specific events to fetch.
	 * @param  string $user_id  User ID to filter logs.
	 * @param  string $ip  IP address to filter logs.
	 * @param  int    $paged  Pagination page number.
	 * @param  int    $per_page  Number of logs per page.
	 *
	 * @return Audit_Log[]|WP_Error Returns an array of Audit_Log objects or WP_Error on failure.
	 * @throws Exception Throws exception on failure.
	 */
	public function fetch( $date_from, $date_to, $events = array(), $user_id = '', $ip = '', $paged = 1, $per_page = 10 ) {
		$internal = Audit_Log::query( $date_from, $date_to, $events, $user_id, $ip, $paged, $per_page );
		$this->log( sprintf( 'Found %s from local', count( $internal ) ), self::AUDIT_LOG );
		if ( ! wd_di()->get( WPMUDEV::class )->is_pro() ) {
			return $internal;
		}
		$checkpoint = get_site_option( self::CACHE_LAST_CHECKPOINT );
		if ( false === $checkpoint ) {
			// This case where user install the plugin, have some local data but never reach to Logs page, then check point will be today.
			$checkpoint = time();
		}
		$checkpoint = (int) $checkpoint;
		$date_from  = ! is_int( $date_from ) ? (int) $date_from : $date_from;
		if ( 0 === count( $internal ) && $checkpoint > $date_from ) {
			// Have to fetch from API.
			$this->log( 'fetch from cloud', self::AUDIT_LOG );
			// Todo:need $paged as 'nopaging'-arg?
			$cloud = $this->query_from_api( $date_from, $date_to );
			if ( is_wp_error( $cloud ) ) {
				$this->log( sprintf( 'Fetch error %s', $cloud->get_error_message() ), self::AUDIT_LOG );

				return $cloud;
			}
			if ( count( $cloud ) ) {
				// No data from cloud too.
				Audit_Log::mass_insert( $cloud );
				// Because this is roughly fetch, so we have to filter out again using the local data.
				$internal = Audit_Log::query( $date_from, $date_to, $events, $user_id, $ip, $paged, $per_page );
			}
			// Cache the last time fetch, this will be useful in case of mixed data.
			update_site_option( self::CACHE_LAST_CHECKPOINT, $date_from );
			// This case we have the data, however, maybe it can be out of the cached range, so we have to check.
			// Note that, the out of range only happen with date_from, as the local always have the newest data.
		} elseif ( $checkpoint > $date_from ) {
			// We have some data out of range, fetch and cache.
			$this->log(
				sprintf(
					'checkpoint %s - date from %s',
					wp_date( 'Y-m-d H:i:s', $checkpoint ),
					wp_date( 'Y-m-d H:i:s', $date_from )
				),
				self::AUDIT_LOG
			);
			$cloud = $this->query_from_api( $date_from, $checkpoint );
			if ( is_wp_error( $cloud ) ) {
				$this->log( sprintf( 'Fetch error %s', $cloud->get_error_message() ), self::AUDIT_LOG );

				return $cloud;
			}
			if ( is_array( $cloud ) ) {
				// Silence the error here, as we actually have data.
				Audit_Log::mass_insert( $cloud );
				$internal = Audit_Log::query( $date_from, $date_to, $events, $user_id, $ip, $paged, $per_page );
				// Cache the last time fetch, this will be useful in case of mixed data.
				update_site_option( self::CACHE_LAST_CHECKPOINT, $date_from );
			}
		}

		return $internal;
	}

	/**
	 * Queries audit logs from the API.
	 *
	 * @param  int $date_from  Start date for the query.
	 * @param  int $date_to  End date for the query.
	 *
	 * @return array|WP_Error Returns an array of logs or WP_Error on failure.
	 * @throws Exception Throws exception on failure.
	 */
	public function query_from_api( $date_from, $date_to ) {
		$date_format = 'Y-m-d H:i:s';
		$date_to     = wp_date( $date_format, $date_to );
		$date_from   = wp_date( $date_format, $date_from );
		$args        = array(
			'site_url'  => network_site_url(),
			'order_by'  => 'timestamp',
			'order'     => 'desc',
			'nopaging'  => true,
			'timezone'  => get_option( 'gmt_offset' ),
			'date_from' => $date_from,
			'date_to'   => $date_to,
		);

		$this->attach_behavior( WPMUDEV::class, WPMUDEV::class );
		$data = $this->make_wpmu_request(
			WPMUDEV::API_AUDIT,
			$args,
			array( 'method' => 'GET' ),
			true
		);

		if ( is_wp_error( $data ) ) {
			$this->log( sprintf( 'Fetch error %s', $data->get_error_message() ), self::AUDIT_LOG );

			return $data;
		}

		if ( 'success' !== $data['status'] ) {
			return new WP_Error(
				Error_Code::API_ERROR,
				esc_html__( 'Something wrong happen, please try again!', 'defender-security' )
			);
		}

		return $data['data'];
	}


	/**
	 * Delete all local audit log entries from database and reset checkpoint.
	 *
	 * @return void
	 */
	public function reset(): void {
		Audit_Log::truncate();
		delete_site_option( self::CACHE_LAST_CHECKPOINT );
	}

	/**
	 * Cleans up old logs based on storage settings.
	 *
	 * @throws Exception When the $duration cannot be parsed as an interval.
	 */
	public function audit_clean_up_logs() {
		$audit_settings = wd_di()->get( Audit_Logging::class );
		$interval       = $this->calculate_date_interval( $audit_settings->storage_days );
		// Since v5.7.0.
		$interval = apply_filters( 'wpdef_audit_logs_store_backward', $interval );
		$interval = is_string( $interval ) ? $interval : (string) $interval;

		try {
			$interval_obj = new DateInterval( $interval );
		} catch ( Exception ) {
			// Fallback if the filter supplied an incorrect value.
			$interval_obj = new DateInterval( 'P6M' );
		}

		$date_from = ( new DateTime() )->setTimezone( wp_timezone() )
					->sub( new DateInterval( 'P1Y' ) )
					->setTime( 0, 0, 0 );
		$date_to   = ( new DateTime() )->setTimezone( wp_timezone() )
					->sub( $interval_obj );

		if ( $date_from < $date_to ) {
			// Count the logs that should be deleted.
			$logs_count = Audit_Log::count( $date_from->getTimestamp(), $date_to->getTimestamp() );
			if ( $logs_count > 0 ) {
				$this->log( 'Cleaning up old logs from ' . $date_from->format( 'Y-m-d H:i:s' ) . ' to ' . $date_to->format( 'Y-m-d H:i:s' ), self::AUDIT_LOG );
				// Since v5.0.0.
				$delete_count = apply_filters( 'wpdef_audit_limit_deleted_logs', 50 );
				Audit_Log::delete_old_logs(
					$date_from->getTimestamp(),
					$date_to->getTimestamp(),
					is_int( $delete_count ) ? $delete_count : (int) $delete_count,
				);
			}
		}
	}

	/**
	 * Sends data to the API using cURL.
	 *
	 * @param  array $data  Data to be sent to the API.
	 *
	 * @return mixed Returns the response from the API.
	 */
	public function curl_to_api( $data ) {
		$this->attach_behavior( WPMUDEV::class, WPMUDEV::class );
		$ret = $this->make_wpmu_request(
			WPMUDEV::API_AUDIT_ADD,
			$data,
			array(
				'method'  => 'POST',
				'timeout' => 3,
				'headers' => array(
					'apikey' => $this->get_apikey(),
				),
			)
		);

		return $ret;
	}

	/**
	 * Strips the protocol from a URL.
	 *
	 * @param  string $url  URL to process.
	 *
	 * @return string Returns the URL without the protocol.
	 */
	private function strip_protocol( $url ) {
		$parts = wp_parse_url( $url );
		$host  = $parts['host'] . ( $parts['path'] ?? null );

		return rtrim( $host, '/' );
	}

	/**
	 * Returns the API endpoint.
	 *
	 * @return string Returns the API endpoint URL.
	 */
	private function get_endpoint(): string {
		return defined( 'WPMUDEV_CUSTOM_AUDIT_SERVER' )
			? constant( 'WPMUDEV_CUSTOM_AUDIT_SERVER' )
			: 'https://audit.wpmudev.org/';
	}

	/**
	 * Queue all the events listeners, so we can listen and build log base on user behaviors.
	 * Never catch if it runs from WP CLI or CRON.
	 */
	public function enqueue_event_listener() {
		if ( ! wp_doing_cron() && ! defender_is_wp_cli() ) {
			$events_class = array(
				new Component\Audit\Comment_Audit(),
				new Component\Audit\Core_Audit(),
				new Component\Audit\Media_Audit(),
				new Component\Audit\Post_Audit(),
				new Component\Audit\User_Audit(),
				new Component\Audit\Options_Audit(),
				new Component\Audit\Menu_Audit(),
				new Component\Audit\Theme_Audit(),
				new Component\Audit\Feature_Audit(),
				new Component\Audit\Password_Audit(),
				new Component\Audit\Application_Password_Audit(),
			);

			foreach ( $events_class as $class ) {
				// since 2.4.7.
				$hooks = apply_filters( 'wp_defender_audit_hooks', $class->get_hooks() );
				foreach ( $hooks as $key => $hook ) {
					$func = function () use ( $key, $hook, $class ) {
						global $wp_filter;
						if ( isset( $wp_filter['gettext'] ) ) {
							$gettext_callbacks = $wp_filter['gettext']->callbacks;

							// Disable all gettext filters.
							$wp_filter['gettext']->callbacks = array();
						}

						// This is arguments of the hook.
						$args = func_get_args();
						// This is hook data, defined in each event class.
						$class->build_log_data( $key, $args, $hook );

						// Add all filters back for gettext.
						if ( isset( $wp_filter['gettext'], $gettext_callbacks ) ) {
							$wp_filter['gettext']->callbacks = $gettext_callbacks;
						}
					};
					add_action(
						$key,
						$func,
						11,
						is_array( $hook['args'] ) || $hook['args'] instanceof Countable ? count( $hook['args'] ) : 0
					);
				}
			}
		}
	}

	/**
	 * Logs audit events.
	 */
	public function log_audit_events() {
		$events = Array_Cache::get( 'logs', 'audit', array() );

		if ( ! ( is_array( $events ) || $events instanceof Countable ? count( $events ) : 0 )
			|| ! class_exists( Audit_Log::class )
		) {
			return;
		}
		$model = new Audit_Log();

		if ( ( is_array( $events ) || $events instanceof Countable ? count( $events ) : 0 ) > 1 ) {
			if ( $model->has_method( 'mass_insert' ) ) {
				$model->mass_insert( $events );

				return;
			}
		}

		foreach ( $events as $event ) {
			$model->import( $event );
			$model->synced = 0;
			$model->save();
		}
	}
}
