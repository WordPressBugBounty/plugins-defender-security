<?php
/**
 * Handles interactions with the database table for audit logs.
 *
 * @package WP_Defender\Model
 */

namespace WP_Defender\Model;

use WP_Defender\DB;
use WP_Defender\Component\Crypt;
use ReflectionException;

/**
 * Model for the  audit log table.
 */
class Audit_Log extends DB {

	public const EVENT_TYPE_USER = 'user', EVENT_TYPE_SYSTEM = 'system', EVENT_TYPE_COMMENT = 'comment',
		EVENT_TYPE_MEDIA         = 'media', EVENT_TYPE_SETTINGS = 'settings', EVENT_TYPE_CONTENT = 'content',
		EVENT_TYPE_MENU          = 'menu';

	/**
	 * Table name.
	 *
	 * @var string
	 */
	protected $table = 'defender_audit_log';

	/**
	 * Primary key column.
	 *
	 * @var int
	 * @defender_property
	 */
	public $id;
	/**
	 * Table column for timestamp.
	 *
	 * @var int
	 * @defender_property
	 */
	public $timestamp;
	/**
	 * Persisted experimental fractional key, kept as a decimal string.
	 *
	 * @var string|null
	 * @defender_property
	 */
	public $fractional_timestamp;
	/**
	 * Table column for event type.
	 *
	 * @var string
	 * @defender_property
	 */
	public $event_type;
	/**
	 * Table column for action type.
	 *
	 * @var string
	 * @defender_property
	 */
	public $action_type;
	/**
	 * Table column for site url.
	 *
	 * @var string
	 * @defender_property
	 */
	public $site_url;
	/**
	 * Table column for user id.
	 *
	 * @var int
	 * @defender_property
	 */
	public $user_id;
	/**
	 * Table column for context.
	 *
	 * @var string
	 * @defender_property
	 */
	public $context;
	/**
	 * Table column for ip.
	 *
	 * @var string
	 * @defender_property
	 */
	public $ip;
	/**
	 * Table column for message.
	 *
	 * @var string
	 * @defender_property
	 */
	public $msg;
	/**
	 * Table column for blog id.
	 *
	 * @var int
	 * @defender_property
	 */
	public $blog_id;
	/**
	 * Table column for synced flag.
	 *
	 * @var bool
	 * @defender_property
	 */
	public $synced;
	/**
	 * Table column for ttl.
	 *
	 * @var int
	 * @defender_property
	 */
	public $ttl;
	/**
	 * Safe columns.
	 *
	 * @var array
	 */
	public $safe = array(
		'id',
		'timestamp',
		'fractional_timestamp',
		'event_type',
		'action_type',
		'site_url',
		'user_id',
		'context',
		'ip',
		'msg',
		'blog_id',
		'synced',
		'ttl',
	);

	/**
	 * Generate a key only for a new queued event, before persisting it.
	 *
	 * @return bool|int The save result.
	 */
	public function save(): bool|int {
		if ( 0 === (int) $this->synced
			&& ( null === $this->fractional_timestamp || '' === $this->fractional_timestamp ) ) {
			global $wpdb;
			$table = $wpdb->base_prefix . $this->table;
			// Include synced rows too, to avoid reusing a recently flushed key.
			// phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$keys = $wpdb->get_col(
				$wpdb->prepare(
					"SELECT fractional_timestamp FROM `{$table}` WHERE timestamp = %d AND site_url = %s AND fractional_timestamp IS NOT NULL",
					$this->timestamp,
					$this->site_url
				)
			);
			// phpcs:enable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			if ( ! is_array( $keys ) || $wpdb->last_error ) {
				return false;
			}
			$used = array_fill_keys( $keys, true );
			if ( count( $used ) >= 999999 ) {
				return false;
			}
			$fraction = Crypt::random_int( 1, 999999 );
			do {
				$key      = $this->timestamp . '.' . sprintf( '%06d', $fraction );
				$fraction = $fraction % 999999 + 1;
			} while ( isset( $used[ $key ] ) );
			$this->fractional_timestamp = $key;
		}

		return parent::save();
	}

	/**
	 * Give keyless logs unique fractional keys and mark them unsynced: one key lookup and one UPDATE per batch.
	 *
	 * @param self[] $logs Logs without a fractional key.
	 *
	 * @return self[] Logs persisted with a key; empty when a query fails.
	 */
	public static function assign_keys( array $logs ): array {
		if ( array() === $logs ) {
			return array();
		}
		global $wpdb;
		$table = $wpdb->base_prefix . 'defender_audit_log';

		$groups = array();
		foreach ( $logs as $log ) {
			$group_key = $log->site_url . '|' . $log->timestamp;
			if ( ! isset( $groups[ $group_key ] ) ) {
				$groups[ $group_key ] = array(
					'site_url'  => $log->site_url,
					'timestamp' => $log->timestamp,
				);
			}
		}

		$where_clauses = array();
		$params        = array();
		foreach ( $groups as $group ) {
			$where_clauses[] = '( site_url = %s AND timestamp = %d )';
			$params[]        = $group['site_url'];
			$params[]        = $group['timestamp'];
		}

		$where_sql = implode( ' OR ', $where_clauses );
		// phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare
		$existing_rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT site_url, timestamp, fractional_timestamp FROM `{$table}`
				WHERE fractional_timestamp IS NOT NULL AND fractional_timestamp != ''
				AND ( {$where_sql} )",
				$params
			)
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare
		if ( ! is_array( $existing_rows ) || $wpdb->last_error ) {
			return array();
		}

		$used_keys = array();
		foreach ( $existing_rows as $row ) {
			$group_key = $row->site_url . '|' . $row->timestamp;
			$used_keys[ $group_key ][ (string) $row->fractional_timestamp ] = true;
		}

		$keys       = array();
		$ready_logs = array();
		foreach ( $logs as $log ) {
			$group_key = $log->site_url . '|' . $log->timestamp;
			if ( ! isset( $used_keys[ $group_key ] ) ) {
				$used_keys[ $group_key ] = array();
			}
			if ( count( $used_keys[ $group_key ] ) >= 999999 ) {
				continue;
			}
			$fraction = Crypt::random_int( 1, 999999 );
			do {
				$key      = $log->timestamp . '.' . sprintf( '%06d', $fraction );
				$fraction = $fraction % 999999 + 1;
			} while ( isset( $used_keys[ $group_key ][ $key ] ) );

			$used_keys[ $group_key ][ $key ] = true;
			$keys[ $log->id ]                = $key;
			$ready_logs[]                    = $log;
		}

		if ( array() === $ready_logs ) {
			return array();
		}

		$cases  = array();
		$params = array();
		foreach ( $keys as $id => $key ) {
			$cases[]  = 'WHEN %d THEN %s';
			$params[] = $id;
			$params[] = $key;
		}
		$ids_placeholder = implode( ', ', array_fill( 0, count( $keys ), '%d' ) );
		$params          = array_merge( $params, array_keys( $keys ) );
		$cases_sql       = implode( ' ', $cases );
		// phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare
		$res = $wpdb->query(
			$wpdb->prepare( "UPDATE `$table` SET synced = 0, fractional_timestamp = CASE id $cases_sql END WHERE id IN ($ids_placeholder)", $params )
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare
		if ( false === $res || $wpdb->last_error ) {
			return array();
		}

		// Set keys only after the UPDATE succeeds, so callers never send unsaved keys.
		foreach ( $ready_logs as $log ) {
			$log->fractional_timestamp = $keys[ $log->id ];
			$log->synced               = 0;
		}

		return $ready_logs;
	}

	/**
	 * Mark logs synced in a single query.
	 *
	 * @param int[] $ids Row IDs.
	 */
	public static function mark_synced( array $ids ): void {
		if ( array() === $ids ) {
			return;
		}
		global $wpdb;
		$table        = $wpdb->base_prefix . 'defender_audit_log';
		$placeholders = implode( ', ', array_fill( 0, count( $ids ), '%d' ) );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare
		$wpdb->query( $wpdb->prepare( "UPDATE `$table` SET synced = 1 WHERE id IN ($placeholders)", $ids ) );
	}

	/**
	 * Truncate the table, as this is mostly use for cache, when we fetch new data, old data should be removed for
	 * consistent sync with API side.
	 */
	public static function truncate() {
		$orm = self::get_orm();
		$orm->get_repository( self::class )->truncate();
	}

	/**
	 * Get the very last item, mostly use for testing.
	 *
	 * @return self|null
	 */
	public static function get_last() {
		$orm = self::get_orm();

		return $orm->get_repository( self::class )
					->where( 'synced', 'in', array( 0, 1 ) )
					->order_by( 'id', 'desc' )
					->first();
	}

	/**
	 * Sometimes we need the pre of last, for testing.
	 *
	 * @return self|null
	 */
	public static function get_pre_last() {
		$orm   = self::get_orm();
		$model = $orm->get_repository( self::class )
					->where( 'synced', 'in', array( 0, 1 ) )
					->order_by( 'id', 'desc' )
					->limit( 2, 0 )
					->get();

		return array_pop( $model );
	}

	/**
	 * Get logs that need to be flushed.
	 *
	 * @return self[]
	 */
	public static function get_logs_need_flush() {
		$orm = self::get_orm();

		return $orm->get_repository( self::class )->where( 'synced', 0 )->limit( 50 )->get();
	}

	/**
	 * Get log models by IDs.
	 *
	 * @param  int[] $ids  Row IDs.
	 *
	 * @return self[]
	 */
	public static function get_by_ids( array $ids ): array {
		return self::get_orm()->get_repository( self::class )->where( 'id', 'in', $ids )->order_by( 'id' )->get();
	}

	/**
	 * Query logs from internal cache.
	 *
	 * @param  int      $date_from  The start date we want to query, in timestamp format.
	 * @param  int      $date_to  The date end for the query, in timestamp format.
	 * @param  array    $events  Type of the event, e.g. comment, user, system.
	 * @param  string   $user_id  Who trigger this event, if it 0, will be guest.
	 * @param  string   $ip  IP of who trigger this.
	 * @param  int|bool $paged  Current page.
	 * @param  int      $per_page  Number of logs per page.
	 *
	 * @return array
	 */
	public static function query(
		$date_from,
		$date_to,
		$events = array(),
		$user_id = '',
		$ip = '',
		$paged = 1,
		$per_page = 10
	): array {
		$orm     = self::get_orm();
		$builder = $orm->get_repository( self::class );
		$builder->where( 'timestamp', '>=', $date_from )
				->where( 'timestamp', '<=', $date_to );

		if ( is_array( $events )
			&& count( $events )
			&& count( array_diff( $events, self::allowed_events() ) ) === 0 ) {
			$builder->where( 'event_type', 'in', $events );
		}

		if ( is_numeric( $user_id ) && $user_id > 0 ) {
			$builder->where( 'user_id', $user_id );
		}

		if ( is_string( $ip ) && '' !== trim( $ip ) ) {
			$builder->where( 'ip', 'like', "%$ip%" );
		}
		$builder->order_by( 'timestamp', 'desc' );

		if ( false !== $paged ) {
			// If paged == false, then it will be no paging.
			$per_page = max( 1, (int) $per_page );
			$offset   = ( $paged - 1 ) * $per_page;
			$builder->limit( $per_page, $offset );
		}

		return $builder->get();
	}

	/**
	 * Clean up the old logs depending on the storage settings.
	 *
	 * @param  int      $date_from  The start date we want to query, in timestamp format.
	 * @param  int      $date_to  The date end for the query, in timestamp format.
	 * @param  int|null $limit  Limit.
	 *
	 * @return void
	 */
	public static function delete_old_logs( $date_from, $date_to, $limit = null ) {
		$orm     = self::get_orm();
		$builder = $orm->get_repository( self::class );
		$builder->where( 'timestamp', '>=', $date_from )
				->where( 'timestamp', '<=', $date_to );

		if ( null === $limit ) {
			$builder->delete_all();
		} else {
			$builder->order_by( 'id' )
					->limit( $limit )
					->delete_by_limit();
		}
	}

	/**
	 * Counts the number of records in the database table that match the given criteria.
	 *
	 * @param  int    $date_from  The start date to filter records by.
	 * @param  int    $date_to  The end date to filter records by.
	 * @param  array  $events  (optional) An array of event types to filter records by.
	 * @param  string $user_id  (optional) The user ID to filter records by.
	 * @param  string $ip  (optional) The IP address to filter records by.
	 *
	 * @return int The number of records that match the given criteria.
	 */
	public static function count( $date_from, $date_to, $events = array(), $user_id = '', $ip = '' ) {
		$orm     = self::get_orm();
		$builder = $orm->get_repository( self::class );
		$builder->where( 'timestamp', '>=', $date_from )
				->where( 'timestamp', '<=', $date_to );
		if ( count( $events ) && count( array_diff( $events, self::allowed_events() ) ) === 0 ) {
			$builder->where( 'event_type', 'in', $events );
		}

		if ( is_numeric( $user_id ) && $user_id > 0 ) {
			$builder->where( 'user_id', $user_id );
		}

		if ( is_string( $ip ) && '' !== trim( $ip ) ) {
			$builder->where( 'ip', 'like', "%$ip%" );
		}

		return (int) $builder->count();
	}

	/**
	 * Mass insert logs, usually fetched from API.
	 *
	 * @param  array $data    An array of data to be inserted into the Audit_Log table.
	 * @param  int   $synced  Whether the logs have already been synced.
	 *
	 * @return void
	 * @throws ReflectionException If the import method of the Audit_Log class throws a ReflectionException.
	 */
	public static function mass_insert( $data, $synced = 1 ) {
		// Use raw sql for faster.
		foreach ( $data as $datum ) {
			// Cloud timestamps may contain fractions; local dates remain in seconds.
			if ( isset( $datum['timestamp'] ) ) {
				$datum['timestamp'] = (int) $datum['timestamp'];
			}
			$item = new Audit_Log();
			$item->import( $datum );
			$item->fractional_timestamp = isset( $datum['fractional_timestamp'] )
				? (string) $datum['fractional_timestamp']
				: null;
			$item->synced               = $synced;
			$item->save();
		}
	}

	/**
	 * Retrieves a record from the database by its ID.
	 *
	 * @param  int $id  The ID of the record to retrieve.
	 *
	 * @return mixed The retrieved record, or null if not found.
	 */
	public static function get_by_id( $id ) {
		$orm = self::get_orm();

		return $orm->get_repository( self::class )->find_by_id( $id );
	}

	/**
	 * Get allowed types.
	 *
	 * @return array
	 */
	public static function allowed_events(): array {
		return array(
			self::EVENT_TYPE_USER,
			self::EVENT_TYPE_SYSTEM,
			self::EVENT_TYPE_COMMENT,
			self::EVENT_TYPE_MEDIA,
			self::EVENT_TYPE_SETTINGS,
			self::EVENT_TYPE_CONTENT,
			self::EVENT_TYPE_MENU,
		);
	}
}
