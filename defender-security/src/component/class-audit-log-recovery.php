<?php
/**
 * Prepares historical synced audit logs lacking a fractional key for re-sending.
 *
 * @package WP_Defender\Component
 */

namespace WP_Defender\Component;

use WP_Defender\Model\Audit_Log;

/**
 * Recovery selection and preparation of keyless synced audit logs.
 *
 * @todo Remove this class after 1 year (October 2027).
 */
class Audit_Log_Recovery {

	/**
	 * Site option holding the highest row ID already checked.
	 */
	public const CURSOR = 'wd_audit_recovery_cursor';

	/**
	 * Rows checked per call, so each hourly run reads a fixed slice instead of the whole table.
	 */
	private const SCAN_WINDOW = 300;

	/**
	 * Select keyless synced rows, then make them unsynced with a fractional key.
	 *
	 * The highest-ID keyless row of each site_url + timestamp group is skipped (assumed to be the
	 * only one the API retained). That is a recovery assumption, not proven API write order.
	 *
	 * @param int $limit Maximum number of rows to prepare.
	 *
	 * @return Audit_Log[] Rows successfully persisted as unsynced with a key.
	 */
	public static function prepare( int $limit = 50 ): array {
		global $wpdb;
		$limit = min( 50, $limit );
		if ( $limit < 1 ) {
			return array();
		}
		$table  = $wpdb->base_prefix . 'defender_audit_log';
		$cursor = (int) get_site_option( self::CURSOR, 0 );
		// phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$window = $wpdb->get_col(
			$wpdb->prepare( "SELECT id FROM `$table` WHERE id > %d ORDER BY id ASC LIMIT %d", $cursor, self::SCAN_WINDOW )
		);
		if ( ! is_array( $window ) || $wpdb->last_error || array() === $window ) {
			return array();
		}
		$window_end = (int) end( $window );
		// Survivors are computed over complete groups by the NOT-highest check, before LIMIT applies.
		$ids = $wpdb->get_col(
			$wpdb->prepare(
				"SELECT t.id FROM `$table` t WHERE t.id > %d AND t.id <= %d
				AND t.synced = 1 AND ( t.fractional_timestamp IS NULL OR t.fractional_timestamp = '' )
				AND EXISTS ( SELECT 1 FROM `$table` n WHERE n.site_url = t.site_url AND n.timestamp = t.timestamp
					AND n.synced = 1 AND ( n.fractional_timestamp IS NULL OR n.fractional_timestamp = '' ) AND n.id > t.id )
				ORDER BY t.id ASC LIMIT %d",
				$cursor,
				$window_end,
				$limit
			)
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		if ( ! is_array( $ids ) || $wpdb->last_error ) {
			return array();
		}

		if ( ! count( $ids ) ) {
			update_site_option( self::CURSOR, $window_end );
			return array();
		}
		// A full batch may leave candidates in the window; resume after the last one.
		$next_cursor = count( $ids ) === $limit ? (int) end( $ids ) : $window_end;

		$logs = Audit_Log::get_by_ids( array_map( 'intval', $ids ) );
		if ( array() === $logs ) {
			return array();
		}

		$ready_logs = Audit_Log::assign_keys( $logs );
		if ( array() !== $ready_logs ) {
			update_site_option( self::CURSOR, $next_cursor );
		}

		return $ready_logs;
	}
}
