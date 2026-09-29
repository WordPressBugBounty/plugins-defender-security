<?php
/**
 * CSV export component.
 *
 * @package WP_Defender\Component\Export
 */

declare(strict_types=1);

namespace WP_Defender\Component\Export;

use RuntimeException;

/**
 * Handles CSV exports and formula injection neutralization.
 */
class Csv {

	/**
	 * Neutralizes an externally influenced string to prevent CSV formula injection.
	 *
	 * Prefixes values whose first effective character (after accounting for leading
	 * whitespace and control characters) is '=', '+', '-', or '@' with an apostrophe.
	 *
	 * @param mixed $value The cell value to sanitize.
	 *
	 * @return mixed
	 */
	public static function neutralize_cell( $value ) {
		if ( ! is_string( $value ) ) {
			return $value;
		}

		if ( 1 === preg_match( '/^[\s\x00-\x1F\x7F]*[=+@-]/', $value ) ) {
			return "'" . $value;
		}

		return $value;
	}

	/**
	 * Neutralizes all string cells in a CSV row to prevent formula injection.
	 *
	 * @param array $row The row data to neutralize.
	 *
	 * @return array
	 */
	public static function neutralize_row( array $row ): array {
		return array_map( array( self::class, 'neutralize_cell' ), $row );
	}

	/**
	 * Writes a row to an open file pointer as CSV after neutralizing cells for formula injection.
	 *
	 * @param resource $stream    The open file pointer.
	 * @param array    $fields    An array of values.
	 * @param string   $separator The field delimiter.
	 * @param string   $enclosure The field enclosure.
	 * @param string   $escape    The escape character. Empty string (default) disables
	 *                            backslash escaping and uses RFC 4180 quote-doubling instead.
	 *
	 * @return int|false
	 */
	public static function write_row( $stream, array $fields, string $separator = ',', string $enclosure = '"', string $escape = '' ): bool|int {
		return fputcsv( $stream, self::neutralize_row( $fields ), $separator, $enclosure, $escape );
	}

	/**
	 * Exports data as a CSV file to the browser for download.
	 *
	 * @param string   $module  Module identifier used to build the download filename
	 *                          (e.g. 'audit-logs' → 'wdf-audit-logs-export-{date}.csv').
	 * @param iterable $rows    The rows of data.
	 * @param array    $headers Column headers. Pass an empty array (default) to omit the header row.
	 *
	 * @return void
	 * @throws RuntimeException If writing the BOM, header, or any data row to the output stream fails.
	 */
	public static function to_browser( string $module, iterable $rows, array $headers = array() ): void {
		$filename = 'wdf-' . $module . '-export-' . wp_date( 'ymdHis' ) . '.csv';
		$testing  = defined( 'WP_DEFENDER_TESTING' ) && WP_DEFENDER_TESTING;

		// Flush and close every active output buffer so the CSV streams directly
		// to the browser instead of accumulating in memory (shared hosts, caching
		// plugins, and debug bars all tend to leave OB layers open).
		// Skipped in test mode so ob_start() capture buffers remain intact.
		if ( ! $testing ) {
			while ( ob_get_level() > 0 ) {
				ob_end_clean();
			}
		}

		if ( ! headers_sent() ) {
			header( 'Content-Type: text/csv; charset=utf-8' );
			header( 'Content-Disposition: attachment; filename="' . sanitize_file_name( $filename ) . '"' );
			header( 'X-Content-Type-Options: nosniff' );
			header( 'Cache-Control: no-store, no-cache, must-revalidate, private' );
			header( 'Pragma: no-cache' );
			header( 'Expires: 0' );
		}

		$stream = fopen( 'php://output', 'w' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen
		if ( false === $stream ) {
			if ( ! $testing ) {
				exit();
			}
			return;
		}

		try {
			// UTF-8 BOM — makes Excel on Windows open the file with the correct
			// encoding without forcing the user through the import wizard.
			if ( false === fwrite( $stream, "\xEF\xBB\xBF" ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
				throw new RuntimeException( 'Failed to write CSV BOM to output stream.' );
			}

			if ( array() !== $headers && false === self::write_row( $stream, $headers ) ) {
				throw new RuntimeException( 'Failed to write CSV header row to output stream.' );
			}

			foreach ( $rows as $row ) {
				if ( false === self::write_row( $stream, (array) $row ) ) {
					throw new RuntimeException( 'Failed to write CSV data row to output stream.' );
				}
			}
		} finally {
			fclose( $stream ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
		}

		if ( ! $testing ) {
			exit();
		}
	}
}
