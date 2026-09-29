<?php
/**
 * Handles core integrity scan.
 *
 * @package WP_Defender\Behavior\Scan_Item
 */

namespace WP_Defender\Behavior\Scan_Item;

use WP_Error;
use Calotes\Base\File;
use WP_Defender\Traits\IO;
use WP_Defender\Model\Scan;
use Calotes\Component\Behavior;
use WP_Defender\Traits\Formats;
use WP_Defender\Model\Scan_Item;
use WP_Defender\Traits\File_Operations;
use WP_Defender\Controller\Scan as Scan_Controller;
use WP_Defender\Behavior\Scan\Core_Integrity as Core_Integrity_Scan;
use WP_Filesystem_Base;

/**
 * This class represents a behavior related to core integrity in the WP_Defender plugin.
 */
class Core_Integrity extends Behavior {

	use Formats;
	use IO;
	use File_Operations;

	/**
	 * Return general data so we can output on frontend.
	 *
	 * @return array
	 */
	public function to_array(): array {
		$data = $this->owner->raw_data;
		$file = $data['file'];

		list( $file_created_at, $file_size, $deleted ) = $this->get_file_meta( $file );

		return array(
			'id'         => $this->owner->id,
			'type'       => Scan_Item::TYPE_INTEGRITY,
			'file_name'  => pathinfo( $file, PATHINFO_BASENAME ),
			'full_path'  => $file,
			'date_added' => $file_created_at,
			'size'       => $file_size,
			'scenario'   => $data['type'],
			'deleted'    => $deleted,
			'short_desc' => $this->get_short_description(),
		);
	}

	/**
	 * We will get the origin code by looking into svn repo.
	 *
	 * @return false|string|WP_Error
	 */
	private function get_origin_code() {
		global $wp_filesystem;
		// Initialize the WP filesystem, no more using 'file-put-contents' function.
		if ( ! $wp_filesystem instanceof WP_Filesystem_Base ) {
			require_once ABSPATH . '/wp-admin/includes/file.php';
			WP_Filesystem();
		}
		global $wp_version;
		$data            = $this->owner->raw_data;
		$file            = wp_normalize_path( $data['file'] );
		$relative_path   = str_replace( wp_normalize_path( ABSPATH ), '', $file );
		$source_file_url = "https://core.svn.wordpress.org/tags/$wp_version/" . $relative_path;
		$ds              = DIRECTORY_SEPARATOR;
		if ( ! function_exists( 'download_url' ) ) {
			require_once ABSPATH . 'wp-admin' . $ds . 'includes' . $ds . 'file.php';
		}
		$tmp = download_url( $source_file_url );
		if ( is_wp_error( $tmp ) ) {
			return $tmp;
		}
		$content = $wp_filesystem->get_contents( $tmp );
		wp_delete_file( $tmp );
		$trusted_checksum = $this->get_trusted_checksum( $relative_path );

		if ( ! is_string( $content ) || ! is_string( $trusted_checksum ) ) {
			return new WP_Error(
				'defender_core_checksum_unavailable',
				esc_html__( 'The trusted WordPress core checksum is unavailable.', 'defender-security' )
			);
		}

		if ( ! hash_equals( strtolower( $trusted_checksum ), md5( $content ) ) ) {
			return new WP_Error(
				'defender_core_checksum_mismatch',
				esc_html__( 'The downloaded WordPress core file failed checksum verification.', 'defender-security' )
			);
		}

		return $content;
	}

	/**
	 * Get the trusted WordPress checksum for a core file.
	 *
	 * New scan items persist the checksum used to identify the modification.
	 * The temporary scan cache and the WordPress checksum API are fallbacks for
	 * scan items created before that checksum was stored with the issue.
	 *
	 * @param string $relative_path Core file path relative to ABSPATH.
	 * @return string|null
	 */
	private function get_trusted_checksum( $relative_path ) {
		$data = $this->owner->raw_data;
		if ( isset( $data['checksum'] ) && is_string( $data['checksum'] ) ) {
			return $data['checksum'];
		}

		$checksums = get_site_option( Core_Integrity_Scan::CACHE_CHECKSUMS, array() );
		if ( is_array( $checksums ) && isset( $checksums[ $relative_path ] ) && is_string( $checksums[ $relative_path ] ) ) {
			return $checksums[ $relative_path ];
		}

		if ( ! function_exists( 'get_core_checksums' ) ) {
			require_once ABSPATH . 'wp-admin/includes/update.php';
		}

		global $wp_version, $wp_local_package;
		$locale    = isset( $wp_local_package ) && '' !== $wp_local_package ? $wp_local_package : 'en_US';
		$checksums = get_core_checksums( $wp_version, $locale );
		if ( isset( $checksums[ $wp_version ] ) && is_array( $checksums[ $wp_version ] ) ) {
			$checksums = $checksums[ $wp_version ];
		}

		return is_array( $checksums ) && isset( $checksums[ $relative_path ] ) && is_string( $checksums[ $relative_path ] )
			? $checksums[ $relative_path ]
			: null;
	}

	/**
	 * Restore the file with its origin content.
	 *
	 * @return void|array|WP_Error
	 */
	public function resolve() {
		global $wp_filesystem;
		// Initialize the WP filesystem, no more using 'file-put-contents' function.
		if ( ! $wp_filesystem instanceof WP_Filesystem_Base ) {
			require_once ABSPATH . '/wp-admin/includes/file.php';
			WP_Filesystem();
		}

		$data = $this->owner->raw_data;
		if ( 'modified' !== $data['type'] ) {
			// Should not be here unless case changed.
			return;
		}

		$origin = $this->get_origin_code();
		if ( false === $origin || is_wp_error( $origin ) ) {
			return;
		}

		$path = $data['file'];
		$ret  = $wp_filesystem->put_contents( $path, $origin );
		if ( $ret ) {
			$scan = Scan::get_last();
			$scan->remove_issue( $this->owner->id );
			$this->log( sprintf( '%s is deleted', $path ), Scan_Controller::SCAN_LOG );

			do_action( 'wpdef_fixed_scan_issue', 'core_integrity', 'resolve' );

			return array( 'message' => esc_html__( 'This item has been resolved.', 'defender-security' ) );
		} else {
			return new WP_Error(
				'defender_permissions_denied',
				esc_html__(
					'Permissions Denied. Defender does not have the needed permissions to edit the file. Please change file permissions to 640 or contact your hosting provider so they could change them for you.',
					'defender-security'
				)
			);
		}
	}

	/**
	 * Ignore the suspicious file.
	 *
	 * @return array
	 */
	public function ignore(): array {
		$scan       = Scan::get_last();
		$data       = $this->owner->raw_data;
		$issue_name = '<b>' . pathinfo( $data['file'], PATHINFO_BASENAME ) . '</b>';
		$res        = $scan->ignore_issue( $this->owner->id );
		if ( ! $res ) {
			return array(
				'type_notice' => 'error',
				'message'     => $this->get_failed_ignore_result( $issue_name ),
			);
		}

		return array(
			'message' => sprintf(
			/* translators: %s: Scan issue name. */
				esc_html__( 'You’ve successfully ignored the security issue related to %s.', 'defender-security' ),
				$issue_name
			),
		);
	}

	/**
	 * Restore the ignored suspicious file.
	 *
	 * @return array
	 */
	public function unignore(): array {
		$scan = Scan::get_last();
		$scan->unignore_issue( $this->owner->id );

		return array( 'message' => esc_html__( 'The suspicious file has been successfully restored.', 'defender-security' ) );
	}

	/**
	 * Delete the file or whole folder.
	 *
	 * @return array|WP_Error
	 */
	public function delete() {
		$data = $this->owner->raw_data;
		$scan = Scan::get_last();

		// Check if the file exists and is readable. If not, remove it from the scan result and log the result.
		$file = $data['file'];
		if ( ! file_exists( $file ) || ! is_readable( $file ) ) {
			$scan->remove_issue( $this->owner->id );
			$this->log(
				sprintf( '%s is not readable and will be removed from the scan result', $file ),
				Scan_Controller::SCAN_LOG
			);

			return array( 'message' => esc_html__( 'This item has been deleted.', 'defender-security' ) );
		} elseif ( 'unversion' === $data['type'] && $this->delete_infected_file( $file ) ) {
			return $this->after_delete( $file, $scan, 'core_integrity' );
		} elseif ( 'dir' === $data['type'] && $this->delete_dir( $file ) ) {
			return $this->after_delete( $file, $scan, 'core_integrity' );
		}

		return $this->get_permission_error( $file );
	}

	/**
	 *  Return the source code depending on the type of the issue:
	 *  If it is unversion, return full source,
	 *  if it is dir, we return a list of files,
	 *  if it is modified, we will return the current code & origin.
	 *
	 * @return array
	 */
	public function pull_src(): array {
		global $wp_filesystem;
		// Initialize the WP filesystem, no more using 'file-put-contents' function.
		if ( ! $wp_filesystem instanceof WP_Filesystem_Base ) {
			require_once ABSPATH . '/wp-admin/includes/file.php';
			WP_Filesystem();
		}

		$data = $this->owner->raw_data;
		if ( ! file_exists( $data['file'] ) && ! is_dir( $data['file'] ) ) {
			return array(
				'code'   => '',
				'origin' => '',
			);
		}
		switch ( $data['type'] ) {
			case 'unversion':
				return array( 'code' => $wp_filesystem->get_contents( $data['file'] ) );
			case 'dir':
				$dir_tree = new File( $data['file'], true, true, array(), array(), false );

				return array( 'code' => implode( PHP_EOL, $dir_tree->get_dir_tree() ) );
			case 'modified':
			default:
				$origin = $this->get_origin_code();

				return array(
					'code'   => $wp_filesystem->get_contents( $data['file'] ),
					'origin' => is_string( $origin ) ? $origin : '',
				);
		}
	}

	/**
	 * Retrieves a short description based on the type of data.
	 *
	 * @return string The short description.
	 */
	private function get_short_description(): string {
		$data = $this->owner->raw_data;
		if ( 'unversion' === $data['type'] ) {
			return esc_html__( 'Unknown file in WordPress core', 'defender-security' );
		} elseif ( 'dir' === $data['type'] ) {
			return esc_html__( 'This directory does not belong to WordPress core', 'defender-security' );
		} elseif ( 'modified' === $data['type'] ) {
			return esc_html__( 'This WordPress core file appears modified', 'defender-security' );
		}

		return '';
	}
}
