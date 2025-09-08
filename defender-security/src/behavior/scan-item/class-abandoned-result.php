<?php
/**
 * Handles abandoned plugin scan item.
 *
 * @package WP_Defender\Behavior\Scan_Item
 */

namespace WP_Defender\Behavior\Scan_Item;

use WP_Defender\Traits\IO;
use WP_Defender\Model\Scan;
use WP_Defender\Traits\Plugin;
use Calotes\Component\Behavior;
use WP_Defender\Model\Scan_Item;
use WP_Defender\Controller\Scan as Scan_Controller;

/**
 * Class Abandoned_Result.
 */
class Abandoned_Result extends Behavior {

	use IO;
	use Plugin;

	/**
	 * Return general data so we can output on frontend.
	 *
	 * @return array
	 */
	public function to_array(): array {
		$data = $this->owner->raw_data;

		return array(
			'id'           => $this->owner->id,
			'type'         => $this->owner->type,
			'file_name'    => $data['name'],
			'version'      => $data['version'],
			'plugin_url'   => $data['url'],
			'tested_wp'    => $data['tested_wp'],
			'short_desc'   => $this->get_short_desc( $this->owner->type ),
			'deletable'    => ! $this->is_active_plugin( $data['slug'] ),
			'reason_text'  => $data['reason_text'],
			'last_updated' => $data['last_updated'],
			// Follow consistency with other types. Need for WP-CLI command. Full path = base slug for this item.
			'full_path'    => $data['slug'],
		);
	}

	/**
	 * There is not resolve-action for the current scan type.
	 *
	 * @return void
	 */
	public function resolve() {}

	/**
	 * Ignore the abandoned plugin for the current scan.
	 *
	 * @return array An array with a message indicating successful ignore.
	 */
	public function ignore(): array {
		$scan = Scan::get_last();
		$scan->ignore_issue( $this->owner->id );

		return array( 'message' => esc_html__( 'The plugin has been successfully ignored.', 'defender-security' ) );
	}

	/**
	 * Allow the abandoned plugin for the current scan.
	 *
	 * @return array An array with a message indicating successful restoration.
	 */
	public function unignore(): array {
		$scan = Scan::get_last();
		$scan->unignore_issue( $this->owner->id );

		return array( 'message' => esc_html__( 'The plugin has been successfully restored.', 'defender-security' ) );
	}

	/**
	 * Remove a plugin at the specified path.
	 *
	 * @param  string $path  The plugin path.
	 *
	 * @return bool
	 */
	private function maybe_remove( string $path ): bool {
		if ( is_dir( $path ) ) {
			return $this->delete_dir( $path );
		} else {
			// Sometimes a plugin consists of one file.
			wp_delete_file( $path );
			return true;
		}
	}

	/**
	 * Removes a plugin based on the provided data, checking if it is active and has the necessary permissions.
	 *
	 * @param  array $data  An array containing information about the plugin to be removed.
	 *
	 * @return array An array with the status of the removal process and any related messages.
	 */
	private function remove_plugin( array $data ): array {
		$active = $this->is_active_plugin( $data['slug'] );
		if ( $active ) {
			return array(
				'type_notice' => 'error',
				'message'     => esc_html__( 'This plugin cannot be removed because it is active.', 'defender-security' ),
			);
		}

		$abs_path = wp_normalize_path( WP_PLUGIN_DIR ) . DIRECTORY_SEPARATOR . $data['slug'];
		if ( file_exists( $abs_path ) && ! $this->maybe_remove( $abs_path ) ) {
			return array(
				'type_notice' => 'error',
				'message'     => esc_html__(
					'Defender does not have enough permission to remove this plugin.',
					'defender-security'
				),
			);
		}

		$message = sprintf(
		/* translators: %s: Plugin name. */
			esc_html__( '%s plugin', 'defender-security' ),
			'<b>' . $data['name'] . '</b>'
		);
		$this->log( $message . ' is deleted', Scan_Controller::SCAN_LOG );
		$model = Scan::get_last();
		$model->remove_issue( $this->owner->id );
		// No makes sense to remove related issue(-s) because it's whole folder. Not file.

		do_action( 'wpdef_fixed_scan_issue', 'abandoned_plugin', 'delete' );

		return array(
			'message' => esc_html__( 'This item has been permanently removed', 'defender-security' ),
		);
	}

	/**
	 * Delete whole folder.
	 *
	 * @return array
	 */
	public function delete(): array {
		$data = $this->owner->raw_data;
		return $this->remove_plugin( $data );
	}

	/**
	 *  Get the short description.
	 *
	 * @param  string $type Scan type.
	 *
	 * @return string
	 */
	private function get_short_desc( string $type ): string {
		return Scan_Item::TYPE_PLUGIN_OUTDATED === $type
			? sprintf(
			/* translators: %s: Time period. */
				esc_html__( 'No updates released by the author in the past %s', 'defender-security' ),
				\WP_Defender\Behavior\Scan\Abandoned_Plugin::get_outdated_period()
			)
			: esc_html__( 'Removed from the wordpress.org repository', 'defender-security' );
	}
}
