<?php
/**
 * Handles
 *
 * @package WP_Defender\Component\Security_Tweaks
 */

namespace WP_Defender\Component\Security_Tweaks;

/**
 * Class WP_Version
 */
class WP_Version extends Abstract_Security_Tweaks {

	/**
	 * Component slug name.
	 *
	 * @var string
	 */
	public string $slug = 'wp-version';

	/**
	 * Check whether the issue has been resolved or not.
	 *
	 * @return bool
	 */
	public function check() {
		return $this->is_resolved();
	}

	/**
	 * Here is the code for processing.
	 *
	 * @return bool
	 */
	public function process() {
		return true;
	}

	/**
	 * This is for un-do stuff that has be done in @process.
	 *
	 * @return bool
	 */
	public function revert() {
		return true;
	}

	/**
	 * Shield up.
	 *
	 * @return bool
	 */
	public function shield_up() {
		return true;
	}

	/**
	 * Check whether the issue is resolved or not.
	 *
	 * @return bool
	 */
	private function is_resolved() {
		global $wp_version;

		return version_compare( $wp_version, $this->get_latest_version(), '=' );
	}

	/**
	 * Get the latest WordPress version.
	 *
	 * @return string|false on failure
	 */
	public function get_latest_version() {
		if ( ! function_exists( 'get_core_updates' ) ) {
			include_once ABSPATH . 'wp-admin/includes/update.php';
		}

		$data = get_core_updates();

		if ( ! is_array( $data ) || array() === $data ) {
			wp_version_check( array(), true );
			$data = get_core_updates( array( 'dismissed' => true ) );
		}

		// For bool value and empty array.
		if ( ! is_array( $data ) || array() === $data ) {
			return false;
		}

		return reset( $data )->version;
	}

	/**
	 * Retrieve the tweak's label.
	 *
	 * @return string
	 */
	public function get_label(): string {
		return wp_strip_all_tags( 'Update WordPress', 'wpdef' );
	}

	/**
	 * Get the error reason.
	 *
	 * @return string
	 */
	public function get_error_reason(): string {
		return sprintf(
			/* translators: 1. Open tag. 2. Close tag. */
			esc_html__(
				'%1$sWordPress is out of date%2$s and may expose details hackers can use.',
				'defender-security'
			),
			'<strong>',
			'</strong>',
		);
	}

	/**
	 * Return a summary data of this tweak.
	 *
	 * @return array
	 */
	public function to_array(): array {
		return array(
			'slug'             => $this->slug,
			'title'            => $this->get_label(),
			'errorReason'      => $this->get_error_reason(),
			'successReason'    => wp_strip_all_tags( 'WordPress is up to date.', 'wpdef' ),
			'misc'             => array(
				'latest_wp'          => $this->get_latest_version(),
				'core_update_url'    => network_admin_url( 'update-core.php' ),
				'show_revert_button' => false,
				'show_action_button' => false,
			),
			'bulk_description' => wp_strip_all_tags(
				'Outdated WordPress installs can leave your site vulnerable. Update WordPress to the latest version to help protect your site and keep security up to date.',
				'wpdef'
			),
			'bulk_title'       => $this->get_label(),
		);
	}
}
