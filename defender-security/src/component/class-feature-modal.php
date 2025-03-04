<?php
/**
 * Manages the display of "What's New" modals  dashboard.
 *
 * @package WP_Defender\Component
 */

namespace WP_Defender\Component;

use WP_Defender\Component;
use WP_Defender\Behavior\WPMUDEV;
use WP_Defender\Traits\Defender_Dashboard_Client;
use WP_Defender\Model\Setting\Antibot_Global_Firewall_Setting;

/**
 * Use different actions for "What's new" modals.
 *
 * @since 2.5.5
 */
class Feature_Modal extends Component {
	use Defender_Dashboard_Client;

	/**
	 * Feature data for the last active "What's new" modal.
	 */
	public const FEATURE_SLUG    = 'wd_show_feature_strong_password';
	public const FEATURE_VERSION = '5.1.0';

	/**
	 * Get modals that are displayed on the Dashboard page.
	 *
	 * @param  bool $force_hide  The modal is not displayed in every version, so we need a flag that will control the
	 *                       display process.
	 *
	 * @return array
	 * @since 2.7.0 Use one template for Welcome modal and dynamic data.
	 */
	public function get_dashboard_modals( $force_hide = false ): array {
		$is_displayed = $force_hide ? false : $this->display_last_modal( self::FEATURE_SLUG );
		$title        = esc_html__( 'New! Strong Password Rule', 'defender-security' );
		$current_user = wp_get_current_user();

		$desc  = '<p class="text-base leading-22px mb-15px">';
		$desc .= sprintf(
			/* translators: %s: Name. */
			esc_html__(
				'Hey %s, security just got stronger! You can now require users to set strong passwords when registering or updating their credentials. This helps protect your site from unauthorized access and password breaches.',
				'defender-security'
			),
			esc_html( $current_user->display_name )
		);
		$desc .= '</p>';

		$desc .= '<div class="feature-highlights">';
		$desc .= '<span class="text-gray-500 font-bold">' . esc_html__( 'What’s New?', 'defender-security' ) . '</span>';
		$desc .= '<ul><li><span class="sui-icon-check-tick" aria-hidden="true"></span>' . esc_html__( 'Enforce strong password strength rules.', 'defender-security' ) . '</li>
			<li><span class="sui-icon-check-tick" aria-hidden="true"></span>' . esc_html__( 'Improve security without manual intervention.', 'defender-security' ) . '</li>
			<li><span class="sui-icon-check-tick" aria-hidden="true"></span>' . esc_html__( 'Manage all password-related settings in one place.', 'defender-security' ) . '</li></ul>';
		$desc .= '</div>';

		$button_title = esc_html__( 'Go to Password Rules', 'defender-security' );

		return array(
			'show_welcome_modal' => $is_displayed,
			'welcome_modal'      => array(
				'title'           => $title,
				'desc'            => $desc,
				'banner_1x'       => defender_asset_url( '/assets/img/modal/welcome-modal.png' ),
				'banner_2x'       => defender_asset_url( '/assets/img/modal/welcome-modal@2x.png' ),
				'banner_alt'      => esc_html__( 'Modal for Strong Password Rule', 'defender-security' ),
				'button_title'    => $button_title,
				// Additional information.
				'additional_text' => $this->additional_text(),
				'read_more_title' => esc_html__( 'DISMISS', 'defender-security' ),
				'read_more_url'   => network_admin_url( 'admin.php?page=wdf-advanced-tools&view=password-rules' ),
			),
		);
	}

	/**
	 * Display modal if:
	 * plugin version has important changes,
	 * plugin settings have been reset before -> this is not fresh install,
	 * Whitelabel > Documentation, Tutorials and What’s New Modal > checked Show tab OR Whitelabel is disabled.
	 *
	 * @param  string $key  The feature slug to check.
	 *
	 * @return bool
	 */
	protected function display_last_modal( $key ): bool {
		$info = defender_white_label_status();

		return (bool) get_site_option( $key ) && ! $info['hide_doc_link'];
	}

	/**
	 * Upgrades site options related to feature modals based on the database version.
	 */
	public function upgrade_site_options(): void {
		$db_version    = get_site_option( 'wd_db_version' );
		$feature_slugs = array(
			// Important slugs to display Onboarding, e.g. after the click on Reset settings.
			array(
				'slug' => 'wp_defender_shown_activator',
				'vers' => '2.4.0',
			),
			array(
				'slug' => 'wp_defender_is_free_activated',
				'vers' => '2.4.0',
			),
			// The latest feature.
			array(
				'slug' => 'wd_show_feature_antibot',
				'vers' => '5.0.0',
			),
			// The current feature.
			array(
				'slug' => self::FEATURE_SLUG,
				'vers' => self::FEATURE_VERSION,
			),
		);
		foreach ( $feature_slugs as $feature ) {
			if ( version_compare( $db_version, $feature['vers'], '==' ) ) {
				// The current feature.
				update_site_option( $feature['slug'], true );
			} else {
				// Old one.
				delete_site_option( $feature['slug'] );
			}
		}
	}

	/**
	 * Get additional text.
	 *
	 * @return string
	 */
	private function additional_text(): string {
		return '';
	}

	/**
	 * Delete welcome modal key.
	 *
	 * @return void
	 */
	public static function delete_modal_key(): void {
		delete_site_option( self::FEATURE_SLUG );
	}
}
