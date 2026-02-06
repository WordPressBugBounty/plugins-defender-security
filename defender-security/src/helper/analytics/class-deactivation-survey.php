<?php
/**
 * Responsible for gathering analytics data.
 *
 * @package WP_Defender\Helper\Analytics
 */

namespace WP_Defender\Helper\Analytics;

use WP_Defender\Event;
use WP_Defender\Traits\Plugin;

/**
 * Gather analytics data.
 */
class Deactivation_Survey extends Event {

	use Plugin;

	public const EVENT_DATA_OPTION = 'wp_defender_event_times';

	/**
	 * Provides data for the frontend.
	 *
	 * @return array An array of data for the frontend.
	 */
	public function data_frontend(): array {
		return array();
	}

	/**
	 * Converts the current state of the object to an array.
	 *
	 * @return array Returns an associative array of object properties.
	 */
	public function to_array(): array {
		return array();
	}

	/**
	 * Imports data into the model.
	 *
	 * @param array $data Data to be imported into the model.
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
	}

	/**
	 * Exports strings.
	 *
	 * @return array
	 */
	public function export_strings() {
		return array();
	}

	/**
	 * Get a list of active features.
	 *
	 * @return array
	 */
	private function get_active_features(): array {
		$google_recaptcha = false;
		$turnstile        = false;
		$captcha          = wd_di()->get( \WP_Defender\Model\Setting\Captcha::class );
		if ( $captcha->enabled ) {
			$turnstile        = 'turnstile' === $captcha->active_type;
			$google_recaptcha = 'turnstile' !== $captcha->active_type;
		}
		$ua_model = wd_di()->get( \WP_Defender\Model\Setting\User_Agent_Lockout::class );

		$features = array(
			'antibot'                   => wd_di()->get( \WP_Defender\Model\Setting\Antibot_Global_Firewall_Setting::class )->enabled,
			'audit_logging'             => wd_di()->get( \WP_Defender\Model\Setting\Audit_Logging::class )->enabled,
			'google_recaptcha'          => $google_recaptcha,
			'cloudflare_turnstile'      => $turnstile,
			'404_detection'             => wd_di()->get( \WP_Defender\Model\Setting\Notfound_Lockout::class )->enabled,
			'login_protection'          => wd_di()->get( \WP_Defender\Model\Setting\Login_Lockout::class )->enabled,
			'user_agent_banning'        => $ua_model->enabled,
			'fake_crawler'              => $ua_model->enabled ? $ua_model->fake_bots_enabled : false,
			'two_factor_authentication' => wd_di()->get( \WP_Defender\Model\Setting\Two_Fa::class )->enabled,
			'mask_login_area'           => wd_di()->get( \WP_Defender\Model\Setting\Mask_Login::class )->enabled,
			'security_headers'          => wd_di()->get( \WP_Defender\Model\Setting\Security_Headers::class )->is_any_activated(),
			'pwned_passwords'           => wd_di()->get( \WP_Defender\Model\Setting\Password_Protection::class )->enabled,
			'strong_password'           => wd_di()->get( \WP_Defender\Model\Setting\Strong_Password::class )->enabled,
		);

		return array_keys(
			array_filter(
				$features,
				function ( $value ) {
					return true === $value;
				}
			)
		);
	}

	/**
	 * Get Date & Time properties.
	 *
	 * @return array
	 */
	private function get_date_time_properties(): array {
		$properties  = array();
		$event_times = get_site_option( self::EVENT_DATA_OPTION, array() );
		$time_events = array(
			'Installation Date' => 'plugin_installed',
			'Activation Date'   => 'plugin_activated',
			'Last Updated'      => 'plugin_upgraded',
		);

		foreach ( $time_events as $event_name => $event_key ) {
			if ( isset( $event_times[ $event_key ] ) ) {
				$event_value = $event_times[ $event_key ];
				if ( is_int( $event_value ) && $event_value > 0 ) {
					$properties[ $event_name ] = gmdate( 'c', $event_value );
				}
			}
		}

		return $properties;
	}

	/**
	 * Track Deactivation survey.
	 *
	 * @param array $properties Array of properties.
	 *
	 * @return void
	 */
	public function track_deactivation_survey( $properties ) {
		if ( ! defender_is_wp_cli() ) {
			$properties = array_merge(
				$properties,
				array(
					'active_plugins'  => $this->get_active_plugin_names(),
					'active_features' => $this->get_active_features(),
				),
				$this->get_date_time_properties()
			);

			$this->forced_track(
				'Deactivation Survey',
				$properties
			);
		}
	}
}
