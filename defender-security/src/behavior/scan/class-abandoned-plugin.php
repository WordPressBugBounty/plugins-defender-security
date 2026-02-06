<?php
/**
 * Handle abandoned plugin scan.
 *
 * @package WP_Defender\Behavior\Scan
 */

namespace WP_Defender\Behavior\Scan;

use Calotes\Component\Behavior;
use WP_Defender\Component\Scan as Scan_Component;
use WP_Defender\Controller\Scan as Scan_Controller;
use WP_Defender\Model\Scan;
use WP_Defender\Model\Scan_Item;
use WP_Defender\Traits\IO;
use WP_Defender\Traits\Plugin;

/**
 * Handle abandoned plugin scan.
 */
class Abandoned_Plugin extends Behavior {

	use IO;
	use Plugin;

	/**
	 * Hold the Scan model or null if not set.
	 *
	 * @var Scan|null
	 */
	private ?Scan $scan;

	/**
	 * Outdated plugin period.
	 *
	 * @var string
	 */
	private const OUTDATED_PERIOD = '2 years';

	/**
	 * Initialize Scan instance.
	 *
	 * @param Scan $scan The Scan model.
	 */
	public function __construct( Scan $scan ) {
		$this->scan = $scan;
	}

	/**
	 * Get the outdated period of the plugin.
	 *
	 * @return string
	 */
	public static function get_outdated_period(): string {
		// Filter to override outdated threshold period.
		$period = apply_filters( 'wpdef_scan_outdated_period', self::OUTDATED_PERIOD );
		$period = is_string( $period ) ? $period : (string) $period;
		// If time period is invalid, use the default one.
		return strtotime( '- ' . $period ) ? $period : self::OUTDATED_PERIOD;
	}

	/**
	 * Check if there are abandoned plugins.
	 *
	 * @return bool
	 */
	public function abandoned_plugin_check(): bool {
		$ignored_issues = $this->get_ignored_issues();

		$actioned_plugins = get_site_option( Scan_Component::PLUGINS_ACTIONED );
		$plugin_list      = Scan_Component::are_actioned_plugins( $actioned_plugins )
			? $actioned_plugins
			: $this->get_plugin_slugs();

		foreach ( $plugin_list as $slug => $plugin_data ) {
			$this->check_abandoned_plugin_by( $slug );
		}

		$this->scan->calculate_percent( 100, 4 );
		$this->add_ignored_issues( $ignored_issues );

		return true;
	}

	/**
	 * Retrieve the list of ignored issues.
	 *
	 * @return array The list of ignored issues.
	 */
	private function get_ignored_issues(): array {
		$last = Scan::get_last();

		return is_object( $last )
			? $last->get_issues(
				Scan::get_abandoned_types(),
				Scan_Item::STATUS_IGNORE
			)
			: array();
	}

	/**
	 * Add ignored issues to the scan.
	 *
	 * @param  array $ignored_issues  The array of ignored issues to add.
	 */
	private function add_ignored_issues( array $ignored_issues ) {
		if ( array() !== $ignored_issues ) {
			foreach ( $ignored_issues as $issue ) {
				$this->scan->add_item( $issue->type, $issue->raw_data, Scan_Item::STATUS_IGNORE );
			}
		}
	}

	/**
	 * Handle the error by different actions, e.g. logging.
	 *
	 * @param  string $error_message  The error message.
	 */
	private function handle_error( string $error_message ) {
		$this->log( $error_message, Scan_Controller::SCAN_LOG );
	}

	/**
	 * Prepare data before saving.
	 *
	 * @param array $body_json      Data from WP API.
	 * @param array $plugin_details Data from local plugin headers.
	 *
	 * @return array {
	 *     Plugin data. Values will be empty if not supplied by the plugin or API sides.
	 *
	 *     @type string $name         Plugin name.
	 *     @type string $slug         Plugin slug.
	 *     @type string $url          Plugin URL.
	 *     @type string $version      Plugin version.
	 *     @type string $tested_wp    Latest tested WordPress version.
	 *     @type string $last_updated Last updated date.
	 *     @type string $reason_text  Reason for saving or update.
	 * }
	 */
	private function prepare_item_data( array $body_json, array $plugin_details ): array {
		$data = array();
		// Check plugin name.
		if ( isset( $body_json['name'] ) ) {
			$data['name'] = $body_json['name'];
		} elseif ( isset( $plugin_details['Name'] ) ) {
			$data['name'] = $plugin_details['Name'];
		} else {
			$data['name'] = '';
		}
		// Check plugin slug.
		if ( isset( $body_json['slug'] ) ) {
			$data['slug'] = $body_json['slug'];
		} elseif ( isset( $plugin_details['slug'] ) ) {
			$data['slug'] = $plugin_details['slug'];
		} else {
			$data['slug'] = '';
		}
		// Check plugin URL. Sometimes URL values are empty.
		if ( isset( $body_json['homepage'] ) && '' !== $body_json['homepage'] ) {
			$data['url'] = $body_json['homepage'];
		} elseif ( isset( $plugin_details['PluginURI'] ) && '' !== $plugin_details['PluginURI'] ) {
			$data['url'] = $plugin_details['PluginURI'];
		} elseif ( isset( $plugin_details['AuthorURI'] ) && '' !== $plugin_details['AuthorURI'] ) {
			$data['url'] = $plugin_details['AuthorURI'];
		} else {
			$data['url'] = '';
		}
		// Check plugin version.
		if ( isset( $body_json['version'] ) ) {
			$data['version'] = $body_json['version'];
		} elseif ( isset( $plugin_details['Version'] ) ) {
			$data['version'] = $plugin_details['Version'];
		} else {
			$data['version'] = '';
		}
		// Check a tested WP version.
		if ( isset( $body_json['tested'] ) ) {
			$data['tested_wp'] = $body_json['tested'];
		} else {
			$data['tested_wp'] = '';
		}
		// Check plugin updated time.
		if ( isset( $body_json['closed_date'] ) ) {
			$data['last_updated'] = $body_json['closed_date'];
		} elseif ( isset( $body_json['last_updated'] ) ) {
			$data['last_updated'] = $body_json['last_updated'];
		} else {
			$data['last_updated'] = '';
		}
		// Specific key for closed plugin.
		if ( isset( $body_json['reason_text'] ) ) {
			$data['reason_text'] = $body_json['reason_text'];
		} else {
			$data['reason_text'] = '';
		}

		return $data;
	}

	/**
	 * Get list of plugin slugs whose names do not match the specified names on wp.org.
	 */
	private function get_plugin_slugs_with_mismatched_names(): array {
		return array(
			'miniorange-malware-protection',
			'admin-bar-user-switching',
			'custom-post-template',
		);
	}

	/**
	 * Is abandoned plugin?
	 *
	 * @param string $slug The slug to check.
	 *
	 * @return bool
	 */
	public function check_abandoned_plugin_by( string $slug ): bool {
		// Check if the plugin is not from wp.org.
		$premium_plugin_slugs = get_site_option( Plugin_Integrity::PLUGIN_PREMIUM_SLUGS, array() );
		if ( ( is_array( $premium_plugin_slugs ) && in_array( $slug, $premium_plugin_slugs, true ) )
			|| ! $this->is_likely_wporg_slug( $slug )
		) {
			return true;
		}
		if ( $this->scan->is_issue_ignored( $slug ) ) {
			$this->log( sprintf( 'skip %s because it is already ignored.', $slug ), Scan_Controller::SCAN_LOG );
			return true;
		}

		$results = $this->handle_wp_org_response_by( $slug );
		if ( ! $results['success'] ) {
			$this->handle_error( $results['message'] );

			return false;
		} else {
			$body_json      = $results['body'];
			$plugin_details = $this->get_plugin_details_by( $slug );
			if (
				isset( $body_json['name'], $plugin_details['Name'] )
				&& $plugin_details['Name'] !== $body_json['name']
				&& ! in_array( $slug, $this->get_plugin_slugs_with_mismatched_names(), true )
			) {
				// This is a premium plugin with the same slug as on wp.org but with another name OR the plugin developer named the plugin differently on wp.org and inside the main file.
				return false;
			}

			if ( isset( $body_json['error'] ) && 'closed' === $body_json['error'] ) {
				$this->log( sprintf( 'Plugin slug closed: %s', $slug ), Scan_Controller::SCAN_LOG );

				$this->scan->add_item(
					Scan_Item::TYPE_PLUGIN_CLOSED,
					$this->prepare_item_data( $body_json, $plugin_details )
				);

				return true;
			}

			if ( '' !== $body_json['last_updated'] ) {
				$last_updated_time = $body_json['last_updated'];
				$ttl               = strtotime( $last_updated_time );
				if ( $ttl < strtotime( '- ' . self::get_outdated_period() ) ) {
					$this->log( sprintf( 'Plugin slug outdated: %s', $slug ), Scan_Controller::SCAN_LOG );
					$plugin_details = $this->prepare_item_data( $body_json, $plugin_details );
					// Improve the date view.
					$plugin_details['last_updated'] = gmdate( 'F j, Y', $ttl );

					$this->scan->add_item(
						Scan_Item::TYPE_PLUGIN_OUTDATED,
						$plugin_details
					);

					return true;
				}
			}

			return false;
		}
	}
}
