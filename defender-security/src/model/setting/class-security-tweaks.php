<?php
/**
 * Handle tweaks settings.
 *
 * @package WP_Defender\Model\Setting
 */

namespace WP_Defender\Model\Setting;

use Calotes\Model\Setting;

/**
 * Model for tweaks settings.
 */
class Security_Tweaks extends Setting {

	/**
	 * Option name.
	 *
	 * @var string
	 */
	protected $table = 'hardener_settings';

	/**
	 * Store a list of issues tweaks, as slug.
	 *
	 * @var array
	 */
	public $issues = array();

	/**
	 * Store a list of fixed tweaks, as slug.
	 *
	 * @var array
	 */
	public $fixed = array();

	/**
	 * Store a list of ignored tweaks, as slug.
	 *
	 * @var array
	 */
	public $ignore = array();

	/**
	 * Contains all the data generated by rules.
	 *
	 * @var array
	 */
	public $data = array();

	/**
	 * Last time visit into the hardener page.
	 *
	 * @var integer
	 */
	public $last_seen;

	/**
	 * Last notification sent out.
	 *
	 * @var integer
	 */
	public $last_sent;
	/**
	 * Automate tweaks
	 *
	 * @var bool
	 */
	public $automate = false;

	/**
	 * Check if a tweak is ignored.
	 *
	 * @param  string $slug  Tweak slug.
	 *
	 * @return bool
	 */
	public function is_tweak_ignore( $slug ): bool {
		// Empty ignored tweak is string on old versions, so change it to array.
		if ( is_string( $this->ignore ) ) {
			$this->ignore = empty( $this->ignore ) ? array() : array( $this->ignore );
			$this->save();
		}

		return in_array( $slug, $this->ignore, true );
	}

	/**
	 * Mark a tweak as actioned.
	 *
	 * @param  string $status  Status.
	 * @param  string $slug  Tweak slug.
	 */
	public function mark( $status, $slug ) {
		foreach ( array( 'issues', 'fixed', 'ignore' ) as $collection ) {
			$arr   = $this->$collection;
			$index = array_search( $slug, $arr, true );
			if ( false !== $index ) {
				unset( $arr[ $index ] );
			}
			$this->$collection = $arr;
		}
		if ( \WP_Defender\Controller\Security_Tweaks::STATUS_RESTORE === $status ) {
			$status = \WP_Defender\Controller\Security_Tweaks::STATUS_ISSUES;
		}
		$collection      = $this->{$status};
		$collection[]    = $slug;
		$this->{$status} = $collection;
		$this->save();
	}

	/**
	 * Define settings labels.
	 *
	 * @return array
	 */
	public function labels(): array {
		return array(
			'data'     => 'data',
			'fixed'    => esc_html__( 'Actioned', 'defender-security' ),
			'issues'   => esc_html__( 'Recommendations', 'defender-security' ),
			'ignore'   => esc_html__( 'Ignored', 'defender-security' ),
			'automate' => 'automate',
		);
	}

	/**
	 * Todo: Find a less expensive way.
	 *
	 * @return array
	 */
	public function get_tweak_types(): array {
		return array(
			'count_fixed'   => count( $this->fixed ),
			'count_ignored' => count( $this->ignore ),
			'count_issues'  => count( $this->issues ),
		);
	}
}
