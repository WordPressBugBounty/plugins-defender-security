<?php
/**
 * Class Check_Challenge_Options
 *
 * @package WP_Defender\Component\Altcha
 */

namespace WP_Defender\Component\Altcha;

/**
 * Class Check_Challenge_Options
 */
class Check_Challenge_Options extends Base_Challenge_Options {
	/**
	 * Check_Challenge_Options constructor.
	 *
	 * @param string $algorithm The hashing algorithm.
	 * @param string $salt The salt used in hashing.
	 * @param int    $number The number associated with the challenge.
	 */
	public function __construct(
		string $algorithm,
		string $salt,
		int $number
	) {
		parent::__construct( $algorithm, self::DEFAULT_MAX_NUMBER, null, $salt, $number, array() );
	}
}
