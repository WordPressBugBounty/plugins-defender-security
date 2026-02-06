<?php
/**
 * Class Challenge
 *
 * @package WP_Defender\Component\Altcha
 */

namespace WP_Defender\Component\Altcha;

/**
 * Class Challenge
 */
class Challenge {
	/**
	 * Challenge constructor.
	 *
	 * @param string $algorithm The hashing algorithm.
	 * @param string $challenge The challenge string.
	 * @param int    $max_number The maximum number associated with the challenge.
	 * @param string $salt The salt used in hashing.
	 * @param string $signature The signature of the challenge.
	 */
	public function __construct(
		public string $algorithm,
		public string $challenge,
		public int $max_number,
		public string $salt,
		public string $signature
	) {
	}
}
