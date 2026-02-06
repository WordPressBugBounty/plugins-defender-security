<?php
/**
 * Class Payload
 *
 * @package WP_Defender\Component\Altcha
 */

namespace WP_Defender\Component\Altcha;

/**
 * Class Payload
 */
class Payload {
	/**
	 * Payload constructor.
	 *
	 * @param string $algorithm The hashing algorithm.
	 * @param string $challenge The challenge string.
	 * @param int    $number The number associated with the challenge.
	 * @param string $salt The salt used in hashing.
	 * @param string $signature The signature of the payload.
	 */
	public function __construct(
		public string $algorithm,
		public string $challenge,
		public int $number,
		public string $salt,
		public string $signature
	) {
	}
}
