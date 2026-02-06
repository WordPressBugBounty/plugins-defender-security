<?php
/**
 * Class Base_Challenge_Options
 *
 * @package WP_Defender\Component\Altcha
 */

namespace WP_Defender\Component\Altcha;

/**
 * Base class for challenge options.
 *
 * @phpstan-type ChallengeParams array<string, null|scalar>
 */
class Base_Challenge_Options {
	public const DEFAULT_MAX_NUMBER = 1000000;

	/**
	 * The salt used in hashing.
	 *
	 * @var string
	 */
	public string $salt;

	/**
	 * Options for creation of a new challenge.
	 *
	 * @see Challenge_Options for options with sane defaults.
	 *
	 * @param string                  $algorithm  The hashing algorithm.
	 * @param int                     $max_number The maximum number associated with the challenge.
	 * @param null|\DateTimeInterface $expires    Optional expiration time for the challenge.
	 * @param string                  $salt       The salt used in hashing.
	 * @param int                     $number     The number associated with the challenge.
	 * @param array                   $params     Optional URL-encoded query parameters.
	 */
	public function __construct(
		public string $algorithm,
		public int $max_number,
		public ?\DateTimeInterface $expires,
		string $salt,
		public int $number,
		public array $params
	) {
		if ( $expires ) {
			$params['expires'] = $expires->getTimestamp();
		}

		if ( is_array( $params ) && array() !== $params ) {
			$salt .= '?' . http_build_query( $params );
		}

		// Add a delimiter to prevent parameter splicing.
		if ( ! str_ends_with( $salt, '&' ) ) {
			$salt .= '&';
		}

		$this->salt = $salt;
	}
}
