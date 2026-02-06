<?php
/**
 * Class Challenge_Options
 *
 * @package WP_Defender\Component\Altcha
 */

namespace WP_Defender\Component\Altcha;

use WP_Defender\Component\Altcha\Hasher\Algorithm;
use WP_Defender\Component\Crypt;

/**
 * Class Challenge_Options.
 *
 * @phpstan-import-type ChallengeParams from Base_Challenge_Options
 */
class Challenge_Options extends Base_Challenge_Options {
	private const DEFAULT_SALT_LENGTH = 12;

	/**
	 * Options for creation of a new challenge with sane defaults.
	 *
	 * @param string                  $algorithm  Hashing algorithm to use (`SHA-1`, `SHA-256`, `SHA-512`, default:
	 *                                            `SHA-256`).
	 * @param int                     $max_number  Maximum number for the random number generator (default: 1,000,000).
	 * @param null|\DateTimeInterface $expires    Optional expiration time for the challenge.
	 * @param array                   $params     Optional URL-encoded query parameters.
	 * @param int                     $salt_length Length of the random salt (default: 12 bytes).
	 */
	public function __construct(
		string $algorithm = Algorithm::SHA256,
		int $max_number = self::DEFAULT_MAX_NUMBER,
		?\DateTimeInterface $expires = null,
		array $params = array(),
		int $salt_length = self::DEFAULT_SALT_LENGTH
	) {
		$salt_length = max( self::DEFAULT_SALT_LENGTH, $salt_length );

		parent::__construct(
			$algorithm,
			$max_number,
			$expires,
			bin2hex( Crypt::random_bytes( $salt_length ) ),
			Crypt::random_int( 0, $max_number ),
			$params
		);
	}
}
