<?php
/**
 * The Algorithm class for hashing algorithms.
 *
 * @package    WP_Defender\Component\Altcha\Hasher
 */

namespace WP_Defender\Component\Altcha\Hasher;

/**
 * Class Algorithm
 */
final class Algorithm {
	public const SHA1   = 'SHA-1';
	public const SHA256 = 'SHA-256';
	public const SHA512 = 'SHA-512';

	/**
	 * Tries to check if the given value is a valid algorithm.
	 *
	 * @param string|null $value The algorithm value.
	 *
	 * @return string|null The valid algorithm or null if invalid.
	 */
	public static function try_from( ?string $value ): ?string {
		if ( null === $value ) {
			return null;
		}

		return self::is_valid( $value ) ? $value : null;
	}

	/**
	 * Checks if the given value is a valid algorithm.
	 *
	 * @param string $value The algorithm value.
	 *
	 * @return bool True if valid, false otherwise.
	 */
	public static function is_valid( string $value ): bool {
		return in_array(
			$value,
			array(
				self::SHA1,
				self::SHA256,
				self::SHA512,
			),
			true
		);
	}
}
