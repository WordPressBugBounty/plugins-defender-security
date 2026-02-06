<?php
/**
 * Handles hashing operations for Altcha.
 *
 * @package WP_Defender\Component\Altcha\Hasher
 */

namespace WP_Defender\Component\Altcha\Hasher;

/**
 * Class Hasher
 */
class Hasher implements HasherInterface {
	/**
	 * Hashes the given data using the specified algorithm.
	 *
	 * @param string $algorithm The hashing algorithm to use.
	 * @param string $data The data to hash.
	 *
	 * @return string The hashed data.
	 */
	public function hash( string $algorithm, string $data ): string {
		return match ( $algorithm ) {
			Algorithm::SHA1 => sha1( $data, true ),
			Algorithm::SHA256 => hash( 'sha256', $data, true ),
			Algorithm::SHA512 => hash( 'sha512', $data, true ),
		};
	}

	/**
	 * Hashes the given data using the specified algorithm and returns the hash in hexadecimal format.
	 *
	 * @param string $algorithm The hashing algorithm to use.
	 * @param string $data The data to hash.
	 *
	 * @return string The hashed data in hexadecimal format.
	 */
	public function hash_hex( string $algorithm, string $data ): string {
		return bin2hex( $this->hash( $algorithm, $data ) );
	}

	/**
	 * Hashes the given data using HMAC with the specified algorithm and HMAC key.
	 *
	 * @param string $algorithm The hashing algorithm to use.
	 * @param string $data The data to hash.
	 * @param string $hmac_key The HMAC key to use.
	 *
	 * @return string The HMAC hashed data.
	 */
	public function hash_hmac( string $algorithm, string $data, string $hmac_key ): string {
		return match ( $algorithm ) {
			Algorithm::SHA1 => hash_hmac( 'sha1', $data, $hmac_key, true ),
			Algorithm::SHA256 => hash_hmac( 'sha256', $data, $hmac_key, true ),
			Algorithm::SHA512 => hash_hmac( 'sha512', $data, $hmac_key, true ),
		};
	}

	/**
	 * Hashes the given data using HMAC with the specified algorithm and HMAC key, returning the hash in hexadecimal format.
	 *
	 * @param string $algorithm The hashing algorithm to use.
	 * @param string $data The data to hash.
	 * @param string $hmac_key The HMAC key to use.
	 *
	 * @return string The HMAC hashed data in hexadecimal format.
	 */
	public function hash_hmac_hex( string $algorithm, string $data, string $hmac_key ): string {
		return bin2hex( $this->hash_hmac( $algorithm, $data, $hmac_key ) );
	}
}
