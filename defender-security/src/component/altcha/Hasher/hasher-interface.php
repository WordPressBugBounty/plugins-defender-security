<?php
/**
 * The interface for hasher class.
 *
 * @package    WP_Defender\Component\Altcha\Hasher
 */

namespace WP_Defender\Component\Altcha\Hasher;

interface HasherInterface {
	/**
	 * Hashes the given data using the specified algorithm.
	 *
	 * @param string $algorithm The hashing algorithm to use.
	 * @param string $data The data to hash.
	 *
	 * @return string The hashed data.
	 */
	public function hash( string $algorithm, string $data ): string;

	/**
	 * Hashes the given data using the specified algorithm and returns the hash in hexadecimal format.
	 *
	 * @param string $algorithm The hashing algorithm to use.
	 * @param string $data The data to hash.
	 *
	 * @return string The hashed data in hexadecimal format.
	 */
	public function hash_hex( string $algorithm, string $data ): string;

	/**
	 * Hashes the given data using HMAC with the specified algorithm and HMAC key.
	 *
	 * @param string $algorithm The hashing algorithm to use.
	 * @param string $data The data to hash.
	 * @param string $hmac_key The HMAC key to use.
	 *
	 * @return string The HMAC hashed data.
	 */
	public function hash_hmac( string $algorithm, string $data, string $hmac_key ): string;

	/**
	 * Hashes the given data using HMAC with the specified algorithm and HMAC key, returning the hash in hexadecimal format.
	 *
	 * @param string $algorithm The hashing algorithm to use.
	 * @param string $data The data to hash.
	 * @param string $hmac_key The HMAC key to use.
	 *
	 * @return string The HMAC hashed data in hexadecimal format.
	 */
	public function hash_hmac_hex( string $algorithm, string $data, string $hmac_key ): string;
}
