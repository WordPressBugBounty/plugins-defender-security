<?php
/**
 * Class Altcha
 *
 * @package WP_Defender\Component\Altcha
 */

namespace WP_Defender\Component\Altcha;

use WP_Defender\Component\Altcha\Hasher\Algorithm;
use WP_Defender\Component\Altcha\Hasher\Hasher;
use WP_Defender\Component\Altcha\Hasher\HasherInterface;

/**
 * Class Altcha.
 */
class Altcha {
	/**
	 * The HMAC key used for signing.
	 *
	 * @var string
	 */
	private string $hmac_key;

	/**
	 * The hasher instance.
	 *
	 * @var HasherInterface
	 */
	private HasherInterface $hasher;

	/**
	 * Altcha constructor.
	 *
	 * @param string          $hmac_key The HMAC key used for signing.
	 * @param HasherInterface $hasher   The hasher instance to use.
	 */
	public function __construct(
		string $hmac_key,
		?HasherInterface $hasher = null
	) {
		$this->hmac_key = $hmac_key;
		$this->hasher   = $hasher ?? new Hasher();
	}

	/**
	 * Decodes a base64-encoded JSON payload.
	 *
	 * @param string $payload The base64-encoded JSON payload.
	 *
	 * @return null|array
	 */
	private function decode_payload( string $payload ): ?array {
		$decoded = base64_decode( $payload, true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode

		if ( ! $decoded ) {
			return null;
		}

		try {
			$data = json_decode( $decoded, true, 2, \JSON_THROW_ON_ERROR );
		} catch ( \JsonException | \ValueError ) {
			return null;
		}

		if ( ! is_array( $data ) || array() === $data ) {
			return null;
		}

		return $data;
	}

	/**
	 * Verifies and builds a Payload object from the given data.
	 *
	 * @param array|string $data The data to verify and build the payload from.
	 */
	private function verify_and_build_solution_payload( string|array $data ): ?Payload {
		if ( is_string( $data ) ) {
			$data = $this->decode_payload( $data );
		}

		if ( null === $data
			|| ! isset( $data['algorithm'], $data['challenge'], $data['number'], $data['salt'], $data['signature'] )
			|| ! is_string( $data['algorithm'] )
			|| ! is_string( $data['challenge'] )
			|| ! is_string( $data['salt'] )
			|| ! is_string( $data['signature'] )
			|| ! is_int( $data['number'] )
		) {
			return null;
		}

		$algorithm = Algorithm::try_from( $data['algorithm'] ?? null );

		if ( ! $algorithm ) {
			return null;
		}

		return new Payload( $algorithm, $data['challenge'], $data['number'], $data['salt'], $data['signature'] );
	}

	/**
	 * Extracts parameters from the salt string of a Payload.
	 *
	 * @param Payload $payload The Payload object.
	 *
	 * @return array
	 */
	private function extract_params( Payload $payload ): array {
		$salt_parts = explode( '?', $payload->salt );
		if ( count( $salt_parts ) > 1 ) {
			parse_str( $salt_parts[1], $params );

			return $params;
		}

		return array();
	}

	/**
	 * Creates a new challenge for ALTCHA.
	 *
	 * @param Base_Challenge_Options $options The options for creating the challenge.
	 *
	 * @return Challenge The challenge data to be passed to ALTCHA.
	 */
	public function create_challenge( ?Base_Challenge_Options $options = null ): Challenge {
		if ( null === $options ) {
			$options = new Challenge_Options();
		}

		$challenge = $this->hasher->hash_hex( $options->algorithm, $options->salt . $options->number );
		$signature = $this->hasher->hash_hmac_hex( $options->algorithm, $challenge, $this->hmac_key );

		return new Challenge( $options->algorithm, $challenge, $options->max_number, $options->salt, $signature );
	}

	/**
	 * Verifies an ALTCHA solution.
	 *
	 * @param array|string $data         The solution payload to verify.
	 * @param bool         $check_expires Whether to check if the challenge has expired.
	 *
	 * @return bool True if the solution is valid.
	 */
	public function verify_solution( string|array $data, bool $check_expires = true ): bool {
		$payload = $this->verify_and_build_solution_payload( $data );
		if ( ! $payload ) {
			return false;
		}

		$params = $this->extract_params( $payload );
		if ( $check_expires && isset( $params['expires'] ) && is_numeric( $params['expires'] ) ) {
			$expire_time = (int) $params['expires'];
			if ( time() > $expire_time ) {
				return false;
			}
		}

		$challenge_options = new Check_Challenge_Options(
			$payload->algorithm,
			$payload->salt,
			$payload->number
		);

		$expected_challenge = $this->create_challenge( $challenge_options );

		$challenge_ok = hash_equals(
			$expected_challenge->challenge,
			$payload->challenge
		);

		$signature_ok = hash_equals(
			$expected_challenge->signature,
			$payload->signature
		);

		return $challenge_ok && $signature_ok;
	}
}
