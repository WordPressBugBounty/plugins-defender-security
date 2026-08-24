<?php
/**
 * Handles WebAuthn functionalities providing methods to manage and verify user credentials.
 *
 * @package WP_Defender\Component
 */

namespace WP_Defender\Component;

use WP_User;
use WP_DEFENDER_VENDOR\Webauthn\PublicKeyCredentialSource;
use WP_DEFENDER_VENDOR\Webauthn\PublicKeyCredentialUserEntity;
use WP_DEFENDER_VENDOR\Webauthn\TrustPath\CertificateTrustPath;
use WP_DEFENDER_VENDOR\Webauthn\TrustPath\EcdaaKeyIdTrustPath;
use WP_DEFENDER_VENDOR\Webauthn\TrustPath\EmptyTrustPath;
use WP_Defender\Traits\Webauthn as Webauthn_Trait;
use WP_DEFENDER_VENDOR\Webauthn\PublicKeyCredentialSourceRepository;

/**
 * Handles WebAuthn functionalities providing methods to manage and verify user credentials.
 *
 * @since 3.0.0
 */
class Webauthn implements PublicKeyCredentialSourceRepository {

	use Webauthn_Trait;

	/**
	 * Option key for storing user credentials.
	 *
	 * @var string
	 */
	public const CREDENTIAL_OPTION_KEY = 'user_credentials';

	/**
	 * Meta key for storing credentials having userHandle mismatch.
	 *
	 * @var string
	 */
	public const USER_HANDLE_MISMATCH_KEY = 'user_handle_match_failed';

	/**
	 * User ID that findOneByCredentialId() lookups are currently scoped to.
	 * Must be set only via set_expected_user_id() from trusted server-side
	 * context (e.g. the WP_User passed down the 2FA login chain) — never
	 * derived from request input inside this class.
	 *
	 * @var int|null
	 */
	private $expected_user_id = null;

	/**
	 * Restrict findOneByCredentialId() to a specific user's credential set.
	 * Call this before delegating to Webauthn\Server so the library's internal
	 * repository lookups stay scoped to the expected 2FA target user.
	 *
	 * @param int|null $user_id Trusted user ID, or null to clear the scope.
	 *
	 * @return void
	 */
	public function set_expected_user_id( ?int $user_id ): void {
		$this->expected_user_id = $user_id;
	}

	/**
	 * Get user credentials.
	 *
	 * @param int $user_id The user ID.
	 *
	 * @return array
	 */
	public function getCredentials( int $user_id ): array {
		return $this->get_user_meta( $user_id, self::CREDENTIAL_OPTION_KEY );
	}

	/**
	 * Set user credentials.
	 *
	 * @param int   $user_id The user ID.
	 * @param array $data   The credentials data.
	 *
	 * @return bool
	 */
	public function setCredentials( int $user_id, array $data ): bool {
		return false !== $this->update_user_meta( $user_id, self::CREDENTIAL_OPTION_KEY, $data );
	}

	/**
	 * Get one credential by credential ID.
	 * {@inheritDoc}
	 * Interface-mandated single-parameter signature. Scoping to a specific
	 * user is done via $this->expected_user_id, set beforehand through
	 * set_expected_user_id() by trusted calling code — never via $_POST.
	 *
	 * @param string $public_key_credential_id The public key credential ID.
	 *
	 * @return PublicKeyCredentialSource|null
	 */
	public function findOneByCredentialId( string $public_key_credential_id ): ?PublicKeyCredentialSource {
		if ( null === $this->expected_user_id ) {
			// No trusted scope set — deny rather than search globally.
			// Never needs an unscoped, cross-account lookup.
			return null;
		}

		$data = $this->getCredentials( $this->expected_user_id );
		$key  = base64_encode( $public_key_credential_id ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
		if ( isset( $data[ $key ]['credential_source'] ) ) {
			$credential_source = $data[ $key ]['credential_source']; // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode

			return PublicKeyCredentialSource::createFromArray( $this->normalize_legacy_trust_path( $credential_source ) );
		}

		return null;
	}

	/**
	 * Get all credentials of a user
	 *
	 * @param PublicKeyCredentialUserEntity $public_key_credential_user_entity The user entity.
	 *
	 * @return array
	 */
	public function findAllForUserEntity( PublicKeyCredentialUserEntity $public_key_credential_user_entity ): array {
		$credentials = array();
		$username    = $public_key_credential_user_entity->getName();
		$user        = get_user_by( 'login', $username );

		if ( is_object( $user ) ) {
			$credentials = $this->findAllForUserByType( $user->ID );
		}

		return $credentials;
	}

	/**
	 * Get all credentials of a user by authenticator type.
	 *
	 * @param int         $user_id The user ID.
	 * @param null|string $type   The type of authenticator.
	 *
	 * @return array
	 * @since 3.1.0
	 */
	public function findAllForUserByType( int $user_id, $type = null ): array {
		$sources   = array();
		$user_data = $this->getCredentials( $user_id );

		if ( is_array( $user_data ) ) {
			foreach ( $user_data as $data ) {
				if (
					! in_array( $type, array( null, '' ), true )
					&& isset( $data['authenticator_type'] )
					&& '' !== $data['authenticator_type']
					&& $type !== $data['authenticator_type']
				) {
					continue;
				}

				if ( isset( $data['credential_source'] ) ) {
					$sources[] = PublicKeyCredentialSource::createFromArray(
						$this->normalize_legacy_trust_path( $data['credential_source'] )
					);
				}
			}
		}

		return $sources;
	}

	/**
	 * Map trust-path class names stored by Defender 6.1 to their Mozart-prefixed 6.2 classes.
	 *
	 * @param array $credential_source Stored WebAuthn credential source.
	 *
	 * @return array
	 */
	private function normalize_legacy_trust_path( array $credential_source ): array {
		$legacy_type = $credential_source['trustPath']['type'] ?? null;
		$legacy_map  = array(
			'Webauthn\\TrustPath\\EmptyTrustPath'       => EmptyTrustPath::class,
			'Webauthn\\TrustPath\\EcdaaKeyIdTrustPath'  => EcdaaKeyIdTrustPath::class,
			'Webauthn\\TrustPath\\CertificateTrustPath' => CertificateTrustPath::class,
		);

		if ( is_string( $legacy_type ) && isset( $legacy_map[ $legacy_type ] ) ) {
			$credential_source['trustPath']['type'] = $legacy_map[ $legacy_type ];
		}

		return $credential_source;
	}

	/**
	 * Store credential into database.
	 *
	 * @param PublicKeyCredentialSource $public_key_credential_source The credential source to store.
	 *
	 * @return void
	 */
	public function saveCredentialSource( PublicKeyCredentialSource $public_key_credential_source ): void {
		$user_id = get_current_user_id();
		$data    = $this->getCredentials( $user_id );
		$key     = base64_encode( $public_key_credential_source->getPublicKeyCredentialId() ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode

		if ( ! isset( $data[ $key ] ) ) {
			$data[ $key ] = array(
				'label'              => defender_get_data_from_request( 'name', 'p' ) ?? '',
				'added'              => time(),
				'authenticator_type' => defender_get_data_from_request( 'type', 'p' ) ?? '',
				'user'               => $public_key_credential_source->getUserHandle(),
				'credential_source'  => $public_key_credential_source,
			);
		} else {
			$data[ $key ]['credential_source'] = $public_key_credential_source;
		}

		$this->setCredentials( $user_id, $data );
	}

	/**
	 * Get userHandle mismatch list.
	 *
	 * @param  int $user_id  The user ID.
	 *
	 * @return array
	 * @since 3.4.0
	 */
	public function getUserHandleMatchFailed( int $user_id ): array {
		$meta_key = $this->option_prefix . self::USER_HANDLE_MISMATCH_KEY;
		$meta_val = get_user_meta( $user_id, $meta_key, true );

		return is_array( $meta_val ) ? $meta_val : array();
	}

	/**
	 * Set userHandle mismatch list.
	 *
	 * @param  int   $user_id  The user ID.
	 * @param  array $meta_val  The mismatches to set.
	 *
	 * @return void
	 * @since 3.4.0
	 */
	public function setUserHandleMatchFailed( int $user_id, array $meta_val ): void {
		$meta_key = $this->option_prefix . self::USER_HANDLE_MISMATCH_KEY;
		update_user_meta( $user_id, $meta_key, $meta_val );
	}

	/**
	 * Add authenticators to userHandle mismatch list.
	 *
	 * @param  WP_User $user  The user object.
	 * @param  array   $data  The data to add.
	 *
	 * @return void
	 * @since 3.4.0
	 */
	public function addUserHandleMatchFailed( $user, $data ): void {
		if ( isset( $user->ID ) && $user->ID > 0 && '' !== $data['rawId'] ) {
			$meta_val                = $this->getUserHandleMatchFailed( $user->ID );
			$meta_val['show_notice'] = $meta_val['show_notice'] ?? true;

			if ( ! isset( $meta_val['authenticators'] ) || array() === $meta_val['authenticators'] || ! in_array( $data['rawId'], $meta_val['authenticators'], true ) ) {
				$meta_val['authenticators'][] = $data['rawId'];
			}

			$this->setUserHandleMatchFailed( $user->ID, $meta_val );
		}
	}

	/**
	 * Remove authenticator from userHandle mismatch list.
	 *
	 * @param  int    $user_id  The user ID.
	 * @param  string $auth_id  The authenticator ID to remove.
	 *
	 * @return void
	 * @since 3.4.0
	 */
	public function removeUserHandleMatchFailed( int $user_id, string $auth_id ): void {
		if ( '' !== $auth_id ) {
			$meta_val = $this->getUserHandleMatchFailed( $user_id );

			if ( isset( $meta_val['authenticators'] ) && is_array( $meta_val['authenticators'] ) && array() !== $meta_val['authenticators'] ) {
				$pos = array_search( $auth_id, $meta_val['authenticators'], true );

				if ( false !== $pos ) {
					array_splice( $meta_val['authenticators'], $pos, 1 );
					$this->setUserHandleMatchFailed( $user_id, $meta_val );
				}
			}
		}
	}

	/**
	 * Disable userHandle mismatch notice.
	 *
	 * @param  int $user_id  The user ID.
	 *
	 * @return void
	 * @since 3.4.0
	 */
	public function disableUserHandleMatchFailedNotice( int $user_id ): void {
		$meta_val                = $this->getUserHandleMatchFailed( $user_id );
		$meta_val['show_notice'] = false;

		$this->setUserHandleMatchFailed( $user_id, $meta_val );
	}
}
