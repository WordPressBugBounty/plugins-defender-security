<?php
/**
 * Deactivation Survey Modal
 *
 * @package WP_Defender
 */

?>
<div class="<?php echo esc_attr( sprintf( ' sui-%s ', DEFENDER_SUI ) ); ?>">
	<div class="sui-wrap">
		<div class="sui-modal sui-modal-lg">
			<div
				role="dialog"
				id="wpdef-deactivation-survey-modal"
				class="sui-modal-content wpdef-deactivation-survey-modal"
				aria-modal="true"
				aria-labelledby="title-wpdef-deactivation-survey-modal"
				aria-describedby="desc-wpdef-deactivation-survey-modal"
			>
				<div class="sui-box" role="document">
					<div class="sui-box-header">
						<h3 class="sui-box-title">
							<img src="<?php echo esc_url( defender_asset_url( '/assets/img/defender-30.svg' ) ); ?>" width="30" srcset="<?php echo esc_url( defender_asset_url( '/assets/img/defender-64.svg' ) ); ?> 2x" alt="<?php esc_attr_e( 'Defender', 'defender-security' ); ?>" aria-hidden="true" />
							<?php esc_html_e( 'Deactivate Defender?', 'defender-security' ); ?>
						</h3>
						<div class="sui-actions-right">
							<button type="button" class="sui-button-icon" onclick="window.SUI?.closeModal( true );">
								<span class="sui-icon-close sui-md" aria-hidden="true"></span>
								<span class="sui-screen-reader-text"><?php esc_html_e( 'Close this dialog window', 'defender-security' ); ?></span>
							</button>
						</div>
					</div>
					<div class="sui-box-body">
						<p class="sui-description">
							<?php
							printf(
								/* translators: %s: Support link */
								esc_html__( 'Please tell us why. Your feedback helps us improve. %s', 'defender-security' ),
								$is_pro ? '<a id="wpdef-request-assistance-link" target="_blank" href="' . esc_url( $docs_link ) . '">' . esc_html__( 'Need Help?', 'defender-security' ) . '</a>' : ''
							);
							?>
						</p>
						<div class="wpdef-deactivation-field-row">
							<label for="wpdef-temp-deactivate-field" class="sui-radio wpdef-deactivation-field" data-placeholder="<?php esc_html_e( 'What issue are you debugging? (optional)', 'defender-security' ); ?>">
								<input
									type="radio"
									name="deactivation_reason"
									id="wpdef-temp-deactivate-field"
									aria-labelledby="label-wpdef-temp-deactivate-field"
									value="temp_deactivate"
								/>
								<span aria-hidden="true"></span>
								<span id="label-wpdef-temp-deactivate-field"><?php esc_html_e( 'Temporary deactivation for debugging', 'defender-security' ); ?></span>
							</label>
						</div>

						<div class="wpdef-deactivation-field-row">
							<label for="wpdef-not-working-field" class="sui-radio wpdef-deactivation-field" data-placeholder="<?php esc_html_e( 'What issue did you face? (optional)', 'defender-security' ); ?>">
								<input
									type="radio"
									name="deactivation_reason"
									id="wpdef-not-working-field"
									aria-labelledby="label-wpdef-not-working-field"
									value="not_working"
								/>
								<span aria-hidden="true"></span>
								<span id="label-wpdef-not-working-field"><?php esc_html_e( "Can't make it work", 'defender-security' ); ?></span>
							</label>
						</div>

						<div class="wpdef-deactivation-field-row">
							<label for="wpdef-breaks-site-field" class="sui-radio wpdef-deactivation-field" data-placeholder="<?php esc_html_e( 'What issue did you face? (optional)', 'defender-security' ); ?>">
								<input
									type="radio"
									name="deactivation_reason"
									id="wpdef-breaks-site-field"
									aria-labelledby="label-wpdef-breaks-site-field"
									value="breaks_site"
								/>
								<span aria-hidden="true"></span>
								<span id="label-wpdef-breaks-site-field"><?php esc_html_e( 'Breaks the site or other plugins/services', 'defender-security' ); ?></span>
							</label>
						</div>

						<div class="wpdef-deactivation-field-row">
							<label for="wpdef-expected-beter-field" class="sui-radio wpdef-deactivation-field" data-placeholder="<?php esc_html_e( 'What could we do better? (optional)', 'defender-security' ); ?>">
								<input
									type="radio"
									name="deactivation_reason"
									id="wpdef-expected-beter-field"
									aria-labelledby="label-wpdef-expected-beter-field"
									value="expected_better"
								/>
								<span aria-hidden="true"></span>
								<span id="label-wpdef-expected-beter-field"><?php esc_html_e( "Doesn't meet expectations", 'defender-security' ); ?></span>
							</label>
						</div>

						<div class="wpdef-deactivation-field-row">
							<label for="wpdef-found-better-field" class="sui-radio wpdef-deactivation-field" data-placeholder="<?php esc_html_e( 'Which plugin and how is it better? (optional)', 'defender-security' ); ?>">
								<input
									type="radio"
									name="deactivation_reason"
									id="wpdef-found-better-field"
									aria-labelledby="label-wpdef-found-better-field"
									value="found_better"
								/>
								<span aria-hidden="true"></span>
								<span id="label-wpdef-found-better-field"><?php esc_html_e( 'Found a better plugin', 'defender-security' ); ?></span>
							</label>
						</div>

						<div class="wpdef-deactivation-field-row">
							<label for="wpdef-not-required-field" class="sui-radio wpdef-deactivation-field" data-placeholder="<?php esc_html_e( 'Please tell us why. (optional)', 'defender-security' ); ?>">
								<input
									type="radio"
									name="deactivation_reason"
									id="wpdef-not-required-field"
									aria-labelledby="label-wpdef-not-required-field"
									value="not_required"
								/>
								<span aria-hidden="true"></span>
								<span id="label-wpdef-not-required-field"><?php esc_html_e( 'No longer required', 'defender-security' ); ?></span>
							</label>
						</div>

						<div class="wpdef-deactivation-field-row">
							<label for="wpdef-other-field" class="sui-radio wpdef-deactivation-field" data-placeholder="<?php esc_html_e( 'Please tell us why. (optional)', 'defender-security' ); ?>">
								<input
									type="radio"
									name="deactivation_reason"
									id="wpdef-other-field"
									aria-labelledby="label-wpdef-other-field"
									value="other_issues"
								/>
								<span aria-hidden="true"></span>
								<span id="label-wpdef-other-field"><?php esc_html_e( 'Other', 'defender-security' ); ?></span>
							</label>
							<div id="wpdef-deactivation-user-message-field" class="sui-hidden">
								<textarea
									placeholder="<?php esc_html_e( 'Please tell us why. (optional)', 'defender-security' ); ?>"
									class="sui-form-control"
									aria-describedby="description-wpdef-deactivation-user-message"
								></textarea>
							</div>
						</div>
					</div>
					<div class="sui-box-footer">
						<button type="button" class="sui-button-ghost sui-button wpdef-skip-deactivate-button"><?php esc_html_e( 'Skip & Deactivate', 'defender-security' ); ?></button>
						<div class="sui-actions-right">
							<button type="button" class="sui-button-blue sui-button wpdef-submit-deactivate-button"><?php esc_html_e( 'Submit & Deactivate', 'defender-security' ); ?></button>
						</div>
					</div>
				</div>
			</div>
		</div>
	</div>
</div>
