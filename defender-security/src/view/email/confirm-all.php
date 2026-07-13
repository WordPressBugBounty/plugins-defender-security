<?php
/**
 * Email template for a single subscription invite covering all notification modules.
 *
 * Variables: $name, $email, $site_url, $modules (array of ['title' => string]), $url
 *
 * @package WP_Defender
 */

?>
<h1 style="font-family:inherit;font-size:25px;line-height:30px;color:inherit;margin-top:10px;margin-bottom:30px">
	<?php esc_html_e( 'Confirm your subscriptions', 'defender-security' ); ?>
</h1>
<p style="color:#1A1A1A;font-family:Roboto,Arial,sans-serif;font-size:16px;font-weight:normal;line-height:24px;margin:0;padding:0 0 28px;text-align:left;">
	<?php
	/* translators: %s: Recipient name. */
	printf( esc_html__( 'Hi %s,', 'defender-security' ), esc_html( $name ) );
	?>
</p>
<p style="font-family:inherit;font-size:16px;margin:0 0 20px">
	<?php
	printf(
		/* translators: 1. Site URL. 2. Recipient email. */
		esc_html__(
			'An administrator from %1$s has subscribed %2$s to the following notifications. Click Confirm Subscriptions below to confirm them.',
			'defender-security'
		),
		'<strong>' . esc_url( $site_url ) . '</strong>',
		'<strong>' . esc_html( $email ) . '</strong>'
	);
	?>
</p>
<table style="width:100%;border-collapse:collapse;margin:0 0 30px">
	<?php foreach ( $modules as $module ) : ?>
		<tr>
			<td style="padding:10px 0;border-bottom:1px solid #E7E7E7;font-family:Roboto,Arial,sans-serif;font-size:15px;color:#1A1A1A;">
				<?php echo esc_html( $module['title'] ); ?>
			</td>
		</tr>
	<?php endforeach; ?>
</table>
<p style="margin:0;padding:0;text-align:center">
	<a class="button view-full"
		style="font-family:Roboto,Arial,sans-serif;font-size:16px;font-weight:normal;line-height:20px;text-align:center;margin-bottom:0;"
		href="<?php echo esc_url( $url ); ?>"><?php esc_html_e( 'Confirm Subscriptions', 'defender-security' ); ?></a>
</p>
