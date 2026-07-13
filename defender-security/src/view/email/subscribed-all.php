<?php
/**
 * Email template for confirming multiple notification subscriptions.
 *
 * Variables: $subject, $name, $modules (array of ['title' => string])
 *
 * @package WP_Defender
 */

?>
<h1 style="font-family:inherit;font-size:25px;line-height:30px;color:inherit;margin-top:10px;margin-bottom:30px">
	<?php echo esc_html( $subject ); ?>
</h1>
<p style="color:#1A1A1A;font-family:Roboto,Arial,sans-serif;font-size:16px;font-weight:normal;line-height:24px;margin:0;padding:0 0 28px;text-align:left;word-wrap:normal;">
	<?php
	/* translators: %s: Name. */
	printf( esc_html__( 'Hi %s', 'defender-security' ), esc_html( $name ) );
	?>
	,
</p>
<p style="font-family:inherit;font-size:16px;margin:0 0 20px">
	<?php esc_html_e( 'You are now subscribed to the following notifications:', 'defender-security' ); ?>
</p>
<table style="width:100%;border-collapse:collapse;margin:0 0 30px">
	<?php foreach ( $modules as $module ) : ?>
		<tr>
			<td style="padding:10px 0;border-bottom:1px solid #E7E7E7;font-family:Roboto,Arial,sans-serif;font-size:15px;color:#1A1A1A;">
				<?php echo esc_html( $module['title'] ); ?>
			</td>
			<td style="padding:10px 0;border-bottom:1px solid #E7E7E7;font-family:Roboto,Arial,sans-serif;font-size:15px;text-align:right;">
				<a style="text-decoration:none;color:#0059FF;" href="<?php echo esc_url( $module['url'] ); ?>">
					<?php esc_html_e( 'unsubscribe', 'defender-security' ); ?>
				</a>
			</td>
		</tr>
	<?php endforeach; ?>
</table>
