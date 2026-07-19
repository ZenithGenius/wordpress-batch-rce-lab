<?php
/**
 * Plugin Name: wp2shell Batch Guard (mitigation)
 * Description: Rejects anonymous calls to the REST batch endpoint, closing the
 *              wp2shell / CVE-2026-63030 pre-auth vector until you can update to
 *              WordPress 7.0.2 / 6.9.5. Drop into wp-content/mu-plugins/.
 *
 * This is a stop-gap, not a substitute for patching. It denies /batch/v1 to
 * unauthenticated callers, which is where the pre-auth desync is reached. Logged-in
 * users with a valid nonce still get batch (WooCommerce and the block editor use it).
 */

if ( ! defined( 'ABSPATH' ) ) { exit; }

add_filter(
	'rest_pre_dispatch',
	function ( $result, $server, $request ) {
		// $request->get_route() is normalised regardless of /wp-json/ vs ?rest_route=
		$route = $request->get_route();
		if ( is_string( $route ) && 0 === strpos( ltrim( $route, '/' ), 'batch/v1' ) ) {
			if ( ! is_user_logged_in() ) {
				// Optional: leave a breadcrumb for the blue team.
				if ( function_exists( 'error_log' ) ) {
					error_log( sprintf(
						'[wp2shell-guard] blocked anonymous batch request from %s',
						isset( $_SERVER['REMOTE_ADDR'] ) ? $_SERVER['REMOTE_ADDR'] : 'unknown'
					) );
				}
				return new WP_Error(
					'rest_batch_forbidden',
					'Batch requests are not available.',
					array( 'status' => 401 )
				);
			}
		}
		return $result;
	},
	1, // run early, before the batch controller
	3
);
