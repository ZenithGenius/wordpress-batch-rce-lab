<?php
/**
 * Plugin Name: wp2shell lab - author__not_in sink (LAB ONLY)
 * Description: Models the real-world precondition for CVE-2026-60137 by forwarding
 *              a request parameter straight into WP_Query's author__not_in argument,
 *              which is exactly what a vulnerable plugin or theme does. It exists ONLY
 *              inside this lab and must never be deployed. It proves that unsanitized
 *              input reaches SQL by reporting whether the query raised a benign error;
 *              it runs a normal SELECT and extracts no data.
 *
 * Trigger:  GET /?wp2shell_sink=1&exclude=<value>
 */

if ( ! defined( 'ABSPATH' ) ) { exit; }

add_action( 'init', function () {
	if ( ! isset( $_GET['wp2shell_sink'] ) ) {
		return;
	}

	global $wpdb;
	$exclude = isset( $_GET['exclude'] ) ? wp_unslash( $_GET['exclude'] ) : '1';

	// Inspect the query error ourselves instead of printing it to the page.
	$prev = $wpdb->suppress_errors( true );
	$wpdb->last_error = '';

	// The sink: a vulnerable plugin passing request input into author__not_in.
	new WP_Query( array(
		'author__not_in'   => $exclude,   // <-- unsanitized in 6.9.0-6.9.4 / 7.0.0-7.0.1
		'posts_per_page'   => 1,
		'no_found_rows'    => true,
		'suppress_filters' => true,
	) );

	$err = $wpdb->last_error;
	$wpdb->suppress_errors( $prev );

	header( 'Content-Type: text/plain' );
	if ( $err !== '' ) {
		echo "SINK: db_error\n";
		echo "unsanitized input reached the SQL WHERE clause.\n";
		echo "error: " . substr( $err, 0, 200 ) . "\n";
	} else {
		echo "SINK: ok\n";
		echo "no SQL error: input was coerced to integers (patched) or was benign.\n";
	}
	exit;
} );
