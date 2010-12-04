<?php

if (!$this->version) return false; // did someone attempt to run this?

//

$this->options['version'] = install($this->options['version'], $this->version);
add_site_option('httpbl_reloaded_options',$this->options);


function install($version = false, $current = false) {
	//echo 'installing';
	switch ($version){
		case '0.1.alpha':
		//case '0.1.beta':
			break; //we are up to date
		default: // latest version
			global $wpdb;
			$wpdb->httpblr_log = $wpdb->base_prefix . 'httpblr_log';
			if ( $wpdb->get_var("SHOW TABLES LIKE '{$wpdb->httpblr}'") != $wpdb->httpblr ) {
				create_log_table_0_1_alpha();
			} else {
				//something is wrong
				drop_table($wpdb->httpblr_log);
				create_log_table_0_1_alpha();
			}
		}
		return $current;
		
		
}

// Truncate table
function truncate_table($table) {
	global $wpdb;
	return $wpdb->query("TRUNCATE {$table};");
}

// Drop table
function drop_table($table) {
	global $wpdb;
	return $wpdb->query("DROP TABLE {$table};");
}

function create_log_table_0_1_alpha() {
	global $wpdb;
	$sql = "CREATE TABLE `{$wpdb->httpblr_log}` ( " .
		"`id` BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT, " .
		"`blog_id` BIGINT(20) UNSIGNED NOT NULL, " .
		"`ip` VARCHAR(16)  NOT NULL, " .
		"`time` DATETIME  NOT NULL, " .
		"`user_agent` VARCHAR(255)  NOT NULL DEFAULT 'unknown', " .
		"`httpbl_response` VARCHAR(16)  NOT NULL DEFAULT 'unknown', " .
		"`blocked` TINYINT(1) NOT NULL, " .
		"PRIMARY KEY (`id`) " .
		");";
	return $wpdb->query($sql);
}
