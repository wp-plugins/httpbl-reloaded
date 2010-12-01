<?php
/*
Plugin Name: http:BL Reloaded WordPress Plugin
Plugin URI: http://wordpress.org/extend/plugins/httpbl-reloaded/
Description: http:BL WordPress Plugin allows you to verify IP addresses of clients connecting to your blog against the <a href="http://www.projecthoneypot.org/?rf=28499">Project Honey Pot</a> database. 
Author: deadpan110
Version: 0.1.alpha
Author URI: http://ind-web.com/
License: This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.
Credits: Based on the original http:BL plugin by Jan Stępień ( http://stepien.cc/~jan ) and others.
*/


class httpBLreloaded {
	var $honeypots;
	var $options = array();
	
	function __construct() {
		//load_plugin_textdomain( 'httpBLreloaded', basename( dirname( __FILE__ ) )  . 'languages', basename( dirname( __FILE__ ) ) . '/languages' );
		$this->get_options();
		add_action('init', array($this,'check_visitor'),1);
		add_action('init', array($this,'init'));
		add_action('wp_footer', array($this,'echo_honeypot_html'));
		add_action('admin_menu', array($this,'add_admin_pages'));
		add_action('wp_dashboard_setup', array($this,'add_dashboard_widget'));
	}
	
	function add_dashboard_widget() {
		// only administrators can see this
		if (!current_user_can('administrator')) return;
		wp_add_dashboard_widget('httpblr_dashboard_widget', 'http:BL Reloaded', array($this,'dashboard_widget_function'));
			global $wp_meta_boxes;
	//echo '<pre>';
	//print_r($wp_meta_boxes);
	//echo '</pre>';
	// Get the regular dashboard widgets array
	$normal_dashboard = $wp_meta_boxes['dashboard']['normal']['core'];
	// Backup and delete our new dashboard widget from the end of the array
	$widget_backup = array('httpblr_dashboard_widget' => $normal_dashboard['httpblr_dashboard_widget']);
	unset($normal_dashboard['httpblr_dashboard_widget']);
	
	// Merge the two arrays together so our widget is at the beginning
	//$sorted_dashboard = array_merge($widget_backup, $normal_dashboard);
	// Save the sorted array back into the original metaboxes
	$wp_meta_boxes['dashboard']['normal']['core'] = $normal_dashboard;
	$wp_meta_boxes['dashboard']['side']['core'] = array_merge($widget_backup, $wp_meta_boxes['dashboard']['side']['core']);
	
	
	}
	
	function dashboard_widget_function() {
		//echo '<h4 class="alignleft">Take control of your own Web...</h4>';
		echo "<p>This site is protected using Project Honey Pot!</p>";
		echo "<blockquote>Project Honey Pot is the first and only distributed system for identifying spammers and the spambots they use to scrape addresses from your website.</blockquote>";
		echo "<p>The <strong>http:BL Reloaded</strong> plugin by <strong>IND-Web.com</strong> has been enabled for all our site owners. It has not yet been released to the public but more features are coming soon.</p>";
		echo "<h5>Planned Features</h5>";
		echo "<ul>";
		echo "<li>Optionally disable this on your site.</li>";
		echo "<li>View a list of IP addresses that were blocked on your site.</li>";
		echo "<li>View a log of all IP addresses that have been blocked across the <strong>IND-Web.com</strong> network.</li>";
		echo "<li>...and much more</li>";
		echo "</ul>";
		echo "<h5>Notes</h5>";
		echo "<p>We are currently blocking IP addresses obtained from the Project Honey Pot database that are known comment spammers, harvesters and just plain suspicious that score 30 or more and have been active within the last 14 days (see the <a href='http://www.projecthoneypot.org/threat_info.php'>Project Honey Pot Threat Rating</a> for how this is calculated). If you have any concerns, please email <a href='mailto:support@ind-web.com'>IND-Web.com support</a>.</p>";
		
	}

	
	// get all the options for the plugin
	function get_options() {
		$defaults = array(
			'userIP' => false,
			'timeout' => 0,
			'access_key' => false,
			'blacklist_msg' => __('Your IP has been reported as blacklisted by Project Honey Pot due to high levels of abnormal activity. If you are sure you are not a spammer or harvester, please check all the computers using your IP address for trojans and botnets with an up to date virus checker and then contact Project Honey Pot to have your IP address removed from the blacklist.','httpBLreloaded'),
			'age_thres' => 14,
			'threat_thres_d' => 30, // default threshold
			'threat_thres_h' => false, // harvester threshold
			'threat_thres_s' => false, // spammer threshold
			'threat_thres_c' => false, // commenter threshold
			'deny' => array(1 => false, 2 => false, 4 => false),
			//'deny_2' => false,
			//'deny_4' => false,
			'honeypots' => array(),
		);

		
		// allow other plugins to adjust the options
		$this->options = apply_filters( 'httpbl_reloaded_options', array_merge ($defaults, get_site_option('httpbl_reloaded_options',array())));

		if (defined('HTTPBL_ACCESS_KEY')) $this->options['access_key'] = HTTPBL_ACCESS_KEY;
		
		//echo '<pre>';
		//print_r($this->options);
		//echo '</pre>';
	}
	
	function init() {	
		if (!function_exists('is_multisite')) {
			add_action('admin_notices', array($this,'msg_version_error'));
			return false;
		}
	
		if (isset($_POST['httpblr_save']))  $this->set_options();
		if (isset($_POST['httpblr_reset'])) $this->del_options();
	}
	
	function set_options() {
		if (false === $this->admin_permission_check()) return;
		
			/*
	 * [userIP] => 12341234
    [access_key] => 1341341353
    [age_thres] => 14
    [threat_thres_d] => 302452
    [blacklist_msg] => Your IP has been reported as blacklisted by Project Honey Pot due to high levels of abnormal activity. If you are sure you are not a spammer or harvester, please check all the computers using your IP address for trojans and botnets with an up to date virus checker and then contact Project Honeypot to have your IP address removed from the blacklist.
    [honeypots] => 524524524
    [deny_1] => 1
    [deny_2] => 1
    [deny_4] => 1
    [threat_thres_s] => 245
    [threat_thres_h] => 24
    [threat_thres_c] => 2452
    [httpblr_save] => Save Settings
    */
    
		if (isset($_POST['userIP'])) {
			$this->options['userIP'] = $_POST['userIP'];
			$this->options['timeout'] = time();
		} else {
			$this->options['userIP'] = false;
		}
		
		$this->options['access_key'] = $_POST['access_key'];
		$this->options['age_thres'] = $_POST['age_thres'];
		$this->options['threat_thres_d'] = $_POST['threat_thres_d'];
		$this->options['threat_thres_s'] = $_POST['threat_thres_s'];
		$this->options['threat_thres_h'] = $_POST['threat_thres_h'];
		$this->options['threat_thres_c'] = $_POST['threat_thres_c'];
		$this->options['deny'][1] = $_POST['deny_1'];
		$this->options['deny'][2] = $_POST['deny_2'];
		$this->options['deny'][4] = $_POST['deny_4'];
		$this->options['blacklist_msg'] = $_POST['blacklist_msg'];
		

		
		
		if (isset($_POST['honeypots'])) {
			$this->options['honeypots'] = array();
			foreach(explode("\n",$_POST['honeypots']) as $honeypot ) {
				$honeypot = trim($honeypot);
				if (!empty($honeypot)) $this->options['honeypots'][] .= $honeypot;			
			}
			unset($honeypot);
		}
		
		add_site_option('httpbl_reloaded_options',$this->options);
		
		add_action('admin_notices', array($this,'msg_options_update'));
		
	}
	
	
	function del_options() {
		if (false === $this->admin_permission_check()) return;
		
		delete_site_option('httpbl_reloaded_options');
		
		add_action('admin_notices', array($this,'msg_options_reset'));
		
	}

	function msg_version_error() {
		if (!current_user_can('install_plugins')) return;
		$output = '<div id="httpblr_version_error" class="error fade">' . "\n";
		$output .= '<p>' . "\n";
		$output .= '<strong>' . __( 'http:BL reloaded needs WordPress 3.0 and above to work correctly.','httpBLreloaded' ) . '</strong><br />' . "\n";
		$output .= sprintf(__('You should use the original <a href="%1$s">http:BL</a> plugin from the WordPress Plugin Directory instead.','httpBLreloaded' ), 'http://wordpress.org/extend/plugins/httpbl/') . "\n";
		$output .= '</p>' . "\n";
		$output .= '</div>' . "\n";
		echo $output;
	}
	
	function msg_options_update() {
		if (false === $this->admin_permission_check()) return;
		$output = '<div id="httpblr_options_update" class="updated fade">' . "\n";
		$output .= '<p>' . "\n";
		$output .= '<strong>' . __( 'http:BL options saved.','httpBLreloaded' ) . '</strong>' . "\n";
		$output .= '</p>' . "\n";
		$output .= '</div>' . "\n";
		echo $output;
	}
	
	function msg_options_reset() {
		if (false === $this->admin_permission_check()) return;
		$output = '<div id="httpblr_options_update" class="updated fade">' . "\n";
		$output .= '<p>' . "\n";
		$output .= '<strong>' . __( 'http:BL options reset.','httpBLreloaded' ) . '</strong>' . "\n";
		$output .= '</p>' . "\n";
		$output .= '</div>' . "\n";
		echo $output;
	}
		

	// return true or false depending on admin status
	function admin_permission_check() {
		if (is_multisite() && current_user_can('manage_network')) return true;
		if (!is_multisite() && current_user_can('administrator')) return true;
		return false;
	}
		
		
		
	
		
	function add_admin_pages() {
		if (is_multisite()) {
		// This is a multi site install
			if (current_user_can( 'manage_network' )) {
				// configuration page in Super Admin
				add_submenu_page("ms-admin.php", "http:BL Reloaded WordPress Plugin",
					"http:BL Reloaded", 10, __FILE__, array($this,'configuration_page'));
			}
		} else {
			// This is a single install
			if (current_user_can( 'administrator' )) {
				// configuration page in Settings
				add_submenu_page("options-general.php", "http:BL Reloaded WordPress Plugin",
					"http:BL Reloaded", 10, __FILE__, array($this,'configuration_page'));
			}
		}
	
		if (current_user_can('subscribe')) {
			// We do not mind subscribers viewing the logs

		}
		
		
		//echo '<pre>';
		//print_r($_POST);
		//echo '</pre>';

		
		
	}	
		
		
	//}
/*	
	// get one random honeypot from our store
	function get_honeypot() {
		if (false === $this->honeypots) return;
		if (empty($this->honeypots)) {
			// fill pots with honey
			$this->honeypots = array('http://hp1.com/','http://hp2.com/','http://hp3.com/');
		}
		return $this->honeypots[array_rand($this->honeypots)];
	}
*/		
	
	function echo_honeypot_html() {
		echo $this->honeypot_html() . "\n";
	}
	
	
	// creates honeypot html
	function honeypot_html() {
		if (empty($this->options['honeypots'])) return;
		
		// Pick a random honeypot
		$honeypot = $this->options['honeypots'][array_rand($this->options['honeypots'])];
		// generate some random text for the link
		$text = wp_generate_password( rand(5, 15), false, false );

		$rand = rand(1, 7);
		switch($rand) {
			case 1:
				return '<a href="' . $honeypot . '"><!-- ' . $text . ' --></a>';
			case 2:
				return '<a href="' . $honeypot . '" style="display: none;">' . $text . '</a>';
			case 3:
				return '<div style="display: none;"><a href="' . $honeypot . '">' . $text . '</a></div>';
			case 4:
				return '<a href="' . $honeypot . '" title="' . $text . '"></a>';
			case 5:
				return '<!-- <a href="' . $honeypot . '">' . $text . '</a> -->';
			case 6:
				return '<a href="' . $honeypot . '"><span style="display: none;">' . $text . '</span></a>';
			case 7:
				return '<div style="display: none;" id="' . $text . '">' . $honeypot . '</div>';
		}
	}
	
	// creates hidetext html
	function hidetext_html($hidetext) {
		if (!$hidetext) return;
		$rand = rand(1, 7);
		switch($rand) {
			case 1:
				return '<!-- ' . $hidetext . ' -->';
			case 2:
				return '<div style="display: none;">' . $hidetext . '</div>';
			case 3:
				return '<span style="display: none;">' . $hidetext . '</span>';
			case 4:
				return '<!-- <div>' . $hidetext . '</div> -->';
			case 5:
				return '<!-- <span>' . $hidetext . '</span> -->';
			case 6:
				return '<code style="display: none;">' . $hidetext . '</code>';
			case 7:
				return '<strong style="display: none;">' . $hidetext . '</strong>';
		}
	}

	// This function converts text into its ASCII equivilent with optional content fillers
	function str_to_ascii($string,$content = false, $honeypot = false) {
		for($i = 0; $i != strlen($string); $i++) {
			$asciiString .= "&#".ord($string[$i]).";";
			if ($content) { // insert post content
				if (($i % (strlen($string) / count($content))) == 0) {
					$asciiString .= array_shift($content);
				}
			}
			if ($honeypot) { // insert honeypots
				if (($i % (strlen($string) / (count($honeypot) * 2))) == 0) {
					$asciiString .= $this->honeypot_html();
					//(
					//	$this->options['honeypots'][array_rand($this->options['honeypots'])]
					//	);
				}
			}
		}
		return $asciiString;
	}
	
	// This function strips text of html,short codes, email addresses, spaces and urls
	function str_to_plain($string) {
		$replacement = "";
		// Attempt to strip HTML tags
		$string = strip_tags($string);
		// Attempt to remove Shortcodes
		$string = strip_shortcodes($string);
		// Attempt to remove email addresses
		$pattern = "/[^@\s]*@[^@\s]*\.[^@\s]*/";
		$string = preg_replace($pattern, $replacement, $string);
		// Attempt to remove URL's
		$pattern = "/[a-zA-Z]*[:\/\/]*[A-Za-z0-9\-_]+\.+[A-Za-z0-9\.\/%&=\?\-_]+/i";
		$string = preg_replace($pattern, $replacement, $string);
		// Attempt to strip spaces
		$sPattern = '/\s+/m'; 
		$sReplace = ' ';

		//echo $sTestString . '<br />';
		$string = preg_replace( $sPattern, $sReplace, $string );
		
		return $string;
	}
/*
	// die with a blacklist message for bots and humans to read
	function blacklist_message() {
		global $wpdb;
		$blockedmsg = 'Your IP has been reported as blacklisted by Project Honey Pot due to high levels of abnormal activity. If you are sure you are not a spammer or harvester, please check all the computers using your IP address for trojans and botnets with an up to date virus checker and then contact Project Honeypot to have your IP address removed from the blacklist.';

		$message_array = $wpdb->get_row("SELECT * FROM $wpdb->posts WHERE post_status = 'publish' ORDER BY RAND() LIMIT 1");
		$content_array = explode(' ',$this->str_to_plain($message_array->post_content));
		// split into phrases between 2 and 5 words in length
		while ($content_array) {
			$phrase = '';
			for ($i = 1; $i <= rand(2,5); $i++) {
			$phrase .= array_shift($content_array) . ' ';
			}
			$newcontent[] .= $this->hidetext_html($phrase);
		}
		$this->blacklist_die(
			$this->str_to_ascii(
				$this->str_to_plain($blockedmsg),
				$newcontent,
				array ('http://hp1','http://hp2')
				),
			$message_array->post_title,
			array('response' => 200)
			);
	}
*/


	// just like wp_die but with some modifications
	function blacklist_die() {
		// Do NOT cache this page with wp-super-cache
		// If wp-super-cache is in use and the requested page has been cached,
		// bad users will only see this notice when they post a comment
		// currently there is no workaround
		if (!defined('DONOTCACHEPAGE')) define( 'DONOTCACHEPAGE', true);
		
		
		global $wpdb;
//print_r($this->options);
		$content_array = $wpdb->get_row("SELECT post_content, post_title FROM $wpdb->posts WHERE post_status = 'publish' ORDER BY RAND() LIMIT 1");
		
		
		$post_content = $content_array->post_content;
		$post_title = $content_array->post_title;
		
		
		// we really want a long post.
		// Incase someone has used a single URL as a post, we generate some junk too
		// TODO: * 5 below may be too high to stop division by 0 in str_to_ascii
		while (strlen($post_content) < (strlen($this->options['blacklist_msg']) * 5)){
			$post_content .= ' ' . wp_generate_password( rand(5, 15), false, false ) . ' ' . $post_content;
		}


		$post_content = explode(' ',$this->str_to_plain($post_content));
		// split into phrases between 2 and 5 words in length
		while ($post_content) {
			$phrase = '';
			for ($i = 1; $i <= rand(2,5); $i++) {
			$phrase .= array_shift($post_content) . ' ';
			}
			$newcontent[] .= $this->hidetext_html($phrase);
		}
		//$post_content = explode(' ',$this->str_to_plain($post_content));
		//print_r($post_content);

		// create the garbled message
		$post_content = $this->str_to_ascii($this->str_to_plain($this->options['blacklist_msg']),$newcontent, $this->options['honeypots']);
		
		//$defaults = array( 'response' => 200 );
		//$r = wp_parse_args($args, $defaults);

		$have_gettext = function_exists('__');
		
		// WordPress likes to echo language_attributes so we emulate out own
		if (function_exists('language_attributes')) {
			$doctype = 'html';
			$attributes = array();
			$output = false;
			if ( function_exists( 'is_rtl' ) )
				$attributes[] = 'dir="' . ( is_rtl() ? 'rtl' : 'ltr' ) . '"';
	
			if ( $lang = get_bloginfo('language') ) {
				if ( get_option('html_type') == 'text/html' || $doctype == 'html' )
					$attributes[] = "lang=\"$lang\"";
			}
			$language_attributes = implode(' ', $attributes);
			$language_attributes = apply_filters('language_attributes', $language_attributes);
		}
		
		// Locate wp-admin as wp_die() does
		if ( defined( 'WP_SITEURL' ) && '' != WP_SITEURL )
			$admin_dir = WP_SITEURL . '/wp-admin/';
		elseif ( function_exists( 'get_bloginfo' ) && '' != get_bloginfo( 'wpurl' ) )
			$admin_dir = get_bloginfo( 'wpurl' ) . '/wp-admin/';
		elseif ( strpos( $_SERVER['PHP_SELF'], 'wp-admin' ) !== false )
			$admin_dir = '';
		else
			$admin_dir = 'wp-admin/';
		
		if ( !function_exists( 'did_action' ) || !did_action( 'admin_head' ) ) :
			if ( !headers_sent() ) {
				status_header( 200 );
				nocache_headers();
				header( 'Content-Type: text/html; charset=utf-8' );
			}

			$text_direction = 'ltr';
			if ( isset($r['text_direction']) && 'rtl' == $r['text_direction'] )
				$text_direction = 'rtl';
			elseif ( function_exists( 'is_rtl' ) && is_rtl() )
				$text_direction = 'rtl';
		
			$output = '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">' . "\n";
			//$output .= '<!-- Ticket #11289, IE bug fix: always pad the error page with enough characters such that it is greater than 512 bytes, even after gzip compression abcdefghijklmnopqrstuvwxyz1234567890aabbccddeeffgghhiijjkkllmmnnooppqqrrssttuuvvwwxxyyzz11223344556677889900abacbcbdcdcededfefegfgfhghgihihjijikjkjlklkmlmlnmnmononpopoqpqprqrqsrsrtstsubcbcdcdedefefgfabcadefbghicjkldmnoepqrfstugvwxhyz1i234j567k890laabmbccnddeoeffpgghqhiirjjksklltmmnunoovppqwqrrxsstytuuzvvw0wxx1yyz2z113223434455666777889890091abc2def3ghi4jkl5mno6pqr7stu8vwx9yz11aab2bcc3dd4ee5ff6gg7hh8ii9j0jk1kl2lmm3nnoo4p5pq6qrr7ss8tt9uuvv0wwx1x2yyzz13aba4cbcb5dcdc6dedfef8egf9gfh0ghg1ihi2hji3jik4jkj5lkl6kml7mln8mnm9ono -->';
			$output .= '<html xmlns="http://www.w3.org/1999/xhtml" ' . $language_attributes . '>' . "\n";
			$output .= '<head>' . "\n";
			$output .= '<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />' . "\n";
			
			$output .= '<meta name="robots" content="noindex">' . "\n"; 
			$output .= '<meta name="robots" content="noarchive">' . "\n"; 
			$output .= '<meta name="robots" content="follow">' . "\n";
			$output .= '<title>' . $post_title . '</title>' . "\n";
			$output .= '<link rel="stylesheet" href="' . $admin_dir . 'css/install.css" type="text/css" />' . "\n";
			if ( 'rtl' == $text_direction ) :
				$output .= '<link rel="stylesheet" href="' . $admin_dir . 'css/install-rtl.css" type="text/css" />' . "\n";
			endif;
			$output .= '</head>' . "\n";
			$output .= '<body style="margin-top: 50px;">' . "\n";
		endif;
		
		$output .= '<h2>' . $this->str_to_ascii(__('WARNING', 'httpBLreloaded') . ' - ' . $_SERVER['REMOTE_ADDR'],array($this->hidetext_html($title)), false) . '</h2>' . "\n";
		$output .= $post_content . "\n";
		$output .= '</body>' . "\n";
		$output .= '</html>';
		echo $output;
		die();
	}
	
	// The visitor verification function
	function check_visitor() {
		
		//print_r($this->options);
		//$_SERVER['REMOTE_ADDR'] = '195.55.130.44';
		
		// Blacklist message test only if not on the admin pages
		if (!is_admin()) {
			if ($this->options['userIP'] == $_SERVER['REMOTE_ADDR']) {
				if ($this->options['timeout'] >= (time() - 900)) $this->blacklist_die();
			}
		}
		
		// No access key set so we do nothing else here
		if (!$this->options['access_key']) return;
		
		// Check WordPress transient cache for results
		// This cache is not network wide unless a replacement object cache plugin is used
		// We only want to reduce the DNS queries in case a users web server has no DNS caching
		if (false === ($result = get_transient('httpblr_' . $_SERVER['REMOTE_ADDR']))) {
			// The http:BL query (I love this - a simple 1 liner)
			$result = explode( ".", gethostbyname( $this->options['access_key'] . "." .
				implode ( ".", array_reverse( explode( ".",
				$_SERVER["REMOTE_ADDR"] ) ) ) .
				".dnsbl.httpbl.org" ) );
			// Store the transient
			if ( $result[0] == 127 ) {
				// Store result for 600 seconds
				set_transient('httpblr_' . $_SERVER['REMOTE_ADDR'], $result, 600);
			} else {
				// Store result for 3600 seconds
				$result = array('0','0','0','0');
				set_transient('httpblr_' . $_SERVER['REMOTE_ADDR'], $result, 3600);
			}
		} 
		
		// If the result is not positive, we do nothing else
		// (logging of all visitors is no longer supported as that is a job for another plugin)
		if ( $result[0] != 127 ) return;

			// Get thresholds
			//$age_thres = get_site_option('httpbl_age_thres');
			//$threat_thres = get_site_option('httpbl_threat_thres');
			//$threat_thres_s = get_site_option('httpbl_threat_thres_s');
			//$threat_thres_h = get_site_option('httpbl_threat_thres_h');
			//$//threat_thres_c = get_site_option('httpbl_threat_thres_c');

			//for ($i = 0; pow(2, $i) <= 4; $i++) {
			//	$value = pow(2, $i);
			//	$denied[$value] = $this->option['deny_' . $value];
			//}
			
			//print_r($denied);
			
			//die;
			
			
			//$hp = get_site_option('httpbl_hp');
			
			// Assume that visitor's OK
			$age = false;
			$threat = false;
			$deny = false;
			$blocked = false;
			
			// Check age threshold
			if ( $result[1] < $this->options['age_thres'] )
				$age = true;

			// Check suspicious threat
			if ( $result[3] & 1 ) {
				if ( $this->options['threat_thres_s'] ) {
					if ( $result[2] > $this->options['threat_thres_s'] )
						$threat = true;
				} else {
					if ( $result[2] > $this->options['threat_thres_d'] )
						$threat = true;
				}
			}

			// Check harvester threat
			if ( $result[3] & 2 ) {
				if ( $this->options['threat_thres_h'] ) {
					if ( $result[2] > $this->options['threat_thres_h'] )
						$threat = true;
				} else {
					if ( $result[2] > $this->options['threat_thres_d'] )
						$threat = true;
				}
			}

			// Check comment spammer threat
			if ( $result[3] & 4 ) {
				if ( $this->options['threat_thres_c'] ) {
					if ( $result[2] > $this->options['threat_thres_c'] )
						$threat = true;
				} else {
					if ( $result[2] > $this->options['threat_thres_d'] )
						$threat = true;
				}
			}

			foreach ( $this->options['deny'] as $key => $value ) {
				if ( ($result[3] - $result[3] % $key) > 0
					and $value)
					$deny = true;
			}
			
			// If he's not OK
			if ( $deny && $age && $threat ) {
				$blocked = true;
				$this->blacklist_die();

				// If we've got a Honey Pot link
				//if ( $hp ) {
				//	header( "HTTP/1.1 301 Moved Permanently ");
				//	header( "Location: $hp" );
				//}
			}

			// Logging is on the TODO list
			return;

			// Are we logging?
			if (get_site_option("httpbl_log") == true) {

				// At first we assume that the visitor
				// should be logged
				$log = true;

				// Checking if he's not one of those, who
				// are not logged
				$ips = explode(" ",
					get_site_option("httpbl_not_logged_ips"));
				foreach ($ips as $ip) {
					if ($ip == $_SERVER["REMOTE_ADDR"])
						$log = false;
				}

				// Don't log search engine bots
				if ($result[3] == 0) $log = false;

				// If we log only blocked ones
				if (get_site_option("httpbl_log_blocked_only")
					and !$blocked) {
					$log = false;
				}

				// If he can be logged, we log him
				if ($log)
					httpbl_add_log($_SERVER["REMOTE_ADDR"],
					$_SERVER["HTTP_USER_AGENT"],
					implode($result, "."), $blocked);
			}
			if ($blocked) die();	// My favourite line.
		//}
	}
	
	function configuration_page() {
		if (is_multisite()) {
			if (!current_user_can('manage_network'))
				wp_die(__('You do not thave the correct permissions to access this page.','httpBLreloaded'));
		} else {
			if (!current_user_can('administrator'))
				wp_die(__('You do not thave the correct permissions to access this page.','httpBLreloaded'));
		}
			
		// The page contents.
		$output = '<div class="wrap">' . "\n";
		$output .= '<h2>http:BL Reloaded WordPress Plugin</h2>' . "\n";
		$output .= '<p>' . sprintf(__('The http:BL Reloaded WordPress Plugin allows you to verify IP addresses of clients connecting to your blog against the <a href="%1$s">Project Honey Pot</a> database.','httpBLreloaded'), 'http://www.projecthoneypot.org/?rf=84178') . '</p>' . "\n";
		$output .= '<h3>' . __('Configuration','httpBLreloaded') . '</h3>';
		$output .= '<form action="" method="post" id="httpbl_conf">';

		$output .= '<h4>' . __('Testing options','httpBLreloaded') . '</h4>';
		$output .= '<p><label for="httpblruserip">' . __('Blacklist yourself','httpBLreloaded') . '</label> <input id="httpblruserip" type="text" name="userIP" value="" /> (' . sprintf(__('Your current IP address is %1$s','httpBLreloaded'), '<code>' . $_SERVER['REMOTE_ADDR'] . '</code>') . ')</p>';
		$output .= '<p><small>' . __('Enter your IP address here to test what the site will look like to a human that has been unfortunately blocked. This option will NOT use the Project Honey Pot database or deny you access to any of the WordPress Administration pages.','httpBLreloaded') . '</small></p>';
		$output .= '<p><small>' . __('To ensure that you do not get locked out of your site, this option will time out after 15 minutes.','httpBLreloaded') . '</small></p>';

		$output .= '<h4>' . __('Main options','httpBLreloaded') . '</h4>';
		$output .= '<p><label for="httpblrkey">' . __('http:BL Access Key','httpBLreloaded') . '</label> <input id="httpblrkey" type="text" name="access_key" value="' . $this->options['access_key'] . '" /></p>';
		$output .= '<p><small>' . sprintf(__('An Access Key is required to perform a http:BL query. You can get your key at <a href="%1$s">http:BL Access Management page</a>. You need to register a free account at the Project Honey Pot website to get one.','httpBLreloaded'),'http://www.projecthoneypot.org/httpbl_configure.php') . '</small></p>';
		$output .= '<p><label for="httpblrage">' . __('Age threshold','httpBLreloaded') . '</label> <input id="httpblrage" type="text" name="age_thres" value="' . $this->options['age_thres'] . '" /></p>';
		$output .= '<p><small>' . __('http:BL service provides you information about the date of the last activity of a checked IP. Due to the fact that the information in the Project Honey Pot database may be obsolete, you may set an age threshold, counted in days. If the verified IP has not been active for a period of time longer than the threshold it will be regarded as harmless.','httpBLreloaded') . '</small></p>';
		$output .= '<p><label for="httpblrthreatthres">' . __('General threat score threshold','httpBLreloaded') . '</label> <input id="httpblsthreatthres" type="text" name="threat_thres_d" value="' . $this->options['threat_thres_d'] . '" /></p>';
		$output .= '<p><small>' . __('Each suspicious IP address is given a threat score. This scored is asigned by Project Honey Pot basing on various factors, such as the IP activity or the damage done during the visits. The score is a number between 0 and 255, where 0 is no threat at all and 255 is extremely harmful. In the field above you may set the threat score threshold. IP address with a score greater than the given number will be regarded as harmful.','httpBLreloaded') . '</small></p>';
		
		$output .= '<fieldset>';
		$output .= '<p><legend>' . __('Blacklist Message') . '</legend></p>';
		$output .= '<textarea class="code" name="blacklist_msg" cols="60" rows="6">';
		$output .= $this->options['blacklist_msg'];
		$output .= '</textarea>';
		$output .= '<p><small>' . __('This message will be shown to unfortunate humans that find themselves locked out of your site. Do not use any HTML as the text will be converted into ASCII codes. The page source will contain text from a random post or page and any links to Honey Pots if they are available.','httpBLreloaded') . '</small></p>';
		$output .= '</fieldset>';

		$output .= '<fieldset>';
		$output .= '<p><legend>' . __('Honey Pot List') . '</legend></p>';
		$output .= '<textarea class="code" name="honeypots" cols="60" rows="6">';
		if (!empty($this->options['honeypots'])) {
			foreach($this->options['honeypots'] as $honeypot ) {
				$output .= $honeypot . "\r\n";
			}
			unset($honeypot);
		}
		$output .= '</textarea>';
		$output .= '</fieldset>';
		$output .= '<p><small>' . __('If you have got any Honey Pots or Quick Links, you may redirect all unwelcome visitors to them. These links will also be hidden throughout the site. Be creative and make use of URL shortening services so you can use the same Honey Pot several times (one per line).','httpBLreloaded') . '</small></p>';
		$output .= '<p><small>' . sprintf(__('More details are available at the <a href="%1$s">http:BL API Specification page</a>.'),'http://www.projecthoneypot.org/httpbl_api.php') . '</small></p>';

		$output .= '<h4>' . __('Protection options','httpBLreloaded') . '</h4>';
		$output .= '<fieldset>';
		$output .= '<legend>' . __('Types of visitors to be treated as malicious','httpBLreloaded') . '</legend>';
		$output .= '<p><input type="checkbox" name="deny_1" value="1" ' . ($this->options['deny'][1] ? 'checked="true"' : '') . ' /> ' . __('Suspicious','httpBLreloaded') . '</p>';
		$output .= '<p><input type="checkbox" name="deny_2" value="1" ' . ($this->options['deny'][2] ? 'checked="true"' : '') . ' /> ' . __('Harvesters','httpBLreloaded') . '</p>';
		$output .= '<p><input type="checkbox" name="deny_4" value="1" ' . ($this->options['deny'][4] ? 'checked="true"' : '') . ' /> ' . __('Comment spammers','httpBLreloaded') . '</p>';
		$output .= '<p><small>' . __('The field above allows you to specify which types of visitors should be regarded as harmful. It is recommended to tick all of them.','httpBLreloaded') . '</small></p>';
		$output .= '</fieldset>';
		
		$output .= '<h4>' . __('Advanced options','httpBLreloaded') . '</h4>';
		$output .= '<p><ul>';
		$output .= '<li><label for="httpblrthress">' . __('Suspicious threat score threshold','httpBLreloaded') . '</label> <input id="httpblrthress" type="text" name="threat_thres_s" value="' . $this->options['threat_thres_s'] . '" /></li>';
		$output .= '<li><label for="httpblrthresh">' . __('Harvester threat score threshold','httpBLreloaded') . '</label> <input id="httpblrthresh" type="text" name="threat_thres_h" value="' . $this->options['threat_thres_h'] . '" /></li>';
		$output .= '<li><label for="httpblrthresc">' . __('Comment spammer threat score threshold','httpBLreloaded') . '</label> <input id="httpblrthresc" type="text" name="threat_thres_c" value="' . $this->options['threat_thres_c'] . '" /></li>';
		$output .= '</ul></p>';
		$output .= '<p><small>' . __('These values override the general threat score threshold. Leave blank to use the general threat score threshold.','httpBLreloaded') . '</small></p>';

		$output .= '<p><input class="button" type="submit" name="httpblr_save" value="' . __('Save Settings','httpBLreloaded') . '" /> <input class="button" type="submit" name="httpblr_reset" value="' . __('Reset Defaults','httpBLreloaded') . '" /></p>';
		
		$output .= '</form>';

		echo $output;

/*	<h4>Logging options</h4>
		<p>Enable logging <input type='checkbox' name='enable_log' value='1' <?php echo $log_checkbox ?>/></p>
		<p><small>If you enable logging all visitors which are recorded in the Project Honey Pot's database will be logged in the database and listed in the table below. Remember to create a proper table in the database before you enable this option!</small></p>
		<p>Log only blocked visitors <input type='checkbox' name='log_blocked_only' value='1' <?php echo $log_blocked_only_checkbox ?>/></p>
		<p><small>Enabling this option will result in logging only blocked visitors. The rest shall be forgotten.</small></p>
		<p>Not logged IP addresses <input type='text' name='not_logged_ips' value='<?php echo $not_logged_ips ?>'/></p>
		<p><small>Enter a space-separated list of IP addresses which will not be recorded in the log.</small></p>
	<h4>Statistics options</h4>
		<p>Enable stats <input type='checkbox' name='enable_stats' value='1' <?php echo $stats_checkbox ?>/></p>
		<p><small>If stats are enabled the plugin will get information about its performance from the database, allowing it to be displayed using <code>httpbl_stats()</code> function.</small></p>
		<p>Output pattern <input type='text' name='stats_pattern' value='<?php echo $stats_pattern ?>'/></p>
		<p><small>This input field allows you to specify the output format of the statistics. You can use following variables: <code>$block</code> will be replaced with the number of blocked visitors, <code>$pass</code> with the number of logged but not blocked visitors, and <code>$total</code> with the total number of entries in the log table. HTML is welcome. PHP won't be compiled.</small></p>
		<fieldset>
		<label>Output link</label>
		<p><input type="radio" name="stats_link" value="0" <?php echo $stats_link_radio[0]; ?>/> Disabled</p>
		<p><input type="radio" name="stats_link" value="1" <?php echo $stats_link_radio[1]; ?>/> <a href="http://www.projecthoneypot.org/?rf=28499">Project Honey Pot</a></p>
		<p><input type="radio" name="stats_link" value="2" <?php echo $stats_link_radio[2]; ?>/> <a href="http://wordpress.org/extend/plugins/httpbl/">http:BL WordPress Plugin</a></p>
		</fieldset>
		<p><small>Should we enclose the output specified in the field above with a hyperlink?</small></p>
	<div style="float:right"><a href="http://www.projecthoneypot.org/?rf=28499"><img src="<?php echo get_option("siteurl") . "/wp-content/plugins/httpbl/";?>project_honey_pot_button.png" height="31px" width="88px" border="0" alt="Stop Spam Harvesters, Join Project Honey Pot"></a></div>
		<p><input type='submit' name='httpbl_save' value='Save Settings' /></p>
	</form>
<?php
	if (get_site_option("httpbl_log")) {
?>
	<hr/>
	*/
	}
		
	
}
new httpBLreloaded();

return;
global $wpdb;
$string ="This is an example string with a few specialy symbols: *?%&/äö$ü!";
$results = $wpdb->get_row("SELECT * FROM $wpdb->posts WHERE post_status = 'publish' ORDER BY RAND() LIMIT 1");


$oldcontent = explode(' ',httpblr_str_to_plain($results->post_content .' ' . $results->post_content));
$newcontent = array();
//foreach( $oldcontent as $words ) {
	
	

//print_r($newcontent);
//die;

echo strlen($results->post_content) . '/' . count($newcontent);
$blockedmsg = 'NOTICE: Your IP has been reported as blacklisted by Project Honey Pot due to high levels of abnormal activity. If you are sure you are not a spammer, please check all the computers using your IP address for trojans and botnets with an up to date virus checker and then contact project honeypot to have your IP removed from the blacklist.';

//print_r($results);
wp_die(httpblr_str_to_ascii(httpblr_str_to_plain($blockedmsg),$newcontent, array ('http://hp1','http://hp2')),$results->post_title, array('response' => 200));

// This function takes an array 


// This function converts text into its ASCII equivilent with optional content
function httpblr_str_to_ascii($string,$content = false, $honeypot = false) {
	
	for($i = 0; $i != strlen($string); $i++) {
		$asciiString .= "&#".ord($string[$i]).";";
		if ($content) { 
			if (($i % (strlen($string) / count($content))) == 0) {
				$asciiString .= array_shift($content);
			}
		}
		if ($honeypot) { 
			if (($i % (strlen($string) / (count($honeypot) * 2))) == 0) {
				$asciiString .= '<!-- ' . $honeypot[array_rand($honeypot)] . ' -->';
			}
		}
	}
	return $asciiString;
}

// This function strips text of html,short codes, email addresses and urls
function httpblr_str_to_plain($string) {
	
	// Attempt to strip HTML tags
	$string = strip_tags($string);

	// Attempt to remove Shortcodes
	$string = strip_shortcodes($string);
	
	// Attempt to remove email addresses
	$pattern = "/[^@\s]*@[^@\s]*\.[^@\s]*/";
	$replacement = "[removed]";
	$string = preg_replace($pattern, $replacement, $string);
	
	// Attempt to remove URL's
	$pattern = "/[a-zA-Z]*[:\/\/]*[A-Za-z0-9\-_]+\.+[A-Za-z0-9\.\/%&=\?\-_]+/i";
	$replacement = "[removed]";
	$string = preg_replace($pattern, $replacement, $string);
	
	return $string;
}

function httpblr_() {}


// prepare the admin pages
function httpbl_admin_init() {
	if (!is_admin()) return; // we are not on the admin pages
	
	if (!function_exists('is_multisite')) {
		add_action('admin_notices', 'httpbl_wp_version_warning');
		return false;
	}
	
	if (is_multisite()) {
		// This is a multi site install
		if (current_user_can( 'manage_network' )) {
			// configuration page
			add_action("admin_menu", "httpbl_ms_config_page");
		}
	} else {
		// This is a single install
		if (current_user_can( 'administrator' )) {
			// configuration page
			add_action("admin_menu", "httpbl_wp_config_page");
		}
	}
	
	if (current_user_can('subscribe')) {
		// We do not mind subscribers viewing the logs

	}
}
add_action("init", "httpbl_admin_init",10);


//** Prepare submenu pages **//
function httpbl_ms_config_page() {
	add_submenu_page("ms-admin.php", "http:BL Reloaded WordPress Plugin",
		"http:BL Reloaded", 10, __FILE__, "httpbl_configuration");
}

function httpbl_wp_config_page() {
	add_submenu_page("options-general.php", "http:BL Reloaded WordPress Plugin",
		"http:BL Reloaded", 10, __FILE__, "httpbl_configuration");
}

function httpbl_wp_version_warning() {
	if (current_user_can('install_plugins')) {
		echo "<div id='httpbl-wp-version-warning' class='error fade'>";
		echo "<p>";
		echo "<strong>" . __( 'http:BL reloaded needs WordPress 3.0 and above to work correctly.', 'httbl_reloaded' ) . "</strong><br />";
		echo sprintf(__('You should use the original <a href="%1$s">http:BL</a> plugin from the WordPress Plugin Directory instead.', 'httbl_reloaded' ), "http://wordpress.org/extend/plugins/httpbl/");
		echo "</p>";
		echo "</div>\n";
	}
}
	

add_action("init", "httpbl_check_visitor",1);
add_action("wp_footer", "httpbl_honey_pot");
if ( get_site_option('httpbl_stats') )
	add_action("init", "httpbl_get_stats",10);







	
	// Add a line to the log table
	function httpbl_add_log($ip, $user_agent, $response, $blocked)
	{
		global $wpdb;
		echo $wpdb->base_prefix;
		die;
		global $GLOBALS;
		$time = gmdate("Y-m-d H:i:s",
			time() + get_site_option('gmt_offset') * 60 * 60 );
		$blocked = ($blocked ? 1 : 0);
		$wpdb =& $GLOBALS['wpdb'];
		$user_agent = mysql_real_escape_string($user_agent);
		$query = "INSERT INTO ".$wpdb->base_prefix."httpbl_log ".
			"(ip, time, user_agent, httpbl_response, blocked)".
			" VALUES ( '$ip', '$time', '$user_agent',".
			"'$response', $blocked);";
		$results = $wpdb->query($query);
	}

	// Get latest 50 entries from the log table
	function httpbl_get_log()
	{
		global $GLOBALS;
		$query = "SELECT * FROM ".$GLOBALS['table_prefix'].
			"httpbl_log ORDER BY id DESC LIMIT 50";
		$wpdb =& $GLOBALS['wpdb'];
		return $wpdb->get_results($query);
	}
	
	// Get numbers of blocked and passed visitors from the log table
	// and place them in $httpbl_stats_data[]
	function httpbl_get_stats()
	{
		global $GLOBALS, $httpbl_stats_data;
		$query = "SELECT blocked,count(*) FROM ".$GLOBALS['table_prefix'].
			"httpbl_log GROUP BY blocked";
		$wpdb =& $GLOBALS['wpdb'];
		$results = $wpdb->get_results($query,ARRAY_N);
		foreach ((array)$results as $row) {
			if ($row[0] == 1) {
				$httpbl_stats_data['blocked'] = $row[1];
			} else {
				$httpbl_stats_data['passed'] = $row[1];
			}
		}
		$results = NULL;
	}
	
	// Display stats. Output may be configured at the plugin's config page.
	function httpbl_stats()
	{
		global $httpbl_stats_data;
		$pattern = get_site_option('httpbl_stats_pattern');
		$link = get_site_option('httpbl_stats_link');
		$search = array(
			'$block',
			'$pass',
			'$total'
			);
		$replace = array(
			$httpbl_stats_data['blocked'],
			$httpbl_stats_data['passed'],
			$httpbl_stats_data['blocked']+$httpbl_stats_data['passed']
			);
		$link_prefix = array(
			"",
			"<a href='http://www.projecthoneypot.org/?rf=28499'>",
			"<a href='http://wordpress.org/extend/plugins/httpbl/'>"
			);
		$link_suffix = array(
			"",
			"</a>",
			"</a>"
			);
		echo $link_prefix[$link].
			str_replace($search, $replace, $pattern).
			$link_suffix[$link];
	}
	
	// Check whether the table exists
	function httpbl_check_log_table()
	{
		global $GLOBALS;
		$wpdb =& $GLOBALS['wpdb'];
		$result = $wpdb->get_results("SHOW TABLES");
		foreach ($result as $stdobject) {
			foreach ($stdobject as $table) {
				if ($GLOBALS['table_prefix'].
					"httpbl_log" == $table) {
					return true;
				}
			}
		}
		return false;
	}
	
	// Truncate the log table
	function httpbl_truncate_log_table()
	{
		global $GLOBALS;
		$wpdb =& $GLOBALS['wpdb'];
		return $wpdb->get_results("TRUNCATE ".
			$GLOBALS['table_prefix']."httpbl_log;");
	}

	// Drop the log table
	function httpbl_drop_log_table()
	{
		global $GLOBALS;
		update_site_option('httpbl_log', false);
		$wpdb =& $GLOBALS['wpdb'];
		return $wpdb->get_results("DROP TABLE ".
			$GLOBALS['table_prefix']."httpbl_log;");
	}
	
	// Create a new log table
	function httpbl_create_log_table()
	{
		global $GLOBALS;
		// No "IF NOT EXISTS" as we create it only if it does
		// not exist.
		$sql = 'CREATE TABLE `' . $GLOBALS['table_prefix'] . 'httpbl_log` ('
			.'	`id` INT( 6 ) NOT NULL AUTO_INCREMENT PRIMARY KEY ,'
			.'	`ip` VARCHAR( 16 ) NOT NULL DEFAULT \'unknown\' ,'
			.'	`time` DATETIME NOT NULL ,'
			.'	`user_agent` VARCHAR( 255 ) NOT NULL DEFAULT \'unknown\' ,'
			.'	`httpbl_response` VARCHAR( 16 ) NOT NULL ,'
			.'	`blocked` BOOL NOT NULL'
			.')';
		$wpdb =& $GLOBALS['wpdb'];
		// TODO check for errors.
		$wpdb->query($sql);
	}
	
	


//	function httpbl_honey_pot()
//	{
//		$hp = get_option('httpbl_hp');
//		if ( $hp )
//			echo '<div style="display: none;"><a href="' . $hp . '">' . wp_generate_password( rand(5, 15), false, false ) . '</a></div>';
//	}

// honeypot link generator
function httpbl_honey_pot() {
	$hp = get_site_option('httpbl_hp');
		if (!$hp) return; // no honeypots set
		
	//$rand_keys = array_rand($input, 2)
	// generate a random string using WordPress' password generator
	$text = wp_generate_password( rand(5, 15), false, false );
	$rand = rand(1, 9);
	switch($rand) {
		case 1:
			echo '<a href="http://node1.ind-web.com/requirement.php"><!-- ' . $text . ' --></a>';
			break;
		case 2:
			echo '<a href="http://node1.ind-web.com/requirement.php" style="display: none;">' . $text . '</a>';
			break;
		case 3:
			echo '<div style="display: none;"><a href="http://node1.ind-web.com/requirement.php">' . $text . '</a></div>';
			break;
		case 4:
			echo '<a href="http://node1.ind-web.com/requirement.php"></a>';
			break;
		case 5:
			echo '<!-- <a href="http://node1.ind-web.com/requirement.php">' . $text . '</a> -->';
			break;
		case 6:
			echo '<div style="position: absolute; top: -250px; left: -250px;"><a href="http://node1.ind-web.com/requirement.php">' . $text . '</a></div>';
			break;
		case 7:
			echo '<a href="http://node1.ind-web.com/requirement.php"><span style="display: none;">' . $text . '</span></a>';
			break;
		case 8:
			echo '<a href="http://node1.ind-web.com/requirement.php"><div style="height: 0px; width: 0px;">' . $text . '</div></a>';
			break;
		default:
			echo '<div style="display: none;">
			</div>';
	}
	
}




	function httpbl_configuration()
	{
		// If the save button was clicked...
		if (isset($_POST["httpbl_save"])) {
			// ...the options are updated.
			update_site_option('httpbl_key', $_POST["key"] );
			update_site_option('httpbl_age_thres', $_POST["age_thres"] );
			update_site_option('httpbl_threat_thres',
				$_POST["threat_thres"] );
			update_site_option('httpbl_threat_thres_s', 
				$_POST["threat_thres_s"] );
			update_site_option('httpbl_threat_thres_h', 
				$_POST["threat_thres_h"] );
			update_site_option('httpbl_threat_thres_c', 
				$_POST["threat_thres_c"] );

			for ($i = 0; pow(2, $i) <= 4; $i++) {
				$value = pow(2, $i);
				$denied[$value] = update_site_option('httpbl_deny_'.
					$value, ($_POST["deny_".$value] == 1 ?
					true : false));
			}
			update_site_option('httpbl_hp', $_POST["hp"] );
			update_site_option('httpbl_log',
				( $_POST["enable_log"] == 1 ? true : false ));
			update_site_option('httpbl_log_blocked_only',
				( $_POST["log_blocked_only"] == 1 ?
				true : false ));
			update_site_option('httpbl_not_logged_ips',
				$_POST["not_logged_ips"] );
			update_site_option('httpbl_stats',
				( $_POST["enable_stats"] == 1 ? true : false ));
			update_site_option('httpbl_stats_pattern',
				$_POST["stats_pattern"] );
			update_site_option('httpbl_stats_link',
				$_POST["stats_link"] );
		}
		
		// Should we purge the log table?
		if (isset($_POST["httpbl_truncate"]))
			httpbl_truncate_log_table();

		// Should we delete the log table?
		if (isset($_POST["httpbl_drop"]))
			httpbl_drop_log_table();
		
		// Should we create a new log table?
		if (isset($_POST["httpbl_create"]))
			httpbl_create_log_table();
		
		// If we log, but there's no table.
		if (get_site_option('httpbl_log') and !httpbl_check_log_table()) {
			httpbl_create_log_table();
		}

		// If it seems like the first launch,
		// few options should be set as defaults.
		if ( get_site_option( "httpbl_key" ) == "" )
			update_site_option( "httpbl_key" , "abcdefghijkl" );
		if ( get_site_option( "httpbl_age_thres" ) == 0 )
			update_site_option( "httpbl_age_thres" , "14" );
		if ( get_site_option( "httpbl_threat_thres" ) == 0 )
			update_site_option( "httpbl_threat_thres" , "30" );
		
		// Get data to be displayed in the form.
		$key = get_site_option('httpbl_key');
		$threat_thres = get_site_option('httpbl_threat_thres');
		$threat_thres_s = get_site_option('httpbl_threat_thres_s');
		$threat_thres_h = get_site_option('httpbl_threat_thres_h');
		$threat_thres_c = get_site_option('httpbl_threat_thres_c');
		$age_thres = get_site_option('httpbl_age_thres');
		for ($i = 0; pow(2, $i) <= 4; $i++) {
			$value = pow(2, $i);
			$denied[$value] = get_site_option('httpbl_deny_' . $value);
			$deny_checkbox[$value] = ($denied[$value] ?
				"checked='true'" : "");
		}
		$hp = get_site_option('httpbl_hp');
		$not_logged_ips = get_site_option('httpbl_not_logged_ips');
		$log_checkbox = ( get_site_option('httpbl_log') ?
			"checked='true'" : "");
		$log_blocked_only_checkbox = ( 
			get_site_option('httpbl_log_blocked_only') ?
			"checked='true'" : "");
		$stats_checkbox = ( get_site_option('httpbl_stats') ?
			"checked='true'" : "");
		$stats_pattern = get_site_option('httpbl_stats_pattern');
		$stats_link = get_site_option('httpbl_stats_link');
		$stats_link_radio = array();
		for ($i = 0; $i < 3; $i++) {
			if ($stats_link == $i) {
				$stats_link_radio[$i] = "checked='true'";
				break;
			}
		}

		// The page contents.
?>
<div class='wrap'>
	<h2>http:BL Reloaded WordPress Plugin</h2>
	<p><a href="#conf">Configuration</a>
<?php
	// No need to link to the log section, if we're not logging
	if (get_site_option("httpbl_log")) {
?>
| <a href="#log">Log</a></p>
<?php
	}
?>
	<p>The http:BL WordPress Plugin allows you to verify IP addresses of clients connecting to your blog against the <a href="http://www.projecthoneypot.org/?rf=28499">Project Honey Pot</a> database.</p>
	<a name="conf"></a>
	<h3>Configuration</h3>
	<form action='' method='post' id='httpbl_conf'>
	<h4>Testing options</h4>
		<p>Blacklist yourself <input type='text' name='userIP' value='<?php echo $key ?>' /> </p>
		<p><small>Enter your IP address here to test what the site will look like to a human that has been unfortunately blocked. This option will NOT use the Project Honey Pot database or deny you access to any of the WordPress Administration pages.</small></p>
	<h4>Main options</h4>
		<p>http:BL Access Key <input type='text' name='key' value='<?php echo $key ?>' /> </p>
		<p><small>An Access Key is required to perform a http:BL query. You can get your key at <a href="http://www.projecthoneypot.org/httpbl_configure.php">http:BL Access Management page</a>. You need to register a free account at the Project Honey Pot website to get one.</small></p>
		<p>Age threshold <input type='text' name='age_thres' value='<?php echo $age_thres ?>'/></p>
		<p><small>http:BL service provides you information about the date of the last activity of a checked IP. Due to the fact that the information in the Project Honey Pot database may be obsolete, you may set an age threshold, counted in days. If the verified IP hasn't been active for a period of time longer than the threshold it will be regarded as harmless.</small></p>
		<p>General threat score threshold <input type='text' name='threat_thres' value='<?php echo $threat_thres ?>'/></p>
		<p><small>Each suspicious IP address is given a threat score. This scored is asigned by Project Honey Pot basing on various factors, such as the IP's activity or the damage done during the visits. The score is a number between 0 and 255, where 0 is no threat at all and 255 is extremely harmful. In the field above you may set the threat score threshold. IP address with a score greater than the given number will be regarded as harmful.</small></p>
		<p><ul>
		<li>Suspicious threat score threshold <input type='text' name='threat_thres_s' value='<?php echo $threat_thres_s ?>'/></li>
		<li>Harvester threat score threshold <input type='text' name='threat_thres_h' value='<?php echo $threat_thres_h ?>'/></li>
		<li>Comment spammer threat score threshold <input type='text' name='threat_thres_c' value='<?php echo $threat_thres_c ?>'/></li>
		</ul></p>
		<p><small>These values override the general threat score threshold. Leave blank to use the general threat score threshold.</small></p>
		<fieldset>
		<label>Types of visitors to be treated as malicious</label>
		<p><input type='checkbox' name='deny_1' value='1' <?php echo $deny_checkbox[1] ?>/> Suspicious</p>
		<p><input type='checkbox' name='deny_2' value='1' <?php echo $deny_checkbox[2] ?>/> Harvesters</p>
		<p><input type='checkbox' name='deny_4' value='1' <?php echo $deny_checkbox[4] ?>/> Comment spammers</p>
		</fieldset>
		<p><small>The field above allows you to specify which types of visitors should be regarded as harmful. It is recommended to tick all of them.</small></p>
		<p>Honey Pot <input type='text' name='hp' value='<?php echo $hp ?>'/></p>
		<p><small>If you've got a Honey Pot or a Quick Link you may redirect all unwelcome visitors to it. If you leave the following field empty all harmful visitors will be given a blank page instead of your blog.</small></p>
		<p><small>More details are available at the <a href="http://www.projecthoneypot.org/httpbl_api.php">http:BL API Specification page</a>.</small></p>
	<h4>Logging options</h4>
		<p>Enable logging <input type='checkbox' name='enable_log' value='1' <?php echo $log_checkbox ?>/></p>
		<p><small>If you enable logging all visitors which are recorded in the Project Honey Pot's database will be logged in the database and listed in the table below. Remember to create a proper table in the database before you enable this option!</small></p>
		<p>Log only blocked visitors <input type='checkbox' name='log_blocked_only' value='1' <?php echo $log_blocked_only_checkbox ?>/></p>
		<p><small>Enabling this option will result in logging only blocked visitors. The rest shall be forgotten.</small></p>
		<p>Not logged IP addresses <input type='text' name='not_logged_ips' value='<?php echo $not_logged_ips ?>'/></p>
		<p><small>Enter a space-separated list of IP addresses which will not be recorded in the log.</small></p>
	<h4>Statistics options</h4>
		<p>Enable stats <input type='checkbox' name='enable_stats' value='1' <?php echo $stats_checkbox ?>/></p>
		<p><small>If stats are enabled the plugin will get information about its performance from the database, allowing it to be displayed using <code>httpbl_stats()</code> function.</small></p>
		<p>Output pattern <input type='text' name='stats_pattern' value='<?php echo $stats_pattern ?>'/></p>
		<p><small>This input field allows you to specify the output format of the statistics. You can use following variables: <code>$block</code> will be replaced with the number of blocked visitors, <code>$pass</code> with the number of logged but not blocked visitors, and <code>$total</code> with the total number of entries in the log table. HTML is welcome. PHP won't be compiled.</small></p>
		<fieldset>
		<label>Output link</label>
		<p><input type="radio" name="stats_link" value="0" <?php echo $stats_link_radio[0]; ?>/> Disabled</p>
		<p><input type="radio" name="stats_link" value="1" <?php echo $stats_link_radio[1]; ?>/> <a href="http://www.projecthoneypot.org/?rf=28499">Project Honey Pot</a></p>
		<p><input type="radio" name="stats_link" value="2" <?php echo $stats_link_radio[2]; ?>/> <a href="http://wordpress.org/extend/plugins/httpbl/">http:BL WordPress Plugin</a></p>
		</fieldset>
		<p><small>Should we enclose the output specified in the field above with a hyperlink?</small></p>
	<div style="float:right"><a href="http://www.projecthoneypot.org/?rf=28499"><img src="<?php echo get_option("siteurl") . "/wp-content/plugins/httpbl/";?>project_honey_pot_button.png" height="31px" width="88px" border="0" alt="Stop Spam Harvesters, Join Project Honey Pot"></a></div>
		<p><input type='submit' name='httpbl_save' value='Save Settings' /></p>
	</form>
<?php
	if (get_site_option("httpbl_log")) {
?>
	<hr/>
	<a name="log"></a>
	<h3>Log</h3>
	<form action='' method='post' name='httpbl_log'><p>
<?php
	// Does a log table exist?
	$httpbl_table_exists = httpbl_check_log_table();
	// If it exists display a log purging form and output log
	// in a nice XHTML table.
	if ($httpbl_table_exists === true) {
?>
	<script language="JavaScript"><!--
	var response;
	// Delete or purge confirmation.
	function httpblConfirm(action) {
		response = confirm("Do you really want to "+action+
			" the log table ?");
		return response;
	}
	//--></script>
	<input type='submit' name='httpbl_truncate' value='Purge the log table' onClick='return httpblConfirm("purge")'/>
	<input type='submit' name='httpbl_drop' value='Delete the log table' style="margin:0 0 0 30px" onClick='return httpblConfirm("delete")'/>
	</p></form>
	<p>A list of 50 most recent visitors listed in the Project Honey Pot's database.</p>
	<table cellpadding="5px" cellspacing="3px">
	<tr>
		<th>ID</th>
		<th>IP</th>
		<th>Date</th>
		<th>User agent</th>
		<th>Last seen<sup>1</sup></th>
		<th>Threat</th>
		<th>Type<sup>2</sup></th>
		<th>Blocked</th>
	</tr>
<?php
	// Table with logs.
	// Get data from the database.
	$results = httpbl_get_log();
	$i = 0;
	$threat_type = array( "", "S", "H", "S/H", "C", "S/C", "H/C", "S/H/C");
	foreach ($results as $row) {
		// Odd and even rows look differently.
		$style = ($i++ % 2 ? " class='alternate'" : "" );
		echo "\n\t<tr$style>";
		foreach ($row as $key => $val) {
			if ($key == "ip")
				// IP address lookup in the Project Honey Pot database.
				$val = "<a href='http://www.projecthoneypot.org/ip_" . $val .
					"' target='_blank'>" . $val . "</a>";
			if ($key == "user_agent")
				// In case the user agent string contains
				// unwelcome characters.
				$val = htmlentities($val, ENT_QUOTES);
			if ($key == "blocked")
				$val = ($val ? "<strong>YES</strong>" : "No");
			if ($key == "httpbl_response") {
				// Make the http:BL response human-readible.
				$octets = explode( ".", $val);
				$plural = ( $octets[1] == 1 ? "" : "s");
				$lastseen = $octets[1]." day$plural";
				$td = "\n\t\t<td><small>$lastseen</small></td>".
					"\n\t\t<td><small>".$octets[2].
					"</small></td>\n\t\t<td><small>".
					$threat_type[$octets[3]].
					"</small></td>";
			} else {
				// If it's not an http:BL response it's
				// displayed in one column.
				$td = "\n\t\t<td><small>$val</small></td>";
			}
			echo $td;
		}
		echo "\n\t</tr>";
	}
?>
	</table>
	<p><small><sup>1</sup> Counting from the day of visit.</small></p>
	<p><small><sup>2</sup> S - suspicious, H - harvester, C - comment spammer.</small></p>
<?php
	} else if ($httpbl_table_exists === false) {
?>
	It seems that you haven't got a log table yet. Maybe you'd like to <input type='submit' name='httpbl_create' value='create it' /> ?
	</p></form>
<?php
	}

	// End of if (get_option("httpbl_log"))
	}
?>
</div>
<?php
	}	
?>
