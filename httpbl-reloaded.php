<?php
/*
Plugin Name: http:BL Reloaded WordPress Plugin
Plugin URI: http://wordpress.org/extend/plugins/httpbl-reloaded/
Description: http:BL WordPress Plugin allows you to verify IP addresses of clients connecting to your blog against the <a href="http://www.projecthoneypot.org/?rf=28499">Project Honey Pot</a> database. 
Author: deadpan110
Version: 0.1.beta1
Author URI: http://ind-web.com/
License: This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.
Credits: Based on the original http:BL plugin by Jan Stępień ( http://stepien.cc/~jan ) and others.
*/


class httpBLreloaded {
	var $version;
	var $options = array();
	
	function __construct() {
		//load_plugin_textdomain( 'httpBLreloaded', basename( dirname( __FILE__ ) )  . 'languages', basename( dirname( __FILE__ ) ) . '/languages' );
		
		global $wpdb;
		$wpdb->httpblr_log = $wpdb->base_prefix . 'httpblr_log';
		
		$this->version = (get_file_data( __FILE__, array('Version' => 'Version'), 'plugin' ));
		$this->version = $this->version['Version'];
		
		$this->get_options();
		if ($this->options['version'] != $this->version) {
			// Install/Upgrade functions
			include_once(dirname(__FILE__) . '/upgrade-functions.php');
		}
		
		
		add_action('init', array($this,'check_visitor'),1);
		add_action('init', array($this,'init'));
		add_action('wp_footer', array($this,'echo_honeypot_html'));
		add_action('admin_menu', array($this,'add_admin_pages'));
		add_action('wp_dashboard_setup', array($this,'add_dashboard_widget'));
		
	}
	
	function add_dashboard_widget() {
		// only administrators can see this
		if (!current_user_can('administrator')) return;
		wp_add_dashboard_widget('httpblr_dashboard_widget', 'http:BL Reloaded (version ' . $this->version . ')', array($this,'dashboard_widget_function'));
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
		echo "<p>The <strong>http:BL Reloaded</strong> plugin by <strong>IND-Web.com</strong> is still under development. More features are coming soon.</p>";
		//echo "<h5>Planned Features</h5>";
		//echo "<ul>";
		//echo "<li>Optionally disable this on your site.</li>";
		//echo "<li>View a list of IP addresses that were blocked on your site.</li>";
		//echo "<li>View a log of all IP addresses that have been blocked across the <strong>IND-Web.com</strong> network.</li>";
		//echo "<li>...and much more</li>";
		//echo "</ul>";
		//echo "<h5>Notes</h5>";
		//echo "<p>We are currently blocking IP addresses obtained from the Project Honey Pot database that are known comment spammers, harvesters and just plain suspicious that score 30 or more and have been active within the last 14 days (see the <a href='http://www.projecthoneypot.org/threat_info.php'>Project Honey Pot Threat Rating</a> for how this is calculated). If you have any concerns, please email <a href='mailto:support@ind-web.com'>IND-Web.com support</a>.</p>";
		
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
			'version' => false,
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
		
		// store our version
		$version = $this->options['version'];
		// delete all options
		delete_site_option('httpbl_reloaded_options');
		// save version
		add_site_option('httpbl_reloaded_options',array('version' => $version));
		// reload defaults
		$this->get_options();
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

				
				// Log the details
				$this->add_log_entry($_SERVER["REMOTE_ADDR"],$_SERVER["HTTP_USER_AGENT"],implode($result, "."),true);
				
				$this->blacklist_die();

			}

			// Log the details if the threat score is greater or equal to 1 but has not been blocked
			if ($result[2] >= 1)
				$this->add_log_entry($_SERVER["REMOTE_ADDR"],$_SERVER["HTTP_USER_AGENT"],implode($result, "."),false);

			return;


	}
	
	function add_log_entry($ip, $user_agent, $response, $blocked = false){
		global $wpdb, $blog_id;
		
		
		$time = gmdate("Y-m-d H:i:s", time() + get_site_option('gmt_offset') * 60 * 60 );
		$user_agent = mysql_real_escape_string($user_agent);
		
		$sql = "SELECT COUNT(*) FROM {$wpdb->httpblr_log} where blog_id = '{$blog_id}' AND ip = '{$ip}';";
		
		if (!$wpdb->get_var($sql)) {
			
			$wpdb->insert($wpdb->httpblr_log,array(
				'blog_id' => $blog_id,
				'ip' => $ip,
				'time' => $time,
				'user_agent' => $user_agent,
				'httpbl_response' => $response,
				'blocked' => $blocked,
				));
				
				//$wpdb->print_error();
		}
		return;

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

		$output .= '<p><input class="button-primary" type="submit" name="httpblr_save" value="' . __('Save Settings','httpBLreloaded') . '" /> <input class="button" type="submit" name="httpblr_reset" value="' . __('Reset Defaults','httpBLreloaded') . '" /></p>';
		
		$output .= '</form>';

		echo $output;


	}
		
	
}
new httpBLreloaded();

return;
