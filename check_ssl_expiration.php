#!/usr/bin/php
<?php
// Check SSL Certificates PLUGIN
//
// Copyright (c) 2016 Matthew Capra, Nagios Enterprises <mcapra@nagios.com>
//  
// $Id: $mcapra@nagios.com

define("PROGRAM", 'check_ssl_expiration.php');
define("VERSION", '1.0.0');
define("STATUS_OK", 0);
define("STATUS_WARNING", 1);
define("STATUS_CRITICAL", 2);
define("STATUS_UNKNOWN", 3);
define("DEBUG", false);


function parse_args() {
    $specs = array(array('short' => 'h',
                         'long' => 'help',
                         'required' => false),
                   array('short' => 'a',
                         'long' => 'address', 
                         'required' => true),
				   array('short' => 't',
                         'long' => 'timeout', 
                         'required' => false),
                   array('short' => 'w', 
                         'long' => 'warning', 
                         'required' => false),
                   array('short' => 'c', 
                         'long' => 'critical', 
                         'required' => false)
    );
    
    $options = parse_specs($specs);
    return $options;
}

function parse_specs($specs) {

    $shortopts = '';
    $longopts = array();
    $opts = array();

    foreach($specs as $spec) {    
        if(!empty($spec['short'])) {
            $shortopts .= "{$spec['short']}:";
        }
        if(!empty($spec['long'])) {
            $longopts[] = "{$spec['long']}:";
        }
    }

    $parsed = getopt($shortopts, $longopts);

    foreach($specs as $spec) {
        $l = $spec['long'];
        $s = $spec['short'];

        if(array_key_exists($l, $parsed) && array_key_exists($s, $parsed)) {
            plugin_error("Command line parsing error: Inconsistent use of flag: ".$spec['long']);
        }
        if(array_key_exists($l, $parsed)) {
            $opts[$l] = $parsed[$l];
        }
        elseif(array_key_exists($s, $parsed)) {
            $opts[$l] = $parsed[$s];
        }
        elseif($spec['required'] == true) {
            plugin_error("Command line parsing error: Required variable ".$spec['long']." not present.");
        }
    }
    return $opts;

}

function debug_logging($message) {
    if(DEBUG) {
        echo $message;
    }
}

function plugin_error($error_message) {
    print("***ERROR***:\n\n{$error_message}\n\n");
    fullusage();
    nagios_exit('', STATUS_UNKNOWN);
}

function nagios_exit($stdout='', $exitcode=0) {
    print($stdout);
    exit($exitcode);
}

function main() {
    $options = parse_args();
    
	
    if(array_key_exists('version', $options)) {
        print('Plugin version: '.VERSION);
        fullusage();
        nagios_exit('', STATUS_OK);
    }

    check_environment();
    check_expiration($options);
}

function check_environment() {
    exec('which nmap 2>&1', $execout, $return_var);
    $whois_path = $execout[0];

    if ($return_var != 0) {
        plugin_error("nmap is not installed in your system.");
    }
}

function check_expiration($options) {
    $execout = "";
	$hosts = array();
	$warning = '';
	$critical = '';
	$count = 0;
	$address = escapeshellarg($options['address']);

	if(strpos($options['address'], '/')) {
		$hosts = ipListFromRange($options['address']);
	}
	else if (strpos($options['address'], ',')) {
		$exp = explode(',',$options['address']);
		foreach($exp as $e) {
			array_push($hosts, $e);
		}
	}
	else array_push($hosts, $options['address']);
	
	if(sizeof($hosts) == 0) {
		nagios_exit('No hosts found!: '.implode('\n', $execout), STATUS_UNKNOWN);
	}
	
	$timeWarning = 86400 * ((!empty($options['warning'])) ? $options['warning'] : 30);
	$timeCritical = 86400 * ((!empty($options['critical'])) ? $options['critical'] : 15);
	$timeout = ((!empty($options['timeout'])) ? $options['timeout'] : 5);
	

	
	if(is_array($hosts))
	{
		foreach($hosts as $host) {
			error_reporting(0);
			$g = stream_context_create (array("ssl" => array("capture_peer_cert" => true)));
			$r = stream_socket_client("ssl://" . $host . ":443", $errno, $errstr, $timeout,
				STREAM_CLIENT_CONNECT, $g);
			$cont = stream_context_get_params($r);
			$rawCert = $cont["options"]["ssl"]["peer_certificate"];

			$data = openssl_x509_parse($rawCert);

			$validFrom = date('Y-m-d H:i:s', $data['validFrom_time_t']);
			$validTo = date('Y-m-d H:i:s', $data['validTo_time_t']);
			
			//check > 0, if not > 0 there's no cert to check or it's malformed
			if($data['validTo_time_t'] > 0) {
				if(($data['validTo_time_t'] < (time() + $timeCritical)) && (!empty($options['critical'])))
					$critical .= $host . ' -- ' . $data['subject']['CN'] . ' -- ' .$validTo . PHP_EOL;
				else if (($data['validTo_time_t'] < (time() + $timeWarning)) && (!empty($options['warning'])))
					$warning .= $host . ' -- ' . $data['subject']['CN'] . ' -- ' . $validTo . PHP_EOL;
				$count++;
			}
		}
	}
	
	
	if($count > 0) {
		if(($warning == '') && ($critical == '')) {
			nagios_exit("OK - " . $count . " Certificate(s) on " . $options['address'] . " look ok!" . PHP_EOL, STATUS_OK);
		}
		else if ($warning == ''){ 
			nagios_exit("CRITICAL - EXPIRATIONS" . PHP_EOL . $critical, STATUS_CRITICAL);
		}
		else {
			nagios_exit("WARNING - EXPIRATIONS" . PHP_EOL . $warning, STATUS_WARNING);
		}
	}
	else {
			nagios_exit("UNKNOWN - Couldn't find any certificates on " . $options['address'] . PHP_EOL, STATUS_UNKNOWN);
	}
	
	
	
}

function ipListFromRange($range){
	if(strpos($range, '/')) {
		$parts = explode('/',$range);
		$exponent = 32-$parts[1].'-';
		$count = pow(2,$exponent);
		$start = ip2long($parts[0]);
		$end = $start+$count;
		return array_map('long2ip', range($start, $end) );
	}
    return $range;
}



function fullusage() {
print(
	"check_ssl_expiration.php - v".VERSION."
        Copyright (c) 2016 Matthew Capra, Nagios Enterprises <mcapra@nagios.com>
	Under GPL v2 License

	This plugin checks the expiration date of an SSL certificate on a remote host (or group of hosts)

	Usage: ".PROGRAM." -h | -a <address> [-c <critical>] [-w <warning>]
	NOTE: -a must be specified

	Options:
	-h
	     Print this help and usage message
	-a
	     The address (or block) we wish to check
	-t
	     The timeout for our checks (seconds), default is 5. If you're scanning an awful lot of IPs, try setting this to 1 or lower. 
	-w
	     Expiration time warning status (days), default 30
	-c
	     Expiration time critical status (days), default 15

	This plugin will use openssl to check a target certificate's expiration date.
	Example:
	     $./".PROGRAM." -a 172.217.4.96 -w 90
	     $./".PROGRAM." -a 172.217.4.96/27 -t 2 -w 90 -c 30 \n\n
	     $./".PROGRAM." -a 172.217.4.96,172.217.4.97,172.217.4.124 -t 2 -w 90 -c 30 \n\n"
    );
}

main();
?>
