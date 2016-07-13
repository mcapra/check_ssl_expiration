# check_ssl_expiration
This Nagios plugin can be used to check SSL certificate expiration for a given IP address or range of IP addresses. 

        Usage: check_ssl_expiration.php -h | -a <address> [-c <critical>] [-w <warning>]
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
             $./check_ssl_expiration.php -a 172.217.4.96 -w 90
             $./check_ssl_expiration.php -a 172.217.4.96/27 -t 2 -w 90 -c 30
             $./check_ssl_expiration.php -a 172.217.4.96,172.217.4.97,172.217.4.124 -t 2 -w 90 -c 30
		 
#-v1.0.0
- Initial release
