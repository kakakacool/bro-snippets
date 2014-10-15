##! Servers utilizing old versions of SSL (2+3) can
##! be vulnerable to a number problems where an 
##! attacker might be able to man-in-the-middle clients
##! or infer data out of the encrypted connection.
##! Our stance is that it's best to know when SSL
##! (non-TLS) is being used on your network and to work
##! to disable it on your servers to prevent attacks
##! against clients using your services.
##!
##! This script watches for local servers speaking in 
##! SSLv2 or SSLv3 and does a notice.
##! 
##! Author: Seth Hall <seth@broala.com>
##! Copyright 2014, Broala.
##!
##! Changes: 
##!   Initial version - Wed Oct 15 12:45:55 EDT 2014

module Broala;

export {
	redef enum Notice::Type += {
		## Indicates that a server offering an 
		## old version of SSL was discovered.
		## This works to detect servers vulnerable
		## to Poodle, but is generally useful to 
		## anything that is using old SSL which 
		## shouldn't be used anymore.
		Old_SSL_Server
	};
}

event ssl_server_hello(c: connection, version: count, possible_ts: time, server_random: string, session_id: string, cipher: count, comp_method: count)
	{
	if ( Site::is_local_addr(c$id$resp_h) &&
	     (version == SSL::SSLv2 || version == SSL::SSLv3) )
		{
		NOTICE([$note=Old_SSL_Server,
		        $msg=fmt("A local server is speaking %s", SSL::version_strings[version]),
		        $sub="Servers speaking SSL (pre-TLS) can be vulnerable to several attacks.  One such attack is Poodle.  http://googleonlinesecurity.blogspot.com/2014/10/this-poodle-bites-exploiting-ssl-30.html",
		        $conn=c,
		        $suppress_for=1day,
		        $identifier=cat(c$id$resp_h, c$id$resp_p)]);
		}
	}