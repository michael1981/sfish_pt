#
# written by Jon Passki - Shavlik Technologies, LLC <jon.passki@shavlik.com>
# This script is (C) Shavlik Technologies, LLC
# BIG-IP(R) is a registered trademark of F5 Networks, Inc.
# F5 BIG-IP Cookie Persistence Decoder
#

include("compat.inc");

if(description)
{
 script_id(20089);
 script_version ("$Revision: 1.11 $");
 script_name(english: "F5 BIG-IP Cookie Information Disclosure");

 script_set_attribute(attribute:"synopsis", value:
"The remote load balancer suffers from an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be a F5 BigIP load balancer which encodes
within a cookie the IP address of the actual web server it is acting
on behalf of.  Additionally, information after 'BIGipServer' is
configured by the user and may be the logical name of the device. 
These values may disclose sensitive information, such as internal IP
addresses and names." );
 script_set_attribute(attribute:"solution", value:
"Contact the vendor for a fix." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
 script_end_attributes();

 script_summary(english: "Check F5 BIG-IP(R) Cookie for information disclosure");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Shavlik Technologies, LLC");
 script_family(english: "Web Servers");
 script_require_ports("Services/www", 80);
 script_dependencie("http_version.nasl");
 exit(0);
}


include("global_settings.inc");
include("http_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port)) exit(0);


ips = NULL;
# Number of HTTP connections.
# - gets reset if a new cookie is found.
retries = 5;
# - max number of retries (does not get reset).
max_retries = 10;
flag = 0;

while(retries-- && max_retries--) {
  # Get a cookie.
  soc = http_open_socket(port);
  if ( ! soc && flag == 0 ) exit(0);
  else if( ! soc )  {
	report_error = 1;
	break;
    }
  flag ++;
 
  req = http_get(item:"/", port:port); 	 
  send(socket:soc, data:req); 	 
  http_headers = http_recv_headers2(socket:soc); 	 
  http_close_socket(soc);

  # If this cookie is replayed in subsequent requests,
  # the load balancer will have an affinity with the back end.
  # This might be a good knowledge base entry.
  enc_ip = enc_port = NULL;
  pat = "^Set-Cookie:.*(BIGipServer([^=]+)=([0-9]+)\.([0-9]+)\.[0-9]+)";
  matches = egrep(pattern:pat, string:http_headers);
  if (matches) {
    foreach match (split(matches)) {
      match = chomp(match);
      cookie = eregmatch(pattern:pat, string:match);
      if (!isnull(cookie)) {
        this_cookie = cookie[1];
        cookie_jar[this_cookie]++;
        debug_print("cookie: ", this_cookie, ".");
        enc_ip = cookie[3];
        enc_port = cookie[4];
        break;
      }
    }
  }
  if (isnull(enc_ip) || isnull(enc_port)) {
    report_error = 2;
    break;
  }

  # If the cookie is new....
  if (isnull(ips[this_cookie]) || isnull(ips[this_cookie])) {
    # Decode the cookie.
    #
    # nb: IP "a.b.c.d" is encoded as "d*256^3 + c*256^2 + b*256 + a".
    dec_ip = string(
      ( enc_ip & 0x000000ff)      , ".",
      ((enc_ip & 0x0000ffff) >> 8), ".",
      ((enc_ip & 0x00ffffff) >> 16), ".",
      (enc_ip >> 24)
    );
    debug_print("ip: ", enc_ip, " -> ", dec_ip, ".");

    # nb: port is merely byte-swapped.
    dec_port = (enc_port & 0x00ff) * 256 + (enc_port >> 8);
    debug_print("port: ", enc_port, " -> ", dec_port, ".");

    # Stash them for later.
    ips[this_cookie] = dec_ip;
    ports[this_cookie] = dec_port;

    # Keep trying to enumerate backend hosts.
    retries = 3;
  }
}


# Generate a report if we got at least one cookie.
if (this_cookie) {
  if(report_error == 1) 
    report = "
The script failed in making a socket connection to the target system
after a previous connection worked.  This may affect the completeness
of the report and you might wish to rerun this test again on the
targeted system. 
";

  if(report_error == 2)
    report = "
The script failed in finding a BIG-IP cookie on the target system
after a previous cookie was found.  This may affect the completeness
of the report and you might wish to rerun this test again on the
targeted system. 
";

  report = report + "
The first column is the original cookie, the second the IP address and
the third the TCP port:
";

  foreach cookie (keys(cookie_jar)) {
    report = string(
      report, "\n",
      "  ", cookie, "\t", ips[cookie], "\t", ports[cookie]
    );
  }

  security_warning(port:port, extra:report);
}
