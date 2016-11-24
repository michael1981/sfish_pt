#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10654);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-2001-0419");
 script_bugtraq_id(2569);
 script_xref(name:"OSVDB", value:"10885");

 script_name(english:"Oracle Application Server ndwfn4.so HTTP Request Remote Overflow");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote server." );
 script_set_attribute(attribute:"description", value:
"It may be possible to make a web server execute arbitrary code by 
sending it a too long url starting with /jsp/
For example:
	GET /jsp/AAAA.....AAAAA" );
 script_set_attribute(attribute:"solution", value:
"Contact your vendor for the latest software release." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 script_summary(english: "Web server buffer overflow");
 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
 script_family(english: "Databases");
 script_dependencie("http_version.nasl", "www_too_long_url.nasl");
 script_exclude_keys("www/too_long_url_crash");
 script_require_ports("Services/www",80);
 script_require_keys("Settings/ParanoidReport");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) exit(0);

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(http_is_dead(port:port))exit(0);

r = http_send_recv3(port: port, method: 'GET', item: strcat("/jsp/", crap(2500)));
if (http_is_dead(port: port, retry: 3))
  security_hole(port);
