#
# (C) Tenable Network Security, Inc.
#

# Ref:
# Date: Thu, 13 Mar 2003 11:48:17 -0500
# From: "@stake Advisories" <advisories@atstake.com>
# To: bugtraq@securityfocus.com
# Subject: Sun ONE (iPlanet) Application Server Connector Module Overflow


include("compat.inc");

if(description)
{
 script_id(11403);
 script_version ("$Revision: 1.10 $");
 script_cve_id("CVE-2002-0387");
 script_bugtraq_id(7082);
 
 script_name(english:"iPlanet Application Server Prefix Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote application server is affected by a buffer overflow 
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote Sun ONE Application Server (formerly known as iPlanet 
Application Server) is vulnerable to a buffer overflow when a user
provides a long buffer after the application service prefix, as in

	GET /[AppServerPrefix]/[long buffer]
	
An attacker may use this flaw to execute arbitrary code on this
host or disable it remotely." );
 script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/pub-cgi/retrieve.pl?doc=fsalert/52022" );
 script_set_attribute(attribute:"solution", value:
"If you are running Application Server 6.5, apply SP1." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 script_summary(english:"Determines if Sun ONE AS SP1 is applied");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "iplanet_app_server_detection.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

d = get_kb_item(string("www/", port, "/SunOneApplicationServer/prefix"));
if( d == NULL ) d = "/NASApp";


res = http_send_recv3(method:"GET", item:string(d,"/nessus/"), port:port);
if (isnull(res)) exit(1, "The remote web server did not respond.");

#
# Post-SP1 replies with a "200 OK" error code, followed by
# an error saying 'GX Error (GX2GX) (blah blah)'
#
if(("ERROR: Unknown Type of Request" >< res[2]))
{
 security_hole(port);
 exit(0);
}

