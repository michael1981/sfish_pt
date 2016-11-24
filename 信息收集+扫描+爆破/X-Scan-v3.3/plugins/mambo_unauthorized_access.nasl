#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if(description)
{
 script_id(16312);
 script_version("$Revision: 1.7 $");

 script_bugtraq_id(12436);
 
 name["english"] = "Mambo Global Variables Unauthorized Access";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that allows
unauthorized access to the affected web site." );
 script_set_attribute(attribute:"description", value:
"The remote version of Mambo Open Source contains a vulnerability which
may allow a remote attacker to gain unauthorized access to the system. 
This arises due to improper implementation of global variables and not
sanitizing user-supplied input." );
 script_set_attribute(attribute:"see_also", value:"http://forum.mamboserver.com/showthread.php?t=29960" );
 script_set_attribute(attribute:"see_also", value:"http://www.mamboportal.com/content/view/2008/2/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to patched version 4.5.1b." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
 summary["english"] = "Checks for index.php malformed request vulnerability";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);

 script_dependencies("mambo_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);

 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/mambo_mos"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 dir = matches[2];

 req = http_get(item:string(dir, "/index.php?GLOBALS[mosConfig_absolute_path]=http://xxx."), port:port);
 r = http_keepalive_send_recv(port:port, data: req, bodyonly:1);
 if( r == NULL )exit(0);
 if( "http://xxx./includes/HTML_toolbar.php" >< r )
 	security_hole(port);
}
