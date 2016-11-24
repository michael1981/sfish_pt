#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
  script_id(12025);
  script_version("$Revision: 1.8 $");
  script_bugtraq_id(9445);
  script_xref(name:"OSVDB", value:"3616");

  script_name(english:"Mambo mod_mainmenu.php mosConfig_absolute_path Parameter Remote File Inclusion");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
remote file include vulnerability." );
 script_set_attribute(attribute:"description", value:
"There is a flaw in the installed version of Mambo Open Source that may
allow an attacker to execute arbitrary remote PHP code on this host
because it fails to sanitize input to the 'mosConfig_absolute_path' of
'modules/mod_mainmenu.php' before using it to include PHP code from
another file. 

Note that, for exploitation of this issue to be successful, PHP's
'register_globals' setting must be enabled." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2004-01/0141.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?472f1d6d" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Mambo Open Source 4.5 Stable (1.0.2) or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  script_summary(english:"Detect mambo code injection vuln");
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");

  script_family(english:"CGI abuses");
  script_dependencies("mambo_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if (! get_port_state(port) ) exit(0);
if (! can_host_php(port:port) ) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/mambo_mos"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 dir = matches[2];

 req = http_get(item:string(dir, "/modules/mod_mainmenu.php?mosConfig_absolute_path=http://xxxxxxx"), port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if ( res == NULL ) exit(0);

 if ("http://xxxxxxx/modules" >< res ) security_warning(port);
}
