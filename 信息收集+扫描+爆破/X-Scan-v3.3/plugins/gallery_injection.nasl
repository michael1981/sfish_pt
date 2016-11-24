#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security 
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CVE
#
# This check covers CVE-2001-1234, but a similar flaw (with a different
# CVE) was found later on.
#
# Ref: http://gallery.menalto.com/modules.php?op=modload&name=News&file=article&sid=50


include("compat.inc");

if(description)
{
 script_id(11115);
 script_bugtraq_id(3397);
 script_version ("$Revision: 1.20 $");
 script_cve_id("CVE-2001-1234");
 script_xref(name:"OSVDB", value:"1967");

 script_name(english:"Bharat Mediratta Gallery includedir Parameter Remote File Inclusion");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a remote
file include vulnerability." );
 script_set_attribute(attribute:"description", value:
"It is possible to make the remote host include php files hosted on a
third-party server using Gallery. 

An attacker may use this flaw to inject arbitrary code in the remote
host and gain a shell with the privileges of the web server." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2001-10/0012.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Gallery 1.2.1 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
 summary["english"] = "Checks for the presence of includes/needinit.php";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if( ! can_host_php(port:port) ) exit(0);
if(http_is_dead(port:port))exit(0);

function check(url)
{
  local_var r, w;
  w = http_send_recv3(item:string(url, "/errors/needinit.php?GALLERY_BASEDIR=http://xxxxxxxx/"),
    method: "GET", port:port);
  if (isnull(w)) exit(1, "the web server did not answer");
  r = strcat(w[0], w[1], '\r\n', w[2]);
 if("http://xxxxxxxx/errors/configure_instructions" >< r)
 	{
 	security_hole(port);
	exit(0);
	}
 
}

check(url:"");
foreach dir (cgi_dirs())
{
 check(url:dir);
}
