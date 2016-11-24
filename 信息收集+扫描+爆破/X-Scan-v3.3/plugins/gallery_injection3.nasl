#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(12030);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-2004-2124");
 script_bugtraq_id(9490);
 script_xref(name:"OSVDB", value:"3737");
 script_xref(name:"Secunia", value:"10712");

 script_name(english:"Gallery HTTP Global Variables File Inclusion");
 script_summary(english:"Checks for the presence of init.php");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a PHP application that is affected by
a remote file inclusion vulnerability." );
 script_set_attribute(attribute:"description", value:
"It is possible to make the remote host include php files hosted
on a third party server using Gallery.

An attacker may use this flaw to inject arbitrary code in the remote
host and gain a shell with the privileges of the web server." );
 script_set_attribute(attribute:"see_also", value:"http://gallery.menalto.com/node/107" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Gallery 1.4.1 pl1 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N" );

 script_end_attributes();
 
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

include("http.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_http_port(default:80, embedded: 0);
if( ! can_host_php(port:port) ) exit(0);

function check(url)
{
  local_var req;

  req = http_send_recv3(method:"GET", item:string(url,"/init.php?HTTP_PST_VARS[GALLERY_BASEDIR]=http://xxxxxxxx./"), port:port);
  if (isnull(req)) exit(0);
  if("http://xxxxxxxx./Version.php" >< req[2])
  {
    security_warning(port);
    exit(0);
  }
}

foreach dir (cgi_dirs()) check(url:dir);
