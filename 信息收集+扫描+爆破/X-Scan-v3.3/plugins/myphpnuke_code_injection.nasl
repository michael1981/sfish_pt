#
# (C) Tenable Network Security, Inc.
#

#
# Ref:
# From: "Frog Man" <leseulfrog@hotmail.com>
# To: bugtraq@securityfocus.com, vulnwatch@vulnwatch.org
# Subject: myPHPNuke : Copy/Upload/Include Files
# Date: Thu, 11 Sep 2003 12:14:09 +0200



include("compat.inc");

if(description)
{
 script_id(11836);
 script_version ("$Revision: 1.10 $");
 script_cve_id("CVE-2006-6795");
 script_xref(name:"OSVDB", value:"36894");

 script_name(english:"myPHPNuke My_eGallery gallery/displayCategory.php basepath Variable Remote File Inclusion");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a PHP application that is affected
by a remote file include vulnerability.." );
 script_set_attribute(attribute:"description", value:
"The remote web server appears to be running myPHPNuke. The installed
version is affected by a remote file include vulnerability in the
'gallery/displayCategory.php' script. An  attacker may use this flaw
to inject arbitrary code in the remote host and gain a shell with the
privileges of the web server." );
 script_set_attribute(attribute:"see_also", value:"http://www.cyber-security.org.tr/DataDetayAll.asp" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 script_summary(english:"Checks for the presence of displayCategory.php");
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
include("global_settings.inc");
include("misc_func.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);



function check(loc)
{
  local_var res;

  res = http_send_recv3(method:"GET", item:string(loc, "/gallery/displayCategory.php?basepath=http://xxxxxxxx"), port:port);
  if (isnull(res)) exit(1, "The remote web server did not respond.");

  if(egrep(pattern:".*http://xxxxxxxx/imageFunctions\.php", string:res[2]))
  {
    security_hole(port);
    exit(0);
  }
}



foreach dir (cgi_dirs())
{
 check(loc:dir);
}
