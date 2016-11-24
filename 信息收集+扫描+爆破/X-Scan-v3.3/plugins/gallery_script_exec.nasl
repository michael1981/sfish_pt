#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(14338);
 script_cve_id("CVE-2004-1466");
 script_bugtraq_id(10968);
 script_xref(name:"OSVDB", value:"9019");
 script_version ("$Revision: 1.10 $");

 script_name(english:"Gallery save_photos.php Arbitrary Command Execution");
 script_summary(english:"Checks for the version of Gallery");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a PHP application that is affected by
a remote command execution vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the Gallery web-based photo album.

There is a flaw in the remote version of this software which may
allow an attacker to execute arbitrary commands on the remote host.

To exploit this flaw, an attacker would require the privileges to
upload files to a remote photo album." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2004-08/0757.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2004-08/0920.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Gallery 1.4.4-pl2 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
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
if(!can_host_php(port:port)) exit(0);

function check(url)
{
  local_var req;
  req = http_send_recv3(method:"GET", item:string(url, "/index.php"),port:port);
  if (isnull(req)) exit(0);
 
  if ( egrep(pattern:".*Powered by.*Gallery.*v(0\.|1\.([0-3]\.|4\.([0-3][^0-9]|4 |4-pl[01]([^0-9]|$))))", string:req[2]) )
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
