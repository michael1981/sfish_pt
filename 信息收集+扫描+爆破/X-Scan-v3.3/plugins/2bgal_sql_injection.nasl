#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(16046);
 script_cve_id("CVE-2004-1415");
 script_bugtraq_id(12083);
 script_xref(name:"OSVDB", value:"12565");
 script_version("$Revision: 1.8 $");
 
 script_name(english:"2BGal disp_album.php id_album Parameter SQL Injection");
 script_summary(english:"SQL Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is susceptible
to a SQL injection attack." );

 script_set_attribute(attribute:"description", value:
"The remote host appears to be running 2BGal, a photo gallery
software written in PHP.

There is a flaw in the 'disp_album.php' script which fails to sanitize
input to the 'id_album' field. This may allow anyone to inject
arbitrary SQL commands. An attacker could exploit this to obtain
sensitive information and possibly gain administrative access to the
remote web application." );

 script_set_attribute(attribute:"see_also", value:
"http://archives.neohapsis.com/archives/bugtraq/2004-12/0344.html" );

 script_set_attribute(attribute:"solution", value:
"The solution is unknown at this time." );

 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# Check starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


function check(dir)
{
  local_var r, buf;
  global_var port;

  r = http_send_recv3(method: "GET", port:port, item:dir + "/disp_album.php?id_album=0+or+1=1");
  if (isnull(r)) exit(0);

  if( "disp_album.php?id_album=0 or 1=1" >< r[2] &&
       '<td class="barreinfo">' >< r[2] )
  {
  security_hole(port);
  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
  exit(0);
}
 
 
 return(0);
}

port = get_http_port(default:80, embedded: 0);

if ( ! can_host_php(port:port) ) exit(0);


foreach dir (cgi_dirs()) 
 {
  check(dir : dir );
 }
