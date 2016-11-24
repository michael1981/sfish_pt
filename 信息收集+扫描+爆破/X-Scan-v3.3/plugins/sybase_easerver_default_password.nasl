#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(19218);
  script_version("$Revision: 1.8 $");
  script_bugtraq_id(14287);
  script_xref(name:"OSVDB", value:"17996");

  script_name(english:"Sybase EAServer WebConsole jaqadmin Default Password");
  script_summary(english:"Checks for default administrator password in Sybase EAServer");

   script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is configured with a default administrator password.'
  );

  script_set_attribute(
    attribute:'description',
    value:"This host appears to be the running the Sybase EAServer Management
with the default administrator accounts still configured (jagadmin/'').
A potential intruder could reconfigure this service in a way that grants
system access."
  );

  script_set_attribute(
    attribute:'solution',
    value:'Change default administrator password'
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://archives.neohapsis.com/archives/bugtraq/2005-07/0247.html'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P'
  );

  script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 8080);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# Check starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


function check(dir)
{
 local_var	r, val, variables;
 global_var	port;

 erase_http_cookie(name: "JAGID");
 r = http_send_recv3(method: "GET", item: string(dir, "/Login.jsp"), port:port);
 if (isnull(r)) exit(0);
 if ("Sybase Management Console Login" >< r[2])
 {
  variables = "j_username=jagadmin&j_password=&submit.x=29&submit.y=10&submit=login";
  r = http_send_recv3(method: "POST ", item: dir+"/j_security_check", data: variables, port: port,
   add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"));
  if (isnull(r)) exit(0);

  val = get_http_cookie(name: "JAGID");
  if (! isnull(val))
  {
   security_hole(port);
   exit(0);
  }
 }

 return(0);
}

port = get_http_port(default:8080);
banner = get_http_banner (port:port);
if ("Server: Jaguar Server Version" >!< banner)
  exit (0);

init_cookiejar();
foreach dir (make_list(cgi_dirs(), "/WebConsole"))
{
 check(dir:dir);
}
