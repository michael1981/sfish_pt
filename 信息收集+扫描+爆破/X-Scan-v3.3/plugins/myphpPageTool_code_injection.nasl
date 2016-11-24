#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11310);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-2007-4947");
 script_xref(name:"OSVDB", value:"43159");

 script_name(english:"myphpPageTool /doc/admin/index.php ptinclude Parameter Remote File Inclusion");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a PHP application that is affected by
a remote file inclusion vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote web server appears to be hosting myphpPageTool. The
installed version fails to properly sanitize user supplied input to
the 'ptinclude' parameter of the '/doc/admin/index.php' script. An
attacker may use this flaw to inject arbitrary code in the remote host
and gain a shell with the privileges of the web server if the server
has 'register_globals' enabled." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2003-02/0005.html" );
 script_set_attribute(attribute:"solution", value:
"Turn off the 'register_globals' option in PHP." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"Checks for the presence of index.html");
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

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);



function check(loc)
{
  local_var res;
  
  res = http_send_recv3(method:"GET", item:string(loc, "/doc/admin/index.php?ptinclude-http://xxxxxxxx"), port:port);
  if (isnull(res)) exit(1, "The remote web server did not respond.");

  if(egrep(pattern:".*http://xxxxxxxx/ptconfig\.php", string:res[2]))
  {
    security_hole(port);
    exit(0);
  }
}


dir = make_list(cgi_dirs());
dirs = make_list();
foreach d (dir)
{
 dirs = make_list(dirs, string(d, "/myphpPageTool"));
}

dirs = make_list(dirs, "", "/myphpPageTool");



foreach dir (dirs)
{
 check(loc:dir);
}
