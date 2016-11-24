#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if(description)
{
 script_id(14817);
 script_version("$Revision: 1.11 $");
 script_cve_id("CVE-2004-1553");
 script_bugtraq_id(11246);
 script_xref(name:"OSVDB", value:"10335");

 script_name(english: "aspWebAlbum album.asp SQL Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to an SQL injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running aspWebAlbum, an ASP script
designed to faciliate the integration of multiple photo albums in a
web-based application.

There is a flaw in the remote software which may allow anyone
to inject arbitrary SQL commands, which may in turn be used to
gain administrative access on the remote host." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of this software" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english: "SQL Injection");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# Check starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

function check(port, req)
{
  local_var	r, variables;

  variables = "txtUserName=%27&txtPassword=&LoginButton=Login";
  r = http_send_recv3(port: port, method: 'POST', version: 11, item: req,
      	add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"),
	data: variables);

  if (isnull(r)) exit(0);

  if("error '80040e14'" >< r[2] &&
     "'Gal_UserUserName = ''''" >< r[2] )
  	{
	security_warning(port);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	exit(0);
	}
  return(0);
}

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if ( ! can_host_asp(port:port) ) exit(0);

foreach dir (cgi_dirs()) 
 {
  if ( is_cgi_installed3(item:dir + "/album.asp", port:port) ) check(port: port, req:dir + "/album.asp?action=processlogin");
 }
