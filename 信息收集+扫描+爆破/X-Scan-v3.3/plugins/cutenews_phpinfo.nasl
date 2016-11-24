#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_version ("$Revision: 1.10 $");
 script_id(11940);
 script_bugtraq_id(9130);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"2880");
 }
 
 name["english"] = "CuteNews Debug Info Disclosure";
 script_name(english:name["english"]);

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to an
information disclosure attack." );
 script_set_attribute(attribute:"description", value:
"There is a bug in the remote version of CuteNews that allows an attacker
to obtain information from a call to the phpinfo() PHP function such as
the username of the user who installed php, if they are a SUDO user, the
IP address of the host, the web server version, the system version (unix
/ linux), and the root directory of the web server." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/346013" );
 script_set_attribute(attribute:"solution", value:
"Disable CuteNews or upgrade to the newest version." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 summary["english"] = "Checks for the presence of cutenews";
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_require_ports("Services/www", 80);
 script_dependencies("cutenews_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);
if(!can_host_php(port:port))exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/cutenews"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  r = http_send_recv3(method:"GET", item:string(dir, "/index.php?debug"), port:port);
  if (isnull(r)) exit(0);
  res = r[2];
  if("CuteNews Debug Information:" >< res)
  {
    security_warning(port);
    exit(0);
  }
}

