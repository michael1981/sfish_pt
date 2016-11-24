#
# (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
  script_id(23963);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2006-6799");
  script_bugtraq_id(21799);
  script_xref(name:"OSVDB", value:"31468");

  script_name(english:"Cacti cmd.php Multiple Variable SQL Injection Arbitrary Command Execution");
  script_summary(english:"Checks if Cacti's cmd.php is remotely accessible");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that allows arbitrary
command execution." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Cacti, a web-based frontend to RRDTool for
network graphing. 

The version of Cacti on the remote host does not properly check
whether ensure the 'cmd.php' script is being run from a commandline
and fails to sanitize user-supplied input before using it in database
queries.  Provided PHP's 'register_argc_argv' parameter is enabled,
which is the default, an attacker can launch SQL injection attacks
against the underlying database and even to execute arbitrary code on
the remote host subject to the privileges of the web server user id." );
 script_set_attribute(attribute:"see_also", value:"http://milw0rm.com/exploits/3029" );
 script_set_attribute(attribute:"see_also", value:"http://forums.cacti.net/about18846.html" );
 script_set_attribute(attribute:"see_also", value:"http://bugs.cacti.net/view.php?id=883" );
 script_set_attribute(attribute:"see_also", value:"http://www.cacti.net/release_notes_0_8_6j.php" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Cacti version 0.8.6j or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Loop through CGI directories.
foreach dir (cgi_dirs())
{
  # Check whether we can pass arguments to the script.
  cgi = strcat(dir, "/cmd.php");
  u = strcat(cgi, "?1+1+0");
  r = http_send_recv3(port: port, method: "GET", item: u);
  if (isnull(r)) exit(0);

  # There's a problem if we can.
  if ("Invalid Arguments.  The first argument must be less" >< r[2])
  {
    info = strcat('\nThe vulnerable CGI is reachable at:\n', build_url(port: port, qs: cgi), '\n\n');
    security_hole(port, extra: info);
    if (COMMAND_LINE) display(info);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
