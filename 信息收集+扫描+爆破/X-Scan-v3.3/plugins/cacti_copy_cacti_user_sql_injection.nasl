#
# (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
  script_id(23964);
  script_version("$Revision: 1.7 $");

  script_bugtraq_id(21823);
  script_xref(name:"OSVDB", value:"49493");

  script_name(english:"Cacti copy_cacti_user.php template_user Variable SQL Injection");
  script_summary(english:"Checks if Cacti's copy_cacti_user.php is remotely accessible");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a SQL
injection issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Cacti, a web-based frontend to RRDTool for
network graphing. 

The version of Cacti on the remote host does not properly check
whether the 'copy_cacti_user.php' script is being run from a
commandline and fails to sanitize user-supplied input before using it
in database queries.  Provided PHP's 'register_argc_argv' parameter is
enabled, which is the default, an attacker can leverage this issue to
launch SQL injection attack against the underlying database and, for
example, add arbitrary administrative users." );
 script_set_attribute(attribute:"see_also", value:"http://milw0rm.com/exploits/3045" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
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
  cgi = strcat(dir, "/copy_cacti_user.php");
  u = strcat(cgi, "?", SCRIPT_NAME);
  r = http_send_recv3(port: port, method: "GET", item: u);
  if (isnull(r)) exit(0);

  # There's a problem if we can.
  if ("php copy_cacti_user.php <template user>" >< r[2])
  {
    info = strcat('\nThe vulnerable CGI is reachable at:\n', build_url(port: port, qs: cgi), '\n\n');
    security_hole(port, extra: info);
    if (COMMAND_LINE) display(info);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
