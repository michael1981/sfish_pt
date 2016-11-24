#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(39480);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2009-2687");
  script_bugtraq_id(35440, 35435);
  script_xref(name:"OSVDB", value:"55222");
  script_xref(name:"OSVDB", value:"55223");
  script_xref(name:"OSVDB", value:"55224");
  script_xref(name:"Secunia", value:"35441");

  script_name(english:"PHP < 5.2.10 Multiple Vulnerabilities");
  script_summary(english:"Checks version of PHP");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server uses a version of PHP that is affected by
multiple vulnerabilities." );

 script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP installed on the remote
host is older than 5.2.10.  Such versions are reportedly affected by
multiple vulnerabilities :

  - Sufficient checks are not performed on fields reserved 
    for offsets in function 'exif_read_data()'. Successful 
    exploitation of this issue could result in a denial of 
    service condition. (bug 48378)

  - Provided 'safe_mode_exec_dir' is not set (not set by
    default), it may be possible to bypass 'safe_mode' 
    restrictions by preceding a backslash in functions 
    such as 'exec()', 'system()', 'shell_exec()', 
    'passthru()' and 'popen()' on a system running PHP 
    on Windows. (bug 45997)");

  script_set_attribute(attribute:"see_also", value:
"http://bugs.php.net/bug.php?id=45997" );
  script_set_attribute(attribute:"see_also", value:
"http://bugs.php.net/bug.php?id=48378" );
  script_set_attribute(attribute:"see_also", value:
"http://www.php.net/releases/5_2_10.php" );
  script_set_attribute(attribute:"see_also", value:
"http://www.php.net/ChangeLog-5.php#5.2.10" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 5.2.10 or later." );
  script_set_attribute(attribute:"cvss_vector", 
  value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P" );

  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include('misc_func.inc');
include("backport.inc");
include("http.inc");

port = get_http_port(default:80);

if (!can_host_php(port:port)) exit(0);

banner = get_http_banner(port:port);
if (banner)
{
  ver = get_php_version(banner:banner);
  if (ver && ver =~ "PHP/([0-4]\.|5\.([01]\.|2\.[0-9]($|[^0-9])))")
  {
    if (report_verbosity > 0)
    {
      ver = strstr(ver, "PHP/") - "PHP/";
      report = string(
        "\n",
        "PHP version ", ver, " appears to be running on the remote host based on\n"
      );

      if (egrep(pattern:"Server:.*PHP/[0-9].", string:banner))
      {
        line = egrep(pattern:"Server:.*PHP/[0-9].", string:banner);
        report = string(
          report, 
          "the following Server response header :\n",
          "\n",
          "  ", line
        );
      }
      else if (egrep(pattern:"^X-Powered-By:.*PHP/[0-9]", string:banner))
      {
        line = egrep(pattern:"^X-Powered-By:.*PHP/[0-9]", string:banner);
        report = string(
          report, 
          "the following X-Powered-By response header :\n",
          "\n",
          "  ", line
        );
      }
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
  }
}
