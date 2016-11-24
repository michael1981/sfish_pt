#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(35750);
  script_version("$Revision: 1.1 $");

  script_cve_id("CVE-2008-5498");
  script_bugtraq_id(33002, 33927);
  script_xref(name:"OSVDB", value:"51031");
  script_xref(name:"Secunia", value:"34081");

  script_name(english:"PHP < 5.2.9 Multiple Vulnerabilities");
  script_summary(english:"Checks version of PHP");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server uses a version of PHP that is affected by
multiple flaws." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP installed on the remote
host is older than 5.2.9.  Such versions may be affected by several
security issues :

  - Background color is not correctly validated with a non true
    color image in function 'imagerotate()'. (CVE-2008-5498)

  - A denial of service condition can be triggered by trying to 
    extract zip files that contain files with relative paths 
    in file or directory names.

  - Function 'explode()' is affected by an unspecified 
    vulnerability.

  - It may be possible to trigger a segfault by passing a 
    specially crafted string to function 'json_decode()'.

  - Function 'xml_error_string()' is affected by a flaw
    which results in messages being off by one." );
 script_set_attribute(attribute:"see_also", value:
"http://news.php.net/php.internals/42762" );
 script_set_attribute(attribute:"see_also", value:
"http://www.php.net/releases/5_2_9.php" );
 script_set_attribute(attribute:"see_also", value:
"http://www.php.net/ChangeLog-5.php#5.2.9" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 5.2.9 or later." );
 script_set_attribute(attribute:"cvss_vector", 
  value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

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
if (!port) exit(0);
if (!can_host_php(port:port)) exit(0);

banner = get_http_banner(port:port);
if (banner)
{
  ver = get_php_version(banner:banner);
  if (ver && ver =~ "PHP/([0-4]\.|5\.([01]\.|2\.[0-8]($|[^0-9])))")
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
