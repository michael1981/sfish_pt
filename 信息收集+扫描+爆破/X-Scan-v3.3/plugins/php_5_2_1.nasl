#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(24907);
  script_version("$Revision: 1.12 $");

  script_cve_id(
    "CVE-2006-6383",
    "CVE-2007-0905",
    "CVE-2007-0906",
    "CVE-2007-0907",
    "CVE-2007-0908",
    "CVE-2007-0909",
    "CVE-2007-0910",
    "CVE-2007-1376",
    "CVE-2007-1380",
    "CVE-2007-1453",
    "CVE-2007-1700",
    "CVE-2007-1701",
    "CVE-2007-1824",
    "CVE-2007-1825",
    "CVE-2007-1884",
    "CVE-2007-1885",
    "CVE-2007-1886",
    "CVE-2007-1887",
    "CVE-2007-1890"
  );
  script_bugtraq_id(
    21508, 
    22496, 
    22805,
    22806,
    22862,
    22922,
    23119,
    23120,
    23219,
    23233, 
    23234, 
    23235, 
    23236, 
    23237, 
    23238
  );
  if (NASL_LEVEL >= 3000)
  {
    script_xref(name:"OSVDB", value:"32763");
    script_xref(name:"OSVDB", value:"32764");
    script_xref(name:"OSVDB", value:"32765");
    script_xref(name:"OSVDB", value:"32766");
    script_xref(name:"OSVDB", value:"32767");
    script_xref(name:"OSVDB", value:"32768");
    script_xref(name:"OSVDB", value:"32776");
    script_xref(name:"OSVDB", value:"32781");
    script_xref(name:"OSVDB", value:"33269");
    script_xref(name:"OSVDB", value:"33933");
    script_xref(name:"OSVDB", value:"33944");
    script_xref(name:"OSVDB", value:"33945");
    script_xref(name:"OSVDB", value:"33955");
    script_xref(name:"OSVDB", value:"33957");
    script_xref(name:"OSVDB", value:"33958");
    script_xref(name:"OSVDB", value:"33959");
    script_xref(name:"OSVDB", value:"33960");
    script_xref(name:"OSVDB", value:"34767");
  }

  script_name(english:"PHP < 5.2.1 Multiple Vulnerabilities");
  script_summary(english:"Checks version of PHP");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server uses a version of PHP that is affected by
multiple flaws." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP installed on the remote
host is older than 5.2.1.  Such versions may be affected by several
issues, including buffer overflows, format string vulnerabilities,
arbitrary code execution, 'safe_mode' and 'open_basedir' bypasses, and
clobbering of super-globals." );
 script_set_attribute(attribute:"see_also", value:"http://www.php.net/releases/5_2_1.php" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 5.2.1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("backport.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


banner = get_http_banner(port:port);
if (banner)
{
  ver = get_php_version(banner:banner);
  if (ver && ver =~ "PHP/5\.([01]\.|2\.0($|[^0-9]))")
  {
    if (report_verbosity)
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

      security_hole(port:port, extra:report);
    }
    else security_hole(port);
  }
}
