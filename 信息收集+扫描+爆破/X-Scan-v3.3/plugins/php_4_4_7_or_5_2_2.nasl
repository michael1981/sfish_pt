#
# Copyright (C) Westpoint Limited
#
# Based on scripts written by Tenable Network Security.
#


include("compat.inc");

if(description)
{
  script_id(25159);
  script_version("$Revision: 1.19 $");

  script_cve_id(
    "CVE-2007-0455",
    "CVE-2007-1001",
    "CVE-2007-1285",
    "CVE-2007-1375",
    "CVE-2007-1396",
    "CVE-2007-1484",
    "CVE-2007-1864",
    "CVE-2007-2509",
    "CVE-2007-2510",
    "CVE-2007-2727",
    "CVE-2007-2748",
    "CVE-2007-4670"
  );
  script_bugtraq_id(22289, 22764, 22990, 23357, 23813, 23818, 23984, 24012);
  script_xref(name:"OSVDB", value:"32769");
  script_xref(name:"OSVDB", value:"33008");
  script_xref(name:"OSVDB", value:"34671");
  script_xref(name:"OSVDB", value:"34672");
  script_xref(name:"OSVDB", value:"34673");
  script_xref(name:"OSVDB", value:"34674");
  script_xref(name:"OSVDB", value:"34675");
  script_xref(name:"OSVDB", value:"34730");
  script_xref(name:"OSVDB", value:"36087");

  script_name(english:"PHP < 4.4.7 / 5.2.2 Multiple Vulnerabilities");
  script_summary(english:"Checks version of PHP");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server uses a version of PHP that is affected by
multiple flaws." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP installed on the remote
host is older than 4.4.7 / 5.2.2.  Such versions may be affected by
several issues, including buffer overflows in the GD library." );
 script_set_attribute(attribute:"see_also", value:"http://www.php.net/releases/4_4_7.php" );
 script_set_attribute(attribute:"see_also", value:"http://www.php.net/releases/5_2_2.php" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PHP 4.4.7 / 5.2.2 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Westpoint Limited.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

#
# The script code starts here
#

include("backport.inc");
include("global_settings.inc");
include("http_func.inc");

# Banner checks of PHP are prone to false-positives so we only run the
# check if the reporting is paranoid.
if (report_paranoia <= 1) exit(0);

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

banner = get_http_banner(port:port);
if (banner)
{
  ver = get_php_version(banner:banner);
  if (ver && ver =~ "PHP/(3\.|4\.([0-3]\.|4\.[0-6]($|[^0-9]))|5\.([01]\.|2\.[01]($|[^0-9])))")
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
