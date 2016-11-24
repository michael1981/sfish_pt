#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(28181);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2007-4887", "CVE-2007-5898", "CVE-2007-5900");
  script_bugtraq_id(26403);
  script_xref(name:"OSVDB", value:"38680");
  script_xref(name:"OSVDB", value:"38681");
  script_xref(name:"OSVDB", value:"38682");
  script_xref(name:"OSVDB", value:"38683");
  script_xref(name:"OSVDB", value:"38684");
  script_xref(name:"OSVDB", value:"38685");

  script_name(english:"PHP < 5.2.5 Multiple Vulnerabilities");
  script_summary(english:"Checks version of PHP");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server uses a version of PHP that is affected by
multiple flaws." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP installed on the remote
host is older than 5.2.5.  Such versions may be affected by various
issues, including but not limited to several buffer overflows." );
 script_set_attribute(attribute:"see_also", value:"http://www.php.net/releases/5_2_5.php" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 5.2.5 or later." );
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
  if (ver && ver =~ "PHP/5\.([01]\.|2\.[0-4]($|[^0-9]))")
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
