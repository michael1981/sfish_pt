#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29833);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2007-3378", "CVE-2007-3997", "CVE-2007-4657", "CVE-2007-4658");
  script_bugtraq_id(24661);
  script_xref(name:"OSVDB", value:"36869");

  script_name(english:"PHP < 4.4.8 Multiple Vulnerabilities");
  script_summary(english:"Checks version of PHP");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server uses a version of PHP that is affected by
multiple issues." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP installed on the remote
host is older than 4.4.8.  Such versions may be affected by several
issues, including integer overflows involving the 'chunk_split',
'strcspn', and 'strspn' functions, and 'safe_mode' / 'open_basedir'
bypasses." );
 script_set_attribute(attribute:"see_also", value:"http://www.php.net/releases/4_4_8.php" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 4.4.8 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("Settings/ParanoidReport");
  exit(0);
}


include("backport.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


# nb: banner checks of open-source software are prone to false-
#     positives so only run the check if reporting is paranoid.
if (report_paranoia < 2) exit(0);


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


banner = get_http_banner(port:port);
if (banner)
{
  ver = get_php_version(banner:banner);
  if (ver && ver =~ "PHP/(3\.|4\.([0-3]\.|4\.[0-7]($|[^0-9])))")
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
