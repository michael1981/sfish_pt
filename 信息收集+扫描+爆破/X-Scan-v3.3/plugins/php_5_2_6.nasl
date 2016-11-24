#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(32123);
  script_version("$Revision: 1.11 $");

  script_cve_id(
    "CVE-2007-4850",
    "CVE-2008-0599",
    #"CVE-2008-0674",         PCRE buffer overflow
    "CVE-2008-1384",
    "CVE-2008-2050",
    "CVE-2008-2051"
  );
  script_bugtraq_id(27413, 28392, 29009);
  script_xref(name:"OSVDB", value:"43219");
  script_xref(name:"OSVDB", value:"44057");
  script_xref(name:"OSVDB", value:"44906");
  script_xref(name:"OSVDB", value:"44907");
  script_xref(name:"OSVDB", value:"44908");
  script_xref(name:"Secunia", value:"30048");

  script_name(english:"PHP < 5.2.6 Multiple Vulnerabilities");
  script_summary(english:"Checks version of PHP");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server uses a version of PHP that is affected by
multiple flaws." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP installed on the remote
host is older than 5.2.6.  Such versions may be affected by the
following issues :

  - A stack buffer overflow in FastCGI SAPI.

  - An integer overflow in printf().

  - An security issue arising from improper calculation
    of the length of PATH_TRANSLATED in cgi_main.c.

  - A safe_mode bypass in cURL.

  - Incomplete handling of multibyte chars inside
    escapeshellcmd().

  - Issues in the bundled PCRE fixed by version 7.6." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2008-03/0321.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2008-05/0103.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2008-05/0107.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.php.net/releases/5_2_6.php" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 5.2.6 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

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
  if (ver && ver =~ "PHP/5\.([01]\.|2\.[0-5]($|[^0-9]))")
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
