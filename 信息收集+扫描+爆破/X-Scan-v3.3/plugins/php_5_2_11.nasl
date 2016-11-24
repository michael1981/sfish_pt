#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(41014);
  script_version("$Revision: 1.2 $");

  script_bugtraq_id(36449);
  script_xref(name:"Secunia", value:"36791");

  script_name(english:"PHP < 5.2.11 Multiple Vulnerabilities");
  script_summary(english:"Checks version of PHP");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote web server uses a version of PHP that is affected by\n",
      "multiple flaws."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "According to its banner, the version of PHP installed on the remote\n",
      "host is older than 5.2.11.  Such versions may be affected by several\n",
      "security issues :\n",
      "\n",
      "  - An unspecified error occurs in certificate validation\n",
      "    inside 'php_openssl_apply_verification_policy'.\n",
      "\n",
      "  - An unspecified input validation vulnerability affects\n",
      "    the color index in 'imagecolortransparent()'.\n",
      "\n",
      "  - An unspecified input validation vulnerability affects\n",
      "    exif processing.\n",
      "\n",
      "  - An denial-of-service issue relates to 'popen' when\n",
      "    invalid modes are passed.\n"
    )
  );

  script_set_attribute(
    attribute:"see_also",
    value:"http://www.php.net/releases/5_2_11.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://news.php.net/php.internals/45597"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.php.net/ChangeLog-5.php#5.2.11"
  );

  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to PHP version 5.2.11 or later."
  );

  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P"
  );
  
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/09/16"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/09/18"
  );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("backport.inc");
include("http.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0, "The web server does not support PHP scripts.");

banner = get_http_banner(port:port);

if (banner)
{
  ver = get_php_version(banner:banner);
  if (ver && ver =~ "PHP/([0-4]\.|5\.([01]\.|2\.([0-9]|10)($|[^0-9])))")
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
      else if(egrep(pattern:"^X-Powered-By:.*PHP/[0-9]", string:banner))
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
