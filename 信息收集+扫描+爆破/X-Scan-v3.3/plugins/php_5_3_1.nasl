#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42862);
  script_version("$Revision: 1.1 $");

  script_bugtraq_id(36554, 36555, 37079);
  script_xref(name:"Secunia", value:"37412");

  script_name(english:"PHP < 5.3.1 Multiple Vulnerabilities");
  script_summary(english:"Checks version of PHP");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server uses a version of PHP that is affected by
multiple flaws."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the version of PHP installed on the remote
host is older than 5.3.1.  Such versions may be affected by several
security issues :

  - Sanity checks are missing in exif processing.

  - It is possible by bypass the 'safe_mode' configuration
    setting using 'tempnam()'.

  - It is possible to bypass the 'open_basedir' 
    configuration setting using 'posix_mkfifo()'.

  - The 'safe_mode_include_dir' configuration setting may
    be ignored.

  - Calling 'popen()' with an invalid mode can cause a 
    crash."
  );

  script_set_attribute(
    attribute:"see_also",
    value:"http://www.php.net/releases/5_3_1.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.php.net/ChangeLog-5.php#5.3.1"
  );

  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to PHP version 5.3.1 or later."
  );

  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P"
  );
  
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/11/19"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/11/20"
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
if (!can_host_php(port:port)) exit(0, "The web server on port "+port+" does not support PHP scripts.");

banner = get_http_banner(port:port);
if (!banner) exit(1, "Failed to retrieve the banner from the web server on port "+port+".");

ver = get_php_version(banner:banner);
if (!ver || ver !~ '^PHP/[0-9]') exit(1, "Failed to extract the PHP version from the banner from port "+port+".");

ver = strstr(ver, "PHP/") - "PHP/";
if (ver =~ "^([0-4]\.|5\.([0-2]\.|3\.0($|[^0-9])))")
{
  if (report_verbosity > 0)
  {
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
  exit(0);
}
else exit(0, "The web server on port "+port+" uses PHP version "+ver+" and is not affected.");
