#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40467);
  script_version("$Revision: 1.1 $");

  script_cve_id(
    "CVE-2009-0023",
    "CVE-2009-1191",
    "CVE-2009-1195",
    "CVE-2009-1890",
    "CVE-2009-1891",
    "CVE-2009-1955",
    "CVE-2009-1956"
  );
  script_bugtraq_id(34663, 35115, 35221, 35251, 35253, 35565, 35623);
  script_xref(name:"OSVDB", value:"53921");
  script_xref(name:"OSVDB", value:"54733");
  script_xref(name:"OSVDB", value:"55057");
  script_xref(name:"OSVDB", value:"55058");
  script_xref(name:"OSVDB", value:"55059");
  script_xref(name:"OSVDB", value:"55553");
  script_xref(name:"OSVDB", value:"55782");

  script_name(english:"Apache 2.x < 2.2.12 Multiple Vulnerabilities");
  script_summary(english:"Checks version in Server response header");
 
  script_set_attribute(
    attribute:"synopsis",
    value:"The remote web server may be affected by several issues."
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "According to its banner, the version of Apache 2.2 installed on the\n",
      "remote host is older than 2.2.12.  Such versions may be affected by\n",
      "several issues, including :\n",
      "\n",
      "  - A heap buffer underwrite flaw exists in the function\n",
      "    'apr_strmatch_precompile()' in the bundled copy of the\n",
      "    APR-util library, which could be triggered when parsing\n",
      "    configuration data to crash the daemon. (CVE-2009-0023)\n",
      "\n",
      "  - A flaw in the mod_proxy_ajp module in version 2.2.11\n",
      "    only may allow a remote attacker to obtain sensitive\n",
      "    response data intended for a client that sent an\n",
      "    earlier POST request with no request body. \n",
      "    (CVE-2009-1191)\n",
      "\n",
      "  - The server does not limit the use of directives in a\n",
      "    .htaccess file as expected based on directives such\n",
      "    as 'AllowOverride' and 'Options' in the configuration\n",
      "    file, which could enable a local user to bypass\n",
      "    security restrictions. (CVE-2009-1195)\n",
      "\n",
      "  - Failure to properly handle an amount of streamed data\n",
      "    that exceeds the Content-Length value allows a remote\n",
      "    attacker to force a proxy process to consume CPU time\n",
      "    indefinitely when mod_proxy is used in a reverse proxy\n",
      "    configuration. (CVE-2009-1890)\n",
      "\n",
      "  - Failure of mod_deflate to stop compressing a file when\n",
      "    the associated network connection is closed may allow a\n",
      "    remote attacker to consume large amounts of CPU if\n",
      "    there is a large (>10 MB) file available that has\n",
      "    mod_deflate enabled. (CVE-2009-1891)\n",
      "\n",
      "  - Using a specially crafted XML document with a large\n",
      "    number of nested entities, a remote attacker may be\n",
      "    able to consume an excessive amount of memory due to\n",
      "    a flaw in the bundled expat XML parser used by the\n",
      "    mod_dav and mod_dav_svn modules. (CVE-2009-1955)\n",
      "\n",
      "  - There is an off-by-one overflow in the function\n",
      "    'apr_brigade_vprintf()' in the bundled copy of the\n",
      "    APR-util library in the way it handles a variable list\n",
      "    of arguments, which could be leveraged on big-endian \n",
      "    platforms to perform information disclosure or denial \n",
      "    of service attacks. (CVE-2009-1956)\n",
      "\n",
      "Note that Nessus has relied solely on the version in the Server\n",
      "response header and did not try to check for the issues themselves or\n",
      "even whether the affected modules are in use."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.apache.org/dist/httpd/CHANGES_2.2.12"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://httpd.apache.org/security/vulnerabilities_22.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Either ensure that the affected modules / directives are not in use or\n",
      "upgrade to Apache version 2.2.12 or later."
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P"
  );
  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/04/22"
  );
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2009/07/27"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/08/02"
  );
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/apache");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("backport.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0, "Port is not open.");


banner = get_backport_banner(banner:get_http_banner(port:port));
if (banner && "Server:" >< banner)
{
  if (report_paranoia < 2 && backported) exit(1, "Security patches may have been backported.");

  server = strstr(banner, "Server:");

  pat = "^Server:.*Apache(-AdvancedExtranetServer)?/([0-9]+\.[^ ]+)";
  ver = NULL;

  matches = egrep(pattern:pat, string:server);
  if (matches)
  {
    foreach match (split(matches, keep:FALSE))
    {
      item = eregmatch(pattern:pat, string:match);
      if (!isnull(item))
      {
        ver = item[2];
        break;
      }
    }
  }

  if (!isnull(ver) && ver =~ "^2\.2\.([0-9]($|[^0-9])|1[01]($|[^0-9]))")
  {
    if (report_verbosity > 0)
    {
      report = string(
        "\n",
        "Apache version ", ver, " appears to be running on the remote host based on\n",
        "the following Server response header :\n",
        "\n",
        "  ", match, "\n"
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    exit(0);
  }
  else exit(0, "The remote host is not affected.");
}
