#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42052);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2009-2699", "CVE-2009-3094", "CVE-2009-3095");
  script_bugtraq_id(36254, 36260, 36596);
  script_xref(name:"OSVDB", value:"57851");
  script_xref(name:"OSVDB", value:"58879");
  script_xref(name:"Secunia", value:"36549");

  script_name(english:"Apache 2.2 < 2.2.14 Multiple Vulnerabilities");
  script_summary(english:"Checks version in Server response header");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote web server is affected by multiple vulnerabilities\n"
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "According to its banner, the version of Apache 2.2 installed on the \n",
      "remote host is older than 2.2.14.  Such versions are potentially\n",
      "affected by multiple vulnerabilities :\n",
      "\n",
      "  - Faulty error handling in the Solaris pollset support \n",
      "    could lead to a denial of service. (CVE-2009-2699)\n",
      "\n",
      "  - The 'mod_proxy_ftp' module allows remote attackers to \n",
      "    bypass intended access restrictions. (CVE-2009-3095)\n",
      "\n",
      "  - The 'ap_proxy_ftp_handler' function in \n",
      "    'modules/proxy/proxy_ftp.c' in the 'mod_proxy_ftp' \n",
      "    module allows remote FTP servers to cause a \n",
      "    denial-of-service. (CVE-2009-3094)\n",
      "\n",
      "Note that the remote web server may not actually be affected by these\n",
      "vulnerabilities as Nessus did not try to determine whether the affected\n",
      "modules are in use or check for the issues themselves."
    )
  );

  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/advisories/17947"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/advisories/17959"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.intevydis.com/blog/?p=59"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://issues.apache.org/bugzilla/show_bug.cgi?id=47645"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.apache.org/dist/httpd/CHANGES_2.2.14"
  );

  script_set_attribute(
    attribute:"solution",
    value:string(
      "Either ensure the affected modules are not in use or upgrade to Apache\n",
      "version 2.2.14 or later."
    )
  );

  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
  );

  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/10/05"
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/10/05"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/10/07"
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
include("http.inc");
include("misc_func.inc");

port = get_http_port(default:80);
if (report_paranoia < 2) exit(0);

banner = get_backport_banner(banner:get_http_banner(port:port));
if (banner && "Server:" >< banner)
{
  if (report_paranoia < 2 && backported) exit(1, "Security patches may have been backported.");

  server = strstr(banner, "Server:");

  pat = "^Server:.*Apache(-AdvancedExtranetServer)?/([0-9]+\.[^ ]+)";
  version = NULL;

  matches = egrep(pattern:pat, string:server);
  if (matches)
  {
    foreach match (split(matches, keep:FALSE))
    {
      item = eregmatch(pattern:pat, string:match);
      if (!isnull(item))
      {
        version = item[2];
        break;
      }
    }
  }

  if (!isnull(version) && version =~ "^2\.2\.([0-9]|1[0-3])($|[^0-9])")
  {
    if (report_verbosity > 0)
    {
      report = string(
        "\n",
        "Apache version ", version, " appears to be running on the remote host based on\n",
        "the following Server response header :\n",
        "\n",
        "  ", match, "\n"
      );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }
  else if (version) exit(0, "Apache "+version+" is listening on port"+port+" and is not affected.");
}
