#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(31408);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2007-3847","CVE-2007-5000","CVE-2007-6388","CVE-2008-0005");
  script_bugtraq_id(25489, 26838, 27234, 27237);
  script_xref(name:"OSVDB", value:"37051");
  script_xref(name:"OSVDB", value:"39134");
  script_xref(name:"OSVDB", value:"40262");
  script_xref(name:"OSVDB", value:"42214");

  script_name(english:"Apache < 1.3.41 Multiple Vulnerabilities (DoS, XSS)");
  script_summary(english:"Checks version in Server response header");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server may be affected by several issues." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apache 1.3 installed on the
remote host is older than 1.3.41.  Such versions may be affected by
several issues, including :

  - A denial of service issue in mod_proxy when parsing
    date-related headers. (CVE-2007-3847)

  - A cross-site scripting issue involving mod_imap.
    (CVE-2007-5000).

  - A cross-site scripting issue in mod_status involving 
    the refresh parameter. (CVE-2007-6388)

  - A cross-site scripting issue using UTF-7 encoding
    in mod_proxy_ftp exists because it does not 
    define a charset. (CVE-2008-0005)

Note that the remote web server may not actually be affected by these
vulnerabilities.  Nessus did not try to determine whether the affected
modules are in use or to check for the issues themselves." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/archive/1/486167/100/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.apache.org/dist/httpd/CHANGES_1.3.41" );
 script_set_attribute(attribute:"see_also", value:"http://httpd.apache.org/security/vulnerabilities_13.html" );
 script_set_attribute(attribute:"solution", value:
"Either ensure that the affected modules are not in use or upgrade to
Apache version 1.3.41 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/apache");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("backport.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);


banner = get_backport_banner(banner:get_http_banner(port:port));
if ("Server:" >!< banner) exit(0);

if ( report_paranoia < 2 && backported ) exit(0);
  server = strstr(banner, "Server:");

if (report_paranoia < 2)
  if ( ! apache_module_is_installed(module: "mod_status", port: port) &&
       ! apache_module_is_installed(module: "mod_proxy", port: port) &&
       ! apache_module_is_installed(module: "mod_proxy_ftp", port: port) &&
       ! apache_module_is_installed(module: "mod_imap", port: port) )
    exit(0);

  pat = "^Server:.*Apache(-AdvancedExtranetServer)?/([0-9]+\.[^ ]+)";
  ver = NULL;
  matches = egrep(pattern:pat, string:server);
  if (matches)
  {
    foreach match (split(matches))
    {
      match = chomp(match);
      ver = eregmatch(pattern:pat, string:match);
      if (!isnull(ver))
      {
        ver = ver[2];
        break;
      }
    }
  }

  # nb: all but one of the vulnerabilities were actually fixed in 1.3.40, 
  #     but per the changelog that version was not released and is
  #     affected by CVE-2007-6388.
  if (!isnull(ver) && ver =~ "^1\.3\.([0-3][0-9]|40)($|[^0-9])")
  {
    if (report_verbosity)
    {
      report = string(
        "\n",
        "According to its banner, Apache version ", ver, " is installed on the\n",
        "remote host.\n"
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }

