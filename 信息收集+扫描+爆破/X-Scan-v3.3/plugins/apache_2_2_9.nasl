#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(33477);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2007-6420", "CVE-2008-2364");
  script_bugtraq_id(27236, 29653);
  script_xref(name:"OSVDB", value:"42937");
  script_xref(name:"OSVDB", value:"46085");
  script_xref(name:"Secunia", value:"30621");

  script_name(english:"Apache < 2.2.9 Multiple Vulnerabilities (DoS, XSS)");
  script_summary(english:"Checks version in Server response header");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server may be affected by several issues." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apache 2.2 installed on the
remote host is older than 2.2.9.  Such versions may be affected by
several issues, including :

  - Improper handling of excessive forwarded interim 
    responses may cause denial-of-service conditions in 
    mod_proxy_http. (CVE-2008-2364)

  - A cross-site request forgery vulnerability in the 
    balancer-manager interface of mod_proxy_balancer.
    (CVE-2007-6420)

Note that the remote web server may not actually be affected by these
vulnerabilities.  Nessus did not try to determine whether the affected
modules are in use or to check for the issues themselves." );
 script_set_attribute(attribute:"see_also", value:"http://www.apache.org/dist/httpd/CHANGES_2.2" );
 script_set_attribute(attribute:"see_also", value:"http://httpd.apache.org/security/vulnerabilities_22.html" );
 script_set_attribute(attribute:"solution", value:
"Either ensure that the affected modules are not in use or upgrade to
Apache version 2.2.9 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

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

banner = get_backport_banner(banner:get_http_banner(port:port));
if (banner && "Server:" >< banner)
{
  if ( report_paranoia < 2 && backported ) exit(0);
  server = strstr(banner, "Server:");

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

  if (!isnull(ver) && ver =~ "^2\.2\.[0-8]$")
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
}
