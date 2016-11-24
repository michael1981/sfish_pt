#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(26023);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2006-5752","CVE-2007-1862","CVE-2007-1863","CVE-2007-3303","CVE-2007-3304","CVE-2007-3847","CVE-2007-4465");
  script_bugtraq_id(24215, 24553, 24645, 24649, 25489, 25653);
  script_xref(name:"OSVDB", value:"37050");
  script_xref(name:"OSVDB", value:"37051");
  script_xref(name:"OSVDB", value:"37052");
  script_xref(name:"OSVDB", value:"37079");
  script_xref(name:"OSVDB", value:"38636");
  script_xref(name:"OSVDB", value:"38641");
  script_xref(name:"OSVDB", value:"38939");

  script_name(english:"Apache < 2.2.6 Multiple Vulnerabilities (DoS, XSS, Info Disc)");
  script_summary(english:"Checks version in Server response header");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server may be affected by one or more issues." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apache 2.2 installed on the
remote host is older than 2.2.6.  Such versions may be affected by
several issues, including :

  - A denial of service vulnerability in mod_proxy. 
  - A cross-site scripting vulnerability in mod_status.
  - A local denial of service vulnerability associated with
    the Prefork MPM module.
  - An information leak in mod_cache.
  - A denial of service vulnerability in mod_cache.

In addition, it offers a workaround for a cross-site scripting issue
in mod_autoindex. 

Note that the remote web server may not actually be affected by these
vulnerabilities.  Nessus did not try to determine whether any of the
affected modules are in use on the remote server or to check for the
issues themselves." );
 script_set_attribute(attribute:"see_also", value:"http://www.apache.org/dist/httpd/CHANGES_2.2" );
 script_set_attribute(attribute:"solution", value:
"Either ensure that the affected modules are not in use or configured
so as to avoid the issues or upgrade to Apache version 2.2.6 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/apache", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("backport.inc");


# nb: banner checks of Apache are prone to false-positives so we only
#     run the check if reporting is paranoid.
if (report_paranoia < 2) exit(0);

port = get_http_port(default:80);

banner = get_backport_banner(banner:get_http_banner(port:port));
if (banner && "Server:" >< banner)
{
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

  if (!isnull(ver) && ver =~ "^2\.2\.[0-5]$")
  {
    report = string(
      "According to its banner, Apache version ", ver, " is installed on the\n",
      "remote host.\n"
    );
    security_warning(port:port, extra:report);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
   }
}
