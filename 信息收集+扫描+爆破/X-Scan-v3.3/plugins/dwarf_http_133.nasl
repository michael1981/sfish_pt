#
# (C) Tenable Network Security
#

include("compat.inc");

if (description)
{
  script_id(21092);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2006-0819", "CVE-2006-0820");
  script_bugtraq_id(17123);
  script_xref(name:"OSVDB", value:"23836");
  script_xref(name:"OSVDB", value:"23837");

  script_name(english:"Dwarf HTTP Server < 1.3.3 Multiple Remote Vulnerabilities (XSS, Disc)");
  script_summary(english:"Checks version of Dwarf HTTP Server");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server suffers from multiple flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Dwarf HTTP Server, a full-featured,
Java-based web server. 

According to its banner, the version of Dwarf HTTP Server on the
remote host reportedly fails to properly validate filename extensions
in URLs.  A remote attacker may be able to leverage this issue to
disclose the source of scripts hosted by the affected application
using specially-crafted requests with dot, space, slash, and NULL
characters. 

In addition, the web server also reportedly fails to sanitize requests
before returning error pages, which can be exploited to conduct
cross-site scripting attacks." );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2006-13/advisory/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Dwarf HTTP Server version 1.3.3 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_require_keys("Settings/ParanoidReport");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) exit(0);


port = get_http_port(default:8080);

banner = get_http_banner(port:port);
if (!banner) exit(0);

if (egrep(pattern:"^server: Dwarf HTTP Server/(0\.|1\.([0-2]\.|3\.[0-2] ))", string:banner)
) {
   security_hole(port);
   set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}
