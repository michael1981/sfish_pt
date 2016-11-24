#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
# This script is released under the GNU GPLv2
#

# Changes by Tenable:
# - Revised plugin title (6/25/09)
# - Changed plugin family (7/6/09)
# - Updated to use compat.inc (11/17/2009)


include("compat.inc");

if (description)
{
script_id(24873);
script_version("$Revision: 1.9 $");

script_cve_id("CVE-2007-1560");
script_bugtraq_id(23085);
script_xref(name:"OSVDB", value:"34367");

 script_set_attribute(attribute:"synopsis", value:
"The remote proxy server is vulnerable to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"A vulnerability in TRACE request processing has been reported in
Squid, which can be exploited by malicious people to cause a denial of
service." );
 script_set_attribute(attribute:"see_also", value:"http://www.squid-cache.org/Advisories/SQUID-2007_1.txt" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to squid 2.6.STABLE12 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

script_name(english:"Squid < 2.6.STABLE12 src/client_side.c clientProcessRequest() function TRACE Request DoS");
script_summary(english: "Determines squid version");
script_category(ACT_GATHER_INFO);
script_copyright(english:"This script is Copyright (C) 2007-2009 David Maciejak");
script_family(english: "Firewalls");
script_dependencies("proxy_use.nasl");
script_require_ports("Services/http_proxy",3128, 8080);
exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

# nb: only run the plugin if we're being paranoid to avoid false-positives,
#     which might arise because the software is open-source.
if (report_paranoia < 2) exit(0);

ports = make_service_list(3128, 8080, "Services/http_proxy");

foreach port (ports)
 if(get_port_state(port))
 {
  res = http_get_cache(item:"/", port:port);
  if(res && egrep(pattern:"[Ss]quid/2\.([0-5]\.|6\.STABLE([0-9][^0-9]|1[01][^0-9]))", string:res))
   security_warning(port);
 }
