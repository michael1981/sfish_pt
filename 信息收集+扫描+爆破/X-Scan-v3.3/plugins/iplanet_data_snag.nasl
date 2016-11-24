#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
 script_id(11856);
 script_version("$Revision: 1.12 $");

 script_cve_id("CVE-2001-0327");
 script_bugtraq_id(6826);
 script_xref(name:"IAVA", value:"2001-a-0007");
 script_xref(name:"IAVA", value:"2002-A-0012");
 script_xref(name:"OSVDB", value:"5704"); 

 script_name(english:"iPlanet Web Server Enterprise Edition URL-encoded Host: Information Disclosure");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure 
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote iPlanet webserver (according to it's version number) is 
vulnerable to a bug wherein a remote user can retrieve sensitive data
from memory allocation pools, or cause a denial of service against the 
server.

*** Since Nessus solely relied on the banner of this server,
*** (and iPlanet 4 does not include the SP level in the banner),
*** to issue this alert, this may be a false positive." );
 script_set_attribute(attribute:"see_also", value:"http://iplanet.com/products/iplanet_web_enterprise/iwsalert4.16.html" );
 script_set_attribute(attribute:"solution", value:
"Update to iPlanet 4.1 SP7 or newer" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 
 script_summary(english:"Check for vulnerable version of iPlanet Webserver");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_keys("www/iplanet");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http.inc");
include("global_settings.inc");
include("misc_func.inc");


port = get_http_port(default:80);

mybanner = get_http_banner(port:port);
if(!mybanner)exit(0);

if(egrep(pattern:"^Server: *Netscape-Enterprise/(4\.[01][^0-9])", string:mybanner))security_warning(port);
