#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(17322);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2005-0808");
  script_bugtraq_id(12795);
  script_xref(name:"OSVDB", value:"14770");

  script_name(english:"Apache Tomcat AJP12 Protocol Malformed Packet Remote DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote AJP connector is affected by a denial of service issue." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apache Tomcat installed on the
remote host suffers from a denial of service vulnerability due to its
failure to handle malformed input.  By submitting a specially-crafted
AJP12 request, an unauthenticated attacker can cause Tomcat to stop
responding.  At present, details on the specific nature of such
requests are not generally known." );
 script_set_attribute(attribute:"see_also", value:"http://www.kb.cert.org/vuls/id/JGEI-6A2LEF" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 5.x or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );
script_end_attributes();

 
  script_summary(english:"Checks for remote malformed request denial of service vulnerability in Apache Tomcat");
  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/http", 80);

  exit(0);
}

include("global_settings.inc");
include ("misc_func.inc");
include ("http.inc");


port = get_http_port(default:80);


banner = get_http_banner(port:port);
if (
  banner &&
  "Tomcat" >< banner &&
  egrep(pattern:"^Server: (Apache )?Tomcat( Web Server)?/([12]\..*|3\.(0\.0|1\.[01]|2\.[0-4]|3\.[01]))([^0-9]|$)", string:banner)
) security_warning(port);
