#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(21155);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2006-0814");
  script_bugtraq_id(16893);
  script_xref(name:"OSVDB", value:"23542");

  script_name(english:"lighttpd on Windows Crafted Filename Request Script Source Disclosure");
  script_summary(english:"Checks version of lighttpd");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server suffers from an information disclosure flaw." );
 script_set_attribute(attribute:"description", value:
"The remote host is running lighttpd, an open-source web server with a
light footprint. 

According to its banner, the version of lighttpd installed on the
remote Windows host fails to properly validate filename extensions in
URLs.  A remote attacker may be able to leverage this issue to
disclose the source of scripts hosted by the affected application
using specially-crafted requests with dot and space characters." );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2006-9/advisory/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to lighttpd for Windows version 1.4.10a or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


banner = get_http_banner(port:port);
if (
  banner &&
  egrep(pattern:"^Server: lighttpd/1\.4\.([0-9][^0-9]?|10) \(Win32\)", string:banner)
) security_warning(port);
