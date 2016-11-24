#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(27582);
  script_version("$Revision: 1.4 $");

  script_bugtraq_id(26174);
  script_xref(name:"OSVDB", value:"41862");
  script_xref(name:"OSVDB", value:"41863");
  script_xref(name:"OSVDB", value:"41864");
  script_xref(name:"OSVDB", value:"41865");
  script_xref(name:"OSVDB", value:"41866");
	
  script_name(english:"DeleGate Proxy Server < 9.7.5 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote proxy server is affected by multiple denial-of-service vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running a version of the 
DeleGate proxy server before 9.7.5. Such versions contain several issues
that could result in service disruptions when processing user input or 
handling malicious traffic." );
 script_set_attribute(attribute:"see_also", value:"http://www.delegate.org/mail-lists/delegate-en/3829" );
 script_set_attribute(attribute:"see_also", value:"http://www.delegate.org/mail-lists/delegate-en/3856" );
 script_set_attribute(attribute:"see_also", value:"http://www.delegate.org/mail-lists/delegate-en/3875" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to DeleGate 9.7.5 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );
 script_end_attributes();

  script_summary(english:"Checks version of DeleGate Proxy server");
  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
  script_dependencies("proxy_use.nasl");	
  script_require_ports("Services/http_proxy", 8080,8081);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) exit(0);

port = get_kb_item("Services/http_proxy");
if (!port) port = 8080;
if (!get_port_state(port)) exit(0);

banner = get_http_banner(port:port);

if (banner && "DeleGate-Ver: " >< banner)
{
  headers = banner - strstr(banner, '\n\n');
  ver = strstr(headers, "DeleGate-Ver: ") - "DeleGate-Ver: ";
  if (ver) ver = ver - strstr(ver, '\n');
  if (ver && " (delay=" >< ver ) ver = ver - strstr(ver, " (delay=");

  # Versions < 9.7.5 are vulnerable
  if (ver =~ "^([0-8]\..*)|(9\.(([0-6]\..*)|7\.[0-4][^0-9]))") 
  {
      extra = 'According to its banner, the remote proxy is DeleGate version '+ ver + '.\n';
      security_warning(port:port,extra:extra);
  }
}
